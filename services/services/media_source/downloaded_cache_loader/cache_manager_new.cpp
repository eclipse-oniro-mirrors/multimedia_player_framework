/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <sys/stat.h>
#include <filesystem>
#include <cstring>
#include "cache_manager.h"
#include "cache_mapping_format.h"
#include "path_validator.h"
#include "sha256_hasher.h"
#include "common/log.h"
#include "media_log.h"

namespace fs = std::filesystem;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedCacheManager"};
const std::string CACHE_MAPPING_FILE = "cache_mapping.txt";
const size_t MAX_CACHE_MAPPING_FILE_SIZE = 10ULL * 1024ULL * 1024ULL;
}

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class MemoryReader {
public:
    MemoryReader(const std::vector<uint8_t>& buffer)
        : buffer_(buffer), offset_(0) {}
    
    bool Read(void* dest, size_t size) {
        if (offset_ + size > buffer_.size()) {
            return false;
        }
        std::memcpy(dest, buffer_.data() + offset_, size);
        offset_ += size;
        return true;
    }
    
    size_t GetOffset() const { return offset_; }
    size_t GetSize() const { return buffer_.size(); }
    bool HasMore() const { return offset_ < buffer_.size(); }

private:
    const std::vector<uint8_t>& buffer_;
    size_t offset_;
};

DownloadedCacheManager::DownloadedCacheManager(const std::string& cacheDir)
    : cacheDir_(cacheDir)
{
    LoadMapping();
    LoadIndex();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create, cacheDir: %{public}s", 
               FAKE_POINTER(this), cacheDir_.c_str());
}

void DownloadedCacheManager::LoadMapping()
{
    CreateDirectories(cacheDir_);
    cacheSize_.store(ScanDirectorySize(cacheDir_), std::memory_order_relaxed);
    std::string path = cacheDir_ + "/" + CACHE_MAPPING_FILE;
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        MEDIA_LOGE("Failed to open cache mapping file: %{public}s", path.c_str());
        return;
    }
    
    auto fileSize = file.tellg();
    if (fileSize == 0 || static_cast<size_t>(fileSize) > MAX_CACHE_MAPPING_FILE_SIZE) {
        MEDIA_LOGI("Mapping file is empty or too large");
        file.close();
        return;
    }
    
    fileBuffer_.resize(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(fileBuffer_.data()), fileSize);
    file.close();
    
    isLoaded_ = true;
    MEDIA_LOGI("Successfully loaded cache mapping file, size: %{public}zu", static_cast<size_t>(fileSize));
}

DownloadedCacheManager::~DownloadedCacheManager()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void DownloadedCacheManager::LoadIndex()
{
    if (!isLoaded_ || fileBuffer_.empty()) {
        MEDIA_LOGW("File buffer not loaded, cannot build index");
        return;
    }
    
    MemoryReader reader(fileBuffer_);
    
    CacheMappingHeader header;
    if (!reader.Read(header.magic, sizeof(header.magic)) ||
        !reader.Read(&header.version, sizeof(header.version)) ||
        !reader.Read(&header.entryCount, sizeof(header.entryCount)) ||
        !reader.Read(header.reserved, sizeof(header.reserved)) ||
        !reader.Read(&header.headerChecksum, sizeof(header.headerChecksum))) {
        MEDIA_LOGE("Failed to read mapping header");
        return;
    }
    
    if (std::memcmp(header.magic, CACHE_MAPPING_MAGIC, 4) != 0) {
        MEDIA_LOGE("Invalid magic number: %{public}c%c%c%c", 
                   header.magic[0], header.magic[1], header.magic[2], header.magic[3]);
        return;
    }
    
    if (header.version != CACHE_MAPPING_VERSION) {
        MEDIA_LOGE("Unsupported version: %{public}u", header.version);
        return;
    }
    
    uint32_t calculatedChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);
    if (header.headerChecksum != calculatedChecksum) {
        MEDIA_LOGE("Header checksum mismatch");
        fs::remove_all(cacheDir_);
        index_.clear();
        LoadMapping();
        return;
    }
    
    for (uint32_t i = 0; i < header.entryCount; ++i) {
        CacheMappingEntry entry;
        
        if (!reader.Read(entry.header.urlHash, sizeof(entry.header.urlHash)) ||
            !reader.Read(&entry.header.pathLength, sizeof(entry.header.pathLength)) ||
            !reader.Read(&entry.header.fileSize, sizeof(entry.header.fileSize)) ||
            !reader.Read(entry.header.reserved, sizeof(entry.header.reserved))) {
            MEDIA_LOGW("Failed to read entry %{public}u header, skipping", i);
            break;
        }
        
        if (entry.header.pathLength > reader.GetSize() - reader.GetOffset()) {
            MEDIA_LOGW("Invalid path length %{public}u at entry %{public}u", 
                      entry.header.pathLength, i);
            break;
        }
        
        entry.filePath.resize(entry.header.pathLength);
        if (!reader.Read(&entry.filePath[0], entry.header.pathLength)) {
            MEDIA_LOGW("Failed to read entry %{public}u path, skipping", i);
            break;
        }
        
        if (!PathValidator::Validate(cacheDir_, entry.filePath)) {
            MEDIA_LOGW("Skipping entry %{public}u with invalid path", i);
            continue;
        }
        
        std::array<uint8_t, 32> hashArr;
        std::memcpy(hashArr.data(), entry.header.urlHash, 32);
        std::string key = SHA256Hasher::HashToString(hashArr);
        
        index_[key].push_back(entry);
    }
}

void DownloadedCacheManager::ReleaseMap()
{
    std::unique_lock<std::mutex> lock(mutex_);
    fileBuffer_.clear();
    isLoaded_ = false;
    MEDIA_LOGD("0x%{public}06" PRIXPTR "ReleaseMap", FAKE_POINTER(this));
}

std::string DownloadedCacheManager::GetMediaCache(const std::string& url)
{
    if (!isLoaded_) {
        LoadMapping();
        LoadIndex();
    }
    std::unique_lock<std::mutex> lock(mutex_);
    
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string key = SHA256Hasher::HashToString(hash);
    
    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end() && !it->second.empty(), "",
        "directory corresponding to the url does not exist");
    
    const CacheMappingEntry& entry = it->second[0];
    std::string relativePath = entry.filePath;
    
    CHECK_AND_RETURN_RET_LOG(!relativePath.empty() && 
        relativePath.find("..") == std::string::npos, "",
        "get media cache file failed: invalid path");
    
    std::string path = cacheDir_ + "/" + relativePath;
    
    return path;
}

bool DownloadedCacheManager::GetCacheMetaData(const std::string& url, CacheMetaData& metadata)
{
    if (!isLoaded_) {
        LoadMapping();
        LoadIndex();
    }
    std::unique_lock<std::mutex> lock(mutex_);
    
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string key = SHA256Hasher::HashToString(hash);
    
    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end() && !it->second.empty(), false,
        "Cache not found for url: %{public}s", url.c_str());
    
    const CacheMappingEntry& entry = it->second[0];
    
    metadata.url = url;
    metadata.size = entry.header.fileSize;
    metadata.type = "application/octet-stream";
    metadata.randomAccess = true;
    metadata.entry = entry.filePath;
    
    return true;
}

std::map<std::string, std::string> DownloadedCacheManager::BuildHttpHeaders(const std::string& url)
{
    CacheMetaData metadata;
    if (!GetCacheMetaData(url, metadata)) {
        MEDIA_LOGE("Failed to get cache metadata for url: %{public}s", url.c_str());
        return {};
    }
    
    std::map<std::string, std::string> headers;
    headers["content-length"] = std::to_string(metadata.size);
    headers["content-type"] = metadata.type;
    
    if (metadata.randomAccess) {
        headers["accept-ranges"] = "bytes";
    }
    
    return headers;
}

bool DownloadedCacheManager::CreateDirectories(const std::string& path)
{
    CHECK_AND_RETURN_RET_LOG(!fs::exists(path) || !fs::is_directory(path), true, "directory exists");
    std::error_code ec;
    bool success = fs::create_directories(path, ec);
    CHECK_AND_RETURN_RET_LOG(success, false, "create_directories error:%{public}s", ec.message().c_str());
    return success;
}

uint64_t DownloadedCacheManager::ScanDirectorySize(const std::string& path)
{
    uint64_t totalSize = 0;
    CHECK_AND_RETURN_RET_LOG(fs::exists(path) && fs::is_directory(path), 0,
        "file not exist or is not directory");
    
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(entry.status())) {
            totalSize += fs::file_size(entry);
        }
    }

    return totalSize;
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS