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
#include "cache_manager.h"
#include "cache_mapping_format.h"
#include "path_validator.h"
#include "sha256_hasher.h"
#include "cache_mapping_serializer.cpp"
#include "media_log.h"

namespace fs = std::experimental::filesystem;

namespace {
constexpr int64_t TIMER_INIT = 10;
constexpr uint64_t MAX_CACHE_FILE_SIZE = 4ULL * 1024ULL * 1024ULL;
constexpr uint64_t CACHE_FILE_SIZE_WATERLINE = 3ULL * 1024ULL * 1024ULL;
constexpr uint64_t NEED_REMOVE_CACHE_SIZE = 800ULL * 1024ULL * 1024ULL;
constexpr std::string CACHE_DIR = "/data/storage/el2/base/cache/avplayer_downloaded_cache";
constexpr std::string CACHE_MAPPING_FILE = "cache_mapping.txt";
constexpr size_t MAX_CACHE_MAPPING_FILE_SIZE = 10ULL * 1024ULL * 1024ULL;
}

namespace OHOS {
namespace Media {
namespace DownloadedCache {
std::once_flag DownloadedCacheManager::onceFlag_;
std::shared_ptr<DownloadedCacheManager> DownloadedCacheManager::cacheManager_;

std::shared_ptr<DownloadedCacheManager> DownloadedCacheManager::Create()
{
    std::call_once(onceFlag_, [] {
        cacheManager_ = std::make_shared<DownloadedCacheManager>();
        MEDIA_LOGI("createManager success");
    });
    return cacheManager_;
}

DownloadedCacheManager::DownloadedCacheManager()
{
    LoadMapping();
    LoadIndex();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

void DownloadedCacheManager::LoadMapping()
{
    CreateDirectories(CACHE_DIR);
    cacheSize_.store(ScanDirectorySize(CACHE_DIR), std::memory_order_relaxed);
    std::string path = CACHE_DIR + fs::path::preferred_separator + CACHE_MAPPING_FILE;
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        MEDIA_LOGE("Failed to open cache mapping file: %{public}s", path.c_str());
        return;
    }
    
    auto fileSize = file.tellg();
    if (fileSize == 0 || fileSize > MAX_CACHE_MAPPING_FILE_SIZE) {
        MEDIA_LOGI("Mapping file is empty or too large");
        file.close();
        return;
    }
    
    fileBuffer_.resize(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(fileBuffer_.data()), fileSize);
    file.close();
    
    isLoaded_ = true;
    MEDIA_LOGI("Successfully loaded cache mapping file, size: %{public}zu", fileSize);
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
    
    std::ifstream file;
    file.rdbuf()->pubsetbuf(reinterpret_cast<char*>(fileBuffer_.data()), fileBuffer_.size());
    
    CacheMappingHeader header;
    if (!CacheMappingDeserializer::ReadHeader(file, header)) {
        MEDIA_LOGE("Failed to read mapping header");
        return;
    }
    
    if (!CacheMappingDeserializer::ValidateHeader(header)) {
        MEDIA_LOGE("Invalid mapping header");
        fs::remove_all(CACHE_DIR);
        index_.clear();
        entryIndex_.clear();
        LoadMapping();
        return;
    }
    
    for (uint32_t i = 0; i < header.entryCount; ++i) {
        CacheMappingEntry entry;
        if (!CacheMappingDeserializer::ReadEntry(file, entry)) {
            MEDIA_LOGW("Failed to read entry %{public}u, skipping", i);
            continue;
        }
        
        std::string key = SHA256Hasher::HashToString(
            std::array<uint8_t, 32>(entry.header.urlHash, entry.header.urlHash + 32));
        
        index_[key].push_back(entry);
        entryIndex_[entry.filePath] = key;
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
        relativePath.find("..") == std::string::npos &&
        relativePath.find('/') != std::string::npos, "",
        "get media cache file failed: invalid path");
    
    std::string path = CACHE_DIR + fs::path::preferred_separator + relativePath;
    
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