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

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "cache_manager.h"
#include "cache_mapping_format.h"
#include "cache_mapping_serializer.h"
#include "cache_mapping_format.h"
#include "media_log.h"

namespace fs = std::experimental::filesystem;
using namespace std::chrono;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DownloadedCacheManager"};
constexpr int64_t TIMER_INIT = 10;
constexpr uint32_t FILED_COUNT = 7;
constexpr uint32_t MAX_FILED_COUNT = 7;
constexpr uint32_t VERSION = 1;
constexpr uint64_t MAX_CACHE_FILE_SIZE = 4ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr uint64_t CACHE_FILE_SIZE_WATERLINE = 3ULL * 1024ULL * 1024ULL * 1024ULL;
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
    if (fileSize == 0) {
        MEDIA_LOGI("Mapping file is empty");
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

    const uint8_t* ptr = fileBuffer_.data();
    size_t fileSize = fileBuffer_.size();
    size_t offset = 0;

    while (offset < fileSize) {
        CHECK_AND_RETURN_LOG(offset + sizeof(CacheMappingHeader) < fileSize,
            "header size exceed file size");
        const CacheMappingHeader* header = reinterpret_cast<const CacheMappingHeader*>(ptr + offset);
        CHECK_AND_RETURN_LOG(header != nullptr, "reinterpret_cast CacheMappingHeader is null");

        if (header->entryCount > MAX_FILED_COUNT) {
            MEDIA_LOGE("file corruption cleans up directory");
            fs::remove_all(CACHE_DIR);
            index_.clear();
            entryIndex_.clear();
            LoadMapping();
            return;
        }

        size_t fieldsSize = header->entryCount * sizeof(CacheMappingEntryHeader);
        CHECK_AND_RETURN_LOG(offset + sizeof(CacheMappingHeader) + fieldsSize < fileSize,
            "fieldSize exceeds file size, fieldCount:%{public}d", header->entryCount);

        const CacheMappingEntryHeader* fields = reinterpretation_cast<const CacheMappingEntryHeader*>(ptr + offset + sizeof(CacheMappingHeader));
        size_t totalSize = sizeof(CacheMappingHeader) + fieldsSize;
        for (uint32_t i = 0; i < header->entryCount; ++i) {
            totalSize += fields[i].fileSize;
        }

        std::string key;
        std::memcpy(&key[0], fields[0].urlHash, 8);

        std::string entry;
        std::memcpy(&entry[0], fields[0].urlHash + 8, 24);

        entryIndex_[entry] = "0";
        index_[key].emplace_back(offset, totalSize);

        offset += totalSize;
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
    std::string key;
    std::memcpy(&key[0], SHA256Hasher::GenerateHash(url).data(), 8);

    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), "",
        "directory corresponding to the url does not exist");

    CacheEntryInfo info;
    CHECK_AND_RETURN_RET_LOG(FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL),
        "", "directory corresponding to the url does not exist");

    std::string entry;
    std::memcpy(&entry[0], it->second[0].urlHash + 8, 24);

    CHECK_AND_RETURN_RET_LOG(!entry.empty() && entry.find("..") == std::string::npos
        && entry.find('/') == std::string::npos && entry.find('\\') == std::string::npos,
        "", "get media cache file failed");

    std::string path = CACHE_DIR + fs::path::preferred_separator + entry;
    CreateDirectories(path.c_str());

    return path;
}

bool DownloadedCacheManager::GetCacheMetaData(const std::string& url, CacheMetaData& metadata)
{
    if (!isLoaded_) {
        LoadMapping();
        LoadIndex();
    }
    std::unique_lock<std::mutex> lock(mutex_);
    std::string key;
    std::memcpy(&key[0], SHA256Hasher::GenerateHash(url).data(), 8);

    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), false,
        "Cache not found for url: %{public}s", url.c_str());

    CacheEntryInfo info;
    CHECK_AND_RETURN_RET_LOG(FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL),
        false, "Failed to find cache entry for url: %{public}s", url.c_str());

    const CacheMappingEntryHeader* header = reinterpretation_cast<const CacheMappingEntryHeader*>(fileBuffer_.data() + info.offset);

    metadata.type = "application/octet-stream";
    metadata.randomAccess = true;
    metadata.size = header->fileSize;
    metadata.url = url;

    std::string entry;
    std::memcpy(&entry[0], header->urlHash + 8, 24);
    metadata.entry = entry;

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

std::string DownloadedCacheManager::ExtractField(const uint8_t* buffer, size_t bufferSize,
                                             size_t entryOffset, uint32_t fieldCount, CacheFieldId targetId)
{
    if (entryOffset + sizeof(CacheMappingHeader) >= bufferSize) {
        return "";
    }

    const CacheMappingHeader* header = reinterpretation_cast<const CacheMappingHeader*>(buffer + entryOffset);
    const CacheMappingEntryHeader* fields = reinterpretation_cast<const CacheMappingEntryHeader*>(buffer + entryOffset + sizeof(CacheMappingHeader));

    size_t contentOffset = sizeof(CacheMappingHeader) + (fieldCount * sizeof(CacheMappingEntryHeader));
    for (uint32_t i = 0; i < fieldCount; ++i) {
        if (fields[i].urlHash[0] == static_cast<uint8_t>(targetId)) {
            if (contentOffset + fields[i].fileSize > bufferSize) {
                MEDIA_LOGE("Field content exceeds buffer size");
                return "";
            }
            return std::string(reinterpret_cast<const char*>(buffer + entryOffset + contentOffset), fields[i].fileSize);
        }
        contentOffset += fields[i].fileSize;
    }

    return "";
}

bool DownloadedCacheManager::FindFirstEqualField(const std::vector<CacheEntryInfo>& entries,
    CacheEntryInfo& result, const std::string& value, CacheFieldId field)
{
    if (fileBuffer_.empty()) {
        MEDIA_LOGE("File buffer is empty");
        return false;
    }

    auto it = std::find_if(entries.begin(), entries.end(),
        [&](const CacheEntryInfo& info) {
            const CacheMappingHeader* header =
                reinterpret_cast<const CacheMappingHeader*>(fileBuffer_.data() + info.offset);
            std::string target = ExtractField(fileBuffer_.data(), fileBuffer_.size(),
                                           info.offset, header->entryCount, field);
            return target == value;
        });

    if (it != entries.end()) {
        result = *it;
        return true;
    }
    return false;
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

std::string DownloadedCacheManager::GetPrefixBeforeUnderscore(const std::string& str)
{
    size_t pos = str.find('_');
    CHECK_AND_RETURN_RET_NOLOG(pos != std::string::npos, str);
    return str.substr(0, pos);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS