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

#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <securec.h>
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
}

namespace OHOS {
namespace Media {
namespace DownloadedCache {

DownloadedCacheManager::DownloadedCacheManager(const std::string& cacheDir)
    : cacheDir_(cacheDir)
{
    LoadCacheMapping();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create, cacheDir: %{public}s",
        FAKE_POINTER(this), cacheDir_.c_str());
}

DownloadedCacheManager::~DownloadedCacheManager()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void DownloadedCacheManager::LoadCacheMapping()
{
    CreateDirectories(cacheDir_);
    std::string path = cacheDir_ + "/" + CACHE_MAPPING_FILE;

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        MEDIA_LOGE("Failed to open cache mapping file: %{public}s", path.c_str());
        return;
    }

    CacheMappingHeader header;
    if (!CacheMappingDeserializer::ReadHeader(file, header)) {
        MEDIA_LOGE("Failed to read mapping header");
        return;
    }

    if (!CacheMappingDeserializer::ValidateHeader(header)) {
        MEDIA_LOGE("Cache mapping file validation failed");
        return;
    }

    std::vector<uint8_t> playbackParamData;
    if (!CacheMappingDeserializer::ReadPlaybackParamData(file, playbackParamData)) {
        MEDIA_LOGW("Failed to read playback param data");
        return;
    }
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    if (!PlayStrategySerializer::Deserialize(playbackParamData, rootUrl_, strategy, filter)) {
        MEDIA_LOGW("Failed to deserialize playback param data");
        return;
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " load root url: %{public}s", FAKE_POINTER(this), rootUrl_.c_str());

    for (uint32_t i = 0; i < header.entryCount; ++i) {
        CacheMappingEntry entry;
        if (!CacheMappingDeserializer::ReadEntry(file, entry, cacheDir_)) {
            MEDIA_LOGW("Failed to read entry %{public}u, skipping", i);
            break;
        }

        std::array<uint8_t, SHA256_LEN> hashArr;
        errno_t ret = memcpy_s(hashArr.data(), SHA256_LEN, entry.header.urlHash, SHA256_LEN);
        if (ret != EOK) {
            MEDIA_LOGW("Skipping entry %{public}u with memcpy_s failed", i);
            continue;
        }

        std::string hashIndex = SHA256Hasher::HashToString(hashArr);
        index_[hashIndex] = entry;
        MEDIA_LOGI("0x%{public}06" PRIXPTR " load entry: %{public}s", FAKE_POINTER(this), hashIndex.c_str());
    }
}

std::string DownloadedCacheManager::GetMediaCache(const std::string& url)
{
    std::unique_lock<std::mutex> lock(mutex_);

    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashIndex = SHA256Hasher::HashToString(hash);

    auto it = index_.find(hashIndex);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), "", "Cache not found for url: %{public}s", url.c_str());

    MEDIA_LOGI("0x%{public}06" PRIXPTR " search entry: %{public}s", FAKE_POINTER(this), hashIndex.c_str());
    const CacheMappingEntry& entry = it->second;
    std::string relativePath = entry.filePath;

    std::string path = cacheDir_ + "/" + relativePath;

    return path;
}

bool DownloadedCacheManager::GetCacheMetaData(const std::string& url, CacheMetaData& metadata)
{
    std::unique_lock<std::mutex> lock(mutex_);

    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashIndex = SHA256Hasher::HashToString(hash);

    auto it = index_.find(hashIndex);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), false, "Cache meta not found for url: %{public}s", url.c_str());

    MEDIA_LOGI("0x%{public}06" PRIXPTR " search meta entry: %{public}s", FAKE_POINTER(this), hashIndex.c_str());
    const CacheMappingEntry& entry = it->second;

    metadata.url = url;
    metadata.size = static_cast<int64_t>(entry.header.fileSize);
    if (metadata.size == 0) {
        std::string fullPath = cacheDir_ + "/" + entry.filePath;
        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0 && st.st_size > 0) {
            metadata.size = static_cast<int64_t>(st.st_size);
        }
    }
    metadata.type = "application/octet-stream";
    metadata.randomAccess = true;
    metadata.entry = entry.filePath;

    return true;
}

std::map<std::string, std::string> DownloadedCacheManager::BuildHttpHeaders(const std::string& url, int64_t fileSize)
{
    CacheMetaData metadata;
    if (!GetCacheMetaData(url, metadata)) {
        MEDIA_LOGE("Failed to get cache metadata for url: %{public}s", url.c_str());
        return {};
    }

    std::map<std::string, std::string> headers;
    headers["content-length"] = std::to_string(fileSize);
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

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS