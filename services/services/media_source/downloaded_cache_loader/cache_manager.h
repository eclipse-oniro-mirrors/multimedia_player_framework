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

#ifndef DOWNLOADED_CACHE_MANAGER_H
#define DOWNLOADED_CACHE_MANAGER_H

#include <string>
#include <map>
#include <mutex>
#include <cstdint>
#include <unordered_map>

#include "cache_mapping_format.h"
#include "media_source.h"
#include "play_strategy_serializer.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {

struct CacheMetaData {
    std::string type;
    bool randomAccess;
    int64_t size;
    std::string url;
    std::string entry;
};

class DownloadedCacheManager {
public:
    explicit DownloadedCacheManager(const std::string& cacheDir);
    ~DownloadedCacheManager();

    std::string GetCacheDir() const { return cacheDir_; }
    std::string GetRootUrl() const { return rootUrl_; }
    std::string GetMediaCache(const std::string& url);
    bool GetCacheMetaData(const std::string& url, CacheMetaData& metadata);
    std::map<std::string, std::string> BuildHttpHeaders(const std::string& url, int64_t fileSize);

private:
    void LoadCacheMapping();
    bool CreateDirectories(const std::string& path);

    std::string cacheDir_;
    std::string rootUrl_;
    std::unordered_map<std::string, CacheMappingEntry> index_;
    std::mutex mutex_;
};
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
#endif // DOWNLOADED_CACHE_MANAGER_H