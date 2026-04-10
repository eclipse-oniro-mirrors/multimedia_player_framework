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

#ifndef CACHE_MANAGER_H
#define CACHE_MANAGER_H

#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <atomic>
#include <memory>
#include <cstdint>
#include <unordered_map>

#include "cache_mapping_format.h"

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
    static std::shared_ptr<DownloadedCacheManager> Create();
    DownloadedCacheManager();
    ~DownloadedCacheManager();

    std::string GetMediaCache(const std::string& url);
    void ReleaseMap();
    bool GetCacheMetaData(const std::string& url, CacheMetaData& metadata);
    std::map<std::string, std::string> BuildHttpHeaders(const std::string& url);

 private:
    void LoadIndex();
    bool CreateDirectories(const std::string& path);
    uint64_t ScanDirectorySize(const std::string& path);
    void LoadMapping();

    static std::shared_ptr<DownloadedCacheManager> cacheManager_;
    static std::once_flag onceFlag_;

    std::vector<uint8_t> fileBuffer_;
    bool isLoaded_ = false;

    std::unordered_map<std::string, std::string> entryIndex_;
    std::unordered_map<std::string, std::vector<CacheMappingEntry>> index_;
    std::mutex mutex_;
    std::atomic<uint64_t> cacheSize_;
};
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
#endif