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

#ifndef DOWNLOADED_FILE_CACHE_MANAGER_H
#define DOWNLOADED_FILE_CACHE_MANAGER_H

#include <string>
#include <cstdint>
#include <memory>

namespace OHOS {
namespace Media {
namespace DownloadedCache {
class DownloadedFileCacheManager {
public:
    explicit DownloadedFileCacheManager(const std::string& cacheDir);

    int32_t Read(const std::string& path, void* buffer, int64_t offset, int64_t size);
    int64_t GetSize(const std::string& path);

private:
    bool IsValidPath(const std::string& inputPath);
    
    std::string cacheDir_;
};
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_FILE_CACHE_MANAGER_H
