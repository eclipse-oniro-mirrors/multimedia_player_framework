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

#ifndef FILE_CAHE_MANAGER_H
#define FILE_CAHE_MANAGER_H

#include <string>
#include <cstdint>

namespace OHOS {
namespace Media {
namespace DownloadedCache {
class DownloadedFileCacheManager {
public:
    static std::shared_ptr<DownloadedFileCacheManager> Create();

    int32_t Read(const std::string& path, void* buffer, int64_t offset, int64_t size);
    int64_t GetSize(const std::string& path);

private:
    bool IsValidPath(const std::string& inputPath);
};
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // FILE_CAHE_MANAGER_H
