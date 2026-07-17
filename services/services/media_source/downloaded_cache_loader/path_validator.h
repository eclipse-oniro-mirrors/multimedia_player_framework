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

#ifndef DOWNLOADED_CACHE_PATH_VALIDATOR_H
#define DOWNLOADED_CACHE_PATH_VALIDATOR_H

#include <string>

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class PathValidator {
public:
    static bool Validate(const std::string& rootPath, const std::string& relativePath);
    static constexpr size_t MAX_PATH_LENGTH = 1024;

private:
    static bool ContainsIllegalCharacters(const std::string& path);
    static bool IsPathEscaped(const std::string& resolvedPath, const std::string& rootPath);
    static std::string NormalizePath(const std::string& path);
};

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_CACHE_PATH_VALIDATOR_H