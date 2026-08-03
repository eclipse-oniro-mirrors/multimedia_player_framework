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

#ifndef MEDIA_SOURCE_PATH_UTILS_H
#define MEDIA_SOURCE_PATH_UTILS_H

#include <string>

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

enum PathValidateResult : int32_t {
    PATH_VALIDATE_OK = 0,
    PATH_VALIDATE_ERROR_EMPTY = -1,
    PATH_VALIDATE_ERROR_TRAVERSAL = -2,
    PATH_VALIDATE_ERROR_NOT_ABSOLUTE = -3,
    PATH_VALIDATE_ERROR_REALPATH_FAILED = -4,
};

class PathUtils {
public:
    static PathValidateResult ValidateAndNormalizePath(const std::string &path, std::string &normalizedPath);
    static bool IsPathTraversalSafe(const std::string &path);
};

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SOURCE_PATH_UTILS_H
