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

#include "path_utils.h"

#include <climits>
#include <cstring>
#include <unistd.h>

#include "common/log.h"

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "PathUtils"};
}

bool PathUtils::IsPathTraversalSafe(const std::string &path)
{
    return path.find("..") == std::string::npos;
}

PathValidateResult PathUtils::ValidateAndNormalizePath(const std::string &path, std::string &normalizedPath)
{
    if (path.empty()) {
        MEDIA_LOGE("ValidateAndNormalizePath failed: path is empty");
        return PATH_VALIDATE_ERROR_EMPTY;
    }

    if (!IsPathTraversalSafe(path)) {
        MEDIA_LOGE("ValidateAndNormalizePath failed: path contains traversal sequence");
        return PATH_VALIDATE_ERROR_TRAVERSAL;
    }

    if (path[0] != '/') {
        MEDIA_LOGE("ValidateAndNormalizePath failed: path is not absolute");
        return PATH_VALIDATE_ERROR_NOT_ABSOLUTE;
    }

    char resolved[PATH_MAX] = {0};
    if (realpath(path.c_str(), resolved) != nullptr) {
        normalizedPath = resolved;
        return PATH_VALIDATE_OK;
    }

    size_t lastSlash = path.find_last_of('/');
    std::string parentDir = (lastSlash == 0) ? "/" : path.substr(0, lastSlash);
    char resolvedParent[PATH_MAX] = {0};
    if (realpath(parentDir.c_str(), resolvedParent) == nullptr) {
        MEDIA_LOGE("ValidateAndNormalizePath failed: parent dir realpath failed, errno=%{public}d", errno);
        return PATH_VALIDATE_ERROR_REALPATH_FAILED;
    }

    normalizedPath = resolvedParent;
    if (normalizedPath != "/") {
        normalizedPath += "/";
    }
    normalizedPath += path.substr(lastSlash + 1);
    return PATH_VALIDATE_OK;
}

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS
