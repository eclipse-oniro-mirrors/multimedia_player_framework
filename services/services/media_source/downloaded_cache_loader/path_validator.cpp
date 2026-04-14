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

#include "path_validator.h"
#include "common/log.h"
#include "media_log.h"
#include <algorithm>
#include <sstream>

namespace OHOS {
namespace Media {
namespace DownloadedCache {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedCachePathValidator"};
}

bool PathValidator::Validate(const std::string& rootPath, const std::string& relativePath)
{
    if (relativePath.length() > MAX_PATH_LENGTH) {
        MEDIA_LOGE("Path exceeds max length: %{public}zu", relativePath.length());
        return false;
    }

    if (ContainsIllegalCharacters(relativePath)) {
        MEDIA_LOGE("Path contains illegal characters");
        return false;
    }

    std::string resolvedPath = NormalizePath(rootPath + "/" + relativePath);

    std::string normalizedRoot = NormalizePath(rootPath);

    if (resolvedPath.length() < normalizedRoot.length()) {
        MEDIA_LOGE("Resolved path shorter than root path");
        return false;
    }

    if (resolvedPath.substr(0, normalizedRoot.length()) != normalizedRoot) {
        MEDIA_LOGE("Path escapes root directory");
        return false;
    }

    return true;
}

std::string PathValidator::NormalizePath(const std::string& path)
{
    std::vector<std::string> components;
    std::stringstream ss(path);
    std::string component;

    while (std::getline(ss, component, '/')) {
        if (component.empty() || component == ".") {
            continue;
        }
        if (component == "..") {
            if (!components.empty()) {
                components.pop_back();
            }
        } else {
            components.push_back(component);
        }
    }

    std::string result;
    for (const auto& comp : components) {
        if (!result.empty()) {
            result += "/";
        }
        result += comp;
    }

    return result;
}

bool PathValidator::IsPathEscaped(const std::string& resolvedPath, const std::string& rootPath)
{
    if (resolvedPath.length() < rootPath.length()) {
        return true;
    }
    if (resolvedPath.compare(0, rootPath.length(), rootPath) != 0) {
        return true;
    }
    if (resolvedPath.length() > rootPath.length() &&
        resolvedPath[rootPath.length()] != '/') {
        return true;
    }
    return false;
}

bool PathValidator::ContainsIllegalCharacters(const std::string& path)
{
    for (char c : path) {
        if (static_cast<unsigned char>(c) < 32) {
            if (c != '\t' && c != '\n' && c != '\r') {
                MEDIA_LOGE("Path contains control character: 0x%{public}02X",
                           static_cast<uint8_t>(c));
                return true;
            }
        }
    }
    return false;
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS