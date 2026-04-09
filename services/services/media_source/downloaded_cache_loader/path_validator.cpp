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

#include "cache_mapping_format.h"
#include "../../../../utils/include/media_log.h"
#include <sstream>
#include <algorithm>
#include <limits>

namespace {
constexpr int PATH_MAX_VALUE = 4096;
}

using namespace std::chrono;

using namespace std::chrono;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

bool PathValidator::ValidateRelativePath(const std::string& path)
{
    if (path.empty()) {
        MEDIA_LOGE("Path is empty");
        return false;
    }
    
    if (path.size() > PATH_MAX) {
        MEDIA_LOGE("Path exceeds maximum length: %{public}zu", path.size());
        return false;
    }
    
    if (IsAbsolutePath(path)) {
        MEDIA_LOGE("Path is absolute (starts with /): %{public}s", path.c_str());
        return false;
    }
    
    if (ContainsIllegalCharacters(path)) {
        MEDIA_LOGE("Path contains illegal characters");
        return false;
    }
    
    if (HasPathTraversalAttack(path)) {
        MEDIA_LOGE("Path contains traversal attack patterns");
        return false;
    }
    
    return true;
}

bool PathValidator::IsAbsolutePath(const std::string& path)
{
    if (path.size() >= 1 && path[0] == '/') {
        MEDIA_LOGE("Path is absolute (starts with /): %{public}s", path.c_str());
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

bool PathValidator::HasPathTraversalAttack(const std::string& path)
{
    std::vector<std::string> components;
    std::stringstream ss(path);
    std::string component;
    
    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            components.push_back(component);
        }
    }
    
    for (const auto& comp : components) {
        if (!ValidatePathComponent(comp)) {
            MEDIA_LOGE("Invalid path component: %{public}s", comp.c_str());
            return true;
        }
    }
    
    return false;
}

bool PathValidator::ValidatePathComponent(const std::string& component)
{
    if (component.empty()) {
        return true;
    }
    
    if (component == "." || component == "..") {
        return true;
    }
    
    if (component.find("/../") != std::string::npos || 
        component.find("\\..\\") != std::string::npos) {
        MEDIA_LOGE("Component contains hidden traversal: %{public}s", component.c_str());
        return true;
    }
    
    if (component.find("%2e") != std::string::npos || 
        component.find("%2f") != std::string::npos) {
        MEDIA_LOGE("Component contains URL-encoded traversal: %{public}s", component.c_str());
        return true;
    }
    
    return false;
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS