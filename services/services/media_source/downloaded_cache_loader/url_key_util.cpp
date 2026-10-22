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

#include "url_key_util.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {

namespace {
constexpr size_t SCHEME_SEPARATOR_LEN = 3; // length of "://"
}

std::string UrlKeyUtil::Combine(const std::string& key, const std::string& url)
{
    if (key.empty()) {
        return url;
    }

    size_t schemeEnd = url.find("://");
    size_t pathStart;
    if (schemeEnd != std::string::npos && schemeEnd + SCHEME_SEPARATOR_LEN < url.size()) {
        size_t hostStart = schemeEnd + SCHEME_SEPARATOR_LEN;
        size_t pathPos = url.find_first_of("/?#", hostStart);
        pathStart = (pathPos != std::string::npos) ? pathPos : url.length();
    } else {
        pathStart = 0;
    }

    return key + url.substr(pathStart);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
