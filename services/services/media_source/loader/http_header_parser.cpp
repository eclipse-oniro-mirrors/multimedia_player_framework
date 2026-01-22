/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <sstream>
#include "http_header_parser.h"
#include "common/log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "HttpHeaderParser"};
}

void HttpHeaderParser::ParseHttpHeader(std::map<std::string, std::string>& headerMap,
    const std::string& header)
{
    FALSE_RETURN_MSG(!header.empty(), "header is empty");

    std::istringstream stream(header);
    std::string line;
    while (std::getline(stream, line)) {
        // Remove line breaks
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            break; // Empty line indicates end of header
        }

        // Ignore status lines starting with HTTP/
        if (line.size() >= 5 && line.substr(0, 5) == "HTTP/") {
            continue;
        }

        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            key = TrimWhitespace(key);
            value = TrimWhitespace(value);
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            headerMap[key] = value;
        }
    }
}

std::string HttpHeaderParser::TrimWhitespace(const std::string& str)
{
    auto start = str.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }

    auto end = str.find_last_not_of(" \t");
    return str.substr(start, end - start + 1);
}
} // namespace Media
} // namespace OHOS