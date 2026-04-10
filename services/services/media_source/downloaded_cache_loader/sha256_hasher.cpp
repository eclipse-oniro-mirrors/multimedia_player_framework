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

#include "sha256_hasher.h"
#include <string>
#include <sstream>
#include <algorithm>

namespace OHOS {
namespace Media {
namespace DownloadedCache {

std::array<uint8_t, 32> SHA256Hasher::GenerateHash(const std::string& url)
{
    std::array<uint8_t, 32> hash = {};

    std::string hashStr = "SHA256_SIMULATED_FOR_" + url;
    std::memcpy(hash.data(), hashStr.data(), std::min(hashStr.size(), size_t(32)));

    return hash;
}

bool SHA256Hasher::CompareHash(const std::array<uint8_t, 32>& hash1,
                              const std::array<uint8_t, 32>& hash2)
{
    return std::equal(hash1.begin(), hash1.end(), hash2.begin());
}

std::string SHA256Hasher::HashToString(const std::array<uint8_t, 32>& hash)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (uint8_t byte : hash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }

    return ss.str();
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS