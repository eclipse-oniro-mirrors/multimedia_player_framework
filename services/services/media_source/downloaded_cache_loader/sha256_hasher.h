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

#ifndef DOWNLOADED_CACHE_SHA256_HASHER_H
#define DOWNLOADED_CACHE_SHA256_HASHER_H

#include <array>
#include <string>
#include <cstdint>

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class SHA256Hasher {
private:
    static constexpr int SHA256_LEN = 32;
public:
    static std::array<uint8_t, SHA256_LEN> GenerateHash(const std::string& url);
    static bool CompareHash(const std::array<uint8_t, SHA256_LEN>& hash1,
                       const std::array<uint8_t, SHA256_LEN>& hash2);
    static std::string HashToString(const std::array<uint8_t, SHA256_LEN>& hash);
};

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_CACHE_SHA256_HASHER_H