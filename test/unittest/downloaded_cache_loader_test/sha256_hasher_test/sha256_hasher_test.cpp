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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <array>
#include <securec.h>
#include "sha256_hasher.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class SHA256HasherTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(SHA256HasherTest, SameUrl_SameHash_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    auto hash1 = SHA256Hasher::GenerateHash(url);
    auto hash2 = SHA256Hasher::GenerateHash(url);
    EXPECT_TRUE(SHA256Hasher::CompareHash(hash1, hash2));
}

HWTEST_F(SHA256HasherTest, DifferentUrl_DifferentHash_001, TestSize.Level0)
{
    std::string url1 = "http://example.com/test1.mp4";
    std::string url2 = "http://example.com/test2.mp4";
    auto hash1 = SHA256Hasher::GenerateHash(url1);
    auto hash2 = SHA256Hasher::GenerateHash(url2);
    EXPECT_FALSE(SHA256Hasher::CompareHash(hash1, hash2));
}

HWTEST_F(SHA256HasherTest, EmptyUrl_001, TestSize.Level0)
{
    std::string url = "";
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashStr = SHA256Hasher::HashToString(hash);
    EXPECT_EQ(hashStr.length(), 64);
}

HWTEST_F(SHA256HasherTest, HashToString_Format_001, TestSize.Level0)
{
    std::string url = "test";
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashStr = SHA256Hasher::HashToString(hash);
    EXPECT_EQ(hashStr.length(), 64);
    for (char c : hashStr) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

HWTEST_F(SHA256HasherTest, HashToString_Consistent_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string str1 = SHA256Hasher::HashToString(hash);
    std::string str2 = SHA256Hasher::HashToString(hash);
    EXPECT_EQ(str1, str2);
}

HWTEST_F(SHA256HasherTest, HashArray_Size_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    auto hash = SHA256Hasher::GenerateHash(url);
    EXPECT_EQ(hash.size(), 32);
}

HWTEST_F(SHA256HasherTest, SpecialCharUrl_001, TestSize.Level0)
{
    std::string url = "http://example.com/test?param=value&foo=bar#anchor";
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashStr = SHA256Hasher::HashToString(hash);
    EXPECT_EQ(hashStr.length(), 64);
}

HWTEST_F(SHA256HasherTest, LongUrl_001, TestSize.Level0)
{
    std::string url = "http://example.com/" + std::string(500, 'a') + ".mp4";
    auto hash1 = SHA256Hasher::GenerateHash(url);
    auto hash2 = SHA256Hasher::GenerateHash(url);
    EXPECT_TRUE(SHA256Hasher::CompareHash(hash1, hash2));
}

HWTEST_F(SHA256HasherTest, Utf8Url_001, TestSize.Level0)
{
    std::string url = "http://example.com/\xe4\xb8\xad\xe6\x96\x87.mp4";
    auto hash = SHA256Hasher::GenerateHash(url);
    std::string hashStr = SHA256Hasher::HashToString(hash);
    EXPECT_EQ(hashStr.length(), 64);
}

HWTEST_F(SHA256HasherTest, CompareHash_SameArray_001, TestSize.Level0)
{
    std::array<uint8_t, 32> hash = {};
    for (int i = 0; i < 32; i++) {
        hash[i] = static_cast<uint8_t>(i);
    }
    EXPECT_TRUE(SHA256Hasher::CompareHash(hash, hash));
}

HWTEST_F(SHA256HasherTest, CompareHash_DifferentArray_001, TestSize.Level0)
{
    std::array<uint8_t, 32> hash1 = {};
    std::array<uint8_t, 32> hash2 = {};
    for (int i = 0; i < 32; i++) {
        hash1[i] = static_cast<uint8_t>(i);
        hash2[i] = static_cast<uint8_t>(i + 1);
    }
    EXPECT_FALSE(SHA256Hasher::CompareHash(hash1, hash2));
}

HWTEST_F(SHA256HasherTest, CompareHash_OneDiff_001, TestSize.Level0)
{
    std::array<uint8_t, 32> hash1 = {};
    std::array<uint8_t, 32> hash2 = {};
    for (int i = 0; i < 32; i++) {
        hash1[i] = static_cast<uint8_t>(i);
        hash2[i] = static_cast<uint8_t>(i);
    }
    hash2[31] = 255;
    EXPECT_FALSE(SHA256Hasher::CompareHash(hash1, hash2));
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS