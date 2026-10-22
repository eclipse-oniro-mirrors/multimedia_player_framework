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
#include <string>
#include "url_key_util.h"
#include "sha256_hasher.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class UrlKeyUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(UrlKeyUtilTest, Combine_DifferentCdn_SamePath_SameHashResult, TestSize.Level0)
{
    std::string key = "mykey";
    std::string url1 = "https://cdn1.example.com/path/video.m3u8";
    std::string url2 = "https://cdn2.example.com/path/video.m3u8";

    auto hash1 = SHA256Hasher::GenerateHash(UrlKeyUtil::Combine(key, url1));
    auto hash2 = SHA256Hasher::GenerateHash(UrlKeyUtil::Combine(key, url2));
    EXPECT_EQ(SHA256Hasher::HashToString(hash1), SHA256Hasher::HashToString(hash2));
}

HWTEST_F(UrlKeyUtilTest, Combine_EmptyKey_ReturnsOriginalUrl, TestSize.Level0)
{
    std::string key = "";
    std::string url = "https://cdn.example.com/path/video.m3u8";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, url);
}

HWTEST_F(UrlKeyUtilTest, Combine_UrlWithPort_StripsSchemeHostPort, TestSize.Level0)
{
    std::string key = "mykey";
    std::string url = "https://cdn.example.com:8080/path/video.m3u8";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey/path/video.m3u8");
}

HWTEST_F(UrlKeyUtilTest, Combine_UrlWithQuery_PreservesQuery, TestSize.Level0)
{
    std::string key = "mykey";
    std::string url = "https://cdn.example.com/path/video.m3u8?q=1";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey/path/video.m3u8?q=1");
}

HWTEST_F(UrlKeyUtilTest, Combine_UrlNoPath_HostOnly_ReturnsKeyOnly, TestSize.Level0)
{
    std::string key = "mykey";
    std::string url = "https://cdn.example.com";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey");
}

HWTEST_F(UrlKeyUtilTest, Combine_RelativeUrl_NoScheme_PrependsKey, TestSize.Level0)
{
    std::string key = "mykey";
    std::string url = "relative/path.ts";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykeyrelative/path.ts");
}

HWTEST_F(UrlKeyUtilTest, Combine_UrlWithFragment_PreservesFragment, TestSize.Level1)
{
    std::string key = "mykey";
    std::string url = "https://cdn.example.com/path/video.m3u8#frag";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey/path/video.m3u8#frag");
}

HWTEST_F(UrlKeyUtilTest, Combine_UrlRootPathOnly_ReturnsKeySlash, TestSize.Level1)
{
    std::string key = "mykey";
    std::string url = "https://cdn.example.com/";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey/");
}

HWTEST_F(UrlKeyUtilTest, Combine_EmptyUrl_ReturnsKeyOnly, TestSize.Level1)
{
    std::string key = "mykey";
    std::string url = "";

    std::string result = UrlKeyUtil::Combine(key, url);
    EXPECT_EQ(result, "mykey");
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
