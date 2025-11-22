/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "uri_helper_unit_test.h"

#include <thread>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace Test {
void UriHelperUnitTest::SetUpTestCase(void) {}

void UriHelperUnitTest::TearDownTestCase(void) {}

void UriHelperUnitTest::SetUp(void) {}

void UriHelperUnitTest::TearDown(void) {}


HWTEST_F(UriHelperUnitTest, UriHelper_001, TestSize.Level0)
{
    std::string_view input = "   ";
    UriHelper uriHelper(input);
    ASSERT_EQ(uriHelper.formattedUri_, "");
}

HWTEST_F(UriHelperUnitTest, UriHelper_002, TestSize.Level0)
{
    std::string_view input = "http://www.example.com";
    UriHelper uriHelper(input);
    ASSERT_EQ(uriHelper.formattedUri_, "httpwww.example.com");
}

HWTEST_F(UriHelperUnitTest, UriHelper_003, TestSize.Level0)
{
    std::string_view input = "httpwww.example.com";
    UriHelper uriHelper(input);
    ASSERT_EQ(uriHelper.formattedUri_, "httpwww.example.com");
}

HWTEST_F(UriHelperUnitTest, UriHelper_004, TestSize.Level0)
{
    std::string_view input = "http://";
    UriHelper uriHelper(input);
    ASSERT_EQ(uriHelper.formattedUri_, "http");
}

/**
 * @tc.name: GetHostnameFromURL_001
 * @tc.desc: empty input
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_001, TestSize.Level0)
{
    std::string url = "";
    std::string expected = "";
    EXPECT_EQ(UriHelper::GetHostnameFromURL(url), expected);
}

/**
 * @tc.name: GetHostnameFromURL_002
 * @tc.desc: normal with protocol
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_002, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("http://example.com"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("https://example.com:8080"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("http://example.com/path"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("https://example.com?query=1"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("https://example.com/path?x=1"), "example.com");
}

/**
 * @tc.name: GetHostnameFromURL_003
 * @tc.desc: no protocol
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_003, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("example.com"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("//example.com/path"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("///example.com/path"), "example.com");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("a"), "a");
}

/**
 * @tc.name: GetHostnameFromURL_004
 * @tc.desc: edge case
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_004, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("http://"), "");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("http:///"), "");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("example.com:colon"), "example.com");
}

/**
 * @tc.name: GetHostnameFromURL_005
 * @tc.desc: back slash handling
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_005, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("\\\\server\\path"), "server");
    EXPECT_EQ(UriHelper::GetHostnameFromURL("http:\\\\example.com\\path"), "example.com");
}

/**
 * @tc.name: GetHostnameFromURL_006
 * @tc.desc: user password not handled
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_006, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("https://user:password@example.com:8080/path"), "user");
}

/**
 * @tc.name: GetHostnameFromURL_007
 * @tc.desc: file protocol
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetHostnameFromURL_007, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetHostnameFromURL("file:///C:Users/test"), "C");
}

/**
 * @tc.name: GetProtocolFromURL_001
 * @tc.desc: empty input
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetProtocolFromURL_001, TestSize.Level0)
{
    std::string url = "";
    std::string expected = "";
    EXPECT_EQ(UriHelper::GetProtocolFromURL(url), expected);
}

/**
 * @tc.name: GetProtocolFromURL_002
 * @tc.desc: protocol exist
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetProtocolFromURL_002, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetProtocolFromURL("http://example.com"), "http");
    EXPECT_EQ(UriHelper::GetProtocolFromURL("https://example.com:8080"), "https");
    EXPECT_EQ(UriHelper::GetProtocolFromURL("ftp://files.example.net"), "ftp");
}

/**
 * @tc.name: GetProtocolFromURL_003
 * @tc.desc: protocol not exist
 * @tc.type: FUNC
 */
HWTEST_F(UriHelperUnitTest, GetProtocolFromURL_002, TestSize.Level0)
{
    EXPECT_EQ(UriHelper::GetProtocolFromURL("example.com"), "");
    EXPECT_EQ(UriHelper::GetProtocolFromURL("://example.com:8080"), "");
}

}  // namespace Test
}  // namespace Media
}  // namespace OHOS
