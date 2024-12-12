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

}  // namespace Test
}  // namespace Media
}  // namespace OHOS
