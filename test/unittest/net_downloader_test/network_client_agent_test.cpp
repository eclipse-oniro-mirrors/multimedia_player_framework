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
#include <memory>
#include <vector>
#include "net_downloader_test_common.h"
#include "downloader.h"
#include "network_client_agent.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaDownload {

class NetworkClientAgentTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(NetworkClientAgentTest, Create_001, TestSize.Level0)
{
    bool ret = NetworkClientAgent::Create();
    EXPECT_TRUE(ret);
    NetworkClientAgent::Destroy();
}

HWTEST_F(NetworkClientAgentTest, Create_Multiple_001, TestSize.Level0)
{
    bool ret1 = NetworkClientAgent::Create();
    EXPECT_TRUE(ret1);
    bool ret2 = NetworkClientAgent::Create();
    EXPECT_TRUE(ret2);
    NetworkClientAgent::Destroy();
    NetworkClientAgent::Destroy();
}

HWTEST_F(NetworkClientAgentTest, CreateAfterDestroy_001, TestSize.Level0)
{
    (void)NetworkClientAgent::Create();
    NetworkClientAgent::Destroy();

    bool ret = NetworkClientAgent::Create();
    EXPECT_TRUE(ret);
    NetworkClientAgent::Destroy();
}

HWTEST_F(NetworkClientAgentTest, NewInstance_NullCreateFunc_001, TestSize.Level0)
{
    auto result = NetworkClientAgent::NewInstance(nullptr, nullptr, nullptr, std::nullopt);
    EXPECT_EQ(result, nullptr)
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
