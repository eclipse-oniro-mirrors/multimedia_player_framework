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
#include "net_downloader_test_common.h"
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
    void SetUp(void)
    {
        NetworkClientAgent::Destroy();
    }
    void TearDown(void)
    {
        NetworkClientAgent::Destroy();
    }
};

HWTEST_F(NetworkClientAgentTest, NewInstance_NullCreateFunc_001, TestSize.Level0)
{
    auto result = NetworkClientAgent::NewInstance(nullptr, nullptr, nullptr, std::nullopt);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(NetworkClientAgentTest, Create_FailInTestEnv_001, TestSize.Level0)
{
    bool createResult = NetworkClientAgent::Create();
    EXPECT_FALSE(createResult);
}

HWTEST_F(NetworkClientAgentTest, Create_FailThenNewInstance_001, TestSize.Level0)
{
    bool createResult = NetworkClientAgent::Create();
    EXPECT_FALSE(createResult);

    auto instance = NetworkClientAgent::NewInstance(nullptr, nullptr, nullptr, std::nullopt);
    EXPECT_EQ(instance, nullptr);
}

HWTEST_F(NetworkClientAgentTest, Destroy_CalledTwice_001, TestSize.Level0)
{
    NetworkClientAgent::Destroy();
    NetworkClientAgent::Destroy();
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
