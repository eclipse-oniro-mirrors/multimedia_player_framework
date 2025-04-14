/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "monitor_server_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void MonitorServerTest::SetUpTestCase(void)
{
}

void MonitorServerTest::TearDownTestCase(void)
{
}

void MonitorServerTest::SetUp(void)
{
}

void MonitorServerTest::TearDown(void)
{
}

/**
 * @tc.name  : EnableMonitor
 * @tc.number: EnableMonitor
 * @tc.desc  : FUNC
 */
HWTEST_F(MonitorServerTest, EnableMonitor, TestSize.Level1)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    int32_t ret = MonitorServer::GetInstance().EnableMonitor(pid);
    EXPECT_EQ(ret, 0);
    ret = MonitorServer::GetInstance().DisableMonitor(pid);
    EXPECT_EQ(ret, 0);
}
}
}