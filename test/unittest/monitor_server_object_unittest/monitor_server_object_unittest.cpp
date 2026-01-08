/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "monitor_server_object_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void MonitorServerObjectUnitTest::SetUpTestCase(void)
{
}

void MonitorServerObjectUnitTest::TearDownTestCase(void)
{
}

void MonitorServerObjectUnitTest::SetUp(void)
{
    object_ = std::make_shared<TestMonitorServerObject>();
}

void MonitorServerObjectUnitTest::TearDown(void)
{
    object_ = nullptr;
}

/**
 * @tc.name  : Test IpcAbnormality
 * @tc.number: IpcAbnormality_001
 * @tc.desc  : Test alarmed_ == false
 */
HWTEST_F(MonitorServerObjectUnitTest, IpcAbnormality_001, TestSize.Level0)
{
    ASSERT_NE(object_, nullptr);
    object_->alarmed_ = false;
    auto ret = object_->IpcAbnormality();
    EXPECT_EQ(ret, NUM_1);
}

/**
 * @tc.name  : Test IpcRecovery
 * @tc.number: IpcRecovery_001
 * @tc.desc  : Test alarmed_ == true
 */
HWTEST_F(MonitorServerObjectUnitTest, IpcRecovery_001, TestSize.Level0)
{
    ASSERT_NE(object_, nullptr);
    object_->alarmed_ = true;
    auto ret = object_->IpcRecovery(true);
    EXPECT_EQ(ret, NUM_1);
}

} // namespace Media
} // namespace OHOS