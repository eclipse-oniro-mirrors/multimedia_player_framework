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

#include "monitor_server_unittest.h"

#include <sys/time.h>
#include <string>
#include <unistd.h>
#include "monitor_server_object.h"
#include "media_log.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
static const int32_t PID_TEST = 10;
void PlayerMonitorServerTest::SetUpTestCase(void) {}

void PlayerMonitorServerTest::TearDownTestCase(void) {}

void PlayerMonitorServerTest::SetUp(void)
{
    testPtr = std::make_shared<MonitorServer>();
}

void PlayerMonitorServerTest::TearDown(void)
{
    testPtr = nullptr;
}

/**
* @tc.name: EnableMonitorUnitTest_001
* @tc.desc: EnableMonitorUnitTest_001
* @tc.type: Test EnableMonitor interface
*/
HWTEST_F(PlayerMonitorServerTest, EnableMonitorUnitTest_001, TestSize.Level0)
{
    ASSERT_NE(testPtr, nullptr);
    int32_t pid = PID_TEST;
    MonitorServer::TimeInfo timeInfo(PID_TEST, true);
    testPtr->timesMap_.insert(std::pair<int32_t, MonitorServer::TimeInfo>(pid, timeInfo));
    testPtr->threadRunning_ = true;
    int32_t ret = testPtr->EnableMonitor(pid);
    EXPECT_EQ(ret, 0);
}

/**
* @tc.name: ObjCtrlUnitTest_001
* @tc.desc: ObjCtrlUnitTest_001
* @tc.type: Test ObjCtrl interface
*/
HWTEST_F(PlayerMonitorServerTest, ObjCtrlUnitTest_001, TestSize.Level0)
{
    ASSERT_NE(testPtr, nullptr);
    OHOS::wptr<MonitorServerObject> weakObj1;
    OHOS::wptr<MonitorServerObject> weakObj2;
    std::list<wptr<MonitorServerObject>> recoveryList;
    recoveryList.push_back(weakObj1);
    std::list<wptr<MonitorServerObject>> abnormalList;
    abnormalList.push_back(weakObj2);
    int32_t ret = testPtr->ObjCtrl(recoveryList, abnormalList);
    EXPECT_EQ(ret, 0);
    weakObj1 = nullptr;
    weakObj2 = nullptr;
}

/**
* @tc.name: GetObjListByPidUnitTest_001
* @tc.desc: GetObjListByPidUnitTest_001
* @tc.type: Test GetObjListByPid interface
*/
HWTEST_F(PlayerMonitorServerTest, GetObjListByPidUnitTest_001, TestSize.Level0)
{
    ASSERT_NE(testPtr, nullptr);
    int32_t pid = PID_TEST;
    OHOS::wptr<OHOS::Media::MonitorServerObject> weakObj1;
    std::list<wptr<MonitorServerObject>> recoveryList;
    recoveryList.push_back(weakObj1);
    testPtr->objListMap_.insert(std::pair<int32_t, std::list<wptr<MonitorServerObject>>>(pid, recoveryList));
    int32_t ret = testPtr->GetObjListByPid(pid, recoveryList);
    EXPECT_EQ(ret, 0);
    weakObj1 = nullptr;
}

/**
* @tc.name: GetWaitTimeUnitTest_001
* @tc.desc: GetWaitTimeUnitTest_001
* @tc.type: Test GetWaitTime interface
*/
HWTEST_F(PlayerMonitorServerTest, GetWaitTimeUnitTest_001, TestSize.Level0)
{
    ASSERT_NE(testPtr, nullptr);
    int32_t pid = PID_TEST;
    MonitorServer::TimeInfo timeInfo(PID_TEST, true);
    testPtr->timesMap_.insert(std::pair<int32_t, MonitorServer::TimeInfo>(pid, timeInfo));
    int32_t ret = testPtr->GetWaitTime();
    EXPECT_EQ(ret, PID_TEST);
}

/**
* @tc.name: ObjectIpcAbnormalityUnitTest_001
* @tc.desc: ObjectIpcAbnormalityUnitTest_001
* @tc.type: Test IpcAbnormality interface
*/
HWTEST_F(PlayerMonitorServerTest, ObjectIpcAbnormalityUnitTest_001, TestSize.Level0)
{
    std::shared_ptr<MonitorServerObject> testPtr2 = std::make_shared<TestUser>();
    ASSERT_NE(testPtr2, nullptr);
    testPtr2->alarmed_ = true;
    int32_t ret = -1;
    ret = testPtr2->IpcAbnormality();
    EXPECT_NE(ret, -1);
    testPtr2 = nullptr;
}

/**
* @tc.name: ObjectIpcRecoveryUnitTest_001
* @tc.desc: ObjectIpcRecoveryUnitTest_001
* @tc.type: Test IpcRecovery interface
*/
HWTEST_F(PlayerMonitorServerTest, ObjectIpcRecoveryUnitTest_001, TestSize.Level0)
{
    std::shared_ptr<MonitorServerObject> testPtr2 = std::make_shared<TestUser>();
    ASSERT_NE(testPtr2, nullptr);
    testPtr2->alarmed_ = false;
    bool fromMonitor = true;
    int32_t ret = -1;
    ret = testPtr2->IpcRecovery(fromMonitor);
    EXPECT_NE(ret, -1);
    testPtr2 = nullptr;
}

/**
* @tc.name: ObjectIpcAlarmedFlagUnitTest
* @tc.desc: ObjectIpcAlarmedFlagUnitTest
* @tc.type: Test SetIpcAlarmedFlag interface
*/
HWTEST_F(PlayerMonitorServerTest, ObjectIpcAlarmedFlagUnitTest_001, TestSize.Level0)
{
    std::shared_ptr<MonitorServerObject> testPtr2 = std::make_shared<TestUser>();
    ASSERT_NE(testPtr2, nullptr);
    testPtr2->SetIpcAlarmedFlag();
    EXPECT_NE(testPtr2->alarmed_, false);
    testPtr2->UnSetIpcAlarmedFlag();
    EXPECT_EQ(testPtr2->alarmed_, false);
    testPtr2 = nullptr;
}
} // Media
} // OHOS
