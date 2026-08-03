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

#include "screen_capture_server_function_unittest.h"
#include "screen_capture_monitor_server.h"
#include "mock_screen_capture_monitor_listener.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, IsSystemScreenRecorder_001, TestSize.Level2)
{
    auto &screenCaptureMonitorServer = ScreenCaptureMonitorServer::GetInstance();
    HasSystemPermission();
    screenCaptureMonitorServer.RegisterScreenCaptureMonitorListener(nullptr);
    screenCaptureMonitorServer.UnregisterScreenCaptureMonitorListener(nullptr);
    screenCaptureMonitorServer.SetSystemScreenRecorderPid(-1);
    bool ret = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(15000);
    ASSERT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSystemScreenRecorder_002, TestSize.Level2)
{
    auto &screenCaptureMonitorServer = ScreenCaptureMonitorServer::GetInstance();
    screenCaptureMonitorServer.SetSystemScreenRecorderPid(-1);
    ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorderWorking();
    bool ret = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(-1);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name    : ClearSystemScreenRecorderPid_001
 * @tc.number  : ClearSystemScreenRecorderPid_001
 * @tc.desc    : Test systemScreenRecorderPid_ is cleared after CallOnScreenCaptureFinished with matching pid
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ClearSystemScreenRecorderPid_001, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 20001;
    monitorServer.SetSystemScreenRecorderPid(pid);
    ASSERT_TRUE(monitorServer.IsSystemScreenRecorder(pid));
    monitorServer.CallOnScreenCaptureStarted(pid);
    ASSERT_TRUE(monitorServer.IsSystemScreenRecorderWorking());
    monitorServer.CallOnScreenCaptureFinished(pid);
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorder(pid));
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorderWorking());
}

/**
 * @tc.name    : ClearSystemScreenRecorderPid_002
 * @tc.number  : ClearSystemScreenRecorderPid_002
 * @tc.desc    : Test systemScreenRecorderPid_ is not cleared when CallOnScreenCaptureFinished uses non-matching pid
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ClearSystemScreenRecorderPid_002, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t sysPid = 20002;
    int32_t otherPid = 20003;
    monitorServer.SetSystemScreenRecorderPid(sysPid);
    ASSERT_TRUE(monitorServer.IsSystemScreenRecorder(sysPid));
    monitorServer.CallOnScreenCaptureStarted(otherPid);
    monitorServer.CallOnScreenCaptureFinished(otherPid);
    EXPECT_TRUE(monitorServer.IsSystemScreenRecorder(sysPid));
    monitorServer.SetSystemScreenRecorderPid(-1);
}

/**
 * @tc.name    : ClearSystemScreenRecorderPid_003
 * @tc.number  : ClearSystemScreenRecorderPid_003
 * @tc.desc    : Test OnScreenCaptureFinished callback is still fired before systemScreenRecorderPid_ is cleared
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ClearSystemScreenRecorderPid_003, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 20004;
    sptr<MockScreenCaptureMonitorListener> listener = new MockScreenCaptureMonitorListener();
    ASSERT_NE(listener, nullptr);
    monitorServer.SetScreenCaptureMonitorCallback(listener);
    monitorServer.SetSystemScreenRecorderPid(pid);
    monitorServer.CallOnScreenCaptureStarted(pid);
    ASSERT_EQ(listener->startedCount_, 1);
    ASSERT_EQ(listener->startedPid_, pid);
    monitorServer.CallOnScreenCaptureFinished(pid);
    EXPECT_EQ(listener->finishedCount_, 1);
    EXPECT_EQ(listener->finishedPid_, pid);
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorder(pid));
    monitorServer.RemoveScreenCaptureMonitorCallback(listener);
}

/**
 * @tc.name    : ClearSystemScreenRecorderPid_004
 * @tc.number  : ClearSystemScreenRecorderPid_004
 * @tc.desc    : Test systemScreenRecorderPid_ can be re-set after being cleared (restart lifecycle)
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ClearSystemScreenRecorderPid_004, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 20005;
    monitorServer.SetSystemScreenRecorderPid(pid);
    monitorServer.CallOnScreenCaptureStarted(pid);
    monitorServer.CallOnScreenCaptureFinished(pid);
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorder(pid));
    monitorServer.SetSystemScreenRecorderPid(pid);
    EXPECT_TRUE(monitorServer.IsSystemScreenRecorder(pid));
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorderWorking());
    monitorServer.SetSystemScreenRecorderPid(-1);
}

/**
 * @tc.name    : ClearSystemScreenRecorderPid_005
 * @tc.number  : ClearSystemScreenRecorderPid_005
 * @tc.desc    : Test reused pid of a stopped system recorder is not recognized as system recorder
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ClearSystemScreenRecorderPid_005, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 20006;
    monitorServer.SetSystemScreenRecorderPid(pid);
    monitorServer.CallOnScreenCaptureStarted(pid);
    ASSERT_TRUE(monitorServer.IsSystemScreenRecorderWorking());
    monitorServer.CallOnScreenCaptureFinished(pid);
    ASSERT_FALSE(monitorServer.IsSystemScreenRecorder(pid));
    ASSERT_FALSE(monitorServer.IsSystemScreenRecorderWorking());
    monitorServer.CallOnScreenCaptureStarted(pid);
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorder(pid));
    EXPECT_FALSE(monitorServer.IsSystemScreenRecorderWorking());
    monitorServer.CallOnScreenCaptureFinished(pid);
}
} // namespace Media
} // namespace OHOS
