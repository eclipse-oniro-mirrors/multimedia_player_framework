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
} // namespace Media
} // namespace OHOS
