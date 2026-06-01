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

#include <gtest/gtest.h>
#include "screen_capture_server_function_unittest.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, Can_CREATED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT | CAP_CONFIG), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT | CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING | CAP_PAUSED), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_POPUP_WINDOW_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STARTING_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTING;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STARTED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING | CAP_PAUSED), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_PAUSED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::PAUSED;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_RESUMED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::RESUMED;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STOPPED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->Can(CAP_NONE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_INIT), true);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_CONFIG), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_RUNNING), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_PAUSED), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_ALIVE) && !screenCaptureServer_->Can(CAP_ACTIVE), false);
    EXPECT_EQ(screenCaptureServer_->Can(CAP_POPUP | CAP_RUNNING), false);
}

} // namespace Media
} // namespace OHOS