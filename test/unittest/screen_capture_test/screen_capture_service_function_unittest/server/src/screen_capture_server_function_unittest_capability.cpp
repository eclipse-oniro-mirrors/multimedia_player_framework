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
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_INIT | CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_INIT | CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING | CAP_PAUSED));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_POPUP_WINDOW_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STARTING_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTING;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STARTED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_RUNNING | CAP_PAUSED));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_PAUSED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::PAUSED;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_RESUMED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::RESUMED;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, Can_STOPPED_001, TestSize.Level0)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_NONE));
    EXPECT_TRUE(screenCaptureServer_->IsState(CAP_INIT));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_CONFIG));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ALIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_RUNNING));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_PAUSED));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_ALIVE) && !screenCaptureServer_->IsState(CAP_ACTIVE));
    EXPECT_FALSE(screenCaptureServer_->IsState(CAP_POPUP | CAP_RUNNING));
}

} // namespace Media
} // namespace OHOS
