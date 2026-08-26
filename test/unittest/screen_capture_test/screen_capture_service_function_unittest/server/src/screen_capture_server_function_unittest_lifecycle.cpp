/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"

using testing::Return;
using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, IsCaptureScreen_001, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(100);
    ASSERT_EQ(screenCaptureServer_->IsCaptureScreen(100), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsCaptureScreen_002, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(100);
    ASSERT_EQ(screenCaptureServer_->IsCaptureScreen(999), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnCaptureContentChanged_001, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->curWindowInDisplayId_ = 999;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    screenCaptureServer_->OnCaptureContentChanged(true);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnCaptureContentChanged_002, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->curWindowInDisplayId_ = 999;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    screenCaptureServer_->OnCaptureContentChanged(false);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_, AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnCaptureContentChanged_003, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->curWindowInDisplayId_ = 999;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE;
    screenCaptureServer_->OnCaptureContentChanged(false);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_, AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnCaptureContentChanged_004, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(100);
    screenCaptureServer_->curWindowInDisplayId_ = 100;
    screenCaptureServer_->curWindowLifecycle_ = ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    screenCaptureServer_->OnCaptureContentChanged(false);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnCaptureContentChanged_005, TestSize.Level2)
{
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(100);
    screenCaptureServer_->curWindowInDisplayId_ = 100;
    screenCaptureServer_->curWindowLifecycle_ = ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND;
    screenCaptureServer_->interestWindowId_ = -1;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    screenCaptureServer_->OnCaptureContentChanged(false);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE;
    ScreenCaptureRect rect{0, 0, 100, 200};
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, &rect);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_005, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE;
    ScreenCaptureRect rect{0, 0, 100, 200};
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, &rect);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_, AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckSaLimit_002, TestSize.Level2)
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(true));
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t saUid = IPCSkeleton::GetCallingUid();
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {999, 0};
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appUid = 100;
    appInfo.appPid = 200;
    appInfo.appTokenId = 0;
    appInfo.appFullTokenId = 0;
    ASSERT_EQ(screenCaptureServer_->SetAndCheckSaLimit(appInfo), MSERR_INVALID_OPERATION);
    EXPECT_EQ(screenCaptureServer_->saUid_, -1);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

} // namespace Media
} // namespace OHOS
