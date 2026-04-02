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

#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace {
static const std::string BUTTON_NAME_PAUSE = "pause";
static const std::string BUTTON_NAME_RESUME = "resume";
}

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_Invalid_State_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);

    ASSERT_NE(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_Invalid_State_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_NE(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_Invalid_State_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.strategy.enablePause = false;

    ASSERT_NE(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_Stream_Mode_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_File_Mode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_pause.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCapture_Invalid_State_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);

    ASSERT_NE(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCapture_Invalid_State_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_NE(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCapture_Invalid_State_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);

    ASSERT_NE(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_State_Transition_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_State_Transition_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_File_Mode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_pause.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_With_Audio_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_Stop_After_Pause_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_Stop_After_Resume_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_Invalid_After_Stop_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_NE(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_With_Mic_Audio_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_With_Inner_Audio_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_File_Mode_With_Audio_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_pause.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_File_Mode_With_Mic_Only_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_pause.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIC_MODE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_File_Mode_With_Inner_Only_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_pause.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::INNER_MODE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_Multiple_Cycles_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
        ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
    }
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseResume_State_Verification_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::STARTED);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::PAUSED);

    ASSERT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::RESUMED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCaptureByUser_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCaptureByUser(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::PAUSED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCaptureByUser_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::STARTED);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;

    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ResumeScreenCaptureByUser(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetSCServerCaptureState(), AVScreenCaptureState::RESUMED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseVideoCapture_InvalidScreenId_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = -1;
    screenCaptureServer_->isConsumerStart_ = true;
    ASSERT_EQ(screenCaptureServer_->PauseVideoCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isConsumerStart_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseVideoCapture_InvalidScreenId_002, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    screenCaptureServer_->isConsumerStart_ = true;
    ASSERT_EQ(screenCaptureServer_->PauseVideoCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isConsumerStart_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseVideoCapture_NotConsumerStart_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 100;
    screenCaptureServer_->isConsumerStart_ = false;
    ASSERT_EQ(screenCaptureServer_->PauseVideoCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isConsumerStart_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeVideoCapture_InvalidScreenId_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = -1;
    screenCaptureServer_->isConsumerStart_ = false;
    ASSERT_EQ(screenCaptureServer_->ResumeVideoCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isConsumerStart_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeVideoCapture_InvalidScreenId_002, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    screenCaptureServer_->isConsumerStart_ = false;
    ASSERT_EQ(screenCaptureServer_->ResumeVideoCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isConsumerStart_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseRecorder_NoRecorder_001, TestSize.Level2)
{
    screenCaptureServer_->recorder_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->PauseRecorder(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeRecorder_NoRecorder_001, TestSize.Level2)
{
    screenCaptureServer_->recorder_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->ResumeRecorder(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnResponse_PauseButton_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> screenCaptureServerInner;
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServerInner = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    screenCaptureServerInner->SetScreenCaptureCallback(screenCaptureCb);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServerInner->captureConfig_.strategy.enablePause = true;
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);

    auto notificationSubscriber = NotificationSubscriber();
    int32_t notificationId = screenCaptureServerInner->sessionId_;
    OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption =
        new(std::nothrow) OHOS::Notification::NotificationButtonOption();
    buttonOption->SetButtonName(BUTTON_NAME_PAUSE);
    notificationSubscriber.OnResponse(notificationId, buttonOption);
    ASSERT_EQ(screenCaptureServerInner->GetSCServerCaptureState(), AVScreenCaptureState::PAUSED);

    screenCaptureServerInner->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnResponse_ResumeButton_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> screenCaptureServerInner;
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServerInner = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    screenCaptureServerInner->SetScreenCaptureCallback(screenCaptureCb);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServerInner->captureConfig_.strategy.enablePause = true;
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);

    auto notificationSubscriber = NotificationSubscriber();
    int32_t notificationId = screenCaptureServerInner->sessionId_;
    OHOS::sptr<OHOS::Notification::NotificationButtonOption> pauseOption =
        new(std::nothrow) OHOS::Notification::NotificationButtonOption();
    pauseOption->SetButtonName(BUTTON_NAME_PAUSE);
    notificationSubscriber.OnResponse(notificationId, pauseOption);

    OHOS::sptr<OHOS::Notification::NotificationButtonOption> resumeOption =
        new(std::nothrow) OHOS::Notification::NotificationButtonOption();
    resumeOption->SetButtonName(BUTTON_NAME_RESUME);
    notificationSubscriber.OnResponse(notificationId, resumeOption);
    ASSERT_EQ(screenCaptureServerInner->GetSCServerCaptureState(), AVScreenCaptureState::RESUMED);

    screenCaptureServerInner->Release();
}
} // Media
} // OHOS
