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
#include <algorithm>
#include <gtest/gtest.h>
#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"
#include "mock/mock_audio_capturer.h"
#include "mock/mock_screen_capture_service_providers.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "audio_capturer_wrapper.h"

using testing::Return;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

static constexpr int32_t MAX_LINE_COLOR_RGB = 0xFFFFFF;
static constexpr int32_t MIN_LINE_COLOR_ARGB = 0xFF000000;
static constexpr int32_t MIN_LINE_WIDTH = 1;
static constexpr int32_t MAX_LINE_WIDTH = 10;
static const std::string BUTTON_NAME_MIC = "mic";

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButton_MicButton_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->HandleNotificationButtonResponse(BUTTON_NAME_MIC);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButton_UnknownButton_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->HandleNotificationButtonResponse("unknown_button");
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsCaptureScreen_DisplayIdNotInList_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetDisplayId(static_cast<uint64_t>(1));
    ASSERT_EQ(screenCaptureServer_->IsCaptureScreen(static_cast<uint64_t>(999)), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_NotAliveState_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    AVScreenCaptureContentChangedEvent beforeEvent = screenCaptureServer_->curWindowEvent_;
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    ASSERT_EQ(screenCaptureServer_->curWindowEvent_, beforeEvent);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_AliveState_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    ASSERT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_LineColorOutOfRange_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = MIN_LINE_WIDTH;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = MAX_LINE_COLOR_RGB + 1;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    ASSERT_EQ(screenCaptureServer_->IsSetHighlightConfig(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_LineColorInRange_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = MIN_LINE_WIDTH;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xFF;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    ASSERT_EQ(screenCaptureServer_->IsSetHighlightConfig(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_WrongCaptureMode_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = MIN_LINE_WIDTH;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xFF;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    ASSERT_EQ(screenCaptureServer_->IsSetHighlightConfig(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_LineThicknessOutOfRange_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 0;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xFF;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    ASSERT_EQ(screenCaptureServer_->IsSetHighlightConfig(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_LineColorBelowARGBMin_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = MIN_LINE_WIDTH;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = MIN_LINE_COLOR_ARGB - 1;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    ASSERT_EQ(screenCaptureServer_->IsSetHighlightConfig(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_BothIgnore_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_InnerCapInvalid_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.innerCapInfo.audioSampleRate = 1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_VideoCapInvalid_001, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_SurfaceModeVideoInvalid_001, TestSize.Level2)
{
    SetValidConfig();
    screenCaptureServer_->captureConfig_ = config_;
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->surface_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureFileParams_AudioEncInvalid_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    config_.audioInfo.audioEncInfo.audioCodecformat = static_cast<AudioCodecFormat>(999);
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureFileParams_VideoEncInvalid_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    config_.videoInfo.videoEncInfo.videoCodec = static_cast<VideoCodecFormat>(999);
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureFileParams_InnerCapInvalid_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    config_.audioInfo.innerCapInfo.audioSampleRate = 1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureFileParams_VideoCapInvalid_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioCap_AppPlaybackSource_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    AudioCaptureInfo audioInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    ASSERT_EQ(screenCaptureServer_->InitAudioCap(audioInfo), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSource,
        AudioCaptureSourceType::APP_PLAYBACK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioCap_MicSource_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    AudioCaptureInfo audioInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    ASSERT_EQ(screenCaptureServer_->InitAudioCap(audioInfo), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSource,
        AudioCaptureSourceType::MIC);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioCap_NotInConfigState_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    AudioCaptureInfo audioInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    ASSERT_EQ(screenCaptureServer_->InitAudioCap(audioInfo), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_NotInConfigState_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    VideoCaptureInfo videoInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ConvertTaskIdsToMissionIds_MixedTaskIds_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {1, -1, 5, -3, 10};
    screenCaptureServer_->ConvertTaskIdsToMissionIds();
    ASSERT_EQ(static_cast<int32_t>(screenCaptureServer_->missionInfos_.size()), 3);
    ASSERT_EQ(static_cast<int32_t>(screenCaptureServer_->missionInfos_.front().missionId), 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ConvertTaskIdsToMissionIds_EmptyTaskIds_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs.clear();
    screenCaptureServer_->ConvertTaskIdsToMissionIds();
    ASSERT_EQ(static_cast<int32_t>(screenCaptureServer_->missionInfos_.size()), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GenerateThreadNameByPrefix_001, TestSize.Level2)
{
    std::string result = screenCaptureServer_->GenerateThreadNameByPrefix("TestPrefix_");
    ASSERT_EQ(result.find("TestPrefix_"), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetErrorInfo_001, TestSize.Level2)
{
    screenCaptureServer_->SetErrorInfo(MSERR_UNKNOWN, "test error", StopReason::POST_START_SCREENCAPTURE_HANDLE_FAILURE, true);
    ASSERT_EQ(screenCaptureServer_->statisticalEventInfo_.errCode, MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->statisticalEventInfo_.errMsg, "test error");
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_ExtendedScreen_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->CheckCaptureMode(CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_InvalidMode_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->CheckCaptureMode(static_cast<CaptureMode>(999)), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDataType_InvalidType_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->CheckDataType(static_cast<DataType>(999)), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureMode_HomeScreen_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_HOME_SCREEN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureMode_ExtendedScreen_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetDataType_OriginalStream_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetDataType(DataType::ORIGINAL_STREAM), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.dataType, DataType::ORIGINAL_STREAM);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetDataType_CaptureFile_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetDataType(DataType::CAPTURE_FILE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.dataType, DataType::CAPTURE_FILE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetDataType_Invalid_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetDataType(static_cast<DataType>(999)), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetOutputFile_InvalidFd_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->SetOutputFile(-1), MSERR_INVALID_FD);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetOutputFile_ValidFd_001, TestSize.Level2)
{
    int32_t fd = MakeTestOutputFd();
    ASSERT_EQ(screenCaptureServer_->SetOutputFile(fd), MSERR_OK);
    close(fd);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAllParams_InvalidDataType_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.dataType = static_cast<DataType>(999);
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAllParams_InvalidCaptureMode_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = static_cast<CaptureMode>(999);
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureConfig_SpecifiedWindow_001, TestSize.Level2)
{
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_WINDOW, 42);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_WINDOW);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureConfig_ExtendedScreen_001, TestSize.Level2)
{
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN, -1);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetCurrentMillisecond_001, TestSize.Level2)
{
    int64_t time1 = screenCaptureServer_->GetCurrentMillisecond();
    int64_t time2 = screenCaptureServer_->GetCurrentMillisecond();
    ASSERT_GE(time2, time1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsState_MultipleStates_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ASSERT_EQ(screenCaptureServer_->IsState(CAP_ALIVE), true);
    ASSERT_EQ(screenCaptureServer_->IsState(CAP_PAUSED), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_MuteWhenShareAudioBox_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.state =
        AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->showShareSystemAudioBox_ = true;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    AudioCaptureInfo innerInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        innerInfo, screenCaptureServer_->cbProxy_, "test_inner", screenCaptureServer_->contentFilter_);
    ASSERT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_AlreadyRecording_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    AudioCaptureInfo innerInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK,
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID,
    };
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        innerInfo, screenCaptureServer_->cbProxy_, "test_inner_rec", screenCaptureServer_->contentFilter_);
    wrapper->Start(screenCaptureServer_->appInfo_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
}

} // Media
} // OHOS
