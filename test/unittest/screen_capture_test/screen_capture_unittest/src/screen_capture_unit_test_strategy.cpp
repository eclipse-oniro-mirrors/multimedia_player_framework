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

#include <fcntl.h>
#include <iostream>
#include <string>
#include "media_errors.h"
#include "screen_capture_unit_test.h"
#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;
using namespace OHOS::Rosen;
using namespace OHOS::Media::ScreenCaptureTestParam;

namespace OHOS {
namespace Media {
/**
 * @tc.name: screen_capture_keep_capture_during_call_001
 * @tc.desc: keepCaptureDuringCall == false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_keep_capture_during_call_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_keep_capture_during_call_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_keep_capture_during_call_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForKeepCaptureDuringCall(false));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_keep_capture_during_call_001 after");
}

/**
 * @tc.name: screen_capture_keep_capture_during_call_002
 * @tc.desc: keepCaptureDuringCall == true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_keep_capture_during_call_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_keep_capture_during_call_002 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_keep_capture_during_call_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForKeepCaptureDuringCall(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_keep_capture_during_call_002 after");
}

/**
 * @tc.name: screen_capture_canvas_follow_rotation_001
 * @tc.desc: canvasFollowRotation == true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_canvas_follow_rotation_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_canvas_follow_rotation_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_canvas_follow_rotation_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    screenCapture_->SetCanvasFollowRotationStrategy(true);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_canvas_follow_rotation_001 after");
}

/**
 * @tc.name: screen_capture_enable_b_frame_001
 * @tc.desc: enableBFrame == false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_enable_b_frame_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_enable_b_frame_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_enable_b_frame_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForBFramesEncoding(false));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_enable_b_frame_001 after");
}

/**
 * @tc.name: screen_capture_enable_b_frame_002
 * @tc.desc: enableBFrame == true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_enable_b_frame_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_enable_b_frame_002 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_enable_b_frame_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForBFramesEncoding(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_enable_b_frame_002 after");
}

/**
 * @tc.name: screen_capture_strategy_for_maskmode_001
 * @tc.desc: setStrategyForPrivacyMaskMode == 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_maskmode_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_maskmode_001 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_maskmode_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPrivacyMaskMode(0));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_maskmode_001 E");
}

/**
 * @tc.name: screen_capture_strategy_for_maskmode_002
 * @tc.desc: setStrategyForPrivacyMaskMode == 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_maskmode_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_maskmode_002 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_maskmode_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPrivacyMaskMode(1));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_maskmode_002 E");
}

/**
 * @tc.name: screen_capture_strategy_for_picker_pop_up_001
 * @tc.desc: setStrategyForPickerPopUp == true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_picker_pop_up_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_picker_pop_up_001 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_picker_pop_up_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPickerPopUp(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_picker_pop_up_001 E");
}

/**
 * @tc.name: screen_capture_strategy_for_picker_pop_up_002
 * @tc.desc: setStrategyForPickerPopUp == false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_picker_pop_up_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_picker_pop_up_002 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_picker_pop_up_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPickerPopUp(false));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_picker_pop_up_002 E");
}

/**
 * @tc.name: screen_capture_strategy_for_fill_mode_001
 * @tc.desc: setFillMode == aspect_scale_fit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_fill_mode_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_fill_mode_001 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_fill_mode_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForFillMode(AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_fill_mode_001 E");
}

/**
 * @tc.name: screen_capture_strategy_for_fill_mode_002
 * @tc.desc: setFillMode == scale_to_fill
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_strategy_for_fill_mode_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_fill_mode_002 S");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_strategy_for_fill_mode_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForFillMode(AVScreenCaptureFillMode::SCALE_TO_FILL));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_strategy_for_fill_mode_002 E");
}
} // namespace Media
} // namespace OHOS