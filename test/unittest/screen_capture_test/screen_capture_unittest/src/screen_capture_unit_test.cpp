/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @tc.name: screen_capture_save_file_mix_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_mix_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_mix_01.mp4", recorderInfo);
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
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_01 after");
}

/**
 * @tc.name: screen_capture_save_file_mix_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_mix_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_mix_02.mp4", recorderInfo);
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
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_02 after");
}

/**
 * @tc.name: screen_capture_save_file_mix_03
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_mix_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_mix_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_03 after");
}

/**
 * @tc.name: screen_capture_set_privacy_protect_callback_001
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_set_privacy_protect_callback_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_privacy_protect_callback_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_set_privacy_protect_callback_001.mp4", recorderInfo);
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
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetPrivacyProtectCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_privacy_protect_callback_001 after");
}

/**
 * @tc.name: screen_capture_save_file_mix_04
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_mix_04, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_04 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_mix_04.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_mix_04 after");
}

/**
 * @tc.name: screen_capture_specified_window_file_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window_file_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_01 before");
    std::shared_ptr<ScreenCaptureController> controller =
        ScreenCaptureControllerFactory::CreateScreenCaptureController();
    int32_t sessionId = 0;
    std::string choice = "false";
    controller->ReportAVScreenCaptureUserChoice(sessionId, choice);
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_window_file_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 20, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_file_01 missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    for (OHOS::AAFwk::MissionInfo info : missionInfos) {
        MEDIA_LOGI("screen_capture_specified_window_file_01 missionId : %{public}d", info.id);
    }
    if (missionInfos.size() > 0) {
        config_.videoInfo.videoCapInfo.taskIDs.push_back(missionInfos[0].id);
    } else {
        MEDIA_LOGE("screen_capture_specified_window_file_01 GetMissionInfos failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_01 after");
}

/**
 * @tc.name: screen_capture_specified_window_file_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window_file_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_window_file_02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 20, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_file_02 missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    for (OHOS::AAFwk::MissionInfo info : missionInfos) {
        MEDIA_LOGI("screen_capture_specified_window_file_02 missionId : %{public}d", info.id);
    }
    if (missionInfos.size() > 0) {
        config_.videoInfo.videoCapInfo.taskIDs.push_back(missionInfos[(missionInfos.size()-1)/2].id);
    } else {
        MEDIA_LOGE("screen_capture_specified_window_file_02 GetMissionInfos failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_02 after");
}

/**
 * @tc.name: screen_capture_specified_window_file_03
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window_file_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_window_file_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 20, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_file_03 missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    for (OHOS::AAFwk::MissionInfo info : missionInfos) {
        MEDIA_LOGI("screen_capture_specified_window_file_03 missionId : %{public}d", info.id);
    }
    if (missionInfos.size() > 0) {
        config_.videoInfo.videoCapInfo.taskIDs.push_back(missionInfos[missionInfos.size()-1].id);
    } else {
        MEDIA_LOGE("screen_capture_specified_window_file_03 GetMissionInfos failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_03 after");
}

/**
 * @tc.name: screen_capture_specified_window_file_04
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window_file_04, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_04 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_window_file_04.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 20, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_file_04 missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    if (missionInfos.size() > 0) {
        for (OHOS::AAFwk::MissionInfo info : missionInfos) {
            MEDIA_LOGI("screen_capture_specified_window_file_04 missionId:%{public}d", info.id);
            config_.videoInfo.videoCapInfo.taskIDs.push_back(info.id);
        }
    } else {
        MEDIA_LOGE("screen_capture_specified_window_file_04 GetMissionInfos failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_04 after");
}

/**
 * @tc.name: screen_capture_specified_window
 * @tc.desc: open microphone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window before");
    SetConfig(config_);
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 10, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    if (missionInfos.size() > 0) {
        for (OHOS::AAFwk::MissionInfo info : missionInfos) {
            MEDIA_LOGI("screen_capture_specified_window missionId:%{public}d", info.id);
            config_.videoInfo.videoCapInfo.taskIDs.push_back(info.id);
        }
    } else {
        MEDIA_LOGE("screen_capture_specified_window GetMissionInfos failed");
    }
    OpenFile("screen_capture_specified_window");

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window after");
}

/**
 * @tc.name: screen_capture_specified_window_Rotation
 * @tc.desc: open microphone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_window_Rotation, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_Rotation before");
    SetConfig(config_);
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 10, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_Rotation missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    if (missionInfos.size() > 0) {
        for (OHOS::AAFwk::MissionInfo info : missionInfos) {
            MEDIA_LOGI("screen_capture_specified_window_Rotation missionId:%{public}d", info.id);
            config_.videoInfo.videoCapInfo.taskIDs.push_back(info.id);
        }
    } else {
        MEDIA_LOGE("screen_capture_specified_window_Rotation GetMissionInfos failed");
    }
    OpenFile("screen_capture_specified_window_Rotation");

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    bool canvasRotation = true;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_Rotation after");
}

/**
 * @tc.name: screen_capture_save_file_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_01 after");
}

/**
 * @tc.name: screen_capture_save_file_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    AudioCaptureInfo micCapInfoInvalidChannels = {
        .audioSampleRate = 16000,
        .audioChannels = 0,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.audioInfo.micCapInfo = micCapInfoInvalidChannels;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    AudioCaptureInfo micCapInfoInvalidSampleRate = {
        .audioSampleRate = 0,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    SetRecorderInfo("screen_capture_get_screen_capture_02.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo = micCapInfoInvalidSampleRate;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    AudioCaptureInfo micCapInfoIgnored = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = AudioCaptureSourceType::MIC
    };
    SetRecorderInfo("screen_capture_get_screen_capture_02.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo = micCapInfoIgnored;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_02 after");
}

/**
 * @tc.name: screen_capture_save_file_03
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_03 after");
}

/**
 * @tc.name: screen_capture_save_file_04
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_04, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_04 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_04.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_NE(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_04 after");
}

/**
 * @tc.name: screen_capture_save_file_05
 * @tc.desc: open microphone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_05, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_05 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    OpenFile("screen_capture_get_screen_capture_05");

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_NE(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_05 after");
}

/**
 * @tc.name: screen_capture_save_file_Rotation
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_Rotation, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    OpenFile("screen_capture_save_file_Rotation");

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    bool canvasRotation = true;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_NE(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation after");
}

/**
 * @tc.name: screen_capture_save_file_Rotation_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_Rotation_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_Rotation_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 2720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1260;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool canvasRotation = true;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    canvasRotation = false;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME);
    canvasRotation = true;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_01 after");
}

/**
 * @tc.name: screen_capture_save_file_Rotation_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_Rotation_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_Rotation_02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 2720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1260;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool canvasRotation = true;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_02 after");
}

/**
 * @tc.name: screen_capture_save_file_Rotation_03
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_Rotation_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_get_screen_capture_Rotation_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 2720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1260;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool canvasRotation = false;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_Rotation_03 after");
}

/**
 * @tc.name: screen_capture_specified_screen_file_01
 * @tc.desc: do screencapture with specified screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_screen_file_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_screen_file_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;

    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    MEDIA_LOGI("screen_capture_specified_screen_file_01 screens size:%{public}s, ret:%{public}d",
        std::to_string(screens.size()).c_str(), ret);
    if (screens.size() > 0) {
        MEDIA_LOGI("screen_capture_specified_screen_file_01 screens id(size-1):%{public}s",
            std::to_string(screens[screens.size() - 1]->GetId()).c_str());
        MEDIA_LOGI("screen_capture_specified_screen_file_01 screens id(size-1):%{public}s",
            std::to_string(screens[0]->GetId()).c_str());
        config_.videoInfo.videoCapInfo.displayId = screens[0]->GetId();
    } else {
        MEDIA_LOGE("screen_capture_specified_screen_file_01 GetAllScreens failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_01 after");
}

/**
 * @tc.name: screen_capture_specified_screen_file_02
 * @tc.desc: do screencapture with specified screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_screen_file_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_screen_file_02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;

    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    MEDIA_LOGI("screen_capture_specified_screen_file_02 screens size:%{public}s, ret:%{public}d",
        std::to_string(screens.size()).c_str(), ret);
    if (screens.size() > 0) {
        MEDIA_LOGI("screen_capture_specified_screen_file_02 screens id(size-1):%{public}s",
            std::to_string(screens[screens.size() - 1]->GetId()).c_str());
        MEDIA_LOGI("screen_capture_specified_screen_file_02 screens id(size-1):%{public}s",
            std::to_string(screens[0]->GetId()).c_str());
        config_.videoInfo.videoCapInfo.displayId = screens[0]->GetId();
        EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
        EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
        sleep(RECORDER_TIME);
        EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
        EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    } else {
        MEDIA_LOGE("screen_capture_specified_screen_file_02 GetAllScreens failed");
    }
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_02 after");
}

/**
 * @tc.name: screen_capture_specified_screen_file_03
 * @tc.desc: do screencapture with specified screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_screen_file_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_screen_file_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;

    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    MEDIA_LOGI("screen_capture_specified_screen_file_03 screens size:%{public}s, ret:%{public}d",
        std::to_string(screens.size()).c_str(), ret);
    if (screens.size() > 0) {
        MEDIA_LOGI("screen_capture_specified_screen_file_03 screens id(size-1):%{public}s",
            std::to_string(screens[screens.size() - 1]->GetId()).c_str());
        MEDIA_LOGI("screen_capture_specified_screen_file_03 screens id(size-1):%{public}s",
            std::to_string(screens[0]->GetId()).c_str());
        config_.videoInfo.videoCapInfo.displayId = screens[0]->GetId();
    } else {
        MEDIA_LOGE("screen_capture_specified_screen_file_03 GetAllScreens failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_file_03 after");
}

/**
 * @tc.name: screen_capture_specified_screen_01
 * @tc.desc: screen capture specified screen test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_specified_screen_01, TestSize.Level1)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_01 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    MEDIA_LOGI("screen_capture_specified_screen_01 screens size:%{public}s, ret:%{public}d",
        std::to_string(screens.size()).c_str(), ret);
    if (screens.size() > 0) {
        MEDIA_LOGI("screen_capture_specified_screen_01 screens id(size-1):%{public}s",
            std::to_string(screens[screens.size() - 1]->GetId()).c_str());
        MEDIA_LOGI("screen_capture_specified_screen_01 screens id(size-1):%{public}s",
            std::to_string(screens[0]->GetId()).c_str());
        config_.videoInfo.videoCapInfo.displayId = screens[0]->GetId();
    } else {
        MEDIA_LOGE("screen_capture_specified_screen_01 GetAllScreens failed");
    }
    OpenFile("screen_capture_specified_screen_01");

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_screen_01 after");
}

/**
 * @tc.name: screen_capture_check_param_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfoRateSmall = {
        .audioSampleRate = 0,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfoRateSmall;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioSampleRate = 8000000;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 0;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioChannels = 200;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::APP_PLAYBACK;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_01.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_INVALID;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_01 after");
}

/**
 * @tc.name: screen_capture_check_param_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioEncInfo audioEncInfoBitSmall = {
        .audioBitrate = 0,
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };
    config_.audioInfo.audioEncInfo = audioEncInfoBitSmall;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_02.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.audioEncInfo.audioBitrate = 4800000;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_02.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.audioEncInfo.audioBitrate = 48000;
    config_.audioInfo.audioEncInfo.audioCodecformat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_02 after");
}

/**
 * @tc.name: screen_capture_check_param_03
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_03, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_03 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_03.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    VideoCaptureInfo videoCapInfoWidthSmall = {
        .videoFrameWidth = 0,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };
    config_.videoInfo.videoCapInfo = videoCapInfoWidthSmall;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_03.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_03.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1080;
    config_.videoInfo.videoCapInfo.videoSource = VideoSourceType::VIDEO_SOURCE_BUTT;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_03 after");
}

/**
 * @tc.name: screen_capture_check_param_04
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_04, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_04 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_04.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    VideoEncInfo videoEncInfoBitSmall = {
        .videoCodec = VideoCodecFormat::MPEG4,
        .videoBitrate = 0,
        .videoFrameRate = 30
    };
    config_.videoInfo.videoEncInfo = videoEncInfoBitSmall;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_04.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoEncInfo.videoBitrate = 30000001;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_04.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoEncInfo.videoBitrate = 2000000;
    config_.videoInfo.videoEncInfo.videoFrameRate = 0;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_04.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoEncInfo.videoFrameRate = 300;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_04.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.videoInfo.videoEncInfo.videoFrameRate = 30;
    config_.videoInfo.videoEncInfo.videoCodec = VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_04 after");
}

/**
 * @tc.name: screen_capture_check_param_05
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_05, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_05 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_05.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.dataType = DataType::ENCODED_STREAM;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_05.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.dataType = DataType::INVAILD;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_05.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.dataType = DataType::CAPTURE_FILE;
    config_.captureMode = CaptureMode::CAPTURE_INVAILD;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_05 after");
}

/**
 * @tc.name: screen_capture_check_param_06
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_06, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_06 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_06.mp4", recorderInfo);
    recorderInfo.fileFormat = "avi"; // native default m4a, capi avi
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCapture_->Init(config_); // not check
    config_.recorderInfo.fileFormat = "m4a";
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_06 after");
}

/**
 * @tc.name: screen_capture_check_param_07
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_check_param_07, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_07 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_check_param_07.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.audioInfo.micCapInfo = micCapInfo;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_07.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 1;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    SetRecorderInfo("screen_capture_check_param_07.mp4", recorderInfo);
    config_.recorderInfo = recorderInfo;
    config_.audioInfo.micCapInfo.audioSampleRate = 48000;
    config_.audioInfo.micCapInfo.audioChannels = 1;
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_check_param_07 after");
}

/**
 * @tc.name: screen_capture_video_configure_0001
 * @tc.desc: init with videoFrameWidth -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_configure_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_video_configure_0002
 * @tc.desc: init with videoFrameHeight -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_configure_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameHeight = -1;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_video_configure_0003
 * @tc.desc: init with videoSource yuv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_configure_0003, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_YUV;

    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_video_configure_0004
 * @tc.desc: init with videoSource es
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_configure_0004, TestSize.Level0)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_ES;

    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_without_audio_data
 * @tc.desc: close microphone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_without_audio_data, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    OpenFile("screen_capture_without_audio_data");

    aFlag = 0;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_audio_configure_0001
 * @tc.desc: init with audioSampleRate -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_configure_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.audioInfo.micCapInfo.audioSampleRate = -1;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_audio_configure_0002
 * @tc.desc: init with audioChannels -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_configure_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.audioInfo.micCapInfo.audioChannels = -1;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_audio_configure_0003
 * @tc.desc: init with audioSource SOURCE_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_configure_0003, TestSize.Level2)
{
    SetConfig(config_);
    config_.audioInfo.micCapInfo.audioSource = SOURCE_INVALID;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_avconfigure
 * @tc.desc: init with both audioinfo and videoinfo invaild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_avconfigure, TestSize.Level2)
{
    SetConfig(config_);
    config_.audioInfo.micCapInfo.audioSource = SOURCE_INVALID;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_YUV;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_with_audio_data
 * @tc.desc: open microphone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_with_audio_data, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    OpenFile("screen_capture_with_audio_data");

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_captureMode_0001
 * @tc.desc: screen capture with captureMode -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_captureMode_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.captureMode = static_cast<CaptureMode>(-1);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_captureMode_0002
 * @tc.desc: screen capture with captureMode 5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_captureMode_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.captureMode = static_cast<CaptureMode>(5);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_init_datatype_0001
 * @tc.desc: screen capture init with ENCODED_STREAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_init_datatype_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    config_.dataType = ENCODED_STREAM;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_init_datatype_0002
 * @tc.desc: screen capture init with CAPTURE_FILE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_init_datatype_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    config_.dataType = CAPTURE_FILE;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_init_datatype_0003
 * @tc.desc: screen capture init with INVAILD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_init_datatype_0003, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    config_.dataType = INVAILD;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_audioSampleRate_48000
 * @tc.desc: screen capture with audioSampleRate 48000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audioSampleRate_48000, TestSize.Level2)
{
    SetConfig(config_);
    config_.audioInfo.micCapInfo.audioSampleRate = 48000;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_video_size_0001
 * @tc.desc: screen capture with 160x160
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_size_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 160;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 160;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    std::string name = SCREEN_CAPTURE_ROOT_DIR + "screen_capture_video_size_0001.yuv";
    vFile = fopen(name.c_str(), "w+");
    if (vFile == nullptr) {
        cout << "vFile video open failed, " << strerror(errno) << endl;
    }

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_video_size_0002
 * @tc.desc: screen capture with 640x480
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_size_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 640;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 480;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    std::string name = SCREEN_CAPTURE_ROOT_DIR + "screen_capture_video_size_0002.yuv";
    vFile = fopen(name.c_str(), "w+");
    if (vFile == nullptr) {
        cout << "vFile video open failed, " << strerror(errno) << endl;
    }

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_video_size_0003
 * @tc.desc: screen capture with 1920x1080
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_size_0003, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 1920;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1080;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    std::string name = SCREEN_CAPTURE_ROOT_DIR + "screen_capture_video_size_0003.yuv";
    vFile = fopen(name.c_str(), "w+");
    if (vFile == nullptr) {
        cout << "vFile video open failed, " << strerror(errno) << endl;
    }

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_from_display
 * @tc.desc: screen capture from display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_from_display, TestSize.Level0)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    sptr<Display> display = DisplayManager::GetInstance().GetDefaultDisplaySync();
    ASSERT_NE(display, nullptr);
    cout << "get displayinfo: " << endl;
    cout << "width: " << display->GetWidth() << "; height: " << display->GetHeight() << "; density: " <<
        display->GetDpi() << "; refreshRate: " << display->GetRefreshRate() << endl;

    config_.videoInfo.videoCapInfo.videoFrameWidth = display->GetWidth();
    config_.videoInfo.videoCapInfo.videoFrameHeight = display->GetHeight();

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_0001
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_0001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    int index = 200;
    int index_video_frame = 0;
    audioLoop_ = std::make_unique<std::thread>(&ScreenCaptureUnitTest::AudioLoopWithoutRelease, this);
    while (index) {
        int32_t fence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        sptr<OHOS::SurfaceBuffer> surfacebuffer = screenCapture_->AcquireVideoBuffer(fence, timestamp, damage);
        if (surfacebuffer != nullptr) {
            int32_t length = surfacebuffer->GetSize();
            MEDIA_LOGD("index video:%{public}d, videoBufferLen:%{public}d, timestamp:%{public}" PRId64
                ", size:%{public}d", index_video_frame++, surfacebuffer->GetSize(), timestamp, length);
        } else {
            MEDIA_LOGE("AcquireVideoBuffer failed");
        }
        index--;
    }
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    if (audioLoop_ != nullptr && audioLoop_->joinable()) {
        audioLoop_->join();
        audioLoop_.reset();
        audioLoop_ = nullptr;
    }
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_0002
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_0002, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    int index = 10;
    int index_video_frame = 0;
    audioLoop_ = std::make_unique<std::thread>(&ScreenCaptureUnitTest::AudioLoop, this);
    while (index) {
        int32_t fence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        sptr<OHOS::SurfaceBuffer> surfacebuffer = screenCapture_->AcquireVideoBuffer(fence, timestamp, damage);
        if (surfacebuffer != nullptr) {
            int32_t length = surfacebuffer->GetSize();
            MEDIA_LOGD("index video:%{public}d, videoBufferLen:%{public}d, timestamp:%{public}" PRId64
                ", size:%{public}d", index_video_frame++, surfacebuffer->GetSize(), timestamp, length);
            screenCapture_->ReleaseVideoBuffer();
        } else {
            MEDIA_LOGE("AcquireVideoBuffer failed");
        }
        index--;
    }
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    if (audioLoop_ != nullptr && audioLoop_->joinable()) {
        audioLoop_->join();
        audioLoop_.reset();
        audioLoop_ = nullptr;
    }
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_0003
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_0003, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 0;
    vFlag = 1;
    bool isMicrophone = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME * 2);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_0004
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_0004, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 0;
    bool isMicrophone = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME * 2);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_0005
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_0005, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 0;
    vFlag = 0;
    bool isMicrophone = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME * 2);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_buffertest_Rotation
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_Rotation, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 0;
    vFlag = 0;
    bool isMicrophone = true;
    bool canvasRotation = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCanvasRotation(canvasRotation));
    sleep(RECORDER_TIME * 2);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/**
 * @tc.name: screen_capture_mic_open_close_open
 * @tc.desc: screen capture mic test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_mic_open_close_open, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    std::string name = SCREEN_CAPTURE_ROOT_DIR + "screen_capture_mic_open_close_open.pcm";
    aFile = fopen(name.c_str(), "w+");
    if (aFile == nullptr) {
        cout << "aFile audio open failed, " << strerror(errno) << endl;
    }

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = true;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME * 2);
    isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    sleep(RECORDER_TIME);
    isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_mic_close_open_close
 * @tc.desc: screen capture mic test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_mic_close_open_close, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    std::string name = SCREEN_CAPTURE_ROOT_DIR + "screen_capture_mic_close_open_close.pcm";
    aFile = fopen(name.c_str(), "w+");
    if (aFile == nullptr) {
        cout << "aFile audio open failed, " << strerror(errno) << endl;
    }

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = false;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME * 2);
    isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    sleep(RECORDER_TIME);
    isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

/**
 * @tc.name: screen_capture_with_surface_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_with_surface_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_01 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1280;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_01 CreateRecorder");
    std::shared_ptr<Recorder> recorder = nullptr;
    recorder = RecorderFactory::CreateRecorder();
    int32_t videoSourceId = 0;
    EXPECT_EQ(MSERR_OK, recorder->SetVideoSource(VIDEO_SOURCE_SURFACE_RGBA, videoSourceId));
    EXPECT_EQ(MSERR_OK, recorder->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoEncoder(videoSourceId, VideoCodecFormat::H264));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoSize(videoSourceId, 720, 1280));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoFrameRate(videoSourceId, 30));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoEncodingBitRate(videoSourceId, 2000000));
    OpenFileFd("screen_capture_with_surface_01.mp4");
    ASSERT_TRUE(outputFd_ >= 0);
    EXPECT_EQ(MSERR_OK, recorder->SetOutputFile(outputFd_));
    EXPECT_EQ(MSERR_OK, recorder->Prepare());
    sptr<OHOS::Surface> consumer = recorder->GetSurface(videoSourceId);
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCaptureWithSurface(consumer));
    EXPECT_EQ(MSERR_OK, recorder->Start());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_01 recorder Start");
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorder->Stop(true));
    EXPECT_EQ(MSERR_OK, recorder->Reset());
    EXPECT_EQ(MSERR_OK, recorder->Release());
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_01 after");
}

/**
 * @tc.name: screen_capture_with_surface_02
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_with_surface_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_02 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 480;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 640;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool isMicrophone = true;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_02 CreateRecorder");
    std::shared_ptr<Recorder> recorder = nullptr;
    recorder = RecorderFactory::CreateRecorder();
    int32_t videoSourceId = 0;
    EXPECT_EQ(MSERR_OK, recorder->SetVideoSource(VIDEO_SOURCE_SURFACE_RGBA, videoSourceId));
    EXPECT_EQ(MSERR_OK, recorder->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoEncoder(videoSourceId, VideoCodecFormat::H264));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoSize(videoSourceId, 480, 640));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoFrameRate(videoSourceId, 30));
    EXPECT_EQ(MSERR_OK, recorder->SetVideoEncodingBitRate(videoSourceId, 2000000));
    OpenFileFd("screen_capture_with_surface_02.mp4");
    ASSERT_TRUE(outputFd_ >= 0);
    EXPECT_EQ(MSERR_OK, recorder->SetOutputFile(outputFd_));
    EXPECT_EQ(MSERR_OK, recorder->Prepare());
    sptr<OHOS::Surface> consumer = recorder->GetSurface(videoSourceId);
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCaptureWithSurface(consumer));
    EXPECT_EQ(MSERR_OK, recorder->Start());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_02 recorder Start");
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorder->Stop(true));
    EXPECT_EQ(MSERR_OK, recorder->Reset());
    EXPECT_EQ(MSERR_OK, recorder->Release());
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_02 after");
}

/**
 * @tc.name: screen_capture_buffertest_resize_02
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_resize_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_buffertest_resize_02 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = false;

    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(27000, 480));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 48000));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(27000, 480));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 48000));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(27000, 480));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 48000));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(27000, 480));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 48000));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_buffertest_resize_02 after");
}

/**
 * @tc.name: screen_capture_save_file_resize
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_resize, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_resize before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_resize.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    bool isMicrophone = false;

    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 480));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 480));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 480));
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_NE(MSERR_OK, screenCapture_->ResizeCanvas(270, 480));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_resize after");
}

/**
 * @tc.name: screen_capture_save_file_skip_privacy
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_skip_privacy, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_skip_privacy before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_save_file_skip_privacy.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
            .audioSampleRate = 16000,
            .audioChannels = 2,
            .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    vector<int> windowIds = {-1, 2, 5};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#endif
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_skip_privacy after");
}

/**
 * @tc.name: screen_capture_save_file_skip_privacy_01
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_save_file_skip_privacy_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_skip_privacy_01 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    vector<int> windowIds = {-1, 2, 5};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#endif
    windowIds = {-1, 2, 7};
    sleep(RECORDER_TIME);
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#endif
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_save_file_skip_privacy_01 after");
}

/**
 * @tc.name: screen_capture_with_surface_skip_privacy_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_with_surface_skip_privacy_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_skip_privacy_01 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1280;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    vector<int> windowIds = {-1, 2, 5};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    sptr<OHOS::Surface> consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    consumer->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE);
    auto producer = consumer->GetProducer();
    auto producerSurface = OHOS::Surface::CreateSurfaceAsProducer(producer);
    sptr<IBufferConsumerListener> surfaceCb = OHOS::sptr<ScreenCapBufferDemoConsumerListener>::MakeSptr(consumer);
    consumer->RegisterConsumerListener(surfaceCb);
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCaptureWithSurface(producerSurface));
    sleep(RECORDER_TIME);
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#endif
    sleep(RECORDER_TIME);
    windowIds = {-1, 2, 6};
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
#endif
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIds[0], static_cast<int32_t>(windowIds.size())));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_skip_privacy_01 after");
}

/**
 * @tc.name: screen_capture_buffertest_max_frame_rate_01
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_max_frame_rate_01, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = false;

    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME_5);
    int32_t totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_01 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetMaxVideoFrameRate(5));
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_02 = ((double)totalFrameNum)/RECORDER_TIME_5;
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_03 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetMaxVideoFrameRate(15));
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_04 = ((double)totalFrameNum)/RECORDER_TIME_5;
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_05 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetMaxVideoFrameRate(90));
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_06 = ((double)totalFrameNum)/RECORDER_TIME_5;
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_07 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    EXPECT_TRUE(averageFrameRate_02 < (5 * EXCESS_RATE));
    EXPECT_TRUE(averageFrameRate_03 < (5 * EXCESS_RATE));
    EXPECT_TRUE(averageFrameRate_04 < (15 * EXCESS_RATE));
    EXPECT_TRUE(averageFrameRate_05 < (15 * EXCESS_RATE));
    EXPECT_TRUE(averageFrameRate_06 < (90 * EXCESS_RATE));
    EXPECT_TRUE(averageFrameRate_07 < (90 * EXCESS_RATE));
    cout << "SetMaxVideoFrameRate end averageFrameRate_01: " << averageFrameRate_01 << ",set 5,averageFrameRate_02: "
        << averageFrameRate_02 << " averageFrameRate_03: " << averageFrameRate_03 << ",set 15,averageFrameRate_04: "
        << averageFrameRate_04 << " averageFrameRate_05: " << averageFrameRate_05 << ",set 90,averageFrameRate_06: "
        << averageFrameRate_06 << " averageFrameRate_07: " << averageFrameRate_07 << endl;
}

/**
 * @tc.name: screen_capture_buffertest_max_frame_rate_02
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_buffertest_max_frame_rate_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_buffertest_max_frame_rate_02 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    aFlag = 1;
    vFlag = 1;
    bool isMicrophone = false;

    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME_5);
    int32_t totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_01 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_NE(MSERR_OK, screenCapture_->SetMaxVideoFrameRate(-10));
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_02 = ((double)totalFrameNum)/RECORDER_TIME_5;
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_03 = ((double)totalFrameNum)/RECORDER_TIME_5;
    EXPECT_EQ(MSERR_OK, screenCapture_->SetMaxVideoFrameRate(1000000000));
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_04 = ((double)totalFrameNum)/RECORDER_TIME_5;
    sleep(RECORDER_TIME_5);
    totalFrameNum = screenCaptureCb_->GetFrameNumber();
    double averageFrameRate_05 = ((double)totalFrameNum)/RECORDER_TIME_5;

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    cout << "SetMaxVideoFrameRate end averageFrameRate_01: " << averageFrameRate_01
        << ",set -10,averageFrameRate_02: " << averageFrameRate_02 << " averageFrameRate_03: "
        << averageFrameRate_03 << ",set 1000000000,averageFrameRate_04: " << averageFrameRate_04
        << " averageFrameRate_05: " << averageFrameRate_05 << endl;
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_buffertest_max_frame_rate_02 after");
}

/**
 * @tc.name: screen_capture_with_surface_update_surface
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_with_surface_update_surface, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_update_surface before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1280;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    bool isMicrophone = false;
    screenCapture_->SetMicrophoneEnabled(isMicrophone);
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    sptr<OHOS::Surface> consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    consumer->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE);
    auto producer = consumer->GetProducer();
    auto producerSurface = OHOS::Surface::CreateSurfaceAsProducer(producer);

    sptr<IBufferConsumerListener> surfaceCb = OHOS::sptr<ScreenCapBufferDemoConsumerListener>::MakeSptr(consumer);
    consumer->RegisterConsumerListener(surfaceCb);

    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCaptureWithSurface(producerSurface));
    sleep(RECORDER_TIME);
    MEDIA_LOGI("screenCapture_->UpdateSurface start 1");
    EXPECT_EQ(MSERR_OK, screenCapture_->UpdateSurface(producerSurface));
    MEDIA_LOGI("screenCapture_->UpdateSurface end 1");
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_with_surface_update_surface after");
}

/**
 * @tc.name: screen_capture_specified_window_file_01
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_config_paramer_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_config_paramer_01 before");
    std::shared_ptr<ScreenCaptureController> controller =
        ScreenCaptureControllerFactory::CreateScreenCaptureController();
    int32_t sessionId = 0;
    std::string resultStr = "";
    controller->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_specified_window_file_01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    std::shared_ptr<OHOS::AAFwk::AbilityManagerClient> client_ = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    std::string deviceId = "";
    std::vector<OHOS::AAFwk::MissionInfo> missionInfos;
    auto result = client_->GetMissionInfos(deviceId, 20, missionInfos);
    MEDIA_LOGI("screen_capture_specified_window_file_01 missionInfos size:%{public}s, result:%{public}d",
        std::to_string(missionInfos.size()).c_str(), result);
    for (OHOS::AAFwk::MissionInfo info : missionInfos) {
        MEDIA_LOGI("screen_capture_specified_window_file_01 missionId : %{public}d", info.id);
    }
    if (missionInfos.size() > 0) {
        config_.videoInfo.videoCapInfo.taskIDs.push_back(missionInfos[0].id);
    } else {
        MEDIA_LOGE("screen_capture_specified_window_file_01 GetMissionInfos failed");
    }

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_specified_window_file_01 after");
}

/**
 * @tc.name: screen_capture_presentPicker_test01
 * @tc.desc: do screencapture PresentPicker
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_presentPicker_test01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_presentPicker_test01 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_presentPicker_test01.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
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
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
     EXPECT_EQ(MSERR_OK, screenCapture_->PresentPicker());
#else
    EXPECT_NE(MSERR_OK, screenCapture_->PresentPicker());
#endif
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_presentPicker_test01 after");
}

/**
 * @tc.name: screen_capture_presentPicker_test02
 * @tc.desc: do screencapture PresentPicker
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_presentPicker_test02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_presentPicker_test02 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_presentPicker_test02.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_NE(MSERR_OK, screenCapture_->PresentPicker());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_presentPicker_test02 after");
}

/**
 * @tc.name: screen_capture_set_picker_mode_01
 * @tc.desc: set picker mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_set_picker_mode_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_picker_mode_01 before");
    PickerMode pickerMode = PickerMode::WINDOW_ONLY;
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    EXPECT_EQ(MSERR_OK, screenCapture_->SetPickerMode(pickerMode));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->SetPickerMode(pickerMode));
#endif
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_picker_mode_01 after");
}

/**
 * @tc.name: screen_capture_exclude_picker_windows_01
 * @tc.desc: exclude picker windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_exclude_picker_windows_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_exclude_picker_windows_01 before");
    std::vector<int32_t> windowIDs = {100, 101, 102};
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    EXPECT_EQ(MSERR_OK, screenCapture_->ExcludePickerWindows(windowIDs.data(), windowIDs.size()));
#else
    EXPECT_NE(MSERR_OK, screenCapture_->ExcludePickerWindows(windowIDs.data(), windowIDs.size()));
#endif
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_exclude_picker_windows_01 after");
}

/**
 * @tc.name: screen_capture_exclude_picker_windows_02
 * @tc.desc: exclude picker windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_exclude_picker_windows_02, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_exclude_picker_windows_02 before");
    std::vector<int32_t> windowIDs;
    for (int i = 0; i < 1200; i++) {
        windowIDs.push_back(i);
    }
    EXPECT_NE(MSERR_OK, screenCapture_->ExcludePickerWindows(windowIDs.data(), windowIDs.size()));
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_exclude_picker_windows_02 after");
}

/**
 * @tc.name: screen_capture_set_highlight_for_area_001
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_set_highlight_for_area_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_highlight_for_area_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_set_highlight_for_area_001.mp4", recorderInfo);
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
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.lineThickness = 4;
    highlightConfig.lineColor = 0xff0000ff;
    highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    screenCapture_->SetCaptureAreaHighlight(highlightConfig);
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_highlight_for_area_001 after");
}

/**
 * @tc.name: screen_capture_set_highlight_for_area_002
 * @tc.desc: do screencapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_set_highlight_for_area_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_highlight_for_area_002 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_set_highlight_for_area_002.mp4", recorderInfo);
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
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.lineThickness = 4;
    highlightConfig.lineColor = 0xff0000ff;
    highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CORNER_WRAP;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    screenCapture_->SetCaptureAreaHighlight(highlightConfig);
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_set_highlight_for_area_002 after");
}
/**
 * @tc.name: screen_capture_error_handling_001
 * @tc.desc: 多重错误场景 - 参数错误+权限错误组合
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_error_handling_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_001 before");
    SetConfig(config_);

    // 设置无效的音频参数
    config_.audioInfo.micCapInfo.audioSampleRate = 0;
    config_.audioInfo.micCapInfo.audioChannels = 0;
    config_.audioInfo.micCapInfo.audioSource = SOURCE_INVALID;

    // 设置无效的视频参数
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    config_.videoInfo.videoCapInfo.videoFrameHeight = -1;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_BUTT;

    // 设置无效的数据类型
    config_.dataType = INVAILD;

    // 尝试初始化
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    // 验证状态保持为初始状态
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_001 after");
}

/**
 * @tc.name: screen_capture_error_handling_002
 * @tc.desc: 初始化失败+启动失败组合
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_error_handling_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_002 before");
    SetConfig(config_);

    // 设置无效参数确保初始化失败
    config_ = {};
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));

    // 尝试在初始化失败后启动
    EXPECT_NE(MSERR_OK, screenCapture_->StartScreenCapture());

    // 尝试停止
    EXPECT_NE(MSERR_OK, screenCapture_->StopScreenCapture());

    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_002 after");
}

/**
 * @tc.name: screen_capture_error_handling_003
 * @tc.desc: 资源不足+状态异常组合
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_error_handling_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_003 before");
    SetConfig(config_);

    // 设置超大分辨率模拟资源不足
    config_.videoInfo.videoCapInfo.videoFrameWidth = 8192;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 8192;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_003 after");
}

/**
 * @tc.name: screen_capture_error_handling_004
 * @tc.desc: 回调异常处理为空回调测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_error_handling_004, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_004 before");
    SetConfig(config_);

    // 设置空回调
    EXPECT_NE(MSERR_OK, screenCapture_->SetScreenCaptureCallback(nullptr));

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_004 after");
}

/**
 * @tc.name: screen_capture_error_handling_006
 * @tc.desc: 未初始化就启动测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_error_handling_006, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_006 before");

    // 不初始化直接启动
    EXPECT_NE(MSERR_OK, screenCapture_->StartScreenCapture());

    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_error_handling_006 after");
}

/**
 * @tc.name: screen_capture_state_machine_001
 * @tc.desc: 重复启动操作测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_state_machine_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_001 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 第一次启动
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    // 第二次启动（应该失败或被忽略）
    auto result = screenCapture_->StartScreenCapture();
    MEDIA_LOGI("screen_capture_state_machine_001 result:%{public}d", result);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_001 after");
}

/**
 * @tc.name: screen_capture_state_machine_002
 * @tc.desc: 重复停止操作测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_state_machine_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_002 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 第一次停止（未启动状态）
    auto result1 = screenCapture_->StopScreenCapture();
    MEDIA_LOGI("screen_capture_state_machine_001 result:%{public}d", result1);

    // 启动
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    // 第二次停止
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());

    // 第三次停止
    auto result2 = screenCapture_->StopScreenCapture();
    MEDIA_LOGI("screen_capture_state_machine_001 result:%{public}d", result2);

    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_002 after");
}

/**
 * @tc.name: screen_capture_state_machine_003
 * @tc.desc: 状态回退场景测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_state_machine_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_003 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 启动
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    // 立即停止
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());

    // 尝试再次启动（状态回退测试）
    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_state_machine_003 after");
}

/**
 * @tc.name: screen_capture_concurrent_001
 * @tc.desc: 多实例同时启动测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_concurrent_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_concurrent_001 before");

    SetConfig(config_);

    // 初始化当前实例
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 启动当前实例
    auto result1 = screenCapture_->StartScreenCapture();
    MEDIA_LOGI("screen_capture_state_machine_001 result:%{public}d", result1);

    sleep(1);

    // 停止当前实例
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());

    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_concurrent_001 after");
}

/**
 * @tc.name: screen_capture_privacy_001
 * @tc.desc: 隐私窗口动态变化测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_privacy_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_001 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 设置跳过隐私窗口
    vector<int> windowIDsVec = {1, 3, 5};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIDsVec[0], static_cast<int32_t>(windowIDsVec.size())));

    // 动态更新隐私窗口列表
    windowIDsVec.push_back(7);
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIDsVec[0], static_cast<int32_t>(windowIDsVec.size())));

    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_001 after");
}

/**
 * @tc.name: screen_capture_audio_001
 * @tc.desc: 音频采样率不匹配处理测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_001 before");
    SetConfig(config_);

    // 设置不匹配的采样率
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSampleRate = 48000; // 不匹配
    config_.audioInfo.innerCapInfo.audioChannels = 2;

    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_audio_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);

    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_001 after");
}

/**
 * @tc.name: screen_capture_video_001
 * @tc.desc: 屏幕分辨率动态变化测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_001 before");
    SetConfig(config_);

    // 初始分辨率
    config_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1280;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    // 尝试动态调整画布大小
    EXPECT_EQ(MSERR_OK, screenCapture_->ResizeCanvas(1080, 1920));

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_001 after");
}

/**
 * @tc.name: screen_capture_performance_001
 * @tc.desc: 高帧率下的性能测试
 * @tc.type: PERF
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_performance_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_001 before");
    SetConfig(config_);

    // 设置高帧率
    config_.videoInfo.videoEncInfo.videoFrameRate = 60;
    config_.videoInfo.videoEncInfo.videoBitrate = 10000000;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    // 录制较长时间测试性能
    sleep(5);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_001 after");
}

/**
 * @tc.name: screen_capture_compatibility_001
 * @tc.desc: 非标准分辨率组合测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_001 before");
    SetConfig(config_);

    // 非标准分辨率
    config_.videoInfo.videoCapInfo.videoFrameWidth = 854;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 480;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_001 after");
}

/**
 * @tc.name: screen_capture_compatibility_002
 * @tc.desc: 非标准帧率组合测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_002 before");
    SetConfig(config_);

    // 非标准帧率
    config_.videoInfo.videoEncInfo.videoFrameRate = 24;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_002 after");
}

/**
 * @tc.name: screen_capture_privacy_003
 * @tc.desc: 隐私窗口动态变化测试 - 启动中添加多个窗口
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_privacy_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_003 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 初始设置隐私窗口
    vector<int> windowIDsVec = {1, 3};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIDsVec[0], static_cast<int32_t>(windowIDsVec.size())));

    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    // 录制中添加更多窗口
    windowIDsVec.push_back(5);
    windowIDsVec.push_back(7);
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIDsVec[0], static_cast<int32_t>(windowIDsVec.size())));

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_003 after");
}

/**
 * @tc.name: screen_capture_privacy_004
 * @tc.desc: 隐私模式切换时机测试 - 停止后切换
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_privacy_004, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_004 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 启动
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    // 停止
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());

    // 停止后设置隐私窗口
    vector<int> windowIDsVec = {1, 3, 5};
    EXPECT_EQ(MSERR_OK, screenCapture_->SkipPrivacyMode(&windowIDsVec[0], static_cast<int32_t>(windowIDsVec.size())));

    // 验证设置成功
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_privacy_004 after");
}

/**
 * @tc.name: screen_capture_audio_003
 * @tc.desc: 音频通道数不匹配处理测试 - 文件模式
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_003 before");
    SetConfig(config_);

    // 设置不匹配的通道数
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 1;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;

    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_audio_003.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);

    EXPECT_NE(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_003 after");
}

/**
 * @tc.name: screen_capture_audio_004_1
 * @tc.desc: 音频源类型边界测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_004_1, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_1 before");
    SetConfig(config_);

    // 测试所有音频源类型
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = SOURCE_DEFAULT;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_1 after");
}

/**
 * @tc.name: screen_capture_audio_004_2
 * @tc.desc: 音频源类型边界测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_004_2, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_2 before");
    SetConfig(config_);

    // 测试所有音频源类型
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;

    config_.audioInfo.micCapInfo.audioSource = MIC;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_2 after");
}

/**
 * @tc.name: screen_capture_audio_004_3
 * @tc.desc: 音频源类型边界测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_004_3, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_3 before");
    SetConfig(config_);

    // 测试所有音频源类型
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;

    config_.audioInfo.micCapInfo.audioSource = APP_PLAYBACK;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004 after");
}

/**
 * @tc.name: screen_capture_audio_004_4
 * @tc.desc: 音频源类型边界测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_audio_004_4, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_4 before");
    SetConfig(config_);

    // 测试所有音频源类型
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;

    config_.audioInfo.micCapInfo.audioSource = ALL_PLAYBACK;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_audio_004_4 after");
}

/**
 * @tc.name: screen_capture_video_003
 * @tc.desc: 视频分辨率边界测试 - 极小值
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_003 before");
    SetConfig(config_);

    // 测试最小分辨率
    config_.videoInfo.videoCapInfo.videoFrameWidth = 320;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 240;
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_003 after");
}

/**
 * @tc.name: screen_capture_video_004
 * @tc.desc: 视频帧率边界测试 - 极小值
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_004, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_004 before");
    SetConfig(config_);

    // 测试最小帧率
    config_.videoInfo.videoEncInfo.videoFrameRate = 15;
    config_.videoInfo.videoEncInfo.videoBitrate = 1000000;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_004 after");
}

/**
 * @tc.name: screen_capture_video_005
 * @tc.desc: 视频比特率边界测试 - 极小值
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_005, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_005 before");
    SetConfig(config_);

    // 测试最小比特率
    config_.videoInfo.videoEncInfo.videoBitrate = 100000;
    config_.videoInfo.videoEncInfo.videoFrameRate = 30;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());

    sleep(1);

    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_005 after");
}

/**
 * @tc.name: screen_capture_video_006_1
 * @tc.desc: 视频编码格式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_006_1, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_1 before");
    SetConfig(config_);

    // 测试H264编码
    config_.videoInfo.videoEncInfo.videoCodec = H264;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_1 after");
}

/**
 * @tc.name: screen_capture_video_006_2
 * @tc.desc: 视频编码格式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_006_2, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_2 before");
    SetConfig(config_);

    // 测试H265编码
    config_.videoInfo.videoEncInfo.videoCodec = H265;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_2 after");
}

/**
 * @tc.name: screen_capture_video_006_3
 * @tc.desc: 视频编码格式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_video_006_3, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_3 before");
    SetConfig(config_);

    // 测试MPEG4编码
    config_.videoInfo.videoEncInfo.videoCodec = MPEG4;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_video_006_3 after");
}

/**
 * @tc.name: screen_capture_performance_003
 * @tc.desc: 启动停止延迟测试
 * @tc.type: PERF
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_performance_003, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_003 before");
    SetConfig(config_);

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));

    // 测试启动延迟
    auto startTime = std::chrono::high_resolution_clock::now();
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    int32_t latencyMs = static_cast<int32_t>(duration.count());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_003 start latency: %{public}d ms", latencyMs);

    sleep(1);

    // 测试停止延迟
    startTime = std::chrono::high_resolution_clock::now();
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    endTime = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    int32_t latencyMs1 = static_cast<int32_t>(duration.count());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_003 stop latency: %{public}d ms", latencyMs1);

    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_performance_003 after");
}

/**
 * @tc.name: screen_capture_compatibility_004
 * @tc.desc: 文件格式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_004, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_004 before");
    SetConfig(config_);

    // 测试mp4格式
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_004.mp4", recorderInfo);
    recorderInfo.fileFormat = "mp4";

    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(1);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_004 after");
}

/**
 * @tc.name: screen_capture_compatibility_005_1
 * @tc.desc: 捕获模式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_005_1, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_1 before");
    SetConfig(config_);

    // 测试CAPTURE_HOME_SCREEN模式
    config_.captureMode = CAPTURE_HOME_SCREEN;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_1 after");
}

/**
 * @tc.name: screen_capture_compatibility_005_2
 * @tc.desc: 捕获模式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_005_2, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_2 before");
    SetConfig(config_);

    // 测试CAPTURE_SPECIFIED_SCREEN模式
    config_.captureMode = CAPTURE_SPECIFIED_SCREEN;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_2 after");
}

/**
 * @tc.name: screen_capture_compatibility_005_3
 * @tc.desc: 捕获模式测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_005_3, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_3 before");
    SetConfig(config_);

    // 测试CAPTURE_SPECIFIED_WINDOW模式
    config_.captureMode = CAPTURE_SPECIFIED_WINDOW;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_005_3 after");
}

/**
 * @tc.name: screen_capture_compatibility_006_1
 * @tc.desc: 数据类型测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_006_1, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_006_1 before");
    SetConfig(config_);

    // 测试ORIGINAL_STREAM模式
    config_.dataType = ORIGINAL_STREAM;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_006_1 after");
}

/**
 * @tc.name: screen_capture_compatibility_006_2
 * @tc.desc: 数据类型测试
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_compatibility_006_2, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_006_2 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_006_2.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.audioInfo.micCapInfo = micCapInfo;

    // 测试CAPTURE_FILE模式
    config_.dataType = CAPTURE_FILE;
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());

    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_compatibility_006_2 after");
}

HWTEST_F(ScreenCaptureUnitTest, PauseScreenRecording_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest PauseScreenRecording_001 before");
    SetConfig(config_);

    // 测试mp4格式
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_004.mp4", recorderInfo);
    recorderInfo.fileFormat = "mp4";

    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPause(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(1);
    ASSERT_EQ(MSERR_OK, screenCapture_->PauseScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest PauseScreenRecording_001 after");
}

HWTEST_F(ScreenCaptureUnitTest, PauseScreenRecording_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest PauseScreenRecording_002 before");
    SetConfig(config_);

    // 测试mp4格式
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_004.mp4", recorderInfo);
    recorderInfo.fileFormat = "mp4";

    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPause(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(1);
    ASSERT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    ASSERT_NE(MSERR_OK, screenCapture_->PauseScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest PauseScreenRecording_002 after");
}

HWTEST_F(ScreenCaptureUnitTest, ResumeScreenRecording_001, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest ResumeScreenRecording_001 before");
    SetConfig(config_);

    // 测试mp4格式
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_004.mp4", recorderInfo);
    recorderInfo.fileFormat = "mp4";

    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPause(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(1);
    ASSERT_EQ(MSERR_OK, screenCapture_->PauseScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->ResumeScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest ResumeScreenRecording_001 after");
}

HWTEST_F(ScreenCaptureUnitTest, ResumeScreenRecording_002, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest ResumeScreenRecording_002 before");
    SetConfig(config_);

    // 测试mp4格式
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_compatibility_004.mp4", recorderInfo);
    recorderInfo.fileFormat = "mp4";

    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;

    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->CreateCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StrategyForPause(true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->ReleaseCaptureStrategy());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(1);
    ASSERT_EQ(MSERR_OK, screenCapture_->PauseScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    ASSERT_NE(MSERR_OK, screenCapture_->ResumeScreenRecording());
    ASSERT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest ResumeScreenRecording_002 after");
}

/**
 * @tc.name: screen_capture_multi_display_01
 * @tc.desc: screen capture buffer test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenCaptureUnitTest, screen_capture_multi_display_01, TestSize.Level2)
{
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_multi_display_01 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    vector<uint64_t> displayIds = {0, 1};
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    MultiDisplayCapability multiDisplayCapability;
    EXPECT_EQ(MSERR_OK,
        screenCapture_->GetMultiDisplayCaptureCapability(&displayIds[0], displayIds.size(), &multiDisplayCapability));
    EXPECT_EQ(multiDisplayCapability.isMultiDisplaySupport, false);
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    MEDIA_LOGI("ScreenCaptureUnitTest screen_capture_multi_display_01 after");
}
} // namespace Media
} // namespace OHOS