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

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(screenCaptureServer_->GetMicWorkingState(), false);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_004, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_004.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->GetMicWorkingState(), true);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabledFile_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("set_microphone_enabled_file_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}


HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabledFile_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("set_microphone_enabled_file_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneFile_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("set_microphone_file_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOff();
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOn();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneFile_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("set_microphone_file_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOff();
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOn();
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOff();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneFile_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("set_microphone_file_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = false;
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    ASSERT_EQ(screenCaptureServer_->StartScreenCaptureFile(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabledStream_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}


HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabledStream_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabledStream_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(screenCaptureServer_->StartAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneStream_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOff();
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOn();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}


HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneStream_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOff();
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOn();
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->SetMicrophoneOff();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStart_001, TestSize.Level2)
{
    screenCaptureServer_->isInTelCall_.store(false);
    screenCaptureServer_->isInTelCallAudio_.store(false);
    ASSERT_EQ(screenCaptureServer_->OnTelCallStart(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStart_002, TestSize.Level2)
{
    screenCaptureServer_->isInTelCall_.store(false);
    screenCaptureServer_->isInTelCallAudio_.store(true);
    ASSERT_EQ(screenCaptureServer_->OnTelCallStart(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStop_001, TestSize.Level2)
{
    screenCaptureServer_->isInTelCall_.store(false);
    screenCaptureServer_->isInTelCallAudio_.store(false);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = false;
    ASSERT_EQ(screenCaptureServer_->OnTelCallStop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStop_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->isInTelCall_.store(false);
    screenCaptureServer_->isInTelCallAudio_.store(false);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    ASSERT_EQ(screenCaptureServer_->OnTelCallStop(), MSERR_OK);
}
} // Media
} // OHOS