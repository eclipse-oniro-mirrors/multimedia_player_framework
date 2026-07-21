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
#include "mock/mock_audio_capturer.h"
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

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_006_EmptyChangeInfo, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(AUDIO_STATE_VOIP);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_007_VoIP, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_VOIP, AUDIO_STATE_VOIP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_008_VoIPVideo, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_VOIP, AUDIO_STATE_VOIP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_009_Headset, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = DEVICE_TYPE_WIRED_HEADSET;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_010_HeadsetMixed, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto headsetInfo = std::make_shared<AudioRendererChangeInfo>();
    headsetInfo->rendererState = RendererState::RENDERER_RUNNING;
    headsetInfo->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    headsetInfo->outputDeviceInfo.deviceType_ = DEVICE_TYPE_WIRED_HEADSET;
    changeInfos.push_back(headsetInfo);
    auto speakerInfo = std::make_shared<AudioRendererChangeInfo>();
    speakerInfo->rendererState = RendererState::RENDERER_RUNNING;
    speakerInfo->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    speakerInfo->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(speakerInfo);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_011_TelCall, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_TEL, AUDIO_STATE_TEL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_012_NullptrInChangeInfo, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    changeInfos.push_back(nullptr);
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_005, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_005.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIX_MODE;
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetScreenCaptureServer(screenCaptureServer_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->cbProxy_,
        std::string("InnerAudioCapture_voip_005"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(screenCaptureServer_->innerAudioCapture_);
    screenCaptureServer_->innerAudioCapture_->captureState_ = AudioCapturerWrapperState::CAPTURER_UNKNOWN;
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->innerAudioCapture_->captureState_, AudioCapturerWrapperState::CAPTURER_RECORDING);
    EXPECT_EQ(screenCaptureServer_->micAudioCapture_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_007, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_007.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::INNER_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetScreenCaptureServer(screenCaptureServer_);
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        "InnerAudioCapture_voip_007", true);
    wrapper->bundleName_ = ScreenRecorderBundleName;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetAudioRendererState(AUDIO_STATE_VOIP);
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->innerAudioCapture_->captureState_, AudioCapturerWrapperState::CAPTURER_RECORDING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_002, TestSize.Level2)
{
    screenCaptureServer_->isInTelCall_.store(false);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
    EXPECT_NE(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdated_TelOverlay, TestSize.Level2)
{
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIX_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->isInTelCall_.store(true);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto ret = screenCaptureServer_->SyncAudioCaptures();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdated_InnerStartFail, TestSize.Level2)
{
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIX_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(AUDIO_STATE_HEADSET);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.state =
        AVScreenCaptureParamValidationState::VALIDATION_VALID;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        "OS_InnerAudioCapture", true, false);
    auto ret = screenCaptureServer_->SyncAudioCaptures();
    EXPECT_NE(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdated_MicStopOnTel, TestSize.Level2)
{
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIC_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(AUDIO_STATE_TEL);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto micWrapper =
        CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture", false, true);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    auto ret = screenCaptureServer_->SyncAudioCaptures();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdated_MicStartFail, TestSize.Level2)
{
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIC_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(AUDIO_STATE_VOIP);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.state =
        AVScreenCaptureParamValidationState::VALIDATION_VALID;
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false, false);
    auto ret = screenCaptureServer_->SyncAudioCaptures(false);
    EXPECT_NE(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_SyncAudioCaptures, TestSize.Level2)
{
    screenCaptureServer_->recorderFileAudioType_ = AVScreenCaptureMixMode::MIX_MODE;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->isInTelCall_.load(), true);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnRendererStateChange_CallbackPath, TestSize.Level2)
{
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    screenCaptureServer_->audioSource_ =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetScreenCaptureServer(screenCaptureServer_);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    auto changeInfo = std::make_shared<AudioRendererChangeInfo>();
    changeInfo->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    changeInfo->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    audioRendererChangeInfos.push_back(changeInfo);
    screenCaptureServer_->captureCallback_->OnRendererStateChange(audioRendererChangeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_VOIP, AUDIO_STATE_VOIP);
}
} // namespace Media
} // namespace OHOS
