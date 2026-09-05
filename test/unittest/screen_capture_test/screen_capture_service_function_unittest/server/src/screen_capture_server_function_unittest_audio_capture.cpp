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

#include "cache_buffer.h"
#include "mock/mock_audio_capturer.h"
#include "mock/mock_recorder_service.h"
#include "mock/mock_screen_capture_service_providers.h"
#include "scope_guard.h"
#include "screen_capture_server_function_unittest.h"
#include <audio_info.h>
#include <gtest/gtest.h>
#include <unistd.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {

// ===================== AcquireAudioBuffer (L2813-2845) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicSuccess_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(MakeTestCacheBuffer(AudioCaptureSourceType::MIC));
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_OK);
    EXPECT_NE(audioBuffer, nullptr);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicSourceDefault_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(MakeTestCacheBuffer(AudioCaptureSourceType::SOURCE_DEFAULT));
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::SOURCE_DEFAULT), MSERR_OK);
    EXPECT_NE(audioBuffer, nullptr);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_InnerAllPlayback_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(MakeTestCacheBuffer(AudioCaptureSourceType::ALL_PLAYBACK));
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::ALL_PLAYBACK), MSERR_OK);
    EXPECT_NE(audioBuffer, nullptr);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_InnerAppPlayback_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(MakeTestCacheBuffer(AudioCaptureSourceType::APP_PLAYBACK));
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK), MSERR_OK);
    EXPECT_NE(audioBuffer, nullptr);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicNotRecording_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_UNKNOWN);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_InnerNotRecording_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::ALL_PLAYBACK),
        MSERR_UNKNOWN);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicEmptyBuffer_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_UNKNOWN);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicNullCacheBuf_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(nullptr);
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_UNKNOWN);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== AudioRendererStateUpdate (L3151-3203) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_BluetoothSco_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_BLUETOOTH_SCO;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_BluetoothA2dp_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_BLUETOOTH_A2DP;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_UsbHeadset_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_USB_HEADSET;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_UsbArmHeadset_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_USB_ARM_HEADSET;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_NearLink_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_NEARLINK;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_WiredHeadphones_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_WIRED_HEADPHONES;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_SameState_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    EXPECT_EQ(screenCaptureServer_->AudioRendererStateUpdate(changeInfos), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_PreparedTelState_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_PREPARED;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_TEL, AUDIO_STATE_TEL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_VoIPMasked_B1, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->appName_ = "not.the.screen.recorder";
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioSource_->GetAudioRendererState() & AUDIO_STATE_VOIP, 0);
}

// ===================== StartInnerAudioCapture (L1369-1395) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_CreateFail_B1, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.returnNull = true;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_UNKNOWN_AUDIO_CREATE);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_StartFail_B1, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.startFail = true;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_UNKNOWN_AUDIO_START);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_ShowShareBox_B1, TestSize.Level2)
{
    AcwFlagGuard guard;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->showShareSystemAudioBox_ = true;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
    EXPECT_NE(screenCaptureServer_->innerAudioCapture_, nullptr);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_AlreadyRecording_B1, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_NotValid_B1, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->innerAudioCapture_, nullptr);
}

// ===================== StartMicAudioCapture (L3539-3569) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StartMicAudioCapture_CreateFail_B1, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.returnNull = true;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartMicAudioCapture(false), MSERR_UNKNOWN_AUDIO_CREATE);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartMicAudioCapture_StartFail_B1, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.startFail = true;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartMicAudioCapture(false), MSERR_UNKNOWN_AUDIO_START);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartMicAudioCapture_AlreadyRecording_B1, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StartMicAudioCapture(false), MSERR_OK);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== SetMicrophoneEnabled (L3118-3149) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_NotRunning_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    EXPECT_EQ(screenCaptureServer_->SetMicrophoneEnabled(false), MSERR_OK);
    EXPECT_FALSE(screenCaptureServer_->isMicrophoneSwitchTurnOn_);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_MicConfigInvalid_B1, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    EXPECT_EQ(screenCaptureServer_->SetMicrophoneEnabled(true), MSERR_OK);
}

// ===================== StopAudioCapture (L3525-3537) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StopAudioCapture_BothNull_B1, TestSize.Level2)
{
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StopAudioCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopAudioCapture_WithWrappers_B1, TestSize.Level2)
{
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    auto innerWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    innerWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StopAudioCapture(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

// ===================== StopMicAudio (L3205-3216) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StopMicAudio_NotRecording_B1, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    EXPECT_FALSE(screenCaptureServer_->StopMicAudio());
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

} // namespace Media
} // namespace OHOS
