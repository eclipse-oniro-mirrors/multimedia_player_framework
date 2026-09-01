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

// ===================== AcquireAudioBuffer =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_MicSuccess, TestSize.Level2)
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

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_InnerAllPlayback, TestSize.Level2)
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

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_NotRecording, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_UNKNOWN);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== AudioRendererStateUpdate =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_Headset, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_HEADSET, AUDIO_STATE_HEADSET);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_SpeakerNoHeadset, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_HEADSET, 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_HeadsetMixed, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto headsetInfo = std::make_shared<AudioRendererChangeInfo>();
    headsetInfo->rendererState = RendererState::RENDERER_RUNNING;
    headsetInfo->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    headsetInfo->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    changeInfos.push_back(headsetInfo);
    auto speakerInfo = std::make_shared<AudioRendererChangeInfo>();
    speakerInfo->rendererState = RendererState::RENDERER_RUNNING;
    speakerInfo->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    speakerInfo->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(speakerInfo);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_HEADSET, 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_VoIP, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_VOIP, AUDIO_STATE_VOIP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_VoIPMasked, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->appName_ = "not.the.screen.recorder";
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_VOIP, 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_TelCall, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_PREPARED;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_TEL, AUDIO_STATE_TEL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_EmptyChangeInfo, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->audioRendererState_.store(AUDIO_STATE_VOIP);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load(), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_NullptrInChangeInfo, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    changeInfos.push_back(nullptr);
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->AudioRendererStateUpdate(changeInfos);
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load(), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioRendererStateUpdate_SameState, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->audioRendererState_.store(0);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    EXPECT_EQ(screenCaptureServer_->AudioRendererStateUpdate(changeInfos), MSERR_OK);
}

// ===================== StartInnerAudioCapture =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_CreateFail, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.returnNull = true;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_UNKNOWN_AUDIO_CREATE);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_StartFail, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.startFail = true;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_UNKNOWN_AUDIO_START);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartInnerAudioCapture_AlreadyRecording, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StartInnerAudioCapture(), MSERR_OK);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

// ===================== StartMicAudioCapture =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StartMicAudioCapture_CreateFail, TestSize.Level2)
{
    AcwFlagGuard guard;
    g_acwCreateMockFlags.returnNull = true;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StartMicAudioCapture(false), MSERR_UNKNOWN_AUDIO_CREATE);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartMicAudioCapture_AlreadyRecording, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StartMicAudioCapture(false), MSERR_OK);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== SetMicrophoneEnabled =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_NotRunning, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    EXPECT_EQ(screenCaptureServer_->SetMicrophoneEnabled(false), MSERR_OK);
    EXPECT_FALSE(screenCaptureServer_->isMicrophoneSwitchTurnOn_);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_MicConfigInvalid, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    EXPECT_EQ(screenCaptureServer_->SetMicrophoneEnabled(true), MSERR_OK);
}

// ===================== StopAudioCapture =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StopAudioCapture_BothNull, TestSize.Level2)
{
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->StopAudioCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopAudioCapture_WithWrappers, TestSize.Level2)
{
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    auto innerWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    innerWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->StopAudioCapture(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

// ===================== StopMicAudio =====================

HWTEST_F(ScreenCaptureServerFunctionTest, StopMicAudio_NotRecording, TestSize.Level2)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicAd", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    EXPECT_FALSE(screenCaptureServer_->StopMicAudio());
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== ExcludeContent =====================

HWTEST_F(ScreenCaptureServerFunctionTest, ExcludeContent_NotAlive, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    ScreenCaptureContentFilter filter;
    EXPECT_EQ(screenCaptureServer_->ExcludeContent(filter), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ExcludeContent_AliveNotActive_NoInner, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    ScreenCaptureContentFilter filter;
    filter.windowIDsVec = {1, 2};
    EXPECT_EQ(screenCaptureServer_->ExcludeContent(filter), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->contentFilter_.windowIDsVec, filter.windowIDsVec);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ExcludeContent_InnerCaptureUpdateFails, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnAd", true);
    ScreenCaptureContentFilter contentFilter;
    EXPECT_EQ(screenCaptureServer_->ExcludeContent(contentFilter), MSERR_INVALID_VAL);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
}

// ===================== SyncAudioCaptures =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SyncAudioCaptures_InnerStart, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("sync_audio_inner.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->cbProxy_,
        std::string("InnerSync"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->captureState_ = AudioCapturerWrapperState::CAPTURER_UNKNOWN;
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->innerAudioCapture_->captureState_, AudioCapturerWrapperState::CAPTURER_RECORDING);
    EXPECT_EQ(screenCaptureServer_->micAudioCapture_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SyncAudioCaptures_TelOverlay, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->audioRendererState_.store(0);
    screenCaptureServer_->isInTelCall_.store(true);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SyncAudioCaptures_MicStopOnTel, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::PASSTHROUGH);
    screenCaptureServer_->audioRendererState_.store(AUDIO_STATE_TEL);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicTel", false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    EXPECT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_ = nullptr;
}

// ===================== TelCallStateUpdated =====================

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_NotRunning, TestSize.Level2)
{
    screenCaptureServer_->isInTelCall_.store(false);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_Started, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    auto waitTask = std::make_shared<TaskHandler<void>>([]() {});
    screenCaptureServer_->taskQue_.EnqueueTask(waitTask);
    waitTask->GetResult();
    EXPECT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
    EXPECT_NE(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, TelCallStateUpdated_KeepCaptureDuringCall, TestSize.Level2)
{
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->audioRendererState_.store(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    auto waitTask1 = std::make_shared<TaskHandler<void>>([]() {});
    screenCaptureServer_->taskQue_.EnqueueTask(waitTask1);
    waitTask1->GetResult();
    ASSERT_EQ(screenCaptureServer_->isInTelCall_.load(), true);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    auto waitTask2 = std::make_shared<TaskHandler<void>>([]() {});
    screenCaptureServer_->taskQue_.EnqueueTask(waitTask2);
    waitTask2->GetResult();
    ASSERT_EQ(screenCaptureServer_->isInTelCall_.load(), false);
}

// ===================== OnAudioRendererStateChanged callback =====================

HWTEST_F(ScreenCaptureServerFunctionTest, OnAudioRendererStateChanged_VoIP, TestSize.Level2)
{
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    SetupAudioDataSource(AudioCombinePolicy::MIX_ALL);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> changeInfos;
    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    info->outputDeviceInfo.deviceType_ = AudioStandard::DEVICE_TYPE_SPEAKER;
    changeInfos.push_back(info);
    screenCaptureServer_->OnAudioRendererStateChanged(changeInfos);
    WaitForTaskComplete();
    EXPECT_EQ(screenCaptureServer_->audioRendererState_.load() & AUDIO_STATE_VOIP, AUDIO_STATE_VOIP);
}

} // namespace Media
} // namespace OHOS
