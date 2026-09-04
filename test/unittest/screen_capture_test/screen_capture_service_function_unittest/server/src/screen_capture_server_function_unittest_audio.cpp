/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "audio_capturer_wrapper.h"
#include "image_source.h"
#include "image_type.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "mock/mock_audio_capturer.h"
#include "mock/mock_screen_capture_service_providers.h"
#include "param_wrapper.h"
#include "pixel_map.h"
#include "recorder_server.h"
#include "scope_guard.h"
#include "screen_capture_monitor_listener_proxy.h"
#include "screen_capture_monitor_server.h"
#include "screen_capture_monitor_service_stub.h"
#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"
#include "task_queue.h"
#include "ui_extension_ability_connection.h"
#include "uri_helper.h"
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServerFunctionTest"};
}

namespace OHOS {
namespace Media {
class MockAudioDataSourceListener : public IAudioDataSourceListener {
public:
    void OnAudioDataReady() override
    {
        dataReadyCalled_ = true;
    }
    bool dataReadyCalled_ = false;
};

void ScreenCaptureServerFunctionTest::SetSCInnerAudioCaptureAndPushData(std::shared_ptr<CacheBuffer> innerAudioBuffer)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        "OS_InnerAudioCapture", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(innerAudioBuffer);
}

void ScreenCaptureServerFunctionTest::SetSCMicAudioCaptureAndPushData(std::shared_ptr<CacheBuffer> micAudioBuffer)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(micAudioBuffer);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixAudio_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int channels = 2;
    const int bufferSize = 10;
    const char minChar = -128;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t innerBufferValue[bufferSize] = {minChar, minChar, minChar, minChar, minChar, minChar, minChar, minChar,
        minChar, minChar};
    uint8_t micBufferValue[bufferSize] = {minChar, minChar, minChar, minChar, minChar, minChar, minChar, minChar,
        minChar, minChar};
    memcpy_s(innerBuf.get(), bufferSize, innerBufferValue, bufferSize);
    memcpy_s(micBuf.get(), bufferSize, micBufferValue, bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    char mixData[bufferSize] = {0};
    screenCaptureServer_->audioSource_->MixAudio(*innerAudioBuffer, *micAudioBuffer,
        reinterpret_cast<uint8_t *>(mixData), channels);
    ASSERT_EQ(mixData[0], 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixAudio_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int channels = 2;
    const int bufferSize = 10;
    const char maxChar = 127;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t innerBufferValue[bufferSize] = {maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar,
        maxChar, maxChar};
    uint8_t micBufferValue[bufferSize] = {maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar,
        maxChar, maxChar};
    memcpy_s(innerBuf.get(), bufferSize, innerBufferValue, bufferSize);
    memcpy_s(micBuf.get(), bufferSize, micBufferValue, bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    char mixData[bufferSize] = {0};
    screenCaptureServer_->audioSource_->MixAudio(*innerAudioBuffer, *micAudioBuffer,
        reinterpret_cast<uint8_t *>(mixData), channels);
    ASSERT_EQ(mixData[1], maxChar);
}

// MixAudio input channels param is 0
HWTEST_F(ScreenCaptureServerFunctionTest, MixAudio_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    const char maxChar = 127;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t innerBufferValue[bufferSize] = {maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar,
        maxChar, maxChar};
    uint8_t micBufferValue[bufferSize] = {maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar, maxChar,
        maxChar, maxChar};
    memcpy_s(innerBuf.get(), bufferSize, innerBufferValue, bufferSize);
    memcpy_s(micBuf.get(), bufferSize, micBufferValue, bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    char mixData[bufferSize] = {0};
    screenCaptureServer_->audioSource_->MixAudio(*innerAudioBuffer, *micAudioBuffer,
        reinterpret_cast<uint8_t *>(mixData), 0);
    ASSERT_EQ(mixData[0], 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtMix_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int64_t size = 0;
    screenCaptureServer_->audioSource_->GetSize(size);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->audioSource_->GetSize(size);
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
    screenCaptureServer_->audioSource_->ReadAt(buffer, bufferSize);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtMicMode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetMicCapture(wrapper);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->ReadAtMicMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::RETRY_SKIP);
    MEDIA_LOGI("ReadAtMicMode ret: %{public}d", static_cast<int32_t>(ret));
    screenCaptureServer_->micAudioCapture_->captureState_ = AudioCapturerWrapperState::CAPTURER_UNKNOWN;
    ret = screenCaptureServer_->audioSource_->ReadAtMicMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::RETRY_SKIP);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->audioSource_->SetMicCapture(nullptr);
    ret = screenCaptureServer_->audioSource_->ReadAtMicMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::INVALID);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtMicMode_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(micAudioBuffer);
    screenCaptureServer_->audioSource_->SetMicCapture(wrapper);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->ReadAtMicMode();
    MEDIA_LOGI("ReadAtMicMode ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtInnerMode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        "OS_innerAudioCapture", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetInnerCapture(wrapper);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->ReadAtInnerMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::RETRY_SKIP);
    MEDIA_LOGI("ReadAtInnerMode ret: %{public}d", static_cast<int32_t>(ret));
    screenCaptureServer_->innerAudioCapture_->captureState_ = AudioCapturerWrapperState::CAPTURER_UNKNOWN;
    ret = screenCaptureServer_->audioSource_->ReadAtInnerMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::RETRY_SKIP);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->audioSource_->SetInnerCapture(nullptr);
    ret = screenCaptureServer_->audioSource_->ReadAtInnerMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::INVALID);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtInnerMode_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->SetInnerCapture(screenCaptureServer_->innerAudioCapture_);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->ReadAtInnerMode();
    MEDIA_LOGI("ReadAtInnerMode ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadAtMixMode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->ReadAtMixMode();
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadWriteAudioBufferMix_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMix(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadWriteAudioBufferMix_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = true;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMix(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadWriteAudioBufferMixCore_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadWriteAudioBufferMixCore_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = nullptr;
    screenCaptureServer_->stopAcquireAudioBufferFromAudio_ = true;
    screenCaptureServer_->audioSource_->isInWaitMicSyncState_ = true;
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    screenCaptureServer_->stopAcquireAudioBufferFromAudio_ = true;
    screenCaptureServer_->audioSource_->isInWaitMicSyncState_ = false;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = false;
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    screenCaptureServer_->stopAcquireAudioBufferFromAudio_ = false;
    screenCaptureServer_->audioSource_->isInWaitMicSyncState_ = true;
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    screenCaptureServer_->stopAcquireAudioBufferFromAudio_ = false;
    screenCaptureServer_->audioSource_->isInWaitMicSyncState_ = false;
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReadWriteAudioBufferMixCore_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    innerAudioBuffer = nullptr;
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetFirstAudioTime_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    innerAudioBuffer->timestamp = 2;
    micAudioBuffer->timestamp = 1;
    int64_t resTime = screenCaptureServer_->audioSource_->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(resTime, micAudioBuffer->timestamp);
    innerAudioBuffer->timestamp = 1;
    micAudioBuffer->timestamp = 2;
    resTime = screenCaptureServer_->audioSource_->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(resTime, innerAudioBuffer->timestamp);
    innerAudioBuffer = nullptr;
    resTime = screenCaptureServer_->audioSource_->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(resTime, micAudioBuffer->timestamp);
    auto innerBufNew = std::make_unique<uint8_t[]>(bufferSize);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBufNew), bufferSize, 0, SOURCE_DEFAULT);
    innerAudioBuffer->timestamp = 1;
    micAudioBuffer = nullptr;
    resTime = screenCaptureServer_->audioSource_->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(resTime, innerAudioBuffer->timestamp);
    innerAudioBuffer = nullptr;
    micAudioBuffer = nullptr;
    resTime = screenCaptureServer_->audioSource_->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(resTime, -1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, WriteInnerAudio_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = -1;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->WriteInnerAudio(innerAudioBuffer);
    MEDIA_LOGI("WriteInnerAudio_001 1 ret: %{public}d", static_cast<int32_t>(ret));
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 10;
    ret = screenCaptureServer_->audioSource_->WriteInnerAudio(innerAudioBuffer);
    MEDIA_LOGI("WriteInnerAudio_001 2 ret: %{public}d", static_cast<int32_t>(ret));
}

HWTEST_F(ScreenCaptureServerFunctionTest, WriteMicAudio_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = -1;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->WriteMicAudio(micAudioBuffer);
    MEDIA_LOGI("WriteMicAudio_001 1 ret: %{public}d", static_cast<int32_t>(ret));
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 10;
    ret = screenCaptureServer_->audioSource_->WriteMicAudio(micAudioBuffer);
    MEDIA_LOGI("WriteMicAudio_001 2 ret: %{public}d", static_cast<int32_t>(ret));
}

HWTEST_F(ScreenCaptureServerFunctionTest, WriteMixAudio_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = -1;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->WriteMixAudio(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("WriteMixAudio_001 1 ret: %{public}d", static_cast<int32_t>(ret));
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 10;
    ret = screenCaptureServer_->audioSource_->WriteMixAudio(innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("WriteMixAudio_001 2 ret: %{public}d", static_cast<int32_t>(ret));
}

HWTEST_F(ScreenCaptureServerFunctionTest, InnerMicAudioSync_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 1;
    innerAudioBuffer->timestamp = 31333334;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("InnerMicAudioSync_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InnerMicAudioSync_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 21333334;
    innerAudioBuffer->timestamp = 31333334;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("InnerMicAudioSync_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InnerMicAudioSync_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 31333334;
    innerAudioBuffer->timestamp = 1;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("InnerMicAudioSync_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_SetAppPid_GetAppPid, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    int32_t testPid = 12345;
    screenCaptureServer_->audioSource_->SetAppPid(testPid);
    ASSERT_EQ(screenCaptureServer_->audioSource_->GetAppPid(), testPid);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_GetCurrentTimeNs, TestSize.Level2)
{
    int64_t time1 = GetCurrentTimeNs();
    int64_t time2 = GetCurrentTimeNs();
    ASSERT_GE(time2, time1);
    ASSERT_GT(time1, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_Pause_Resume, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->Pause();
    ASSERT_GT(screenCaptureServer_->audioSource_->pauseStartTime_.load(), 0);
    sleep(1);
    screenCaptureServer_->audioSource_->Resume();
    ASSERT_GT(screenCaptureServer_->audioSource_->pauseDuration_.load(), 0);
    ASSERT_GE(screenCaptureServer_->audioSource_->pauseDuration_.load(), 1000000000); // At least 1 second in ns
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_SetVideoFirstFramePts, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    int64_t testPts = 123456789;
    screenCaptureServer_->audioSource_->SetVideoFirstFramePts(testPts);
    ASSERT_EQ(screenCaptureServer_->audioSource_->firstVideoFramePts_.load(), testPts);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_SetAudioFirstFramePts, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    int64_t testPts = 987654321;
    screenCaptureServer_->audioSource_->SetAudioFirstFramePts(testPts);
    ASSERT_EQ(screenCaptureServer_->audioSource_->firstAudioFramePts_, testPts);
    // Test that it only sets once
    screenCaptureServer_->audioSource_->SetAudioFirstFramePts(111111111);
    ASSERT_EQ(screenCaptureServer_->audioSource_->firstAudioFramePts_, testPts);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_LostFrameNum, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 100000000; // 100ms
    screenCaptureServer_->audioSource_->writedFrameTime_ = 50000000;     // 50ms
    screenCaptureServer_->audioSource_->pauseDuration_ = 0;
    int64_t timestamp = 150000000; // 150ms
    int64_t lostNum = screenCaptureServer_->audioSource_->LostFrameNum(timestamp);
    // (150ms - 0 - (50ms + 100ms)) / frame_duration = 0
    ASSERT_EQ(lostNum, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_HandlePastMicBuffer, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 1000000;
    screenCaptureServer_->audioSource_->lastWriteAudioFramePts_ = 2000000;
    screenCaptureServer_->audioSource_->lastMicAudioFramePts_ = 1500000;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
    // Mock the ReleaseMicAudioBuffer call
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->audioSource_->HandlePastMicBuffer(micAudioBuffer);
    // Buffer should be set to nullptr
    ASSERT_EQ(micAudioBuffer, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_HandleBufferTimeStamp, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    innerAudioBuffer->timestamp = 1000000;
    micAudioBuffer->timestamp = 2000000;
    screenCaptureServer_->audioSource_->lastWriteAudioFramePts_ = 3000000;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->audioSource_->HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    // Inner buffer should be dropped
    ASSERT_EQ(innerAudioBuffer, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_SetMixAudioTypeLog, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->audioType_ = AVScreenCaptureMixBufferType::INNER;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
    screenCaptureServer_->audioSource_->audioTypeSize_ = 10;
    screenCaptureServer_->audioSource_->SetMixAudioTypeLog(AVScreenCaptureMixBufferType::MIC);
    ASSERT_EQ(screenCaptureServer_->audioSource_->audioType_.load(), AVScreenCaptureMixBufferType::MIC);
    ASSERT_EQ(screenCaptureServer_->audioSource_->audioTypeSize_.load(), 1);
    // Call again with same type
    screenCaptureServer_->audioSource_->SetMixAudioTypeLog(AVScreenCaptureMixBufferType::MIC);
    ASSERT_EQ(screenCaptureServer_->audioSource_->audioTypeSize_.load(), 2);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleMicBeforeInnerSync_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 1;
    innerAudioBuffer->timestamp = 3000000000;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("HandleMicBeforeInnerSync_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_NE(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleMicBeforeInnerSync_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 1;
    innerAudioBuffer->timestamp = 3000000000;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("HandleMicBeforeInnerSync_002 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_NE(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleMicBeforeInnerSync_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer->timestamp = 2;
    innerAudioBuffer->timestamp = 3;
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer,
        micAudioBuffer);
    MEDIA_LOGI("HandleMicBeforeInnerSync_003 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    timeWindow = 31333334;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    timeWindow = 1;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = false;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_002 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = true;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_002 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = false;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_003 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = true;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_003 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_004, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_004.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = nullptr;
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = true;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_004 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = false;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_004 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_005, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_005.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = nullptr;
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = true;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_005 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->mixModeAddAudioMicFrame_ = false;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_005 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_006, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_006.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    micAudioBuffer = nullptr;
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = 31333334;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_006 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_006 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncMixMode_007, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_007.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    screenCaptureServer_->StartMicAudioCapture(false);
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCMicAudioCaptureAndPushData(micAudioBuffer);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = 31333334;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow,
        innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_007 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    screenCaptureServer_->micAudioCapture_ = nullptr;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncMixMode_007 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncInnerMode_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow,
        innerAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncInnerMode_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    timeWindow = 31333334;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    innerAudioBuffer = std::make_shared<CacheBuffer>(std::make_unique<uint8_t[]>(bufferSize), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    timeWindow = 1;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncInnerMode_001 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncInnerMode_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow,
        innerAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncInnerMode_002 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
    innerAudioBuffer = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncInnerMode_002 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    timeWindow = 31333334;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, VideoAudioSyncInnerMode_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->StartInnerAudioCapture();
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    int64_t timeWindow = -31333334;
    innerAudioBuffer = nullptr;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->VideoAudioSyncInnerMode(timeWindow,
        innerAudioBuffer);
    MEDIA_LOGI("VideoAudioSyncInnerMode_003 ret: %{public}d", static_cast<int32_t>(ret));
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer,
        micAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<CacheBuffer> micAudioBuffer;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer,
        micAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer;
    std::shared_ptr<CacheBuffer> micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer,
        micAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> innerAudioBuffer;
    std::shared_ptr<CacheBuffer> micAudioBuffer;
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer,
        micAudioBuffer);
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::RETRY_SKIP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SyncAudioCaptures_002, TestSize.Level2)
{
    SetSCInnerAudioCaptureAndPushData(nullptr);
    screenCaptureServer_->innerAudioCapture_->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    auto ret = screenCaptureServer_->SyncAudioCaptures();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SyncAudioCaptures_003, TestSize.Level2)
{
    SetSCInnerAudioCaptureAndPushData(nullptr);
    auto ret = screenCaptureServer_->SyncAudioCaptures();
    EXPECT_EQ(ret, MSERR_OK);
}

// covers OnBufferAvailable: cacheBuffer_ already set -> NotifyDataReady and return
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceOnBufferAvailable_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->OnBufferAvailable(SOURCE_DEFAULT);
    ASSERT_NE(screenCaptureServer_->audioSource_->cacheBuffer_, nullptr);
}

// covers SetInnerCapture clearing the previous capture's callback
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceSetInnerCaptureClearOld_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    auto w1 = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "Inner1", true);
    w1->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetInnerCapture(w1);
    ASSERT_EQ(screenCaptureServer_->audioSource_->innerCapture_, w1);
    auto w2 = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "Inner2", true);
    screenCaptureServer_->audioSource_->SetInnerCapture(w2);
    ASSERT_EQ(screenCaptureServer_->audioSource_->innerCapture_, w2);
    screenCaptureServer_->audioSource_->SetInnerCapture(nullptr);
    ASSERT_EQ(screenCaptureServer_->audioSource_->innerCapture_, nullptr);
}

// covers SetMicCapture clearing the previous capture's callback
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceSetMicCaptureClearOld_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    auto w1 = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "Mic1", false);
    w1->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetMicCapture(w1);
    ASSERT_EQ(screenCaptureServer_->audioSource_->micCapture_, w1);
    auto w2 = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "Mic2", false);
    screenCaptureServer_->audioSource_->SetMicCapture(w2);
    ASSERT_EQ(screenCaptureServer_->audioSource_->micCapture_, w2);
    screenCaptureServer_->audioSource_->SetMicCapture(nullptr);
    ASSERT_EQ(screenCaptureServer_->audioSource_->micCapture_, nullptr);
}

// covers WriteInnerAudio with nullptr -> RETRY_SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceWriteInnerAudio_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> empty;
    ASSERT_EQ(screenCaptureServer_->audioSource_->WriteInnerAudio(empty), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// covers WriteMicAudio with nullptr -> RETRY_SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceWriteMicAudio_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> empty;
    ASSERT_EQ(screenCaptureServer_->audioSource_->WriteMicAudio(empty), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// covers WriteMixAudio with nullptr -> RETRY_SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceWriteMixAudio_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> empty;
    ASSERT_EQ(screenCaptureServer_->audioSource_->WriteMixAudio(empty, empty),
        AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// covers InnerMicAudioSync with negative timestamps -> SKIP_WITHOUT_LOG
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceInnerMicAudioSync_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, -1, SOURCE_DEFAULT);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, -1, SOURCE_DEFAULT);
    ASSERT_EQ(screenCaptureServer_->audioSource_->InnerMicAudioSync(innerAudioBuffer, micAudioBuffer),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers ReadWriteAudioBufferMixCore with both buffers null -> SKIP_WITHOUT_LOG
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadWriteAudioBufferMixCore_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> innerAudioBuffer;
    std::shared_ptr<CacheBuffer> micAudioBuffer;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers HandleSwitchToSpeakerOptimise optimise branch (count > threshold) and else branch
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceHandleSwitchToSpeakerOptimise_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::MIX;
    const int32_t bufferSize = 10;
    auto inner = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnerOpt", true);
    inner->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetInnerCapture(inner);
    screenCaptureServer_->audioSource_->stableStopInnerSwitchCount_ = AudioDataSource::INNER_SWITCH_MIC_REQUIRE_COUNT +
        1;
    auto innerBufA = std::make_unique<uint8_t[]>(bufferSize);
    auto micBufA = std::make_unique<uint8_t[]>(bufferSize);
    auto innerAudioBufferA = std::make_shared<CacheBuffer>(std::move(innerBufA), bufferSize, 100, SOURCE_DEFAULT);
    auto micAudioBufferA = std::make_shared<CacheBuffer>(std::move(micBufA), bufferSize, 100, SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->HandleSwitchToSpeakerOptimise(innerAudioBufferA, micAudioBufferA);
    ASSERT_EQ(innerAudioBufferA, nullptr); // optimise nulls inner
    // else branch: count below threshold increments
    auto inner2 = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnerOpt2", true);
    inner2->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetInnerCapture(inner2);
    screenCaptureServer_->audioSource_->stableStopInnerSwitchCount_ = 0;
    auto innerBufB = std::make_unique<uint8_t[]>(bufferSize);
    auto micBufB = std::make_unique<uint8_t[]>(bufferSize);
    auto innerAudioBufferB = std::make_shared<CacheBuffer>(std::move(innerBufB), bufferSize, 100, SOURCE_DEFAULT);
    auto micAudioBufferB = std::make_shared<CacheBuffer>(std::move(micBufB), bufferSize, 100, SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->HandleSwitchToSpeakerOptimise(innerAudioBufferB, micAudioBufferB);
    ASSERT_EQ(screenCaptureServer_->audioSource_->stableStopInnerSwitchCount_, 1);
}

// covers GetSize with no cacheBuffer -> MSERR_UNKNOWN
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceGetSize_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    int64_t size = -1;
    ASSERT_EQ(screenCaptureServer_->audioSource_->GetSize(size), MSERR_UNKNOWN);
}

// covers ReadAt: no cacheBuffer -> SKIP_WITHOUT_LOG
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAt_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAt(buffer, 10),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers ReadAt: null buffer -> RETRY_IN_INTERVAL
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAt_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0,
        SOURCE_DEFAULT);
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAt(nullptr, bufferSize),
        AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL);
}

// covers ReadAt: WriteTo fails (null ownedBuf) -> silent fill
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAt_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(nullptr, bufferSize, 0,
        SOURCE_DEFAULT);
    uint8_t avMem[bufferSize] = {0};
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avMem, bufferSize, bufferSize);
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAt(buffer, bufferSize), AudioDataSourceReadAtActionState::OK);
}

// covers ReadAt: lost frame -> silent fill
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAt_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize,
        40000000, SOURCE_DEFAULT); // 2 frame durations ahead
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 0;
    screenCaptureServer_->audioSource_->writedFrameTime_ = 0;
    screenCaptureServer_->audioSource_->pauseDuration_ = 0;
    uint8_t avMem[bufferSize] = {0};
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avMem, bufferSize, bufferSize);
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAt(buffer, bufferSize), AudioDataSourceReadAtActionState::OK);
}

// covers ReadAt: success path
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAt_005, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 0;
    screenCaptureServer_->audioSource_->writedFrameTime_ = 0;
    screenCaptureServer_->audioSource_->pauseDuration_ = 0;
    uint8_t avMem[bufferSize] = {0};
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avMem, bufferSize, bufferSize);
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAt(buffer, bufferSize), AudioDataSourceReadAtActionState::OK);
    ASSERT_EQ(screenCaptureServer_->audioSource_->cacheBuffer_, nullptr);
}

// covers ReadAudioBuffer: not CAP_ACTIVE -> SKIP_WITHOUT_LOG
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED; // not active
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers ReadAudioBuffer: recorder file with video but firstVideoFramePts unset -> SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = true;
    screenCaptureServer_->audioSource_->firstVideoFramePts_ = -1;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers ReadAudioBuffer: invalid mix mode -> RETRY_SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INVALID_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = false;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(), AudioDataSourceReadAtActionState::RETRY_SKIP);
}

// covers OnBufferAvailable: cacheBuffer_ null + ReadAudioBuffer not OK (not CAP_ACTIVE)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceOnBufferAvailable_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->audioSource_->OnBufferAvailable(SOURCE_DEFAULT);
    ASSERT_EQ(screenCaptureServer_->audioSource_->cacheBuffer_, nullptr);
}

// covers OnBufferAvailable: cacheBuffer_ null + ReadAudioBuffer OK (MIC_MODE with buffer)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceOnBufferAvailable_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = false;
    const int32_t bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0, SOURCE_DEFAULT);
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(micAudioBuffer);
    screenCaptureServer_->audioSource_->SetMicCapture(wrapper);
    screenCaptureServer_->audioSource_->OnBufferAvailable(SOURCE_DEFAULT);
    ASSERT_NE(screenCaptureServer_->audioSource_->cacheBuffer_, nullptr);
}

// covers NotifyDataReady: listener_ set -> OnAudioDataReady called
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceNotifyDataReady_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    auto listener = std::make_shared<MockAudioDataSourceListener>();
    screenCaptureServer_->audioSource_->SetListener(listener);
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0,
        SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->OnBufferAvailable(SOURCE_DEFAULT);
    ASSERT_TRUE(listener->dataReadyCalled_);
}

// covers GetSize: valid cacheBuffer_ with length > 0 -> MSERR_OK
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceGetSize_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    screenCaptureServer_->audioSource_->cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0,
        SOURCE_DEFAULT);
    int64_t size = 0;
    ASSERT_EQ(screenCaptureServer_->audioSource_->GetSize(size), MSERR_OK);
    ASSERT_EQ(size, bufferSize);
}

// covers LostFrameNum: negative firstAudioFramePts_ / timestamp / pauseDuration / writedFrameTime_ -> 0
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceLostFrameNum_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = -1;
    ASSERT_EQ(screenCaptureServer_->audioSource_->LostFrameNum(1000), 0);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 100;
    ASSERT_EQ(screenCaptureServer_->audioSource_->LostFrameNum(-1), 0);
    screenCaptureServer_->audioSource_->pauseDuration_ = -1;
    ASSERT_EQ(screenCaptureServer_->audioSource_->LostFrameNum(1000), 0);
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = 100;
    screenCaptureServer_->audioSource_->pauseDuration_ = 0;
    screenCaptureServer_->audioSource_->writedFrameTime_ = -1;
    ASSERT_EQ(screenCaptureServer_->audioSource_->LostFrameNum(1000), 0);
}

// covers HandlePastMicBuffer: conditions false (timestamp >= lastWrite) -> buffer not nulled
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceHandlePastMicBuffer_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 100, SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->lastWriteAudioFramePts_ = 100;
    screenCaptureServer_->audioSource_->lastMicAudioFramePts_ = 0;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
    screenCaptureServer_->audioSource_->HandlePastMicBuffer(micAudioBuffer);
    ASSERT_NE(micAudioBuffer, nullptr);
}

// covers HandlePastMicBuffer: conditions true + micCapture_ set -> ReleaseAudioBuffer + null
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceHandlePastMicBuffer_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 100, SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->lastWriteAudioFramePts_ = 200;
    screenCaptureServer_->audioSource_->lastMicAudioFramePts_ = 50;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "MicHBM", false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufSize = 10;
    auto b = std::make_unique<uint8_t[]>(bufSize);
    micWrapper->availBuffers_.push_back(std::make_shared<CacheBuffer>(std::move(b), bufSize, 0, SOURCE_DEFAULT));
    screenCaptureServer_->audioSource_->SetMicCapture(micWrapper);
    screenCaptureServer_->audioSource_->HandlePastMicBuffer(micAudioBuffer);
    ASSERT_EQ(micAudioBuffer, nullptr);
    ASSERT_TRUE(micWrapper->availBuffers_.empty());
}

// covers ReadAtInnerMode: IsSCRecorderFileWithVideo + firstAudioFramePts_ == -1 (L367)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAtInnerMode_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_readatinner_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = true;
    screenCaptureServer_->audioSource_->firstAudioFramePts_ = -1;
    screenCaptureServer_->audioSource_->firstVideoFramePts_ = -1;
    const int32_t bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    std::shared_ptr<CacheBuffer> innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 0,
        SOURCE_DEFAULT);
    SetSCInnerAudioCaptureAndPushData(innerAudioBuffer);
    screenCaptureServer_->audioSource_->SetInnerCapture(screenCaptureServer_->innerAudioCapture_);
    AudioDataSourceReadAtActionState ret = screenCaptureServer_->audioSource_->ReadAtInnerMode();
    ASSERT_EQ(ret, AudioDataSourceReadAtActionState::OK);
}

// covers ReadAudioBuffer: MIX_MODE dispatch (L398) with no captures -> SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = false;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers ReadAudioBuffer: INNER_MODE dispatch (L400) with no innerCapture -> INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_005, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = false;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(), AudioDataSourceReadAtActionState::INVALID);
}

// covers ReadAudioBuffer: MIC_MODE dispatch (L402) with no micCapture -> INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadAudioBuffer_006, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->recorderFileWithVideo_ = false;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadAudioBuffer(), AudioDataSourceReadAtActionState::INVALID);
}

// covers ReadWriteAudioBufferMix: both captures null -> L275 both null -> SKIP
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceReadWriteAudioBufferMix_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    std::shared_ptr<CacheBuffer> innerAudioBuffer;
    std::shared_ptr<CacheBuffer> micAudioBuffer;
    ASSERT_EQ(screenCaptureServer_->audioSource_->ReadWriteAudioBufferMix(innerAudioBuffer, micAudioBuffer),
        AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
}

// covers MixAudio: innerSrc nullptr (mute CacheBuffer) -> L551 return early
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceMixAudio_004, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int bufferSize = 10;
    auto innerAudioBuffer = std::make_shared<CacheBuffer>(nullptr, bufferSize, 0, SOURCE_DEFAULT);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 0, SOURCE_DEFAULT);
    char mixData[bufferSize] = {0};
    screenCaptureServer_->audioSource_->MixAudio(*innerAudioBuffer, *micAudioBuffer,
        reinterpret_cast<uint8_t *>(mixData), 2);
    ASSERT_EQ(mixData[0], 0);
}

// covers HandleBufferTimeStamp: both present -> HandleSwitchToSpeakerOptimise (L463) else branch
HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSourceHandleBufferTimeStamp_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE,
        screenCaptureServer_.get());
    const int32_t bufferSize = 10;
    auto innerBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto micBuf = std::make_unique<uint8_t[]>(bufferSize);
    auto innerAudioBuffer = std::make_shared<CacheBuffer>(std::move(innerBuf), bufferSize, 100, SOURCE_DEFAULT);
    auto micAudioBuffer = std::make_shared<CacheBuffer>(std::move(micBuf), bufferSize, 200, SOURCE_DEFAULT);
    screenCaptureServer_->audioSource_->lastWriteAudioFramePts_ = 50;
    screenCaptureServer_->audioSource_->SetAudioRendererState(0);
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    screenCaptureServer_->audioSource_->lastWriteType_ = AVScreenCaptureMixBufferType::MIX;
    auto inner = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "InnerHBS", true);
    inner->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->audioSource_->SetInnerCapture(inner);
    screenCaptureServer_->audioSource_->stableStopInnerSwitchCount_ = 0;
    screenCaptureServer_->audioSource_->HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    ASSERT_EQ(screenCaptureServer_->audioSource_->stableStopInnerSwitchCount_, 1);
}
} // namespace Media
} // namespace OHOS
