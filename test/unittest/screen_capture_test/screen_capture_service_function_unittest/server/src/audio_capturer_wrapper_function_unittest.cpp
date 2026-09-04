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

#include "image_source.h"
#include "image_type.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "param_wrapper.h"
#include "pixel_map.h"
#include "scope_guard.h"
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "uri_helper.h"
#include <sys/stat.h>
#include <unistd.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
// helper: records whether OnBufferAvailable was invoked
class TestAvailCallback : public AudioBufferAvailableCallback {
public:
    int callCount = 0;
    void OnBufferAvailable(AudioCaptureSourceType type) override
    {
        (void)type;
        callCount++;
    }
};

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
    screenCaptureServer_->innerAudioCapture_->OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture", false);
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Stop(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_->OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture", false);
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Stop(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_->screenCaptureCb_ = nullptr;
    screenCaptureServer_->micAudioCapture_->OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_005, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
    screenCaptureServer_->innerAudioCapture_->screenCaptureCb_ = nullptr;
    screenCaptureServer_->innerAudioCapture_->OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnInterrupt_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    AudioStandard::InterruptEvent interruptEvent;
    AudioCapturerCallbackImpl callback;
    callback.OnInterrupt(interruptEvent);
    callback.OnStateChange(CAPTURER_RUNNING);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ScreenCaptureContentFilter filter;
    filter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO);
    wrapper->UpdateAudioCapturerConfig(filter);
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ScreenCaptureContentFilter filter;
    filter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO);
    wrapper->UpdateAudioCapturerConfig(filter);
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUseUpBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::INNER_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    int64_t currentAudioTime = GetCurrentTimeNs();
    int32_t ret = wrapper->UseUpAllLeftBufferUntil(currentAudioTime);
    (void)ret;
    int64_t currentAudioTime1 = GetCurrentTimeNs();
    wrapper->DropBufferUntil(currentAudioTime1);
    ret = wrapper->UseUpAllLeftBufferUntil(currentAudioTime);
    (void)ret;
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    std::shared_ptr<CacheBuffer> cacheBuf;
    ASSERT_NE(wrapper->AcquireAudioBuffer(cacheBuf), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RELEASED;
    std::shared_ptr<CacheBuffer> cacheBuf;
    ASSERT_NE(wrapper->AcquireAudioBuffer(cacheBuf), MSERR_OK);
}

// covers Start when already recording -> MSERR_UNKNOWN
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_AlreadyRecording, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

// covers UpdateAudioCapturerConfig when audioCapturer_ is nullptr -> MSERR_INVALID_VAL
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ScreenCaptureContentFilter filter;
    ASSERT_EQ(wrapper->UpdateAudioCapturerConfig(filter), MSERR_INVALID_VAL);
}

// covers AcquireAudioBuffer success path and IsStop branch
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0, SOURCE_DEFAULT);
    wrapper->availBuffers_.push_back(cacheBuf);
    std::shared_ptr<CacheBuffer> out;
    ASSERT_EQ(wrapper->AcquireAudioBuffer(out), MSERR_OK);
    ASSERT_EQ(out, cacheBuf);
    // IsStop with non-empty buffer -> MSERR_UNKNOWN
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPPING;
    ASSERT_NE(wrapper->AcquireAudioBuffer(out), MSERR_OK);
}

// covers AcquireAudioBuffer when front buffer is nullptr -> MSERR_UNKNOWN
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(nullptr);
    std::shared_ptr<CacheBuffer> out;
    ASSERT_NE(wrapper->AcquireAudioBuffer(out), MSERR_OK);
}

// covers ReleaseAudioBuffer: not recording -> MSERR_UNKNOWN
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperReleaseAudioBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    ASSERT_NE(wrapper->ReleaseAudioBuffer(), MSERR_OK);
}

// covers ReleaseAudioBuffer: recording but empty -> MSERR_UNKNOWN
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperReleaseAudioBuffer_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    ASSERT_NE(wrapper->ReleaseAudioBuffer(), MSERR_OK);
}

// covers ReleaseAudioBuffer success path
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperReleaseAudioBuffer_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 0, SOURCE_DEFAULT);
    wrapper->availBuffers_.push_back(cacheBuf);
    ASSERT_EQ(wrapper->ReleaseAudioBuffer(), MSERR_OK);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers DropBufferUntil: not recording returns 0; drop path with buffers
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperDropBufferUntil_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    ASSERT_EQ(wrapper->DropBufferUntil(1000), 0);
    // recording: push older buffers, drop until 2000
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufferSize = 10;
    for (int32_t i = 0; i < 3; i++) {
        auto b = std::make_unique<uint8_t[]>(bufferSize);
        wrapper->availBuffers_.push_back(
            std::make_shared<CacheBuffer>(std::move(b), bufferSize, static_cast<int64_t>(i) * 100, SOURCE_DEFAULT));
    }
    int32_t dropped = wrapper->DropBufferUntil(200);
    ASSERT_GE(dropped, 1);
}

// covers UseUpAllLeftBufferUntil: not recording returns OK early; empty -> OK
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUseUpAllLeftBufferUntil_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    ASSERT_EQ(wrapper->UseUpAllLeftBufferUntil(0), MSERR_OK);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    ASSERT_EQ(wrapper->UseUpAllLeftBufferUntil(0), MSERR_OK);
}

// covers IsStop STOPPING state and GetAudioCapturerState / setters
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStateAndSetters_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPPING;
    ASSERT_TRUE(wrapper->IsStop());
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    ASSERT_FALSE(wrapper->IsStop());
    ASSERT_EQ(wrapper->GetAudioCapturerState(), AudioCapturerWrapperState::CAPTURER_RECORDING);
    wrapper->SetIsMute(true);
    ASSERT_TRUE(wrapper->isMute_.load());
    wrapper->SetIsInVoIPCall(true);
    ASSERT_TRUE(wrapper->IsInVoIPCall());
}

// covers CreateCacheBuffer isMute=true path
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperCreateCacheBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {0};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    wrapper->isMute_.store(true);
    auto cacheBuf = wrapper->CreateCacheBuffer(bufDesc, 0, mockCapturer);
    ASSERT_NE(cacheBuf, nullptr);
}

// covers CreateCacheBuffer isMute=false success path
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperCreateCacheBuffer_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    wrapper->isMute_.store(false);
    auto cacheBuf = wrapper->CreateCacheBuffer(bufDesc, 0, mockCapturer);
    ASSERT_NE(cacheBuf, nullptr);
    ASSERT_EQ(cacheBuf->length, bufferSize);
}

// covers OnReadData: GetBufferDesc fails -> early return
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(Return(-1));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->OnReadData(0);
}

// covers OnReadData: bufLength==0 -> Enqueue and return
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->OnReadData(0);
}

// covers OnReadData: deep success path (valid buffer + timestamp, source != MIC/DEFAULT)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    wrapper->screenCaptureCb_ = nullptr;
    wrapper->SetBufferAvailableCallback(nullptr);
    wrapper->OnReadData(0);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
    // also cover source == MIC branch (skip offset)
    wrapper->availBuffers_.clear();
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::MIC;
    wrapper->OnReadData(0);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
}

// covers OnReadData: drop when consume slow (availBuffers size > MAX_AUDIO_BUFFER_SIZE)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {0};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    wrapper->screenCaptureCb_ = nullptr;
    wrapper->SetBufferAvailableCallback(nullptr);
    for (uint32_t i = 0; i <= wrapper->MAX_AUDIO_BUFFER_SIZE; i++) {
        auto b = std::make_unique<uint8_t[]>(bufferSize);
        wrapper->availBuffers_.push_back(std::make_shared<CacheBuffer>(std::move(b), bufferSize, 0, SOURCE_DEFAULT));
    }
    size_t before = wrapper->availBuffers_.size();
    wrapper->OnReadData(0);
    ASSERT_EQ(wrapper->availBuffers_.size(), before); // dropped, not added
}

// covers PartiallyPrintLog: first call (count==0 true, 0%SKIP==0 true), second call (count!=0 false, 1%SKIP!=0 false)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperPartiallyPrintLog_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->PartiallyPrintLog(42, "first_call");
    ASSERT_EQ(wrapper->captureAudioLogCountMap_[42], 1);
    wrapper->PartiallyPrintLog(42, "second_call");
    ASSERT_EQ(wrapper->captureAudioLogCountMap_[42], 2);
}

// covers OnReadData: audioCapturer_ nullptr -> early return at L295
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_005, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->audioCapturer_ = nullptr;
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers OnReadData: bufDesc.buffer == nullptr -> Enqueue and return at L304
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_006, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    bufDesc.buffer = nullptr;
    bufDesc.bufLength = 10;
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers OnReadData: !timeRet (GetTimeStampInfo returns false) -> Enqueue and return at L304
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_007, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {0};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(Return(false));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers OnReadData: !IsRecording (captureState != RECORDING) -> Enqueue and return at L304
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_008, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {0};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers OnReadData: screenCaptureCb_ set (L330) + bufferAvailableCb_ set (L333)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_009, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::MIC;
    wrapper->screenCaptureCb_ = screenCaptureServer_->cbProxy_;
    wrapper->SetBufferAvailableCallback(screenCaptureServer_->audioSource_);
    wrapper->OnReadData(0);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
}

// covers UseUpAllLeftBufferUntil: buffer timestamp >= audioTime -> wait_for predicate true -> OK
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUseUpAllLeftBufferUntil_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    auto cacheBuf = std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 1000, SOURCE_DEFAULT);
    wrapper->availBuffers_.push_back(cacheBuf);
    ASSERT_EQ(wrapper->UseUpAllLeftBufferUntil(500), MSERR_OK);
}

// covers DropBufferUntil: front() == nullptr -> while condition false, no drop
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperDropBufferUntil_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(nullptr);
    int32_t dropped = wrapper->DropBufferUntil(2000);
    ASSERT_EQ(dropped, 0);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
}

// covers SetupCapturerCallbacks: SetCapturerCallback fails -> false
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperSetupCapturerCallbacks_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    ON_CALL(*mockCapturer, SetCapturerCallback(_)).WillByDefault(Return(-1));
    ASSERT_FALSE(wrapper->SetupCapturerCallbacks(mockCapturer));
}

// covers SetupCapturerCallbacks: SetCaptureMode fails -> false
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperSetupCapturerCallbacks_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    ON_CALL(*mockCapturer, SetCaptureMode(_)).WillByDefault(Return(-1));
    ASSERT_FALSE(wrapper->SetupCapturerCallbacks(mockCapturer));
}

// covers SetupCapturerCallbacks: SetCapturerReadCallback fails -> false
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperSetupCapturerCallbacks_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    ON_CALL(*mockCapturer, SetCapturerReadCallback(_)).WillByDefault(Return(-1));
    ASSERT_FALSE(wrapper->SetupCapturerCallbacks(mockCapturer));
}

// covers BuildCapturerOptions: SOURCE_DEFAULT/MIC + VoIP, ALL_PLAYBACK/APP_PLAYBACK + VoIP + contentFilter
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperBuildCapturerOptions_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    OHOS::AudioStandard::AppInfo appInfo;
    // L200: SOURCE_DEFAULT, not VoIP -> SOURCE_TYPE_MIC
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    wrapper->SetIsInVoIPCall(false);
    auto opts = wrapper->BuildCapturerOptions(appInfo);
    ASSERT_EQ(opts.capturerInfo.sourceType, SourceType::SOURCE_TYPE_MIC);
    // L200: MIC, VoIP true -> SOURCE_TYPE_VOICE_COMMUNICATION
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::MIC;
    wrapper->SetIsInVoIPCall(true);
    opts = wrapper->BuildCapturerOptions(appInfo);
    ASSERT_EQ(opts.capturerInfo.sourceType, SourceType::SOURCE_TYPE_VOICE_COMMUNICATION);
    // L204: ALL_PLAYBACK + VoIP true (L208) + contentFilter (L213)
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    wrapper->contentFilter_.filteredAudioContents.insert(
        AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO);
    opts = wrapper->BuildCapturerOptions(appInfo);
    ASSERT_EQ(opts.capturerInfo.sourceType, SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE);
    // L204: APP_PLAYBACK
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::APP_PLAYBACK;
    opts = wrapper->BuildCapturerOptions(appInfo);
    ASSERT_EQ(opts.capturerInfo.sourceType, SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE);
}

// covers SetInnerStreamUsage: VoIP true (L186) + NOTIFICATION not filtered (L181-184 true)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperSetInnerStreamUsage_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->SetIsInVoIPCall(true);
    std::vector<OHOS::AudioStandard::StreamUsage> usages;
    wrapper->SetInnerStreamUsage(usages);
    // MUSIC, ALARM, MOVIE, GAME, AUDIOBOOK, NAVIGATION, UNKNOWN, VOICE_ASSISTANT, VOICE_MESSAGE,
    // NOTIFICATION (not filtered), VOICE_COMMUNICATION, VIDEO_COMMUNICATION = 12
    ASSERT_GE(usages.size(), 12u);
}

// covers UpdateAudioCapturerConfig: UpdatePlaybackCaptureConfig returns non-OK (L158)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    ON_CALL(*mockCapturer, UpdatePlaybackCaptureConfig(_)).WillByDefault(Return(-1));
    wrapper->audioCapturer_ = mockCapturer;
    ScreenCaptureContentFilter filter;
    ASSERT_EQ(wrapper->UpdateAudioCapturerConfig(filter), MSERR_INVALID_VAL);
}

// covers Start: system-param bundleName match + VoIP push_back VOICE_COMMUNICATION + SetAudioSourceConcurrency
// (L62-L72)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_VoIPConcurrency_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    // populate bundleName_ via a first CreateAudioCapturer call (mocked Create returns NiceMock<MockAudioCapturer>)
    ASSERT_NE(wrapper->CreateAudioCapturer(screenCaptureServer_->appInfo_), nullptr);
    std::string bn = wrapper->bundleName_;
    auto &sysParam = GetScreenCaptureSystemParam();
    std::string oldVal = sysParam["const.multimedia.screencapture.screenrecorderbundlename"];
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = bn;
    wrapper->SetIsInVoIPCall(true); // covers L65-67 push_back VOICE_COMMUNICATION
    int32_t ret = wrapper->Start(screenCaptureServer_->appInfo_);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_EQ(wrapper->GetAudioCapturerState(), AudioCapturerWrapperState::CAPTURER_RECORDING);
    ASSERT_TRUE(wrapper->IsRecording());
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = oldVal;
}

// covers CreateCacheBuffer: isMute=false + bufDesc.buffer==nullptr -> memcpy_s fails -> return nullptr (L280-281)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperCreateCacheBuffer_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    bufDesc.buffer = nullptr;
    bufDesc.bufLength = 16; // > 0 so CreateCacheBuffer reaches memcpy_s, not a zero-length path
    wrapper->isMute_.store(false);
    auto cacheBuf = wrapper->CreateCacheBuffer(bufDesc, 100, mockCapturer);
    ASSERT_EQ(cacheBuf, nullptr);
}

// covers OnReadData: CreateCacheBuffer returns nullptr (bufLength > INT32_MAX) -> L327 CHECK fail -> no push
// (L266/L327)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_010, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {0};
    bufDesc.buffer = srcData;
    // INT32_MAX + 1 -> CreateCacheBuffer L266 returns nullptr -> OnReadData L327 CHECK returns early
    bufDesc.bufLength = 2147483648ULL;
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->isMute_.store(false);
    wrapper->screenCaptureCb_ = nullptr;
    wrapper->SetBufferAvailableCallback(nullptr);
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty());
}

// covers OnReadData: audioSource == SOURCE_DEFAULT -> skip INNER_AUDIO_READ_TO_HEAR_TIME offset (L322 first operand
// false)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_011, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->isMute_.store(false);
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    wrapper->screenCaptureCb_ = nullptr;
    wrapper->SetBufferAvailableCallback(nullptr);
    wrapper->OnReadData(0);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
    ASSERT_EQ(wrapper->availBuffers_.front()->sourcetype, AudioCaptureSourceType::SOURCE_DEFAULT);
}

// covers SetBufferAvailableCallback: non-null cb sets bufferAvailableCb_, null clears it (L350)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperSetBufferAvailableCallback_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    // audioSource_ is an AudioDataSource which IS-A AudioBufferAvailableCallback
    std::shared_ptr<AudioBufferAvailableCallback> cb = screenCaptureServer_->audioSource_;
    ASSERT_NE(cb, nullptr);
    wrapper->SetBufferAvailableCallback(cb);
    ASSERT_FALSE(wrapper->bufferAvailableCb_.expired());
    wrapper->SetBufferAvailableCallback(nullptr);
    ASSERT_TRUE(wrapper->bufferAvailableCb_.expired());
}

// covers DropBufferUntil: not recording -> L378 early return; pushed buffer is NOT dropped (distinct from _001)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperDropBufferUntil_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    wrapper->availBuffers_.push_back(std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 100, SOURCE_DEFAULT));
    int32_t ret = wrapper->DropBufferUntil(1000); // 100 < 1000 would drop if recording, but early-returns
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(wrapper->availBuffers_.size(), 1u); // buffer survived: early return skipped the while loop
}

// covers CreateAudioCapturer: AudioCapturer::Create returns nullptr -> Start returns
// MSERR_UNKNOWN_AUDIO_CREATE (L60 CHECK in Start, L243 CHECK in CreateAudioCapturer)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_CreateNull_001, TestSize.Level2)
{
    AcwFlagGuard guard;
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    g_acwCreateMockFlags.returnNull = true;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_),
        MSERR_UNKNOWN_AUDIO_CREATE);
    ASSERT_NE(screenCaptureServer_->innerAudioCapture_->GetAudioCapturerState(),
        AudioCapturerWrapperState::CAPTURER_RECORDING);
}

// covers Start: audioCapturer->Start() returns false -> Release + OnStartFailed +
// captureState_=STOPED, return MSERR_UNKNOWN_AUDIO_START (L79, L86)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_StartFail_001, TestSize.Level2)
{
    AcwFlagGuard guard;
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    g_acwCreateMockFlags.startFail = true;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_),
        MSERR_UNKNOWN_AUDIO_START);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->GetAudioCapturerState(),
        AudioCapturerWrapperState::CAPTURER_STOPED);
}

// covers CreateAudioCapturer: SetupCapturerCallbacks fails (SetCapturerCallback != OK) ->
// Release + return nullptr -> Start fails (L244, L251, L228)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_SetupCallbacksFail_001, TestSize.Level2)
{
    AcwFlagGuard guard;
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    g_acwCreateMockFlags.setCapturerCallbackFail = true;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_),
        MSERR_UNKNOWN_AUDIO_CREATE);
    ASSERT_NE(screenCaptureServer_->innerAudioCapture_->GetAudioCapturerState(),
        AudioCapturerWrapperState::CAPTURER_RECORDING);
}

// covers Start system-param block: SetAudioSourceConcurrency fails (ret != OK) -> log +
// continue; also VoIP push_back (L69, L65). Start still succeeds.
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_AudioSourceConcurrencyFail_001, TestSize.Level2)
{
    AcwFlagGuard guard;
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_NE(wrapper->CreateAudioCapturer(screenCaptureServer_->appInfo_), nullptr);
    std::string bn = wrapper->bundleName_;
    auto &sysParam = GetScreenCaptureSystemParam();
    std::string oldVal = sysParam["const.multimedia.screencapture.screenrecorderbundlename"];
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = bn;
    wrapper->SetIsInVoIPCall(true);
    g_acwCreateMockFlags.setAudioSourceConcurrencyFail = true;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ASSERT_TRUE(wrapper->IsRecording());
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = oldVal;
}

// covers Start system-param block: VoIP=false branch of the isInVoIPCall_ guard (L65 branch 1)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_SysParamNoVoIP_001, TestSize.Level2)
{
    AcwFlagGuard guard;
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_NE(wrapper->CreateAudioCapturer(screenCaptureServer_->appInfo_), nullptr);
    std::string bn = wrapper->bundleName_;
    auto &sysParam = GetScreenCaptureSystemParam();
    std::string oldVal = sysParam["const.multimedia.screencapture.screenrecorderbundlename"];
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = bn;
    wrapper->SetIsInVoIPCall(false); // L65 false branch: skip VOICE_COMMUNICATION push_back
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ASSERT_TRUE(wrapper->IsRecording());
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
    sysParam["const.multimedia.screencapture.screenrecorderbundlename"] = oldVal;
}

// covers BuildCapturerOptions: audioSource == SOURCE_INVALID -> neither DEFAULT/MIC nor
// ALL_PLAYBACK/APP_PLAYBACK -> sourceType not set to PLAYBACK_CAPTURE (L197 branch 3, L216)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperBuildCapturerOptions_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::SOURCE_INVALID;
    OHOS::AudioStandard::AppInfo appInfo = screenCaptureServer_->appInfo_;
    auto opts = wrapper->BuildCapturerOptions(appInfo);
    ASSERT_NE(opts.capturerInfo.sourceType, OHOS::AudioStandard::SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE);
}

// covers NotifyBufferAvailable: not recording -> early return, callback not invoked (L288 branch 1)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperNotifyBufferAvailable_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED; // not recording
    wrapper->screenCaptureCb_ = nullptr;
    auto cb = std::make_shared<TestAvailCallback>();
    wrapper->NotifyBufferAvailable(cb);
    ASSERT_EQ(cb->callCount, 0); // early return at L288: OnBufferAvailable never called
}

// covers UseUpAllLeftBufferUntil: front buffer timestamp < audioTime -> predicate false ->
// wait_for times out -> MSERR_UNKNOWN (L365 branch 1, L367 front!=nullptr true)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUseUpAllLeftBufferUntil_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    const int32_t bufferSize = 10;
    auto buf = std::make_unique<uint8_t[]>(bufferSize);
    // front timestamp = 100, far below audioTime so the predicate stays false until timeout
    wrapper->availBuffers_.push_back(std::make_shared<CacheBuffer>(std::move(buf), bufferSize, 100, SOURCE_DEFAULT));
    ASSERT_EQ(wrapper->UseUpAllLeftBufferUntil(999999999), MSERR_UNKNOWN);
    ASSERT_FALSE(wrapper->availBuffers_.empty()); // buffer not consumed on timeout
}

// covers ReleaseAudioBuffer: availBuffers_ has an entry but front == nullptr -> CHECK fails
// -> MSERR_UNKNOWN (L414 branch 3)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperReleaseAudioBuffer_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(nullptr); // non-empty but front is null
    ASSERT_NE(wrapper->ReleaseAudioBuffer(), MSERR_OK);
}

// covers UseUpAllLeftBufferUntil: front == nullptr -> predicate short-circuits false ->
// wait_for times out -> MSERR_UNKNOWN (L367 null-front branch)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUseUpAllLeftBufferUntil_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(nullptr); // front is null -> front()!=nullptr is false
    ASSERT_EQ(wrapper->UseUpAllLeftBufferUntil(999999999), MSERR_UNKNOWN);
    ASSERT_FALSE(wrapper->availBuffers_.empty());
}

// covers OnReadData: captureState_ flips to non-RECORDING between the L316 check and the
// L332 re-check (Enqueue, called inside CreateCacheBuffer, flips it) -> drop frame (L332)
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnReadData_012, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        screenCaptureServer_->cbProxy_, std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    auto mockCapturer = std::make_shared<testing::NiceMock<MockAudioCapturer>>();
    AudioStandard::BufferDesc bufDesc{};
    const int32_t bufferSize = 10;
    uint8_t srcData[bufferSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    bufDesc.buffer = srcData;
    bufDesc.bufLength = static_cast<size_t>(bufferSize);
    ON_CALL(*mockCapturer, GetBufferDesc(_)).WillByDefault(DoAll(SetArgReferee<0>(bufDesc), Return(0)));
    AudioStandard::Timestamp ts{};
    ts.time.tv_sec = 1;
    ts.time.tv_nsec = 0;
    ON_CALL(*mockCapturer, GetTimeStampInfo(_, _)).WillByDefault(DoAll(SetArgReferee<0>(ts), Return(true)));
    // Enqueue runs inside CreateCacheBuffer (after the L316 IsRecording check, before L332):
    // flip captureState_ so the L332 re-check sees not-recording and drops the frame.
    ON_CALL(*mockCapturer, Enqueue(_)).WillByDefault(testing::Invoke([&wrapper](const AudioStandard::BufferDesc &) {
        wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
        return 0;
    }));
    wrapper->audioCapturer_ = mockCapturer;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->audioInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    wrapper->isMute_.store(false);
    wrapper->screenCaptureCb_ = nullptr;
    wrapper->SetBufferAvailableCallback(nullptr);
    wrapper->OnReadData(0);
    ASSERT_TRUE(wrapper->availBuffers_.empty()); // frame dropped at L332, never pushed
}
} // namespace Media
} // namespace OHOS
