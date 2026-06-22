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

namespace {
static constexpr int64_t AUDIO_CAPTURE_READ_FRAME_TIME = 21333333;
}

namespace OHOS {
namespace Media {
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
    screenCaptureServer_->innerAudioCapture_->OnStartFailed(
        ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
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
    screenCaptureServer_->micAudioCapture_->OnStartFailed(
        ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
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
    screenCaptureServer_->micAudioCapture_->OnStartFailed(
        ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
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
    screenCaptureServer_->innerAudioCapture_->OnStartFailed(
        ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapper_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperRelativeSleep_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(screenCaptureServer_->innerAudioCapture_);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->RelativeSleep(1), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnInterrupt_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, "OS_InnerAudioCapture", true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    AudioStandard::InterruptEvent interruptEvent;
    screenCaptureServer_->innerAudioCapture_->audioCaptureCallback_->OnInterrupt(interruptEvent);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper);
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
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper);
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
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, true);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    int64_t currentAudioTime = 0;
    wrapper->GetCurrentAudioTime(currentAudioTime);
    size_t size = 0;
    wrapper->GetBufferSize(size);
    ASSERT_EQ(wrapper->AddBufferFrom(0, static_cast<int64_t>(size), currentAudioTime), MSERR_OK);
    int32_t ret = wrapper->UseUpAllLeftBufferUntil(currentAudioTime);
    (void)ret;
    int64_t currentAudioTime1 = 0;
    wrapper->GetCurrentAudioTime(currentAudioTime1);
    int64_t currentAudioTime2 = currentAudioTime1 - AUDIO_CAPTURE_READ_FRAME_TIME * 3;
    wrapper->AddBufferFrom(AUDIO_CAPTURE_READ_FRAME_TIME * 3, static_cast<int64_t>(size), currentAudioTime2);
    wrapper->DropBufferUntil(currentAudioTime1);
    ret = wrapper->UseUpAllLeftBufferUntil(currentAudioTime);
    (void)ret;
    ASSERT_EQ(wrapper->Stop(), MSERR_OK);
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStartInTelCall_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_MicAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, false);
    screenCaptureServer_->micAudioCapture_ = wrapper;
    wrapper->SetIsInTelCall(true);
    ASSERT_NE(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    wrapper->screenCaptureCb_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperInTelCall_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_MicAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, true);
    screenCaptureServer_->micAudioCapture_ = wrapper;
    ASSERT_EQ(wrapper->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    wrapper->SetIsInTelCall(true);
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, false);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    std::shared_ptr<AudioBuffer> audioBuffer;
    ASSERT_NE(wrapper->AcquireAudioBuffer(audioBuffer), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperAcquireAudioBuffer_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    SetupAudioDataSource(AVScreenCaptureMixMode::MIX_MODE);
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, false);
    screenCaptureServer_->innerAudioCapture_ = wrapper;
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RELEASED;
    std::shared_ptr<AudioBuffer> audioBuffer;
    ASSERT_NE(wrapper->AcquireAudioBuffer(audioBuffer), MSERR_OK);
}
} // Media
} // OHOS