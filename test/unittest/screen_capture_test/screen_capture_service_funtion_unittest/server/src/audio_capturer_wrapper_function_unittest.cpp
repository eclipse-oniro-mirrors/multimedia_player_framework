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
HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperStart_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
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
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->micAudioCapture_ = std::make_shared<MicAudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_MicAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->micAudioCapture_->bundleName_ = ScreenRecorderBundleName;
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
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->micAudioCapture_ = std::make_shared<MicAudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_MicAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->micAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->micAudioCapture_->Stop(), MSERR_OK);
    screenCaptureServer_->micAudioCapture_->screenCaptureCb_ = nullptr;
    screenCaptureServer_->micAudioCapture_->OnStartFailed(
        ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperPause_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Resume(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperPause_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Resume(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_NE(screenCaptureServer_->innerAudioCapture_->Resume(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperPause_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->innerAudioCapture_->isRunning_store(true);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->innerAudioCapture_->isRunning_store(true);
    screenCaptureServer_->innerAudioCapture_->audioCapture_->Stop();
    screenCaptureServer_->innerAudioCapture_->audioCapture_->Release();
    screenCaptureServer_->innerAudioCapture_->audioCapture_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Stop(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperRelativeSleep_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->RelativeSleep(1), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperOnInterrupt_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
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
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ScreenCaptureContentFilter filter;
    filter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->UpdateAudioCaptureConfig(filter), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioCapturerWrapperUpdateAudioCapturerConfig_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
        screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo, screenCaptureServer_->screenCaptureCb_,
        std::string("OS_InnerAudioCapture"), screenCaptureServer_->contentFilter_);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
    ScreenCaptureContentFilter filter;
    filter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO);
    screenCaptureServer_->innerAudioCapture_->bundleName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->UpdateAudioCaptureConfig(filter), MSERR_OK);
}
} // Media
} // OHOS