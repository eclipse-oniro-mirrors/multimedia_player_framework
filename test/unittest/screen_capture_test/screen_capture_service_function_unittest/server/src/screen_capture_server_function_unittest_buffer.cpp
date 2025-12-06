/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "screen_cap_buffer_consumer_listener.h"
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
/**
* @tc.name: AcquireAudioBuffer_001
* @tc.desc: mic = SOURCE_DEFAULT, inner = ALL_PLAYBACK
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    std::shared_ptr<AudioBuffer> audioBuffer = nullptr;
    ASSERT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::SOURCE_DEFAULT), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::ALL_PLAYBACK), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::SOURCE_DEFAULT), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::ALL_PLAYBACK), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: AcquireAudioBuffer_002
* @tc.desc: mic = MIC, inner = APP_PLAYBACK
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_002, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::MIC;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::APP_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    sleep(RECORDER_TIME / 2);
    std::shared_ptr<AudioBuffer> audioBuffer = nullptr;
    ASSERT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::MIC), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: AcquireVideoBuffer_001
* @tc.desc: isDump_ = false
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireVideoBuffer_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    screenCaptureServer_->surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(
        screenCaptureServer_->consumer_, screenCaptureServer_->screenCaptureCb_);
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    screenCaptureServer_->isDump_ = false;
    ASSERT_NE(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage), MSERR_OK);
    screenCaptureServer_->ReleaseVideoBuffer();
}

/**
* @tc.name: AcquireVideoBuffer_002
* @tc.desc: isDump_ = true
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireVideoBuffer_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    screenCaptureServer_->surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(
        screenCaptureServer_->consumer_, screenCaptureServer_->screenCaptureCb_);
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    screenCaptureServer_->isDump_ = true;
    ASSERT_NE(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage), MSERR_OK);
    screenCaptureServer_->ReleaseVideoBuffer();
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartBufferThread_001, TestSize.Level2)
{
    ScreenCapBufferConsumerListener *surfaceCb = new ScreenCapBufferConsumerListener(nullptr, nullptr);
    surfaceCb->isSurfaceCbInThreadStopped_ = false;
    EXPECT_EQ(surfaceCb->StartBufferThread(), MSERR_OK);
    delete surfaceCb;
    surfaceCb = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = -1;
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_002, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_003, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = -1;
    screenCaptureServer_->consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_004, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->consumer_ = nullptr;
    screenCaptureServer_->isSurfaceMode_ = false;
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_005, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->consumer_ = nullptr;
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->isConsumerStart_ = false;
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopVideoCapture_006, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->consumer_ = nullptr;
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->isConsumerStart_ = true;
    ASSERT_EQ(screenCaptureServer_->StopVideoCapture(), MSERR_OK);
}
} // Media
} // OHOS