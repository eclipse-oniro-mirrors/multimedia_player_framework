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

#include "image_source.h"
#include "image_type.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "param_wrapper.h"
#include "pixel_map.h"
#include "scope_guard.h"
#include "screen_cap_buffer_consumer_listener.h"
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
        screenCaptureServer_->consumer_, screenCaptureServer_->cbProxy_);
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::Rect rsRect;
    screenCaptureServer_->isDump_ = false;
    ASSERT_EQ(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage, rsRect), MSERR_UNKNOWN);
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
        screenCaptureServer_->consumer_, screenCaptureServer_->cbProxy_);
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::Rect rsRect;
    screenCaptureServer_->isDump_ = true;
    ASSERT_EQ(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage, rsRect), MSERR_UNKNOWN);
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

/**
 * @tc.name: AcquireAudioBuffer_NotActive_001
 * @tc.desc: AcquireAudioBuffer rejected when capture is not STARTED/RESUMED (L2819)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_NotActive_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC),
        MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AcquireAudioBuffer_UnsupportedType_001
 * @tc.desc: AcquireAudioBuffer returns MSERR_UNKNOWN for unsupported source type (L2832)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBuffer_UnsupportedType_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::SOURCE_INVALID),
        MSERR_UNKNOWN);
}

/**
 * @tc.name: ReleaseAudioBuffer_NotActive_001
 * @tc.desc: ReleaseAudioBuffer rejected when capture is not STARTED/RESUMED (L2844)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseAudioBuffer_NotActive_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::ALL_PLAYBACK), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: ReleaseAudioBuffer_UnsupportedType_001
 * @tc.desc: ReleaseAudioBuffer returns MSERR_UNKNOWN for unsupported source type (L2859)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseAudioBuffer_UnsupportedType_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->micAudioCapture_ = nullptr;
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::SOURCE_INVALID), MSERR_UNKNOWN);
}

/**
 * @tc.name: AcquireVideoBuffer_NotActive_001
 * @tc.desc: AcquireVideoBuffer rejected when capture is not STARTED/RESUMED (L2870)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireVideoBuffer_NotActive_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->surfaceCb_ = nullptr;
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::Rect rsRect;
    EXPECT_EQ(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage, rsRect),
        MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AcquireVideoBuffer_NullSurfaceCb_001
 * @tc.desc: AcquireVideoBuffer returns MSERR_NO_MEMORY when surfaceCb_ is null (L2873)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AcquireVideoBuffer_NullSurfaceCb_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->surfaceCb_ = nullptr;
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::Rect rsRect;
    EXPECT_EQ(screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage, rsRect),
        MSERR_NO_MEMORY);
}

/**
 * @tc.name: ReleaseVideoBuffer_NotActive_001
 * @tc.desc: ReleaseVideoBuffer rejected when capture is not STARTED/RESUMED (L2915)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseVideoBuffer_NotActive_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->surfaceCb_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ReleaseVideoBuffer(), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: ReleaseVideoBuffer_NullSurfaceCb_001
 * @tc.desc: ReleaseVideoBuffer returns MSERR_NO_MEMORY when surfaceCb_ is null (L2918)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseVideoBuffer_NullSurfaceCb_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->surfaceCb_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ReleaseVideoBuffer(), MSERR_NO_MEMORY);
}
} // namespace Media
} // namespace OHOS
