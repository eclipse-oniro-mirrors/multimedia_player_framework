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