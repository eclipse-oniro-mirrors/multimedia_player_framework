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

// ===================== SetCanvasRotationInner (L3323-3337) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetCanvasRotationInner_InvalidScreenId_B1, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->SetCanvasRotationInner(), MSERR_INVALID_VAL);
}

// ===================== SetScreenScaleMode (L3511-3523) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetScreenScaleMode_InvalidScreen_B1, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->SetScreenScaleMode(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetScreenScaleMode_PreserveAspectRatio_B1, TestSize.Level2)
{
    auto mode = screenCaptureServer_->GetScreenScaleMode(AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO);
    EXPECT_EQ(mode, ScreenScaleMode::UNISCALE_MODE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetScreenScaleMode_ScaleToFill_B1, TestSize.Level2)
{
    auto mode = screenCaptureServer_->GetScreenScaleMode(AVScreenCaptureFillMode::SCALE_TO_FILL);
    EXPECT_EQ(mode, ScreenScaleMode::FILL_MODE);
}

// ===================== MakeVirtualScreenExtended (L2721-2751) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, MakeVirtualScreenExtended_InvalidScreenId_B1, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->MakeVirtualScreenExtended(), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MakeVirtualScreenExtended_DisplayEmpty_B1, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 1;
    screenCaptureServer_->displayIds_.clear();
    EXPECT_EQ(screenCaptureServer_->MakeVirtualScreenExtended(), MSERR_INVALID_VAL);
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
}

// ===================== MakeVirtualScreenMirror (L2707-2719) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, MakeVirtualScreenMirror_InvalidScreenId_B1, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->MakeVirtualScreenMirror(), MSERR_UNKNOWN);
}

// ===================== GetDisplayIdOfWindows (L2590-2628) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, GetDisplayIdOfWindows_DisplayNull_B1, TestSize.Level2)
{
    screenCaptureServer_->displayIds_.clear();
    screenCaptureServer_->missionInfos_.clear();
    EXPECT_EQ(screenCaptureServer_->GetDisplayIdOfWindows(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetDisplayIdOfWindows_WithMissions_B1, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.push_back({1, true});
    screenCaptureServer_->displayIds_.clear();
    EXPECT_EQ(screenCaptureServer_->GetDisplayIdOfWindows(), 0);
    screenCaptureServer_->missionInfos_.clear();
}

// ===================== SetCaptureAreaInner (L3042-3075) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureAreaInner_InvalidScreenId_B2, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = SCREEN_ID_INVALID;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(screenCaptureServer_->SetCaptureAreaInner(0, area), MSERR_INVALID_VAL);
}

// ===================== GetMultiDisplayCaptureCapability (L3077-3093) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, GetMultiDisplayCaptureCapability_SizeInvalid_B2, TestSize.Level2)
{
    std::vector<uint64_t> displayIds = {1};
    MultiDisplayCapability capability;
    EXPECT_EQ(screenCaptureServer_->GetMultiDisplayCaptureCapability(displayIds, capability), MSERR_INVALID_OPERATION);
}

// ===================== ResizeCanvas (L3388-3417) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_NotActive_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(100, 100), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_InvalidWidth_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(0, 100), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_NotOriginalStream_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(100, 100), MSERR_INVALID_OPERATION);
}

// ===================== UpdateSurface (L3419-3437) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateSurface_NotSurfaceMode_B2, TestSize.Level2)
{
    screenCaptureServer_->isSurfaceMode_ = false;
    EXPECT_EQ(screenCaptureServer_->UpdateSurface(nullptr), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateSurface_NotRunning_B2, TestSize.Level2)
{
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    sptr<OHOS::Surface> surface = OHOS::Surface::CreateSurfaceAsConsumer();
    EXPECT_EQ(screenCaptureServer_->UpdateSurface(surface), MSERR_INVALID_OPERATION);
}

// ===================== GetScreenScaleMode (L3495-3509) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, GetScreenScaleMode_UnknownMode_B2, TestSize.Level2)
{
    auto mode = screenCaptureServer_->GetScreenScaleMode(static_cast<AVScreenCaptureFillMode>(99));
    EXPECT_EQ(mode, ScreenScaleMode::UNISCALE_MODE);
}

// ===================== SetCaptureAreaHighlight (L3847-3854) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureAreaHighlight_001, TestSize.Level2)
{
    AVScreenCaptureHighlightConfig config;
    config.lineColor = 0xff0000;
    config.lineThickness = 2;
    config.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    EXPECT_EQ(screenCaptureServer_->SetCaptureAreaHighlight(config), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.highlightConfig.lineColor, 0xff0000);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.highlightConfig.lineThickness, 2);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.highlightConfig.mode,
        ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED);
}

// ===================== SetVirtualScreenAutoRotation (L2492-2500) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetVirtualScreenAutoRotation_NotOriginalStream_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    EXPECT_EQ(screenCaptureServer_->SetVirtualScreenAutoRotation(), MSERR_INVALID_OPERATION);
}

} // namespace Media
} // namespace OHOS
