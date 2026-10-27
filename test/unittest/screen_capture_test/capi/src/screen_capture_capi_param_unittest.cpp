/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <iostream>
#include <string>
#include "media_errors.h"
#include "screen_capture_unit_test.h"
#include "native_avscreen_capture.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;
using namespace OHOS::Media::ScreenCaptureTestParam;

namespace OHOS {
namespace Media {

/*
 * Coverage tests for native_avscreen_capture.cpp C API.
 * These tests call OH_AVScreenCapture_* functions directly (bypassing the mock layer)
 * with nullptr / invalid inputs to exercise error-path branches that are unreachable
 * through the normal mock-based test flow.
 */

/* ==================== Create / Release ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_create_and_release_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_release_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_Release(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_release_repeated_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Init nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_init_nullptr_capture_001, TestSize.Level2)
{
    OH_AVScreenCaptureConfig config = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_Init(nullptr, config));
}

/* ==================== StartScreenCapture nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_start_nullptr_capture_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_StartScreenCapture(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_start_screen_capture_with_surface_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StartScreenCaptureWithSurface(nullptr, nullptr));
}

/* ==================== StopScreenCapture nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_stop_nullptr_capture_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_StopScreenCapture(nullptr));
}

/* ==================== Start/StopScreenRecording nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_start_recording_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_StartScreenRecording(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_stop_recording_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_StopScreenRecording(nullptr));
}

/* ==================== PresentPicker nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_present_picker_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_PresentPicker(nullptr));
}

/* ==================== SetMicrophoneEnabled nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_microphone_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetMicrophoneEnabled(nullptr, true));
}

/* ==================== SetCanvasRotation nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_canvas_rotation_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetCanvasRotation(nullptr, true));
}

/* ==================== ShowCursor nullptr paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_show_cursor_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ShowCursor(nullptr, true));
}

/* ==================== ResizeCanvas paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_resize_canvas_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ResizeCanvas(nullptr, 720, 1280));
}

HWTEST_F(ScreenCaptureUnitTest, capi_resize_canvas_invalid_size_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, OH_AVScreenCapture_ResizeCanvas(capture, 0, 1280));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, OH_AVScreenCapture_ResizeCanvas(capture, 720, 0));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, OH_AVScreenCapture_ResizeCanvas(capture, -1, -1));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetMaxVideoFrameRate paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_max_frame_rate_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetMaxVideoFrameRate(nullptr, 30));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_max_frame_rate_invalid_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetMaxVideoFrameRate(capture, 0));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetMaxVideoFrameRate(capture, -1));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SkipPrivacyMode paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_skip_privacy_nullptr_capture_001, TestSize.Level2)
{
    int32_t windowIds[] = {1, 2, 3};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SkipPrivacyMode(nullptr, windowIds, 3));
}

HWTEST_F(ScreenCaptureUnitTest, capi_skip_privacy_invalid_count_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    int32_t windowIds[] = {1, 2, 3};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SkipPrivacyMode(capture, windowIds, -1));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SkipPrivacyMode(capture, windowIds, 1001));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SkipPrivacyMode(capture, nullptr, 3));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ContentFilter paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_create_release_001, TestSize.Level2)
{
    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
}

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_release_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ReleaseContentFilter(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_add_audio_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ContentFilter_AddAudioContent(nullptr,
            OH_AVScreenCaptureFilterableAudioContent::OH_SCREEN_CAPTURE_NOTIFICATION_AUDIO));
}

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_add_audio_invalid_001, TestSize.Level2)
{
    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ContentFilter_AddAudioContent(filter,
            static_cast<OH_AVScreenCaptureFilterableAudioContent>(999)));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
}

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_add_window_nullptr_001, TestSize.Level2)
{
    int32_t windowIds[] = {1, 2, 3};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(nullptr, windowIds, 3));
}

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_add_window_invalid_001, TestSize.Level2)
{
    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);
    int32_t windowIds[] = {1, 2, 3};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(filter, windowIds, -1));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(filter, windowIds, 1001));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(filter, nullptr, 3));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
}

HWTEST_F(ScreenCaptureUnitTest, capi_exclude_content_nullptr_capture_001, TestSize.Level2)
{
    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ExcludeContent(nullptr, filter));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
}

HWTEST_F(ScreenCaptureUnitTest, capi_exclude_content_nullptr_filter_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ExcludeContent(capture, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== CaptureStrategy paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_create_release_001, TestSize.Level2)
{
    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_release_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ReleaseCaptureStrategy(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_keep_capture_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForKeepCaptureDuringCall(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_canvas_follow_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForCanvasFollowRotation(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_bframes_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForBFramesEncoding(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_privacy_mask_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForPrivacyMaskMode(nullptr, 0));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_privacy_mask_invalid_001, TestSize.Level2)
{
    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForPrivacyMaskMode(strategy, 5));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_picker_popup_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForPickerPopUp(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_fill_mode_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForFillMode(nullptr,
            OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_ASPECT_SCALE_FIT));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_fill_mode_invalid_001, TestSize.Level2)
{
    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForFillMode(strategy,
            static_cast<OH_AVScreenCapture_FillMode>(999)));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_pause_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForPause(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_mic_aec_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StrategyForMicAEC(nullptr, true));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_strategy_nullptr_001, TestSize.Level2)
{
    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureStrategy(nullptr, strategy));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureStrategy(nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
}

/* ==================== SetCaptureAreaHighlight paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_highlight_nullptr_capture_001, TestSize.Level2)
{
    OH_AVScreenCaptureHighlightConfig config = {
        .lineThickness = 1,
        .lineColor = 0x000000,
        .mode = OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CLOSED,
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureAreaHighlight(nullptr, config));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_highlight_invalid_mode_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_AVScreenCaptureHighlightConfig config = {
        .lineThickness = 1,
        .lineColor = 0x000000,
        .mode = static_cast<OH_ScreenCaptureHighlightMode>(999),
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_highlight_invalid_thickness_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_AVScreenCaptureHighlightConfig config = {
        .lineThickness = 0,
        .lineColor = 0x000000,
        .mode = OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CLOSED,
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));
    config.lineThickness = 9;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_highlight_invalid_color_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_AVScreenCaptureHighlightConfig config = {
        .lineThickness = 1,
        .lineColor = 0x12345678,
        .mode = OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CLOSED,
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCaptureArea paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_area_nullptr_001, TestSize.Level2)
{
    OH_Rect area = {.x = 0, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(nullptr, 0, &area));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_area_invalid_displayid_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_Rect area = {.x = 0, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 1000, &area));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, static_cast<uint64_t>(-1), &area));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_area_nullptr_area_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_area_invalid_area_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_Rect area = {.x = -1, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, &area));
    area = {.x = 0, .y = -1, .width = 100, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, &area));
    area = {.x = 0, .y = 0, .width = -1, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, &area));
    area = {.x = 0, .y = 0, .width = 100, .height = -1};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, &area));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== AcquireAudioBuffer paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_acquire_audio_nullptr_001, TestSize.Level2)
{
    OH_AudioBuffer *buffer = static_cast<OH_AudioBuffer *>(malloc(sizeof(OH_AudioBuffer)));
    ASSERT_NE(buffer, nullptr);
    OH_AVSCREEN_CAPTURE_ErrCode ret =
        OH_AVScreenCapture_AcquireAudioBuffer(nullptr, &buffer,
            OH_AudioCaptureSourceType::OH_MIC);
    free(buffer);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, ret);
}

HWTEST_F(ScreenCaptureUnitTest, capi_acquire_audio_nullptr_buffer_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_AcquireAudioBuffer(capture, nullptr,
            OH_AudioCaptureSourceType::OH_MIC));
    OH_AudioBuffer *buffer = nullptr;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_AcquireAudioBuffer(capture, &buffer,
            OH_AudioCaptureSourceType::OH_MIC));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== AcquireVideoBuffer paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_acquire_video_nullptr_001, TestSize.Level2)
{
    int32_t fence = 0;
    int64_t timestamp = 0;
    OH_Rect region = {.x = 0, .y = 0, .width = 100, .height = 100};
    OH_NativeBuffer *result = OH_AVScreenCapture_AcquireVideoBuffer(nullptr, &fence, &timestamp, &region);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(100, region.width);
}

HWTEST_F(ScreenCaptureUnitTest, capi_acquire_video_nullptr_params_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    int64_t timestamp = 0;
    OH_Rect region = {.x = 0, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(nullptr, OH_AVScreenCapture_AcquireVideoBuffer(capture, nullptr, &timestamp, &region));
    int32_t fence = 0;
    EXPECT_EQ(nullptr, OH_AVScreenCapture_AcquireVideoBuffer(capture, &fence, nullptr, &region));
    EXPECT_EQ(nullptr, OH_AVScreenCapture_AcquireVideoBuffer(capture, &fence, &timestamp, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ReleaseVideoBuffer paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_release_video_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ReleaseVideoBuffer(nullptr));
}

/* ==================== ReleaseAudioBuffer paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_release_audio_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_ReleaseAudioBuffer(nullptr,
            OH_AudioCaptureSourceType::OH_MIC));
}

/* ==================== SetCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_callback_nullptr_001, TestSize.Level2)
{
    OH_AVScreenCaptureCallback callback = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_SetCallback(nullptr, callback));
}

/* ==================== SetStateCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_state_callback_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetStateCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_state_callback_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetStateCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCaptureContentChangedCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_content_changed_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureContentChangedCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_content_changed_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureContentChangedCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetErrorCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_error_callback_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetErrorCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_error_callback_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetErrorCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetDataCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_data_callback_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetDataCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_data_callback_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetDataCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetDisplayCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_display_callback_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetDisplayCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_display_callback_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetDisplayCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetSelectionCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_selection_callback_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetSelectionCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_selection_callback_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetSelectionCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== GetCaptureTypeSelected paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_get_capture_type_nullptr_001, TestSize.Level2)
{
    int32_t type = 0;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetCaptureTypeSelected(nullptr, &type));
}

HWTEST_F(ScreenCaptureUnitTest, capi_get_capture_type_nullptr_type_001, TestSize.Level2)
{
    OH_AVScreenCapture_UserSelectionInfo *selection = nullptr;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetCaptureTypeSelected(selection, nullptr));
}

/* ==================== GetDisplayIdSelected paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_get_display_id_nullptr_001, TestSize.Level2)
{
    uint64_t displayId = 0;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetDisplayIdSelected(nullptr, &displayId));
}

HWTEST_F(ScreenCaptureUnitTest, capi_get_display_id_nullptr_out_001, TestSize.Level2)
{
    OH_AVScreenCapture_UserSelectionInfo *selection = nullptr;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetDisplayIdSelected(selection, nullptr));
}

/* ==================== GetMultiDisplayIdsSelected paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_get_multi_display_nullptr_001, TestSize.Level2)
{
    uint64_t *displayIds = nullptr;
    size_t count = 0;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayIdsSelected(nullptr, &displayIds, &count));
}

HWTEST_F(ScreenCaptureUnitTest, capi_get_multi_display_nullptr_out_001, TestSize.Level2)
{
    OH_AVScreenCapture_UserSelectionInfo *selection = nullptr;
    size_t count = 0;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayIdsSelected(selection, nullptr, &count));
    uint64_t *displayIds = nullptr;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayIdsSelected(selection, &displayIds, nullptr));
}

/* ==================== GetMultiDisplayCaptureCapability paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_get_multi_display_cap_nullptr_001, TestSize.Level2)
{
    uint64_t displayIds[] = {0, 1};
    OH_MultiDisplayCapability capability = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(nullptr, displayIds, 2, &capability));
}

HWTEST_F(ScreenCaptureUnitTest, capi_get_multi_display_cap_invalid_count_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    uint64_t displayIds[] = {0, 1};
    OH_MultiDisplayCapability capability = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(capture, displayIds, 1, &capability));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(capture, displayIds, 0, &capability));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(capture, displayIds, 1001, &capability));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_get_multi_display_cap_nullptr_params_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_MultiDisplayCapability capability = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(capture, nullptr, 2, &capability));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_GetMultiDisplayCaptureCapability(capture, nullptr, 0, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetPrivacyProtectCallback paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_privacy_protect_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetPrivacyProtectCallback(nullptr, nullptr, nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_set_privacy_protect_nullptr_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetPrivacyProtectCallback(capture, nullptr, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Pause/Resume paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_pause_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_PauseScreenCapture(nullptr));
}

HWTEST_F(ScreenCaptureUnitTest, capi_resume_nullptr_001, TestSize.Level2)
{
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL, OH_AVScreenCapture_ResumeScreenCapture(nullptr));
}

/* ==================== StartScreenCaptureWithSurface null window paths ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_start_with_surface_null_window_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_StartScreenCaptureWithSurface(capture, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCallback then call again (SetCallback existing callback) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_callback_then_set_again_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);

    OH_AVScreenCaptureCallback callback1 = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_SetCallback(capture, callback1));

    OH_AVScreenCaptureCallback callback2 = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_SetCallback(capture, callback2));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Strategy then SetCaptureStrategy on valid capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_strategy_set_on_capture_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);

    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForKeepCaptureDuringCall(strategy, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForCanvasFollowRotation(strategy, false));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForBFramesEncoding(strategy, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForPrivacyMaskMode(strategy, 0));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForPickerPopUp(strategy, false));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForFillMode(strategy,
            OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_ASPECT_SCALE_FIT));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForPause(strategy, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_StrategyForMicAEC(strategy, false));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        OH_AVScreenCapture_SetCaptureStrategy(capture, nullptr));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ExcludeContent with valid capture + filter (no init) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_exclude_content_valid_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);

    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);

    int32_t windowIds[] = {1, 3, 5};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(filter, windowIds, 3));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ContentFilter_AddAudioContent(filter,
            OH_AVScreenCaptureFilterableAudioContent::OH_SCREEN_CAPTURE_NOTIFICATION_AUDIO));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ContentFilter_AddAudioContent(filter,
            OH_AVScreenCaptureFilterableAudioContent::OH_SCREEN_CAPTURE_CURRENT_APP_AUDIO));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ExcludeContent(capture, filter));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ContentFilter_AddWindowContent with negative window IDs ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_content_filter_add_window_negative_001, TestSize.Level2)
{
    OH_AVScreenCapture_ContentFilter *filter = OH_AVScreenCapture_CreateContentFilter();
    ASSERT_NE(filter, nullptr);
    int32_t windowIds[] = {-1, -3, 5};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ContentFilter_AddWindowContent(filter, windowIds, 3));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseContentFilter(filter));
}

/* ==================== SkipPrivacyMode with valid capture (no init) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_skip_privacy_valid_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    int32_t windowIds[] = {1, 2, 3};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SkipPrivacyMode(capture, windowIds, 3));
    int32_t emptyIds[] = {};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SkipPrivacyMode(capture, emptyIds, 0));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCaptureAreaHighlight valid config on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_highlight_valid_config_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_AVScreenCaptureHighlightConfig config = {
        .lineThickness = 1,
        .lineColor = 0x000000,
        .mode = OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CLOSED,
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));

    config.mode = OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CORNER_WRAP;
    config.lineThickness = 4;
    config.lineColor = 0xffffff;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));

    config.lineColor = 0xff000000;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));

    config.lineColor = 0xffffffff;
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureAreaHighlight(capture, config));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== AcquireAudioBuffer with DataCallback set (should fail) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_acquire_audio_with_data_callback_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);

    auto dataCb = [](OH_AVScreenCapture *cap, OH_AVBuffer *buf,
        OH_AVScreenCaptureBufferType type, int64_t ts, void *data) {
        (void)cap;
        (void)buf;
        (void)type;
        (void)ts;
        (void)data;
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetDataCallback(capture, dataCb, nullptr));

    OH_AudioBuffer *buffer = static_cast<OH_AudioBuffer *>(malloc(sizeof(OH_AudioBuffer)));
    ASSERT_NE(buffer, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_AcquireAudioBuffer(capture, &buffer,
            OH_AudioCaptureSourceType::OH_MIC));
    free(buffer);

    EXPECT_EQ(nullptr,
        OH_AVScreenCapture_AcquireVideoBuffer(capture, nullptr, nullptr, nullptr));

    int32_t fence = 0;
    int64_t timestamp = 0;
    OH_Rect region = {.x = 0, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(nullptr,
        OH_AVScreenCapture_AcquireVideoBuffer(capture, &fence, &timestamp, &region));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_ReleaseVideoBuffer(capture));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_ReleaseAudioBuffer(capture,
            OH_AudioCaptureSourceType::OH_MIC));

    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCaptureArea on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_area_valid_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_Rect area = {.x = 0, .y = 0, .width = 100, .height = 100};
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureArea(capture, 0, &area));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== PresentPicker on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_present_picker_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_PresentPicker(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== StartScreenCapture on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_start_capture_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_StartScreenCapture(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_start_recording_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_StartScreenRecording(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetMicrophoneEnabled on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_microphone_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetMicrophoneEnabled(capture, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCanvasRotation on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_canvas_rotation_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCanvasRotation(capture, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ShowCursor on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_show_cursor_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_ShowCursor(capture, true));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== ResizeCanvas on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_resize_canvas_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_ResizeCanvas(capture, 720, 1280));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetMaxVideoFrameRate on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_max_frame_rate_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_SetMaxVideoFrameRate(capture, 30));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== SetCaptureStrategy on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_set_capture_strategy_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    OH_AVScreenCapture_CaptureStrategy *strategy = OH_AVScreenCapture_CreateCaptureStrategy();
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetCaptureStrategy(capture, strategy));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_ReleaseCaptureStrategy(strategy));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Pause/Resume on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_pause_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_PauseScreenCapture(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_ResumeScreenCapture(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== StopScreenCapture on uninitialized capture ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_stop_capture_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_StopScreenCapture(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_stop_recording_no_init_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_StopScreenRecording(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

} // namespace Media
} // namespace OHOS
