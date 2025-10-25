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

#include <cmath>
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "screencapture_highlight_ndk_fuzzer.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
ScreenCaptureSetAreaHighlightNdkFuzzer::ScreenCaptureSetAreaHighlightNdkFuzzer()
{
}

ScreenCaptureSetAreaHighlightNdkFuzzer::~ScreenCaptureSetAreaHighlightNdkFuzzer()
{
}

const uint32_t MAX_LINE_THICKNESS = 8;
const uint32_t MIN_LINE_THICKNESS = 1;

void SetConfig(OH_AVScreenCaptureConfig &config)
{
    OH_AudioCaptureInfo miccapinfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = OH_SOURCE_DEFAULT
    };

    OH_VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = OH_VIDEO_SOURCE_SURFACE_RGBA
    };

    OH_AudioInfo audioinfo = {
        .micCapInfo = miccapinfo
    };

    OH_VideoInfo videoinfo = {
        .videoCapInfo = videocapinfo
    };

    config = {
        .captureMode = OH_CAPTURE_HOME_SCREEN,
        .dataType = OH_ORIGINAL_STREAM,
        .audioInfo = audioinfo,
        .videoInfo = videoinfo,
    };
}

constexpr uint32_t MAX_LINE_COLOR_RGB = 0x00ffffff;
constexpr uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;

bool ScreenCaptureSetAreaHighlightNdkFuzzer::FuzzScreenCaptureSetAreahighlightNdk(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    screenCapture = OH_AVScreenCapture_Create();

    OH_AVScreenCaptureConfig config;
    SetConfig(config);
    constexpr uint32_t recorderTime = 3000;
    OH_AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.mode = OH_HIGHLIGHT_MODE_CLOSED;
    highlightConfig.lineThickness = GetData<uint32_t>() % MAX_LINE_THICKNESS + MIN_LINE_THICKNESS;
    uint32_t lineColor = GetData<uint32_t>();
    if (lineColor > MAX_LINE_COLOR_RGB  && lineColor < MIN_LINE_COLOR_ARGB) {
        return false;
    }
    highlightConfig.lineColor = lineColor;

    OH_AVScreenCapture_SetMicrophoneEnabled(screenCapture, true);
    OH_AVScreenCapture_SetCaptureAreaHighlight(screenCapture, highlightConfig);
    OH_AVScreenCaptureCallback callback;
    callback.onError = TestScreenCaptureNdkCallback::OnError;
    callback.onAudioBufferAvailable = TestScreenCaptureNdkCallback::OnAudioBufferAvailable;
    callback.onVideoBufferAvailable = TestScreenCaptureNdkCallback::OnVideoBufferAvailable;
    OH_AVScreenCapture_SetCallback(screenCapture, callback);
    OH_AVScreenCapture_Init(screenCapture, config);

    OH_AVScreenCapture_SetPickerMode(screenCapture, OH_CapturePickerMode::OH_CAPTURE_PICKER_MODE_WINDOW_ONLY);
    std::vector<int32_t> excludedWindows = {101, 102, 103};
    OH_AVScreenCapture_ExcludePickerWindows(screenCapture, excludedWindows.data(), excludedWindows.size());

    OH_AVScreenCapture_StartScreenCapture(screenCapture);
    sleep(recorderTime);
    OH_AVScreenCapture_PresentPicker(screenCapture);
    OH_AVScreenCapture_StopScreenCapture(screenCapture);
    OH_AVScreenCapture_Release(screenCapture);
    return true;
}
} // namespace Media

bool FuzzTestScreenCaptureSetAreahighlightNdk(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureSetAreaHighlightNdkFuzzer testScreenCapture;
    return testScreenCapture.FuzzScreenCaptureSetAreahighlightNdk(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestScreenCaptureSetAreahighlightNdk(data, size);
    return 0;
}