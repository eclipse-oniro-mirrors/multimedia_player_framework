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
#include "screen_capture.h"
#include "screencapturesetareahighlight_fuzzer.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
ScreenCaptureSetAreaHighlightFuzzer::ScreenCaptureSetAreaHighlightFuzzer()
{
}

ScreenCaptureSetAreaHighlightFuzzer::~ScreenCaptureSetAreaHighlightFuzzer()
{
}

void SetConfig(AVScreenCaptureConfig &config)
{
    AudioCaptureInfo miccapinfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = SOURCE_DEFAULT
    };

    VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };

    AudioInfo audioinfo = {
        .micCapInfo = miccapinfo,
    };

    VideoInfo videoinfo = {
        .videoCapInfo = videocapinfo
    };

    config = {
        .captureMode = CAPTURE_HOME_SCREEN,
        .dataType = ORIGINAL_STREAM,
        .audioInfo = audioinfo,
        .videoInfo = videoinfo,
    };
}

constexpr uint32_t MAX_LINE_COLOR_RGB = 0x00ffffff;
constexpr uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;
const uint32_t MAX_LINE_THICKNESS = 8;
const uint32_t MIN_LINE_THICKNESS = 1;

bool ScreenCaptureSetAreaHighlightFuzzer::FuzzScreenCaptureSetAreahighlight(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool retFlags = TestScreenCapture::CreateScreenCapture();
    RETURN_IF(retFlags, false);

    AVScreenCaptureConfig config;
    SetConfig(config);
    constexpr uint32_t recorderTime = 3000;
    AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    highlightConfig.lineThickness = GetData<uint32_t>() % MAX_LINE_THICKNESS + MIN_LINE_THICKNESS;
    uint32_t lineColor = GetData<uint32_t>();
    if (lineColor > MAX_LINE_COLOR_RGB  && lineColor < MIN_LINE_COLOR_ARGB) {
        return false;
    }
    highlightConfig.lineColor = lineColor;

    TestScreenCapture::SetCaptureAreaHighlight(highlightConfig);

    std::shared_ptr<TestScreenCaptureCallbackTest> callbackobj
        = std::make_shared<TestScreenCaptureCallbackTest>();
    TestScreenCapture::SetMicrophoneEnabled(true);
    TestScreenCapture::SetScreenCaptureCallback(callbackobj);
    TestScreenCapture::Init(config);

    TestScreenCapture::SetPickerMode(PickerMode::WINDOW_ONLY);
    std::vector<int32_t> excludedWindows = {101, 102, 103};
    TestScreenCapture::ExcludePickerWindows(excludedWindows);

    TestScreenCapture::StartScreenCapture();
    TestScreenCapture::PresentPicker();
    sleep(recorderTime);
    TestScreenCapture::StopScreenCapture();
    TestScreenCapture::Release();
    return true;
}
} // namespace Media

bool FuzzTestScreenCaptureSetAreahighlight(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureSetAreaHighlightFuzzer testScreenCapture;
    return testScreenCapture.FuzzScreenCaptureSetAreahighlight(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestScreenCaptureSetAreahighlight(data, size);
    return 0;
}