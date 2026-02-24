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
#include "screencapturemultidisplayid_ndk_fuzzer.h"
#include "test_template.h"
 
using namespace std;
using namespace OHOS;
using namespace Media;
 
namespace OHOS {
namespace Media {
ScreenCaptureMultiDisplayIdNdkFuzzer::ScreenCaptureMultiDisplayIdNdkFuzzer()
{
}
 
ScreenCaptureMultiDisplayIdNdkFuzzer::~ScreenCaptureMultiDisplayIdNdkFuzzer()
{
}
 
const uint32_t MIN_DISPLAY_COUNT = 1000;
 
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
 
 
bool ScreenCaptureMultiDisplayIdNdkFuzzer::ScreenCaptureMultiDisplayIdNdk(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    constexpr uint32_t recorderTime = 5;
    // set random data
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    screenCapture = OH_AVScreenCapture_Create();
    OH_AVScreenCaptureConfig config;
    SetConfig(config);
    OH_AVScreenCapture_Init(screenCapture, config);
    OH_AVScreenCapture_StartScreenCapture(screenCapture);
 
    vector<uint64_t> displayIds;
    size_t count = GetData<size_t>() % MIN_DISPLAY_COUNT;
    for (size_t i = 0; i < count; i++) {
        displayIds.emplace_back(GetData<uint64_t>());
    }
    OH_MultiDisplayCapability capability;
    OH_AVScreenCapture_GetMultiDisplayCaptureCapability(screenCapture, &displayIds[0], count, &capability);
    sleep(recorderTime);
    OH_AVScreenCapture_PresentPicker(screenCapture);
    OH_AVScreenCapture_StopScreenCapture(screenCapture);
    OH_AVScreenCapture_Release(screenCapture);
    return true;
}
} // namespace Media
 
bool ScreenCaptureMultiDisplayIdNdk(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }
 
    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureMultiDisplayIdNdkFuzzer testScreenCapture;
    return testScreenCapture.ScreenCaptureMultiDisplayIdNdk(data, size);
}
} // namespace OHOS
 
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ScreenCaptureMultiDisplayIdNdk(data, size);
    return 0;
}