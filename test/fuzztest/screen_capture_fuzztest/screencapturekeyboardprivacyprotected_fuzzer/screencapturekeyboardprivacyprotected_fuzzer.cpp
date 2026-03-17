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
#include "screencapturekeyboardprivacyprotected_fuzzer.h"
#include "test_template.h"
#include "i_standard_screen_capture_service.h"
#include "i_screen_capture_service.h"
#include "screen_capture_server.h"
 
using namespace std;
using namespace OHOS;
using namespace Media;
 
namespace OHOS {
namespace Media {
ScreenCaptureKeyboardPrivacyProtectedFuzzer::ScreenCaptureKeyboardPrivacyProtectedFuzzer()
{
}
 
ScreenCaptureKeyboardPrivacyProtectedFuzzer::~ScreenCaptureKeyboardPrivacyProtectedFuzzer()
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
 
 
bool ScreenCaptureKeyboardPrivacyProtectedFuzzer::ScreenCaptureKeyboardPrivacyProtected(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
    if (tempServer_ == nullptr) {
        return 0;
    }
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
    if (screenCaptureServer_ == nullptr || data == nullptr) {
        return 0;
    }
    // set random data
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    ScreenId virtualScreenId = 1;
    bool systemPrivacyProtectionSwitch = true;
    screenCaptureServer_->SystemPrivacyProtected(virtualScreenId, systemPrivacyProtectionSwitch);

    bool retFlags = TestScreenCapture::CreateScreenCapture();
    RETURN_IF(retFlags, false);

    AVScreenCaptureConfig config;
    SetConfig(config);
    constexpr uint32_t recorderTime = 5;

    std::shared_ptr<TestScreenCaptureCallbackTest> callbackobj
        = std::make_shared<TestScreenCaptureCallbackTest>();
    TestScreenCapture::SetScreenCaptureCallback(callbackobj);
    TestScreenCapture::Init(config);
    TestScreenCapture::StartScreenCapture();
    sleep(recorderTime);
    TestScreenCapture::StopScreenCapture();
    TestScreenCapture::Release();
    return true;
}
} // namespace Media
 
bool ScreenCaptureKeyboardPrivacyProtected(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }
 
    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureKeyboardPrivacyProtectedFuzzer testScreenCapture;
    return testScreenCapture.ScreenCaptureKeyboardPrivacyProtected(data, size);
}
} // namespace OHOS
 
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ScreenCaptureKeyboardPrivacyProtected(data, size);
    return 0;
}