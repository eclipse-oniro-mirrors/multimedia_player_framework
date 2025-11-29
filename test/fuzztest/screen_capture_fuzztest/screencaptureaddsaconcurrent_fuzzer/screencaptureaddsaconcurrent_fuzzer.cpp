/*
Copyright (c) 2025 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <cmath>
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "screen_capture.h"
#include "screencaptureaddsaconcurrent_fuzzer.h"
#include "i_standard_screen_capture_service.h"
#include "i_screen_capture_service.h"
#include "screen_capture_server.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS;
using namespace Media;
namespace OHOS {
namespace Media {
ScreenCaptureAddSaConcurrentFuzzer::ScreenCaptureAddSaConcurrentFuzzer()
{
}

ScreenCaptureAddSaConcurrentFuzzer::~ScreenCaptureAddSaConcurrentFuzzer()
{
}

std::shared_ptr<ScreenCaptureServer> screenCaptureServer_ = nullptr;
AVScreenCaptureConfig config_;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
    if (tempServer_ == nullptr) {
        return 0;
    }
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
    return 0;
}
} // namespace OHOS

static std::vector<uint64_t> ConsumeIntList(FuzzedDataProvider& provider)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    std::vector<uint64_t> vec;
    for (size_t i = 0; i < len; ++i) {
        vec.push_back(provider.ConsumeIntegral<uint64_t>());
    }
    return vec;
}

static std::vector<int32_t> ConsumeIntList32(FuzzedDataProvider& provider)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    std::vector<int32_t> vec;
    for (size_t i = 0; i < len; ++i) {
        vec.push_back(provider.ConsumeIntegral<int32_t>());
    }
    return vec;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (screenCaptureServer_ == nullptr || data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);

    static const int ipccodes[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31
    };
    int code = provider.PickValueInArray(ipccodes);

    switch (code) {
        case 0: {
            screenCaptureServer_->Release();
            break;
        }
        case 1: {
            screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN);
            break;
        }
        case 2: {
            screenCaptureServer_->SetDataType(DataType::CAPTURE_FILE);
            break;
        }
        case 3: {
            int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
            RecorderInfo recorderInfo;
            recorderInfo.url = "fd://" + std::to_string(outputFd);
            recorderInfo.fileFormat = "mp4";
            screenCaptureServer_->SetRecorderInfo(recorderInfo);
            break;
        }
        case 4: {
            int outputFd = open("/data/test/media/screen_capture_fuzz_add_sa_concurrent_file_01.mp4", O_RDWR);
            screenCaptureServer_->SetOutputFile(outputFd);
            break;
        }
        case 5: {
            AudioEncInfo audioEncInfo;
            audioEncInfo.audioBitrate = 48000;
            audioEncInfo.audioCodecformat = AudioCodecFormat::AAC_LC;
            screenCaptureServer_->InitAudioEncInfo(audioEncInfo);
            break;
        }
        case 6: {
            AudioCaptureInfo innerCapInfo;
            AudioCaptureInfo micCapInfo;
            innerCapInfo.audioChannels = 2;
            innerCapInfo.audioSampleRate = 16000;
            innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
            micCapInfo.audioChannels = 2;
            micCapInfo.audioSampleRate = 16000;
            micCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
            screenCaptureServer_->InitAudioCap(micCapInfo);
            screenCaptureServer_->InitAudioCap(innerCapInfo);
            break;
        }
        case 7: {
            VideoEncInfo videoEncInfo;
            videoEncInfo.videoBitrate = 2000000;
            videoEncInfo.videoFrameRate = 30;
            videoEncInfo.videoCodec = VideoCodecFormat::H264;
            screenCaptureServer_->InitVideoEncInfo(videoEncInfo);
            break;
        }
        case 8: {
            VideoCaptureInfo videoCapInfo;
            videoCapInfo.videoFrameHeight = 1280;
            videoCapInfo.videoFrameWidth = 720;
            videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
            screenCaptureServer_->InitVideoCap(videoCapInfo);
            break;
        }
        case 9: {
            std::shared_ptr<OHOS::Media::AudioBuffer> audioBuffer;
            screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        case 10: {
            sptr<OHOS::SurfaceBuffer> surfaceBuffer;
            int fence = provider.ConsumeIntegral<int>();
            int64_t timestamp = provider.ConsumeIntegral<int64_t>();
            OHOS::Rect damage;
            screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
            break;
        }
        case 11: {
            screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        case 12: {
            screenCaptureServer_->ReleaseVideoBuffer();
            break;
        }
        case 13: {
            bool isMicrophone = provider.ConsumeBool();
            screenCaptureServer_->SetMicrophoneEnabled(isMicrophone);
            break;
        }
        case 14: {
            bool isPrivacyAuthorityEnabled = provider.ConsumeBool();
            screenCaptureServer_->StartScreenCapture(isPrivacyAuthorityEnabled);
            break;
        }
        case 15: {
            sptr<Surface> surface;
            bool isPrivacyAuthorityEnabled = provider.ConsumeBool();
            screenCaptureServer_->StartScreenCaptureWithSurface(surface, isPrivacyAuthorityEnabled);
            break;
        }
        case 16: {
            screenCaptureServer_->StopScreenCapture();
            break;
        }
        case 17: {
            bool canvasRotation = provider.ConsumeBool();
            screenCaptureServer_->SetCanvasRotation(canvasRotation);
            break;
        }
        case 18: {
            ScreenCaptureContentFilter contentFilter;
            screenCaptureServer_->ExcludeContent(contentFilter);
            break;
        }
        case 19: {
            screenCaptureServer_->ResizeCanvas(720, 1080);
            break;
        }
        case 20: {
            std::vector<uint64_t> windowIDsVec = ConsumeIntList(provider);
            screenCaptureServer_->SkipPrivacyMode(windowIDsVec);
            break;
        }
        case 21: {
            screenCaptureServer_->SetMaxVideoFrameRate(60);
            break;
        }
        case 22: {
            bool showCursor = provider.ConsumeBool();
            screenCaptureServer_->ShowCursor(showCursor);
            break;
        }
        case 23: {
            OHOS::AudioStandard::AppInfo appInfo;
            screenCaptureServer_->SetAndCheckSaLimit(appInfo);
            break;
        }
        case 24: {
            screenCaptureServer_->SetAndCheckLimit();
            break;
        }
        case 25: {
            ScreenCaptureStrategy strategy;
            screenCaptureServer_->SetScreenCaptureStrategy(strategy);
            break;
        }
        case 26: {
            sptr<Surface> surface;
            screenCaptureServer_->UpdateSurface(surface);
            break;
        }
        case 27: {
            OHOS::Rect rect;
            rect.x = 0;
            rect.y = 0;
            rect.w = 5;
            rect.h = 5;
            int displayId = provider.ConsumeIntegral<int>();
            screenCaptureServer_->SetCaptureArea(displayId, rect);
            break;
        }
        case 28: {
            AVScreenCaptureHighlightConfig config;
            screenCaptureServer_->SetCaptureAreaHighlight(config);
            break;
        }
        case 29: {
            screenCaptureServer_->PresentPicker();
            break;
        }
        case 30: {
            std::vector<int32_t> windowIDsVec = ConsumeIntList32(provider);
            screenCaptureServer_->ExcludePickerWindows(windowIDsVec);
            break;
        }
        case 31: {
            screenCaptureServer_->SetPickerMode(PickerMode::SCREEN_ONLY);
            break;
        }
    }

    return 0;
}}