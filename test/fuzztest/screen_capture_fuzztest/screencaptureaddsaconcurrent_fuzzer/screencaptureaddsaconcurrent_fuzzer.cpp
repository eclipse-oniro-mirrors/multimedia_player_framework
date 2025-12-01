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

static const int32_t AUDIO_BIT_RATE = 48000;
static const int32_t AUDIO_CHANNELS = 2;
static const int32_t AUDIO_SAMPLE_RATE = 16000;
static const int32_t VIDEO_BIT_RATE = 2000000;
static const int32_t VIDEO_FRAME_RATE = 30;
static const int32_t VIDEO_FRAME_HEIGHT = 1280;
static const int32_t VIDEO_FRAME_WIDTH = 720;
static const int32_t MAX_VIDEO_FRAME_RATE = 60;
static const int32_t RECT_X = 0;
static const int32_t RECT_Y = 0;
static const int32_t RECT_W = 5;
static const int32_t RECT_H = 5;

enum ScreenCaptureServiceMsg {
    RELEASE = 0,
    SET_CAPTURE_MODE = 1,
    SET_DATA_TYPE = 2,
    SET_RECORDER_INFO = 3,
    SET_OUTPUT_FILE = 4,
    INIT_AUDIO_ENC_INFO = 5,
    INIT_AUDIO_CAP = 6,
    INIT_VIDEO_ENC_INFO = 7,
    INIT_VIDEO_CAP = 8,
    ACQUIRE_AUDIO_BUF = 9,
    ACQUIRE_VIDEO_BUF = 10,
    RELEASE_AUDIO_BUF = 11,
    RELEASE_VIDEO_BUF = 12,
    SET_MIC_ENABLE = 13,
    START_SCREEN_CAPTURE = 14,
    START_SCREEN_CAPTURE_WITH_SURFACE = 15,
    STOP_SCREEN_CAPTURE = 16,
    SET_SCREEN_ROTATION = 17,
    EXCLUDE_CONTENT = 18,
    RESIZE_CANVAS = 19,
    SKIP_PRIVACY = 20,
    SET_MAX_FRAME_RATE = 21,
    SHOW_CURSOR = 22,
    SET_CHECK_SA_LIMIT = 23,
    SET_CHECK_LIMIT = 24,
    SET_STRATEGY = 25,
    UPDATE_SURFACE = 26,
    SET_CAPTURE_AREA = 27,
    SET_HIGH_LIGHT_MODE = 28,
    PRESENT_PICKER = 29,
    EXCLUDE_PICKER_WINDOWS = 30,
    SET_PICKER_MODE = 31,
};
ScreenCaptureAddSaConcurrentFuzzer::ScreenCaptureAddSaConcurrentFuzzer()
{
}

ScreenCaptureAddSaConcurrentFuzzer::~ScreenCaptureAddSaConcurrentFuzzer()
{
}

std::shared_ptr<ScreenCaptureServer> screenCaptureServer_ = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
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

extern "C" int FuzzScreenCaptureConconcurrentTestOne(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        0, 1, 2, 3, 4
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case RELEASE: {
            screenCaptureServer_->Release();
            break;
        }
        case SET_CAPTURE_MODE: {
            screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN);
            break;
        }
        case SET_DATA_TYPE: {
            screenCaptureServer_->SetDataType(DataType::CAPTURE_FILE);
            break;
        }
        case SET_RECORDER_INFO: {
            int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
            RecorderInfo recorderInfo;
            recorderInfo.url = "fd://" + std::to_string(outputFd);
            recorderInfo.fileFormat = "mp4";
            screenCaptureServer_->SetRecorderInfo(recorderInfo);
            break;
        }
        case SET_OUTPUT_FILE: {
            int outputFd = open("/data/test/media/screen_capture_fuzz_add_sa_concurrent_file_01.mp4", O_RDWR);
            screenCaptureServer_->SetOutputFile(outputFd);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestTwo(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        5, 6, 7
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case INIT_AUDIO_ENC_INFO: {
            AudioEncInfo audioEncInfo;
            audioEncInfo.audioBitrate = AUDIO_BIT_RATE;
            audioEncInfo.audioCodecformat = AudioCodecFormat::AAC_LC;
            screenCaptureServer_->InitAudioEncInfo(audioEncInfo);
            break;
        }
        case INIT_AUDIO_CAP: {
            AudioCaptureInfo innerCapInfo;
            AudioCaptureInfo micCapInfo;
            innerCapInfo.audioChannels = AUDIO_CHANNELS;
            innerCapInfo.audioSampleRate = AUDIO_SAMPLE_RATE;
            innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
            micCapInfo.audioChannels = AUDIO_CHANNELS;
            micCapInfo.audioSampleRate = AUDIO_SAMPLE_RATE;
            micCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
            screenCaptureServer_->InitAudioCap(micCapInfo);
            screenCaptureServer_->InitAudioCap(innerCapInfo);
            break;
        }
        case INIT_VIDEO_ENC_INFO: {
            VideoEncInfo videoEncInfo;
            videoEncInfo.videoBitrate = VIDEO_BIT_RATE;
            videoEncInfo.videoFrameRate = VIDEO_FRAME_RATE;
            videoEncInfo.videoCodec = VideoCodecFormat::H264;
            screenCaptureServer_->InitVideoEncInfo(videoEncInfo);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestThree(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        8, 9, 10, 11, 12
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case INIT_VIDEO_CAP: {
            VideoCaptureInfo videoCapInfo;
            videoCapInfo.videoFrameHeight = VIDEO_FRAME_HEIGHT;
            videoCapInfo.videoFrameWidth = VIDEO_FRAME_WIDTH;
            videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
            screenCaptureServer_->InitVideoCap(videoCapInfo);
            break;
        }
        case ACQUIRE_AUDIO_BUF: {
            std::shared_ptr<OHOS::Media::AudioBuffer> audioBuffer;
            screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        case ACQUIRE_VIDEO_BUF: {
            sptr<OHOS::SurfaceBuffer> surfaceBuffer;
            int fence = provider.ConsumeIntegral<int>();
            int64_t timestamp = provider.ConsumeIntegral<int64_t>();
            OHOS::Rect damage;
            screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
            break;
        }
        case RELEASE_AUDIO_BUF: {
            screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        case RELEASE_VIDEO_BUF: {
            screenCaptureServer_->ReleaseVideoBuffer();
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestFour(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        13, 14, 15, 16, 17
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_MIC_ENABLE: {
            bool isMicrophone = provider.ConsumeBool();
            screenCaptureServer_->SetMicrophoneEnabled(isMicrophone);
            break;
        }
        case START_SCREEN_CAPTURE: {
            bool isPrivacyAuthorityEnabled = provider.ConsumeBool();
            screenCaptureServer_->StartScreenCapture(isPrivacyAuthorityEnabled);
            break;
        }
        case START_SCREEN_CAPTURE_WITH_SURFACE: {
            sptr<Surface> surface;
            bool isPrivacyAuthorityEnabled = provider.ConsumeBool();
            screenCaptureServer_->StartScreenCaptureWithSurface(surface, isPrivacyAuthorityEnabled);
            break;
        }
        case STOP_SCREEN_CAPTURE: {
            screenCaptureServer_->StopScreenCapture();
            break;
        }
        case SET_SCREEN_ROTATION: {
            bool canvasRotation = provider.ConsumeBool();
            screenCaptureServer_->SetCanvasRotation(canvasRotation);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestFive(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        18, 19, 20, 21, 22
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case EXCLUDE_CONTENT: {
            ScreenCaptureContentFilter contentFilter;
            screenCaptureServer_->ExcludeContent(contentFilter);
            break;
        }
        case RESIZE_CANVAS: {
            screenCaptureServer_->ResizeCanvas(VIDEO_FRAME_WIDTH, VIDEO_FRAME_HEIGHT);
            break;
        }
        case SKIP_PRIVACY: {
            std::vector<uint64_t> windowIDsVec = ConsumeIntList(provider);
            screenCaptureServer_->SkipPrivacyMode(windowIDsVec);
            break;
        }
        case SET_MAX_FRAME_RATE: {
            screenCaptureServer_->SetMaxVideoFrameRate(MAX_VIDEO_FRAME_RATE);
            break;
        }
        case SHOW_CURSOR: {
            bool showCursor = provider.ConsumeBool();
            screenCaptureServer_->ShowCursor(showCursor);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestSix(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        23, 24, 25, 26, 27
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_CHECK_SA_LIMIT: {
            OHOS::AudioStandard::AppInfo appInfo;
            screenCaptureServer_->SetAndCheckSaLimit(appInfo);
            break;
        }
        case SET_CHECK_LIMIT: {
            screenCaptureServer_->SetAndCheckLimit();
            break;
        }
        case SET_STRATEGY: {
            ScreenCaptureStrategy strategy;
            screenCaptureServer_->SetScreenCaptureStrategy(strategy);
            break;
        }
        case UPDATE_SURFACE: {
            sptr<Surface> surface;
            screenCaptureServer_->UpdateSurface(surface);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzScreenCaptureConconcurrentTestSeven(FuzzedDataProvider& provider)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        27, 28, 29, 30, 31
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_CAPTURE_AREA: {
            OHOS::Rect rect;
            rect.x = RECT_X;
            rect.y = RECT_Y;
            rect.w = RECT_W;
            rect.h = RECT_H;
            int displayId = provider.ConsumeIntegral<int>();
            screenCaptureServer_->SetCaptureArea(displayId, rect);
            break;
        }
        case SET_HIGH_LIGHT_MODE: {
            AVScreenCaptureHighlightConfig config;
            screenCaptureServer_->SetCaptureAreaHighlight(config);
            break;
        }
        case PRESENT_PICKER: {
            screenCaptureServer_->PresentPicker();
            break;
        }
        case EXCLUDE_PICKER_WINDOWS: {
            std::vector<int32_t> windowIDsVec = ConsumeIntList32(provider);
            screenCaptureServer_->ExcludePickerWindows(windowIDsVec);
            break;
        }
        case SET_PICKER_MODE: {
            screenCaptureServer_->SetPickerMode(PickerMode::SCREEN_ONLY);
            break;
        }
        default:
            break;
    }
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (screenCaptureServer_ == nullptr || data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    FuzzScreenCaptureConconcurrentTestOne(provider);
    FuzzScreenCaptureConconcurrentTestTwo(provider);
    FuzzScreenCaptureConconcurrentTestThree(provider);
    FuzzScreenCaptureConconcurrentTestFour(provider);
    FuzzScreenCaptureConconcurrentTestFive(provider);
    FuzzScreenCaptureConconcurrentTestSix(provider);
    FuzzScreenCaptureConconcurrentTestSeven(provider);
    return 0;
}}