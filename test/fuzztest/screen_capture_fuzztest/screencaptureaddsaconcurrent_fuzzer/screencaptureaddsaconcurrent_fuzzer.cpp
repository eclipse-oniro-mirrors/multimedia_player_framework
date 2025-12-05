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
        RELEASE_AUDIO_BUF = 10,
        RELEASE_VIDEO_BUF = 11,
        SET_MIC_ENABLE = 12,
        START_SCREEN_CAPTURE = 13,
        START_SCREEN_CAPTURE_WITH_SURFACE = 14,
        STOP_SCREEN_CAPTURE = 15,
        SET_SCREEN_ROTATION = 16,
        EXCLUDE_CONTENT = 17,
        RESIZE_CANVAS = 18,
        SKIP_PRIVACY = 19,
        SET_MAX_FRAME_RATE = 20,
        SHOW_CURSOR = 21,
        SET_CHECK_SA_LIMIT = 22,
        SET_CHECK_LIMIT = 23,
        SET_STRATEGY = 24,
        UPDATE_SURFACE = 25,
        SET_CAPTURE_AREA = 26,
        SET_HIGH_LIGHT_MODE = 27,
        PRESENT_PICKER = 28,
        EXCLUDE_PICKER_WINDOWS = 29,
        SET_PICKER_MODE = 30,
    };
    ScreenCaptureAddSaConcurrentFuzzer::ScreenCaptureAddSaConcurrentFuzzer() {}

    ScreenCaptureAddSaConcurrentFuzzer::~ScreenCaptureAddSaConcurrentFuzzer() {}

    RecorderInfo recorderInfo_;
    AudioEncInfo audioEncInfo_;
    AudioCaptureInfo innerCapInfo_;
    AudioCaptureInfo micCapInfo_;
    VideoEncInfo videoEncInfo_;
    VideoCaptureInfo videoCapInfo_;
    OHOS::Rect rect_;
    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_ = nullptr;

    extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
    {
        std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
        if (tempServer_ == nullptr) {
            return 0;
        }
        screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
        int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
        recorderInfo_.url = "fd://" + std::to_string(outputFd);
        recorderInfo_.fileFormat = "mp4";
        audioEncInfo_.audioBitrate = AUDIO_BIT_RATE;
        audioEncInfo_.audioCodecformat = AudioCodecFormat::AAC_LC;
        innerCapInfo_.audioChannels = AUDIO_CHANNELS;
        innerCapInfo_.audioSampleRate = AUDIO_SAMPLE_RATE;
        innerCapInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
        micCapInfo_.audioChannels = AUDIO_CHANNELS;
        micCapInfo_.audioSampleRate = AUDIO_SAMPLE_RATE;
        micCapInfo_.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
        videoEncInfo_.videoBitrate = VIDEO_BIT_RATE;
        videoEncInfo_.videoFrameRate = VIDEO_FRAME_RATE;
        videoEncInfo_.videoCodec = VideoCodecFormat::H264;
        videoCapInfo_.videoFrameHeight = VIDEO_FRAME_HEIGHT;
        videoCapInfo_.videoFrameWidth = VIDEO_FRAME_WIDTH;
        videoCapInfo_.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
        rect_.x = RECT_X;
        rect_.y = RECT_Y;
        rect_.w = RECT_W;
        rect_.h = RECT_H;
        return 0;
    }
}  // namespace Media

static std::vector<uint64_t> ConsumeIntList(FuzzedDataProvider &provider)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    std::vector<uint64_t> vec;
    for (size_t i = 0; i < len; ++i) {
        vec.push_back(provider.ConsumeIntegral<uint64_t>());
    }
    return vec;
}

static std::vector<int32_t> ConsumeIntList32(FuzzedDataProvider &provider)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    std::vector<int32_t> vec;
    for (size_t i = 0; i < len; ++i) {
        vec.push_back(provider.ConsumeIntegral<int32_t>());
    }
    return vec;
}

int FuzzScreenCaptureConconcurrentTestOne(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
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
            screenCaptureServer_->SetRecorderInfo(recorderInfo_);
            break;
        }
        case SET_OUTPUT_FILE: {
            int outputFd = open("/data/test/media/screen_capture_fuzz_add_sa_concurrent_file_01.mp4", O_RDWR);
            screenCaptureServer_->SetOutputFile(outputFd);
            break;
        }
        case INIT_AUDIO_ENC_INFO: {
            screenCaptureServer_->InitAudioEncInfo(audioEncInfo_);
            break;
        }
        default: break;
    }
    return 0;
}

int FuzzScreenCaptureConconcurrentTestTwo(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    switch (code) {
        case INIT_AUDIO_CAP: {
            screenCaptureServer_->InitAudioCap(micCapInfo_);
            screenCaptureServer_->InitAudioCap(innerCapInfo_);
            break;
        }
        case INIT_VIDEO_ENC_INFO: {
            screenCaptureServer_->InitVideoEncInfo(videoEncInfo_);
            break;
        }
        case INIT_VIDEO_CAP: {
            screenCaptureServer_->InitVideoCap(videoCapInfo_);
            break;
        }
        case ACQUIRE_AUDIO_BUF: {
            std::shared_ptr<OHOS::Media::AudioBuffer> audioBuffer;
            screenCaptureServer_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        case RELEASE_AUDIO_BUF: {
            screenCaptureServer_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK);
            break;
        }
        default: break;
    }
    return 0;
}

int FuzzScreenCaptureConconcurrentTestThree(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    switch (code) {
        case RELEASE_VIDEO_BUF: {
            screenCaptureServer_->ReleaseVideoBuffer();
            break;
        }
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
        default: break;
    }
    return 0;
}

int FuzzScreenCaptureConconcurrentTestFour(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    switch (code) {
        case SET_SCREEN_ROTATION: {
            bool canvasRotation = provider.ConsumeBool();
            screenCaptureServer_->SetCanvasRotation(canvasRotation);
            break;
        }
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
        default: break;
    }
    return 0;
}

int FuzzScreenCaptureConconcurrentTestFive(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    switch (code) {
        case SHOW_CURSOR: {
            bool showCursor = provider.ConsumeBool();
            screenCaptureServer_->ShowCursor(showCursor);
            break;
        }
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
        default: break;
    }
    return 0;
}

int FuzzScreenCaptureConconcurrentTestSix(FuzzedDataProvider &provider, int code)
{
    if (screenCaptureServer_ == nullptr) {
        return 0;
    }
    switch (code) {
        case SET_CAPTURE_AREA: {
            int displayId = provider.ConsumeIntegral<int>();
            screenCaptureServer_->SetCaptureArea(displayId, rect_);
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
        default: break;
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
    static const int ipccodes[] = {
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    };
    int code = provider.PickValueInArray(ipccodes);
    if (code >= RELEASE && code <= INIT_AUDIO_ENC_INFO) {
        FuzzScreenCaptureConconcurrentTestOne(provider, code);
    } else if (code >= INIT_AUDIO_CAP && code <= RELEASE_AUDIO_BUF) {
        FuzzScreenCaptureConconcurrentTestTwo(provider, code);
    } else if (code >= RELEASE_VIDEO_BUF && code <= STOP_SCREEN_CAPTURE) {
        FuzzScreenCaptureConconcurrentTestThree(provider, code);
    } else if (code >= SET_SCREEN_ROTATION && code <= SET_MAX_FRAME_RATE) {
        FuzzScreenCaptureConconcurrentTestFour(provider, code);
    } else if (code >= SHOW_CURSOR && code <= UPDATE_SURFACE) {
        FuzzScreenCaptureConconcurrentTestFive(provider, code);
    } else if (code >= SET_CAPTURE_AREA && code <= SET_PICKER_MODE) {
        FuzzScreenCaptureConconcurrentTestSix(provider, code);
    }
    return 0;
}
} // namespace OHOS