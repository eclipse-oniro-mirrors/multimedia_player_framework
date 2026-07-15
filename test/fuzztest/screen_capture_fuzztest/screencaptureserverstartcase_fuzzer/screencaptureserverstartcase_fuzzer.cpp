/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "screencaptureserverstartcase_fuzzer.h"
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
ScreenCaptureServerStartCaseFuzzer::ScreenCaptureServerStartCaseFuzzer()
{
}

ScreenCaptureServerStartCaseFuzzer::~ScreenCaptureServerStartCaseFuzzer()
{
}

void ScreenCaptureServerStartCaseFuzzer::SetConfig(RecorderInfo &recorderInfo)
{
    AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK,
    };
    VideoCaptureInfo videoCapInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };
    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };
    AudioInfo audioInfo = {
        .micCapInfo = micCapInfo,
        .innerCapInfo = innerCapInfo,
        .audioEncInfo = audioEncInfo
    };
    VideoInfo videoInfo = {
        .videoCapInfo = videoCapInfo,
        .videoEncInfo = videoEncInfo
    };
    config_ = {
        .captureMode = CaptureMode::CAPTURE_HOME_SCREEN,
        .dataType = DataType::CAPTURE_FILE,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo,
        .recorderInfo = recorderInfo
    };
}

bool ScreenCaptureServerStartCaseFuzzer::FuzzScreenCaptureServerStartCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2 * sizeof(int32_t)) {  // 2 input params
        return false;
    }
    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_;
    std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
    if (tempServer_ == nullptr) {
        return false;
    }
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetConfig(recorderInfo);
    screenCaptureServer_->SetCaptureMode(config_.captureMode);
    screenCaptureServer_->SetDataType(config_.dataType);
    screenCaptureServer_->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServer_->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServer_->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->StartStreamInnerAudioCapture();
    screenCaptureServer_->StartStreamMicAudioCapture();
    std::shared_ptr<TestScreenCaptureCallbackTest> callbackObj = std::make_shared<TestScreenCaptureCallbackTest>();
    TestScreenCapture::SetScreenCaptureCallback(callbackObj);
    screenCaptureServer_->ResizeCanvas(*reinterpret_cast<int32_t *>(data),
        *reinterpret_cast<int32_t *>(data + sizeof(int32_t)));
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
    close(outputFd);
    return true;
}
} // namespace Media

bool FuzzTestScreenCaptureServerStartCase(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < 2 * sizeof(int32_t)) { // 2 input params
        return true;
    }
    ScreenCaptureServerStartCaseFuzzer testScreenCapture;
    return testScreenCapture.FuzzScreenCaptureServerStartCase(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestScreenCaptureServerStartCase(data, size);
    return 0;
}