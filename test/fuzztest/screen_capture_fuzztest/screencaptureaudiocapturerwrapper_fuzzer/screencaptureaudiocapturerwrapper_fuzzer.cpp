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
#include "screencaptureaudiocapturerwrapper_fuzzer.h"
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {

namespace {
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t pos_;
}

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (data_ == nullptr || objectSize > size_ - pos_) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, data_ + pos_, objectSize);
    if (ret != EOK) {
        return {};
    }
    pos_ += objectSize;
    return object;
}

ScreenCaptureAudioCapturerWrapperFuzzer::ScreenCaptureAudioCapturerWrapperFuzzer()
{
}

ScreenCaptureAudioCapturerWrapperFuzzer::~ScreenCaptureAudioCapturerWrapperFuzzer()
{
}

void ScreenCaptureAudioCapturerWrapperFuzzer::SetConfig(RecorderInfo &recorderInfo)
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

bool ScreenCaptureAudioCapturerWrapperFuzzer::FuzzScreenAudioCapturerWrapper(uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2 * sizeof(int32_t)) {  // 2 input params
        return false;
    }
    data_ = data;
    size_ = size;
    pos_ = 0;
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetConfig(recorderInfo);
    std::shared_ptr<ScreenCaptureCallBack> callbackObj = std::make_shared<TestScreenCaptureCallbackTest>();
    ScreenCaptureContentFilter contentFilter;
    shared_ptr<AudioCapturerWrapper> audioCapturerWrapper =
        make_shared<AudioCapturerWrapper>(config_.audioInfo.innerCapInfo, callbackObj, string("name1"), contentFilter);
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appTokenId = IPCSkeleton::GetCallingTokenID();
    appInfo.appFullTokenId = IPCSkeleton::GetCallingFullTokenID();
    appInfo.appUid = IPCSkeleton::GetCallingUid();
    appInfo.appPid = IPCSkeleton::GetCallingPid();
    audioCapturerWrapper->Start(appInfo);
    contentFilter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO);
    audioCapturerWrapper->UpdateAudioCapturerConfig(contentFilter);
    audioCapturerWrapper->GetAudioCapturerState();
    audioCapturerWrapper->RelativeSleep(1);
    audioCapturerWrapper->PartiallyPrintLog(1, "CaptureAudio read audio buffer failed ");
    audioCapturerWrapper->SetIsMute(GetData<bool>());
    audioCapturerWrapper->UseUpAllLeftBufferUntil(GetData<int64_t>());
    size_t  buffersize = 0;
    int64_t currentAudioTime = 0;
    audioCapturerWrapper->GetBufferSize(buffersize);
    uint8_t *buffer = (uint8_t *)malloc(buffersize);
    shared_ptr<AudioBuffer> audioBuffer = make_shared<AudioBuffer>(buffer, 0, 0, AudioCaptureSourceType::ALL_PLAYBACK);
    audioCapturerWrapper->AddBufferFrom(GetData<int64_t>(), GetData<int64_t>(), GetData<int64_t>());
    audioCapturerWrapper->AcquireAudioBuffer(audioBuffer);
    audioCapturerWrapper->DropBufferUntil(GetData<int64_t>());
    audioCapturerWrapper->GetCurrentAudioTime(currentAudioTime);
    audioCapturerWrapper->ReleaseAudioBuffer();
    audioCapturerWrapper->IsRecording();
    audioCapturerWrapper->IsStop();
    audioCapturerWrapper->Stop();
    audioCapturerWrapper->SetIsInTelCall(GetData<bool>());
    audioCapturerWrapper->SetIsInVoIPCall(GetData<bool>());
    audioCapturerWrapper->Start(appInfo);
    audioCapturerWrapper->ReleaseAudioBuffer();
    audioCapturerWrapper->Stop();
    close(outputFd);
    return true;
}

} // namespace Media


bool FuzzTestScreenAudioCapturerWrapper(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < 2 * sizeof(int32_t)) { // 2 input params
        return true;
    }
    ScreenCaptureAudioCapturerWrapperFuzzer testAudioCapturerWrapper;
    return testAudioCapturerWrapper.FuzzScreenAudioCapturerWrapper(data, size);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestScreenAudioCapturerWrapper(data, size);
    return 0;
}