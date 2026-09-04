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
#include <fuzzer/FuzzedDataProvider.h>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "screen_capture.h"
#include "screencaptureaudiocapturerwrapper_fuzzer.h"
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
ScreenCaptureAudioCapturerWrapperFuzzer::ScreenCaptureAudioCapturerWrapperFuzzer()
{
}

ScreenCaptureAudioCapturerWrapperFuzzer::~ScreenCaptureAudioCapturerWrapperFuzzer()
{
}

AudioCaptureSourceType ScreenCaptureAudioCapturerWrapperFuzzer::PickAudioSource(FuzzedDataProvider &fdp)
{
    static const AudioCaptureSourceType audioSources[] = {
        AudioCaptureSourceType::SOURCE_DEFAULT,
        AudioCaptureSourceType::MIC,
        AudioCaptureSourceType::ALL_PLAYBACK,
    };
    uint32_t idx = fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(audioSources) / sizeof(audioSources[0]) - 1);
    return audioSources[idx];
}

AudioCodecFormat ScreenCaptureAudioCapturerWrapperFuzzer::PickAudioCodecFormat(FuzzedDataProvider &fdp)
{
    static const AudioCodecFormat audioCodecFormats[] = {
        AudioCodecFormat::AUDIO_DEFAULT,
        AudioCodecFormat::AAC_LC,
    };
    constexpr uint32_t count = sizeof(audioCodecFormats) / sizeof(audioCodecFormats[0]);
    uint32_t idx = fdp.ConsumeIntegralInRange<uint32_t>(0, count - 1);
    return audioCodecFormats[idx];
}

VideoSourceType ScreenCaptureAudioCapturerWrapperFuzzer::PickVideoSourceType(FuzzedDataProvider &fdp)
{
    static const VideoSourceType videoSourceTypes[] = {
        VideoSourceType::VIDEO_SOURCE_SURFACE_YUV,
        VideoSourceType::VIDEO_SOURCE_SURFACE_ES,
        VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA,
    };
    uint32_t idx = fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(videoSourceTypes) / sizeof(videoSourceTypes[0]) - 1);
    return videoSourceTypes[idx];
}

VideoCodecFormat ScreenCaptureAudioCapturerWrapperFuzzer::PickVideoCodecFormat(FuzzedDataProvider &fdp)
{
    static const VideoCodecFormat videoCodecFormats[] = {
        VideoCodecFormat::VIDEO_DEFAULT,
        VideoCodecFormat::H264,
    };
    constexpr uint32_t count = sizeof(videoCodecFormats) / sizeof(videoCodecFormats[0]);
    uint32_t idx = fdp.ConsumeIntegralInRange<uint32_t>(0, count - 1);
    return videoCodecFormats[idx];
}

CaptureMode ScreenCaptureAudioCapturerWrapperFuzzer::PickCaptureMode(FuzzedDataProvider &fdp)
{
    static const CaptureMode captureModes[] = {
        CaptureMode::CAPTURE_HOME_SCREEN,
        CaptureMode::CAPTURE_SPECIFIED_SCREEN,
        CaptureMode::CAPTURE_SPECIFIED_WINDOW,
        CaptureMode::CAPTURE_SPECIFIED_APP,
    };
    uint32_t idx = fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(captureModes) / sizeof(captureModes[0]) - 1);
    return captureModes[idx];
}

AudioCaptureInfo ScreenCaptureAudioCapturerWrapperFuzzer::CreateAudioCaptureInfo(FuzzedDataProvider &fdp)
{
    return {
        .audioSampleRate = fdp.ConsumeIntegralInRange<int32_t>(8000, 96000),
        .audioChannels = fdp.ConsumeIntegralInRange<int32_t>(1, 8),
        .audioSource = PickAudioSource(fdp)
    };
}

AudioInfo ScreenCaptureAudioCapturerWrapperFuzzer::CreateAudioInfo(FuzzedDataProvider &fdp)
{
    return {
        .micCapInfo = CreateAudioCaptureInfo(fdp),
        .innerCapInfo = CreateAudioCaptureInfo(fdp),
        .audioEncInfo = {
            .audioBitrate = fdp.ConsumeIntegralInRange<int32_t>(1, 96000),
            .audioCodecformat = PickAudioCodecFormat(fdp)
        }
    };
}

VideoInfo ScreenCaptureAudioCapturerWrapperFuzzer::CreateVideoInfo(FuzzedDataProvider &fdp)
{
    return {
        .videoCapInfo = {
            .videoFrameWidth = fdp.ConsumeIntegralInRange<int32_t>(1, 3840),
            .videoFrameHeight = fdp.ConsumeIntegralInRange<int32_t>(1, 2160),
            .videoSource = PickVideoSourceType(fdp)
        },
        .videoEncInfo = {
            .videoCodec = PickVideoCodecFormat(fdp),
            .videoBitrate = fdp.ConsumeIntegralInRange<int32_t>(1, 4000000),
            .videoFrameRate = fdp.ConsumeIntegralInRange<int32_t>(1, 120)
        }
    };
}

void ScreenCaptureAudioCapturerWrapperFuzzer::SetConfig(RecorderInfo &recorderInfo, FuzzedDataProvider &fdp)
{
    config_ = {
        .captureMode = PickCaptureMode(fdp),
        .dataType = static_cast<DataType>(fdp.ConsumeIntegralInRange<int32_t>(0, 2)),
        .audioInfo = CreateAudioInfo(fdp),
        .videoInfo = CreateVideoInfo(fdp),
        .recorderInfo = recorderInfo
    };
}

void ScreenCaptureAudioCapturerWrapperFuzzer::TestCapturerWrapperOperations(
    const shared_ptr<AudioCapturerWrapper> &audioCapturerWrapper, FuzzedDataProvider &fdp)
{
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appTokenId = IPCSkeleton::GetCallingTokenID();
    appInfo.appFullTokenId = IPCSkeleton::GetCallingFullTokenID();
    appInfo.appUid = IPCSkeleton::GetCallingUid();
    appInfo.appPid = IPCSkeleton::GetCallingPid();
    audioCapturerWrapper->Start(appInfo);

    ScreenCaptureContentFilter contentFilter;
    if (fdp.ConsumeBool()) {
        contentFilter.filteredAudioContents.insert(
            AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO);
    }
    if (fdp.ConsumeBool()) {
        contentFilter.filteredAudioContents.insert(
            AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO);
    }
    audioCapturerWrapper->UpdateAudioCapturerConfig(contentFilter);
    audioCapturerWrapper->GetAudioCapturerState();
    int32_t logLevel = fdp.ConsumeIntegralInRange<int32_t>(0, 1);
    audioCapturerWrapper->PartiallyPrintLog(logLevel, "CaptureAudio read audio buffer failed ");
    audioCapturerWrapper->SetIsMute(GetData<bool>());
    audioCapturerWrapper->UseUpAllLeftBufferUntil(GetData<int64_t>());
    shared_ptr<CacheBuffer> cacheBuf;
    audioCapturerWrapper->AcquireAudioBuffer(cacheBuf);
    audioCapturerWrapper->DropBufferUntil(GetData<int64_t>());
    audioCapturerWrapper->ReleaseAudioBuffer();
    audioCapturerWrapper->IsRecording();
    audioCapturerWrapper->IsStop();
    audioCapturerWrapper->Stop();
    audioCapturerWrapper->SetIsInVoIPCall(GetData<bool>());
    audioCapturerWrapper->IsInVoIPCall();
    audioCapturerWrapper->Start(appInfo);
    audioCapturerWrapper->ReleaseAudioBuffer();
    audioCapturerWrapper->Stop();
}

bool ScreenCaptureAudioCapturerWrapperFuzzer::FuzzScreenAudioCapturerWrapper(uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2 * sizeof(int32_t)) {  // 2 input params
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_fuzz_server_start_file_01.mp4", O_RDWR);
    if (outputFd < 0) {
        return false;
    }
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetConfig(recorderInfo, fdp);
    std::shared_ptr<ScreenCaptureCallBack> callbackObj = std::make_shared<TestScreenCaptureCallbackTest>();
    ScreenCaptureContentFilter contentFilter;
    std::string capturerName = fdp.ConsumeRandomLengthString(64);
    shared_ptr<AudioCapturerWrapper> audioCapturerWrapper =
        make_shared<AudioCapturerWrapper>(config_.audioInfo.innerCapInfo, callbackObj, capturerName, contentFilter);
    TestCapturerWrapperOperations(audioCapturerWrapper, fdp);
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
