/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "screen_capture.h"
#include "audiodatasource_fuzzer.h"
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"
#include "test_template.h"
#include "media_log.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {

void SetConfig(AVScreenCaptureConfig &config, FuzzedDataProvider &fdp)
{
    static const AudioCaptureSourceType audioSources[] = {
        SOURCE_DEFAULT,
        MIC,
        ALL_PLAYBACK,
    };
    static const CaptureMode captureModes[] = {
        CaptureMode::CAPTURE_HOME_SCREEN,
        CaptureMode::CAPTURE_SPECIFIED_SCREEN,
        CaptureMode::CAPTURE_SPECIFIED_WINDOW,
        CaptureMode::CAPTURE_SPECIFIED_APP,
    };
    static const DataType dataTypes[] = {
        DataType::ORIGINAL_STREAM,
        DataType::ENCODED_STREAM,
        DataType::CAPTURE_FILE,
    };

    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = fdp.ConsumeIntegralInRange<int32_t>(8000, 96000),
        .audioChannels = fdp.ConsumeIntegralInRange<int32_t>(1, 8),
        .audioSource = audioSources[fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(audioSources) / sizeof(audioSources[0]) - 1)]
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = fdp.ConsumeIntegralInRange<int32_t>(8000, 96000),
        .audioChannels = fdp.ConsumeIntegralInRange<int32_t>(1, 8),
        .audioSource = audioSources[fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(audioSources) / sizeof(audioSources[0]) - 1)]
    };

    VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = fdp.ConsumeIntegralInRange<int32_t>(1, 3840),
        .videoFrameHeight = fdp.ConsumeIntegralInRange<int32_t>(1, 2160),
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };

    AudioEncInfo audioEncInfo = {
        .audioBitrate = fdp.ConsumeIntegralInRange<int32_t>(1, 96000),
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };

    AudioInfo audioinfo = {
        .micCapInfo = micCapinfo,
        .innerCapInfo = innerCapInfo,
        .audioEncInfo = audioEncInfo,
    };

    VideoInfo videoinfo = {
        .videoCapInfo = videocapinfo
    };

    config = {
        .captureMode = captureModes[fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(captureModes) / sizeof(captureModes[0]) - 1)],
        .dataType = dataTypes[fdp.ConsumeIntegralInRange<uint32_t>(0, sizeof(dataTypes) / sizeof(dataTypes[0]) - 1)],
        .audioInfo = audioinfo,
        .videoInfo = videoinfo,
    };
}

void AudioDataSourceFuzzer::Init()
{
    screenCaptureServer_ = MakeScreenCaptureServerShared();
    if (!screenCaptureServer_) {
        return;
    }
    AVScreenCaptureConfig config;
    if (fdp_ != nullptr) {
        SetConfig(config, *fdp_);
    } else {
        AVScreenCaptureConfig defaultConfig = {};
        config = defaultConfig;
    }
    screenCaptureServer_->InitAudioCap(config.audioInfo.innerCapInfo);
    screenCaptureServer_->InitAudioCap(config.audioInfo.micCapInfo);
    screenCaptureServer_->SyncAudioCaptures();
}

void AudioDataSourceFuzzer::Release()
{
    if (screenCaptureServer_) {
        screenCaptureServer_->Release();
        screenCaptureServer_ = nullptr;
    }
}

std::shared_ptr<AudioBuffer> AudioDataSourceFuzzer::CreateAudioBufferInner(int64_t timestamp, uint32_t bufferSize)
{
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % 4);
    uint8_t *innerBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    if (innerBuffer == nullptr) {
        return nullptr;
    }
    auto audioBuffer = std::make_shared<AudioBuffer>(innerBuffer,
        bufferSize, timestamp, type);
    if (audioBuffer == nullptr) {
        free(innerBuffer);
        return nullptr;
    }
    return cacheBuf;
}

std::shared_ptr<AudioBuffer> AudioDataSourceFuzzer::CreateAudioBufferMic(int64_t timestamp, uint32_t bufferSize)
{
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % 4);
    uint8_t *micBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    if (micBuffer == nullptr) {
        return nullptr;
    }
    auto audioBuffer = std::make_shared<AudioBuffer>(micBuffer,
        bufferSize, timestamp, type);
    if (audioBuffer == nullptr) {
        free(micBuffer);
        return nullptr;
    }
    return cacheBuf;
}

std::shared_ptr<AVBuffer> AudioDataSourceFuzzer::CreateAVBuffer(uint32_t bufferSize)
{
    AVbuf.resize(bufferSize);
    auto avBuffer = AVBuffer::CreateAVBuffer(AVbuf.data(), bufferSize);
    if (avBuffer == nullptr) {
        return nullptr;
    }

    return audioBuffer;
}

std::shared_ptr<AudioRendererChangeInfo> AudioDataSourceFuzzer::CreateAudioRendererChangeInfo()
{
    auto changeInfo = std::make_shared<AudioRendererChangeInfo>();
    if (changeInfo == nullptr) {
        return nullptr;
    }

    changeInfo->clientPid = GetData<int32_t>();
    changeInfo->rendererState = RendererState::RENDERER_RUNNING;
    changeInfo->rendererInfo.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    changeInfo->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;

    return changeInfo;
}

bool AudioDataSourceFuzzer::FuzzAudioRendererStateUpdate()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int32_t numInfos = GetData<uint32_t>() % 10;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;

    for (int32_t i = 0; i < numInfos; i++) {
        auto changeInfo = CreateAudioRendererChangeInfo();
        if (changeInfo != nullptr) {
            audioRendererChangeInfos.push_back(changeInfo);
        }
    }

    screenCaptureServer_->AudioRendererStateUpdate(audioRendererChangeInfos);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetAudioRendererState()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int32_t numInfos = GetData<uint32_t>() % 10;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;

    for (int32_t i = 0; i < numInfos; i++) {
        auto changeInfo = CreateAudioRendererChangeInfo();
        if (changeInfo != nullptr) {
            audioRendererChangeInfos.push_back(changeInfo);
        }
    }

    screenCaptureServer_->AudioRendererStateUpdate(audioRendererChangeInfos);
    uint32_t state = audioDataSource->GetAudioRendererState();
    (void)state;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzAudioRendererStateUpdateVoIP()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int32_t numInfos = GetData<uint32_t>() % 10;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;

    for (int32_t i = 0; i < numInfos; i++) {
        auto changeInfo = CreateAudioRendererChangeInfo();
        if (changeInfo != nullptr) {
            audioRendererChangeInfos.push_back(changeInfo);
        }
    }

    screenCaptureServer_->AudioRendererStateUpdate(audioRendererChangeInfos);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHasVoIPStream()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int32_t numInfos = GetData<uint32_t>() % 10;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;

    for (int32_t i = 0; i < numInfos; i++) {
        auto changeInfo = CreateAudioRendererChangeInfo();
        if (changeInfo != nullptr) {
            audioRendererChangeInfos.push_back(changeInfo);
        }
    }
    screenCaptureServer_->AudioRendererStateUpdate(audioRendererChangeInfos);
    uint32_t state = audioDataSource->GetAudioRendererState();
    bool hasVoIP = (state & AUDIO_STATE_VOIP) != 0;
    (void)hasVoIP;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetAndGetAppPid()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int32_t appPid = GetData<int32_t>();
    audioDataSource->SetAppPid(appPid);

    int32_t retrievedPid = audioDataSource->GetAppPid();
    (void)retrievedPid;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetVideoFirstFramePts()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int64_t pts = GetData<int64_t>();
    audioDataSource->SetVideoFirstFramePts(pts);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetAudioFirstFramePts()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int64_t pts = GetData<int64_t>();
    audioDataSource->SetAudioFirstFramePts(pts);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtMixMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    audioDataSource->ReadAtMixMode();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtMicMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());

    audioDataSource->ReadAtMicMode();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtInnerMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());

    audioDataSource->ReadAtInnerMode();
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAt(uint32_t bufferSize)
{
    Init();
    AVScreenCaptureMixMode mode = static_cast<AVScreenCaptureMixMode>(GetData<int32_t>() % 3);
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(mode, screenCaptureServer_.get());

    auto buffer = CreateAVBuffer(bufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAt(buffer, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetSize()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int64_t sizeResult = 0;
    uint8_t eventType = GetData<uint8_t>() % 2;
    if (eventType == 0) {
        if (screenCaptureServer_->innerAudioCapture_) {
            screenCaptureServer_->innerAudioCapture_->ReleaseAudioBuffer();
        }
    }
    audioDataSource->GetSize(sizeResult);
    (void)sizeResult;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzMixModeBufferWrite(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    audioDataSource->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer);
    innerAudioBuffer = nullptr;
    micAudioBuffer = nullptr;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteInnerAudio(uint32_t bufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), bufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteInnerAudio(length, innerAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMicAudio(uint32_t bufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());

    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), bufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMicAudio(length, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMixAudio(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMixAudio(length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzInnerMicAudioSync(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->InnerMicAudioSync(length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncMixMode(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncInnerMode(uint32_t bufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), bufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetFirstAudioTime(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);

    int64_t firstAudioTime = audioDataSource->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    (void)firstAudioTime;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMixCore(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMixCore(length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMix(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMix(length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandlePastMicBuffer(uint32_t bufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), bufferSize);
    audioDataSource->HandlePastMicBuffer(micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleSwitchToSpeakerOptimise(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    audioDataSource->HandleSwitchToSpeakerOptimise(innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleBufferTimeStamp(uint32_t innerBufferSize, uint32_t micBufferSize)
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>(), innerBufferSize);
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>(), micBufferSize);
    audioDataSource->HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzLostFrameNum()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());

    int64_t timestamp = GetData<int64_t>();
    int64_t lostFrameNum = audioDataSource->LostFrameNum(timestamp);
    (void)lostFrameNum;
    Release();
    return true;
}

bool FuzzAudioDataSourceCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    FuzzedDataProvider fdp(data, size);
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    uint32_t innerBufferSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 4096);
    uint32_t micBufferSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 4096);

    AudioDataSourceFuzzer testAudioDataSource;
    testAudioDataSource.fdp_ = &fdp;

    testAudioDataSource.FuzzAudioRendererStateUpdate();
    testAudioDataSource.FuzzGetAudioRendererState();
    testAudioDataSource.FuzzAudioRendererStateUpdateVoIP();
    testAudioDataSource.FuzzHasVoIPStream();
    testAudioDataSource.FuzzSetAndGetAppPid();
    testAudioDataSource.FuzzSetVideoFirstFramePts();
    testAudioDataSource.FuzzSetAudioFirstFramePts();
    testAudioDataSource.FuzzReadAtMixMode();
    testAudioDataSource.FuzzReadAtMicMode();
    testAudioDataSource.FuzzReadAtInnerMode();
    testAudioDataSource.FuzzReadAt(innerBufferSize);
    testAudioDataSource.FuzzGetSize();
    testAudioDataSource.FuzzMixModeBufferWrite(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzWriteInnerAudio(innerBufferSize);
    testAudioDataSource.FuzzWriteMicAudio(micBufferSize);
    testAudioDataSource.FuzzWriteMixAudio(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzInnerMicAudioSync(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzVideoAudioSyncMixMode(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzVideoAudioSyncInnerMode(innerBufferSize);
    testAudioDataSource.FuzzGetFirstAudioTime(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzReadWriteAudioBufferMixCore(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzReadWriteAudioBufferMix(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzHandlePastMicBuffer(micBufferSize);
    testAudioDataSource.FuzzHandleSwitchToSpeakerOptimise(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzHandleBufferTimeStamp(innerBufferSize, micBufferSize);
    testAudioDataSource.FuzzLostFrameNum();
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    FuzzAudioDataSourceCase(data, size);
    return 0;
}
}
}
