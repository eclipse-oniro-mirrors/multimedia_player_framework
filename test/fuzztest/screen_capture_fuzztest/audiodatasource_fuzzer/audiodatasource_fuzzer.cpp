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

void SetConfig(AVScreenCaptureConfig &config)
{
    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = SOURCE_DEFAULT
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 48000,
        .audioChannels = 2,
        .audioSource = ALL_PLAYBACK
    };

    VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };

    AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
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
        .captureMode = CAPTURE_HOME_SCREEN,
        .dataType = ORIGINAL_STREAM,
        .audioInfo = audioinfo,
        .videoInfo = videoinfo,
    };
}

void AudioDataSourceFuzzer::Init()
{
    std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
    if (tempServer_ == nullptr) {
        return;
    }
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
    AVScreenCaptureConfig config;
    SetConfig(config);
    screenCaptureServer_->InitAudioCap(config.audioInfo.innerCapInfo);
    screenCaptureServer_->InitAudioCap(config.audioInfo.micCapInfo);
    screenCaptureServer_->StartStreamInnerAudioCapture();
    screenCaptureServer_->StartStreamMicAudioCapture();
}

void AudioDataSourceFuzzer::Release()
{
    screenCaptureServer_->Release();
}

std::shared_ptr<AudioBuffer> AudioDataSourceFuzzer::CreateAudioBufferInner(int64_t timestamp)
{
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % 4);
    uint8_t *innerBuffer = (uint8_t *)malloc(sizeof(uint8_t) * datasize);
    auto audioBuffer = std::make_shared<AudioBuffer>(innerBuffer,
        datasize, timestamp, type);
    if (audioBuffer == nullptr) {
        return nullptr;
    }
    return audioBuffer;
}

std::shared_ptr<AudioBuffer> AudioDataSourceFuzzer::CreateAudioBufferMic(int64_t timestamp)
{
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(GetData<uint8_t>() % 4);
    uint8_t *micBuffer = (uint8_t *)malloc(sizeof(uint8_t) * datasize);
    auto audioBuffer = std::make_shared<AudioBuffer>(micBuffer,
        datasize, timestamp, type);
    if (audioBuffer == nullptr) {
        return nullptr;
    }
    return audioBuffer;
}

std::shared_ptr<AVBuffer> AudioDataSourceFuzzer::CreateAVBuffer()
{
    AVbuf.resize(datasize);
    auto avBuffer = AVBuffer::CreateAVBuffer(AVbuf.data(), datasize);
    if (avBuffer == nullptr) {
        return nullptr;
    }

    return avBuffer;
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

bool AudioDataSourceFuzzer::FuzzSpeakerStateUpdate()
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

    audioDataSource->SpeakerStateUpdate(audioRendererChangeInfos);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHasSpeakerStream()
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
    
    bool hasSpeaker = audioDataSource->HasSpeakerStream(audioRendererChangeInfos);
    (void)hasSpeaker;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzVoIPStateUpdate()
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
    
    audioDataSource->VoIPStateUpdate(audioRendererChangeInfos);
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
    bool hasVoIP = audioDataSource->HasVoIPStream(audioRendererChangeInfos);
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

bool AudioDataSourceFuzzer::FuzzSetAndGetAppName()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    audioDataSource->SetAppName("appName");
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
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtMixMode(buffer, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtMicMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtMicMode(buffer, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtInnerMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtInnerMode(buffer, length);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAt()
{
    Init();
    AVScreenCaptureMixMode mode = static_cast<AVScreenCaptureMixMode>(GetData<int32_t>() % 3);
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(mode, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
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
    if (GetData<uint8_t>() % 2 == 0) {
        screenCaptureServer_->ReleaseInnerAudioBuffer();
    }
    audioDataSource->GetSize(sizeResult);
    (void)sizeResult;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzMixModeBufferWrite()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    std::shared_ptr<AVMemory> &bufferMem = avBuffer->memory_;
    audioDataSource->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    innerAudioBuffer = nullptr;
    micAudioBuffer = nullptr;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteInnerAudio()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteInnerAudio(avBuffer, length, innerAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMicAudio()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMicAudio(avBuffer, length, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMixAudio()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMixAudio(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzInnerMicAudioSync()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->InnerMicAudioSync(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncMixMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncMixMode(avBuffer, length, timeWindow, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncInnerMode()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncInnerMode(avBuffer, length, timeWindow, innerAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetFirstAudioTime()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    
    int64_t firstAudioTime = audioDataSource->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    (void)firstAudioTime;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMixCore()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMixCore(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMix()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMix(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandlePastMicBuffer()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    audioDataSource->HandlePastMicBuffer(micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleSwitchToSpeakerOptimise()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    audioDataSource->HandleSwitchToSpeakerOptimise(innerAudioBuffer, micAudioBuffer);
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleBufferTimeStamp()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
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
    int32_t lostFrameNum = audioDataSource->LostFrameNum(timestamp);
    (void)lostFrameNum;
    Release();
    return true;
}

bool AudioDataSourceFuzzer::FuzzFillLostBuffer()
{
    Init();
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t lostNum = GetData<int64_t>() % 100;
    int64_t timestamp = GetData<int64_t>() % 1000000;
    uint32_t bufferSize = GetData<uint32_t>() % 1024;
    audioDataSource->FillLostBuffer(lostNum, timestamp, bufferSize);
    Release();
    return true;
}

bool FuzzAudioDataSourceCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    AudioDataSourceFuzzer testAudioDataSource;

    testAudioDataSource.FuzzSpeakerStateUpdate();
    testAudioDataSource.FuzzHasSpeakerStream();
    testAudioDataSource.FuzzVoIPStateUpdate();
    testAudioDataSource.FuzzHasVoIPStream();
    testAudioDataSource.FuzzSetAndGetAppPid();
    testAudioDataSource.FuzzSetAndGetAppName();
    testAudioDataSource.FuzzSetVideoFirstFramePts();
    testAudioDataSource.FuzzSetAudioFirstFramePts();
    testAudioDataSource.FuzzReadAtMixMode();
    testAudioDataSource.FuzzReadAtMicMode();
    testAudioDataSource.FuzzReadAtInnerMode();
    testAudioDataSource.FuzzReadAt();
    testAudioDataSource.FuzzGetSize();
    testAudioDataSource.FuzzMixModeBufferWrite();
    testAudioDataSource.FuzzWriteInnerAudio();
    testAudioDataSource.FuzzWriteMicAudio();
    testAudioDataSource.FuzzWriteMixAudio();
    testAudioDataSource.FuzzInnerMicAudioSync();
    testAudioDataSource.FuzzVideoAudioSyncMixMode();
    testAudioDataSource.FuzzVideoAudioSyncInnerMode();
    testAudioDataSource.FuzzGetFirstAudioTime();
    testAudioDataSource.FuzzReadWriteAudioBufferMixCore();
    testAudioDataSource.FuzzReadWriteAudioBufferMix();
    testAudioDataSource.FuzzHandlePastMicBuffer();
    testAudioDataSource.FuzzHandleSwitchToSpeakerOptimise();
    testAudioDataSource.FuzzHandleBufferTimeStamp();
    testAudioDataSource.FuzzLostFrameNum();
    testAudioDataSource.FuzzFillLostBuffer();
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