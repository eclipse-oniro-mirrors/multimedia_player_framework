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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE,
                                               "AudioDataSourceFuzzer"};
using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {

const int32_t CASE_0 = 0;
const int32_t CASE_1 = 1;
const int32_t CASE_2 = 2;
const int32_t CASE_3 = 3;
const int32_t CASE_4 = 4;
const int32_t CASE_5 = 5;
const int32_t CASE_6 = 6;
const int32_t CASE_7 = 7;
const int32_t CASE_8 = 8;
const int32_t CASE_9 = 9;
const int32_t CASE_10 = 10;
const int32_t CASE_11 = 11;
const int32_t CASE_12 = 12;
const int32_t CASE_13 = 13;
const int32_t CASE_14 = 14;
const int32_t CASE_15 = 15;
const int32_t CASE_16 = 16;
const int32_t CASE_17 = 17;
const int32_t CASE_18 = 18;
const int32_t CASE_19 = 19;
const int32_t CASE_20 = 20;
const int32_t CASE_21 = 21;
const int32_t CASE_22 = 22;
const int32_t CASE_23 = 23;
const int32_t CASE_24 = 24;
const int32_t CASE_25 = 25;
const int32_t CASE_26 = 26;
const int32_t CASE_27 = 27;
const int32_t CASE_28 = 28;

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

AudioDataSourceFuzzer::AudioDataSourceFuzzer()
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

AudioDataSourceFuzzer::~AudioDataSourceFuzzer()
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
    return true;
}

bool AudioDataSourceFuzzer::FuzzHasSpeakerStream()
{
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
    return true;
}

bool AudioDataSourceFuzzer::FuzzVoIPStateUpdate()
{
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
    return true;
}

bool AudioDataSourceFuzzer::FuzzHasVoIPStream()
{
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
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetAndGetAppPid()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int32_t appPid = GetData<int32_t>();
    audioDataSource->SetAppPid(appPid);
    
    int32_t retrievedPid = audioDataSource->GetAppPid();
    (void)retrievedPid;
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetAndGetAppName()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    audioDataSource->SetAppName("appName");
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetVideoFirstFramePts()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t pts = GetData<int64_t>();
    audioDataSource->SetVideoFirstFramePts(pts);
    return true;
}

bool AudioDataSourceFuzzer::FuzzSetAudioFirstFramePts()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t pts = GetData<int64_t>();
    audioDataSource->SetAudioFirstFramePts(pts);
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtMixMode()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtMixMode(buffer, length);
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtMicMode()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtMicMode(buffer, length);
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAtInnerMode()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAtInnerMode(buffer, length);
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadAt()
{
    AVScreenCaptureMixMode mode = static_cast<AVScreenCaptureMixMode>(GetData<int32_t>() % 3);
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(mode, screenCaptureServer_.get());
    
    auto buffer = CreateAVBuffer();
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadAt(buffer, length);
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetSize()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t sizeResult = 0;
    audioDataSource->GetSize(sizeResult);
    (void)sizeResult;
    return true;
}

bool AudioDataSourceFuzzer::FuzzMixModeBufferWrite()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    std::shared_ptr<AVMemory> &bufferMem = avBuffer->memory_;
    audioDataSource->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    innerAudioBuffer = nullptr;
    micAudioBuffer = nullptr;
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteInnerAudio()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteInnerAudio(avBuffer, length, innerAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMicAudio()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMicAudio(avBuffer, length, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzWriteMixAudio()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->WriteMixAudio(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzInnerMicAudioSync()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->InnerMicAudioSync(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncMixMode()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncMixMode(avBuffer, length, timeWindow, innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzVideoAudioSyncInnerMode()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    int64_t timeWindow = GetData<int64_t>();
    audioDataSource->VideoAudioSyncInnerMode(avBuffer, length, timeWindow, innerAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzGetFirstAudioTime()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    
    int64_t firstAudioTime = audioDataSource->GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
    (void)firstAudioTime;
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMixCore()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMixCore(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzReadWriteAudioBufferMix()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto avBuffer = CreateAVBuffer();
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    uint32_t length = GetData<uint32_t>() % 1024;
    audioDataSource->ReadWriteAudioBufferMix(avBuffer, length, innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandlePastMicBuffer()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    audioDataSource->HandlePastMicBuffer(micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleSwitchToSpeakerOptimise()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    audioDataSource->HandleSwitchToSpeakerOptimise(innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzHandleBufferTimeStamp()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    auto innerAudioBuffer = CreateAudioBufferInner(GetData<int64_t>());
    auto micAudioBuffer = CreateAudioBufferMic(GetData<int64_t>());
    audioDataSource->HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    return true;
}

bool AudioDataSourceFuzzer::FuzzLostFrameNum()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t timestamp = GetData<int64_t>();
    int32_t lostFrameNum = audioDataSource->LostFrameNum(timestamp);
    (void)lostFrameNum;
    return true;
}

bool AudioDataSourceFuzzer::FuzzFillLostBuffer()
{
    std::shared_ptr<AudioDataSource> audioDataSource =
        std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    
    int64_t lostNum = GetData<int64_t>() % 100;
    int64_t timestamp = GetData<int64_t>() % 1000000;
    uint32_t bufferSize = GetData<uint32_t>() % 1024;
    audioDataSource->FillLostBuffer(lostNum, timestamp, bufferSize);
    return true;
}

bool FuzzAudioDataSourceCaseInner(AudioDataSourceFuzzer *testAudioDataSource, int32_t testCase)
{
    switch (testCase) {
        case CASE_13:
            return testAudioDataSource->FuzzMixModeBufferWrite();
        case CASE_14:
            return testAudioDataSource->FuzzWriteInnerAudio();
        case CASE_15:
            return testAudioDataSource->FuzzWriteMicAudio();
        case CASE_16:
            return testAudioDataSource->FuzzWriteMixAudio();
        case CASE_17:
            return testAudioDataSource->FuzzInnerMicAudioSync();
        case CASE_18:
            return testAudioDataSource->FuzzVideoAudioSyncMixMode();
        case CASE_19:
            return testAudioDataSource->FuzzVideoAudioSyncInnerMode();
        case CASE_20:
            return testAudioDataSource->FuzzGetFirstAudioTime();
        case CASE_21:
            return testAudioDataSource->FuzzReadWriteAudioBufferMixCore();
        case CASE_22:
            return testAudioDataSource->FuzzReadWriteAudioBufferMix();
        case CASE_23:
            return testAudioDataSource->FuzzHandlePastMicBuffer();
        case CASE_24:
            return testAudioDataSource->FuzzHandleSwitchToSpeakerOptimise();
        case CASE_25:
            return testAudioDataSource->FuzzHandleBufferTimeStamp();
        case CASE_26:
            return testAudioDataSource->FuzzLostFrameNum();
        case CASE_27:
            return testAudioDataSource->FuzzFillLostBuffer();
        default:
            return true;
    }
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
    
    int32_t testCase =  GetData<uint32_t>() % CASE_28;
    MEDIA_LOGI("FuzzAudioDataSourceCase testCase %{public}d ", testCase);
    switch (testCase) {
        case CASE_0:
            return testAudioDataSource.FuzzSpeakerStateUpdate();
        case CASE_1:
            return testAudioDataSource.FuzzHasSpeakerStream();
        case CASE_2:
            return testAudioDataSource.FuzzVoIPStateUpdate();
        case CASE_3:
            return testAudioDataSource.FuzzHasVoIPStream();
        case CASE_4:
            return testAudioDataSource.FuzzSetAndGetAppPid();
        case CASE_5:
            return testAudioDataSource.FuzzSetAndGetAppName();
        case CASE_6:
            return testAudioDataSource.FuzzSetVideoFirstFramePts();
        case CASE_7:
            return testAudioDataSource.FuzzSetAudioFirstFramePts();
        case CASE_8:
            return testAudioDataSource.FuzzReadAtMixMode();
        case CASE_9:
            return testAudioDataSource.FuzzReadAtMicMode();
        case CASE_10:
            return testAudioDataSource.FuzzReadAtInnerMode();
        case CASE_11:
            return testAudioDataSource.FuzzReadAt();
        case CASE_12:
            return testAudioDataSource.FuzzGetSize();
        default:
            return FuzzAudioDataSourceCaseInner(&testAudioDataSource, testCase);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    FuzzAudioDataSourceCase(data, size);
    return 0;
}
}
}