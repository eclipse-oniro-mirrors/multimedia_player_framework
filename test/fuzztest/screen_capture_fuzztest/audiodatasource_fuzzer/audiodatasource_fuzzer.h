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

#ifndef AUDIODATASOURCE_FUZZER
#define AUDIODATASOURCE_FUZZER

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <fuzzer/FuzzedDataProvider.h>
#include "audio_data_source.h"
#include "cache_buffer.h"
#include "screen_capture_server.h"
#include "screen_capture_service_providers.h"
#include "avbuffer.h"
#include "avsharedmemory.h"
#include "media_data_source.h"
#include "audio_capturer_wrapper.h"
#include "audio_info.h"
#define FUZZ_PROJECT_NAME "audiodatasource_fuzzer"

inline std::shared_ptr<OHOS::Media::ScreenCaptureServer> MakeScreenCaptureServerShared()
{
    return std::make_shared<OHOS::Media::ScreenCaptureServer>(OHOS::Media::CreateDefaultProviders());
}

namespace OHOS {
namespace Media {

AudioCaptureSourceType PickAudioSource(FuzzedDataProvider &fdp);
AudioCaptureInfo CreateAudioCaptureInfo(FuzzedDataProvider &fdp);
AudioInfo CreateAudioInfo(FuzzedDataProvider &fdp);
VideoInfo CreateVideoInfo(FuzzedDataProvider &fdp);
CaptureMode PickCaptureMode(FuzzedDataProvider &fdp);
DataType PickDataType(FuzzedDataProvider &fdp);
void SetConfig(AVScreenCaptureConfig &config, FuzzedDataProvider &fdp);

class AudioDataSourceFuzzer {
public:

    bool FuzzAudioRendererStateUpdate();
    bool FuzzGetAudioRendererState();
    bool FuzzAudioRendererStateUpdateVoIP();
    bool FuzzHasVoIPStream();
    bool FuzzSetAndGetAppPid();
    bool FuzzSetVideoFirstFramePts();
    bool FuzzSetAudioFirstFramePts();
    bool FuzzReadAtMixMode();
    bool FuzzReadAtMicMode();
    bool FuzzReadAtInnerMode();
    bool FuzzReadAt(uint32_t bufferSize);
    bool FuzzGetSize();
    bool FuzzMixModeBufferWrite(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzWriteInnerAudio(uint32_t bufferSize);
    bool FuzzWriteMicAudio(uint32_t bufferSize);
    bool FuzzWriteMixAudio(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzInnerMicAudioSync(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzVideoAudioSyncMixMode(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzVideoAudioSyncInnerMode(uint32_t bufferSize);
    bool FuzzGetFirstAudioTime(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzReadWriteAudioBufferMixCore(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzReadWriteAudioBufferMix(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzHandlePastMicBuffer(uint32_t bufferSize);
    bool FuzzHandleSwitchToSpeakerOptimise(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzHandleBufferTimeStamp(uint32_t innerBufferSize, uint32_t micBufferSize);
    bool FuzzLostFrameNum();

private:
    std::shared_ptr<CacheBuffer> CreateCacheBufferInner(int64_t timestamp, uint32_t bufferSize);
    std::shared_ptr<CacheBuffer> CreateCacheBufferMic(int64_t timestamp, uint32_t bufferSize);
    std::shared_ptr<AVBuffer> CreateAVBuffer(uint32_t bufferSize);
    std::shared_ptr<AudioRendererChangeInfo> CreateAudioRendererChangeInfo();
    void Init();
    void Release();

    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_;
    std::vector<uint8_t> AVbuf;
    FuzzedDataProvider *fdp_ = nullptr;
};
bool FuzzAudioDataSourceCase(uint8_t *data, size_t size);
}
}
#endif // AUDIODATASOURCE_FUZZER
