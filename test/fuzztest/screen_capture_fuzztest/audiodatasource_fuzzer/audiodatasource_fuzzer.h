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
#include "audio_data_source.h"
#include "screen_capture_server.h"
#include "avbuffer.h"
#include "avsharedmemory.h"
#include "media_data_source.h"
#include "audio_capturer_wrapper.h"
#include "audio_info.h"
#define FUZZ_PROJECT_NAME "audiodatasource_fuzzer"

namespace OHOS {
namespace Media {
class AudioDataSourceFuzzer {
public:
    AudioDataSourceFuzzer();
    ~AudioDataSourceFuzzer();

    bool FuzzSpeakerStateUpdate();
    bool FuzzHasSpeakerStream();
    bool FuzzVoIPStateUpdate();
    bool FuzzHasVoIPStream();
    bool FuzzSetAndGetAppPid();
    bool FuzzSetAndGetAppName();
    bool FuzzSetVideoFirstFramePts();
    bool FuzzSetAudioFirstFramePts();
    bool FuzzReadAtMixMode();
    bool FuzzReadAtMicMode();
    bool FuzzReadAtInnerMode();
    bool FuzzReadAt();
    bool FuzzGetSize();
    bool FuzzMixModeBufferWrite();
    bool FuzzWriteInnerAudio();
    bool FuzzWriteMicAudio();
    bool FuzzWriteMixAudio();
    bool FuzzInnerMicAudioSync();
    bool FuzzVideoAudioSyncMixMode();
    bool FuzzVideoAudioSyncInnerMode();
    bool FuzzGetFirstAudioTime();
    bool FuzzReadWriteAudioBufferMixCore();
    bool FuzzReadWriteAudioBufferMix();
    bool FuzzHandlePastMicBuffer();
    bool FuzzHandleSwitchToSpeakerOptimise();
    bool FuzzHandleBufferTimeStamp();
    bool FuzzLostFrameNum();
    bool FuzzFillLostBuffer();

private:
    std::shared_ptr<AudioBuffer> CreateAudioBufferInner(int64_t timestamp);
    std::shared_ptr<AudioBuffer> CreateAudioBufferMic(int64_t timestamp);
    std::shared_ptr<AVBuffer> CreateAVBuffer();
    std::shared_ptr<AudioRendererChangeInfo> CreateAudioRendererChangeInfo();

    std::shared_ptr<ScreenCaptureServer> screenCaptureServer_ = nullptr;
    int32_t datasize = 2048;
    std::vector<uint8_t> AVbuf;
};
bool FuzzAudioDataSourceCase(uint8_t *data, size_t size);
bool FuzzAudioDataSourceCaseInner(AudioDataSourceFuzzer *testAudioDataSource, int32_t testCase);
}
}
#endif // AUDIODATASOURCE_FUZZER
