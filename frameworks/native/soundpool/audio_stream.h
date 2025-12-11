/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef AUDIO_STREAM_H
#define AUDIO_STREAM_H

#include <deque>

#include "audio_info.h"
#include "audio_renderer.h"
#include "audio_shared_memory.h"
#include "audio_stream_info.h"
#include "audio_errors.h"
#include "audio_system_manager.h"
#include "cpp/mutex.h"
#include "isoundpool.h"
#include "media_description.h"
#include "media_dfx.h"
#include "soundpool_xcollie.h"
#include "stream_id_manager.h"
#include "thread_pool.h"

namespace OHOS {
namespace Media {
using namespace MediaAVCodec;
class StreamIDManager;

struct AudioBufferEntry {
    AudioBufferEntry(uint8_t *buf, int32_t length) : buffer(std::move(buf)), size(length) {}
    ~AudioBufferEntry()
    {
        if (buffer != nullptr) {
            delete[] buffer;
            buffer = nullptr;
        }
    }
    uint8_t *buffer;
    int32_t size;
};

enum class StreamState : int32_t {
    PREPARED = 1,
    PLAYING = 2,
    PAUSED = 3,
    STOPPED = 4,
    RELEASED = 5,
};

class AudioStream :
    public AudioStandard::AudioRendererFirstFrameWritingCallback,
    public AudioStandard::AudioRendererCallback,
    public AudioStandard::StaticBufferEventCallback,
    public std::enable_shared_from_this<AudioStream> {
public:
    AudioStream(const Format &trackFormat, int32_t &soundID, int32_t &streamID,
        std::shared_ptr<ThreadPool> streamStopThreadPool);
    ~AudioStream();
    void SetPcmBuffer(const std::shared_ptr<AudioBufferEntry> &pcmBuffer, size_t pcmBufferSize);
    void SetManager(std::weak_ptr<OHOS::Media::StreamIDManager> streamIDManager);
    void ConfigurePlayParameters(const AudioStandard::AudioRendererInfo &audioRendererInfo,
        const PlayParams &playParams);
    void ConfigurePlayParametersWithoutLock(const AudioStandard::AudioRendererInfo &audioRendererInfo,
        const PlayParams &playParams);
    int32_t DoPlay();
    int32_t Stop();
    int32_t Release();
    
    void OnFirstFrameWriting(uint64_t latency) override;
    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnStateChange(const AudioStandard::RendererState state,
        const AudioStandard::StateChangeCmdType cmdType) override;
    void OnStaticBufferEvent(AudioStandard::StaticBufferEventId eventId) override;

    int32_t SetVolume(float leftVolume, float rightVolume);
    int32_t SetRate(const AudioStandard::AudioRendererRate &renderRate);
    int32_t SetPriority(int32_t priority);
    int32_t SetPriorityWithoutLock(int32_t priority);
    int32_t SetLoop(int32_t loop);
    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetStreamCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);
    void SetSourceDuration(int64_t durationMs);
    void SetStreamState(StreamState state);
    StreamState GetStreamState();
    int32_t GetSoundID();
    int32_t GetStreamID();
    int32_t GetPriority();
    
private:
    std::shared_ptr<AudioStandard::AudioRenderer> CreateAudioRenderer(
        const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams);
    void DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
        const AudioStandard::AudioRendererInfo &audioRendererInfo);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    void PrepareAudioRenderer(std::shared_ptr<AudioStandard::AudioRenderer> &audioRenderer);
    void GetAvailableAudioRenderer(const AudioStandard::AudioRendererInfo &audioRendererInfo,
        const PlayParams &playParams);
    void DealPlayParamsBeforePlay(const PlayParams &playParams);

    static AudioStandard::AudioRendererRate CheckAndAlignRendererRate(const int32_t rate);
    int32_t PreparePlayInner(const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams);
    int32_t HandleRendererNotStart();

    Format trackFormat_;
    int32_t soundID_ = 0;
    int32_t streamID_ = 0;
    PlayParams playParameters_;
    size_t pcmBufferSize_ = 0;
    std::shared_ptr<AudioBufferEntry> pcmBuffer_ = nullptr;
    std::shared_ptr<AudioStandard::AudioRenderer> audioRenderer_ = nullptr;
    AudioStandard::AudioRendererInfo audioRendererInfo_;
    AudioStandard::AudioSampleFormat sampleFormat_ = AudioStandard::AudioSampleFormat::INVALID_WIDTH;
    AudioStandard::AudioChannel audioChannel_ = AudioStandard::AudioChannel::MONO;

    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolCallback> streamCallback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;

    ffrt::mutex streamLock_;
    std::weak_ptr<ThreadPool> streamStopThreadPool_;
    std::weak_ptr<OHOS::Media::StreamIDManager> manager_;

    int32_t loop_ = 0;
    int32_t priority_ = 0;
    int32_t rendererFlags_ = 0;

    size_t pcmBufferFrameIndex_ = 0;
    int64_t sourceDurationMs_ = 0;
    std::atomic<StreamState> streamState_;
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_STREAM_H
