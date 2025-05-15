/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef CACHE_BUFFER_H
#define CACHE_BUFFER_H

#include <deque>
#include "audio_renderer.h"
#include "audio_info.h"
#include "audio_stream_info.h"
#include "audio_errors.h"
#include "isoundpool.h"
#include "media_description.h"
#include "cpp/mutex.h"
#include "media_dfx.h"
#include "thread_pool.h"
#include "audio_system_manager.h"
#include "soundpool_xcollie.h"
#include "stream_id_manager.h"

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

class CacheBuffer :
    public AudioStandard::AudioRendererWriteCallback,
    public AudioStandard::AudioRendererFirstFrameWritingCallback,
    public AudioStandard::AudioRendererCallback,
    public std::enable_shared_from_this<CacheBuffer> {
public:
    CacheBuffer(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID,
        std::shared_ptr<ThreadPool> cacheBufferStopThreadPool);
    ~CacheBuffer();
    void SetSoundData(const std::shared_ptr<AudioBufferEntry> &cacheData, const size_t &cacheDataTotalSize);
    void SetManager(std::weak_ptr<OHOS::Media::StreamIDManager> streamIDManager);
    void OnWriteData(size_t length) override;
    void OnFirstFrameWriting(uint64_t latency) override;
    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnStateChange(const AudioStandard::RendererState state,
        const AudioStandard::StateChangeCmdType cmdType) override;
    int32_t PreparePlay(const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams);
    void GetAvailableAudioRenderer(const AudioStandard::AudioRendererInfo &audioRendererInfo,
        const PlayParams &playParams);
    int32_t DoPlay(const int32_t streamID);
    int32_t Release();
    int32_t Stop(const int32_t streamID);
    int32_t SetVolume(const int32_t streamID, const float leftVolume, const float rightVolume);
    int32_t SetRate(const int32_t streamID, const AudioStandard::AudioRendererRate renderRate);
    int32_t SetPriority(const int32_t streamID, const int32_t priority);
    int32_t SetLoop(const int32_t streamID, const int32_t loop);
    int32_t SetParallelPlayFlag(const int32_t streamID, const bool parallelPlayFlag);
    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetCacheBufferCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);
    void SetSourceDuration(int64_t durationMs);

    bool IsRunning() const
    {
        return isRunning_.load();
    }
    int32_t GetSoundID() const
    {
        return soundID_;
    }
    int32_t GetStreamID() const
    {
        return streamID_;
    }
    int32_t GetPriority() const
    {
        return priority_;
    }

private:
    static constexpr int32_t NORMAL_PLAY_RENDERER_FLAGS = 0;
    static constexpr int32_t LOW_LATENCY_PLAY_RENDERER_FLAGS = 1;

    std::unique_ptr<AudioStandard::AudioRenderer> CreateAudioRenderer(
        const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams);
    void PrepareAudioRenderer(std::unique_ptr<AudioStandard::AudioRenderer> &audioRenderer);
    void DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
        const AudioStandard::AudioRendererInfo &audioRendererInfo);
    void DealPlayParamsBeforePlay(const PlayParams &playParams);
    static AudioStandard::AudioRendererRate CheckAndAlignRendererRate(const int32_t rate);
    void DealWriteData(size_t length);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    int32_t PreparePlayInner(const AudioStandard::AudioRendererInfo &audioRendererInfo,
        const PlayParams &playParams);
    int32_t GetGlobalId(int32_t soundID);
    void DelGlobalId(int32_t globalId);
    void SetGlobalId(int32_t soundID, int32_t globalId);

    Format trackFormat_;
    std::deque<std::shared_ptr<AudioBufferEntry>> cacheData_;
    std::shared_ptr<AudioBufferEntry> fullCacheData_;
    size_t cacheDataTotalSize_ = 0;
    int32_t soundID_ = 0;
    int32_t streamID_ = 0;
    AudioStandard::AudioSampleFormat sampleFormat_ = AudioStandard::AudioSampleFormat::INVALID_WIDTH;
    PlayParams playParameters_;
    AudioStandard::AudioRendererInfo audioRendererInfo_;

    // use for save audiobuffer
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer_;
    std::atomic<bool> isRunning_ = false;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolCallback> cacheBufferCallback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;
    ffrt::mutex cacheBufferLock_;
    std::weak_ptr<ThreadPool> cacheBufferStopThreadPool_;
    std::weak_ptr<OHOS::Media::StreamIDManager> manager_;

    int32_t loop_ = 0;
    int32_t priority_ = 0;
    int32_t rendererFlags_ = NORMAL_PLAY_RENDERER_FLAGS;

    size_t cacheDataFrameIndex_ = 0;
    int32_t havePlayedCount_ = 0;
    int64_t sourceDurationMs_{};
};
} // namespace Media
} // namespace OHOS
#endif // CACHE_BUFFER_H
