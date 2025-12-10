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
#ifndef STREAM_H
#define STREAM_H

#include <deque>

#include "audio_errors.h"
#include "audio_info.h"
#include "audio_renderer.h"
#include "audio_stream.h"
#include "audio_stream_info.h"
#include "audio_system_manager.h"
#include "cpp/mutex.h"
#include "isoundpool.h"
#include "media_description.h"
#include "media_dfx.h"
#include "parallel_stream_manager.h"
#include "soundpool_xcollie.h"
#include "thread_pool.h"

namespace OHOS {
namespace Media {
using namespace MediaAVCodec;
struct AudioBufferEntry;
class ParallelStreamManager;

class Stream :
    public AudioStandard::AudioRendererWriteCallback,
    public AudioStandard::AudioRendererFirstFrameWritingCallback,
    public AudioStandard::AudioRendererCallback,
    public std::enable_shared_from_this<Stream> {
public:
    Stream(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID,
        std::shared_ptr<ThreadPool> streamStopThreadPool);
    ~Stream();
    void SetSoundData(const std::shared_ptr<AudioBufferEntry> &cacheData, const size_t &cacheDataTotalSize);
    void SetPlayParamAndRendererInfo(const PlayParams &playParameters,
        const AudioStandard::AudioRendererInfo &audioRenderInfo);
    void SetManager(std::weak_ptr<OHOS::Media::ParallelStreamManager> parallelStreamManager);
    void PreparePlay();
    int32_t DoPlay();
    int32_t Stop();
    void OnWriteData(size_t length) override;
    void OnFirstFrameWriting(uint64_t latency) override;
    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnStateChange(const AudioStandard::RendererState state,
        const AudioStandard::StateChangeCmdType cmdType) override;
    int32_t SetVolume(const float leftVolume, const float rightVolume);
    int32_t SetRate(const AudioStandard::AudioRendererRate renderRate);
    int32_t SetPriority(const int32_t priority);
    int32_t SetLoop(const int32_t loop);
    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetStreamCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);
    int32_t GetSoundID();
    int32_t GetStreamID();
    int32_t GetPriority();

private:
    std::unique_ptr<AudioStandard::AudioRenderer> CreateAudioRenderer(
        const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams);
    void DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
        const AudioStandard::AudioRendererInfo &audioRendererInfo);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    void PrepareAudioRenderer(std::unique_ptr<AudioStandard::AudioRenderer> &audioRenderer);
    void DealPlayParamsBeforePlay(const PlayParams &playParams);
    static AudioStandard::AudioRendererRate CheckAndAlignRendererRate(const int32_t rate);
    void DealWriteData(size_t length);
    void AddStopTask();
    int32_t GetGlobalId(int32_t soundID);
    void DelGlobalId(int32_t globalId);
    void SetGlobalId(int32_t soundID, int32_t globalId);

    Format trackFormat_;
    int32_t soundID_ = 0;
    int32_t streamID_ = 0;
    PlayParams playParameters_;
    AudioStandard::AudioRendererInfo audioRendererInfo_;
    size_t cacheDataTotalSize_ = 0;
    std::shared_ptr<AudioBufferEntry> fullCacheData_;

    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer_;
    std::atomic<bool> isRunning_ = false;
    std::atomic<bool> startStopFlag_ = false;
    AudioStandard::AudioSampleFormat sampleFormat_ = AudioStandard::AudioSampleFormat::INVALID_WIDTH;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;
    std::shared_ptr<ISoundPoolCallback> streamCallback_ = nullptr;
    ffrt::mutex streamLock_;
    std::weak_ptr<ThreadPool> streamStopThreadPool_;
    std::weak_ptr<OHOS::Media::ParallelStreamManager> manager_;

    int32_t loop_ = 0;
    int32_t priority_ = 0;
    int32_t rendererFlags_ = 0;
    size_t cacheDataFrameIndex_ = 0;
    int32_t havePlayedCount_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // STREAM_H
