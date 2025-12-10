
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
#ifndef STREAM_ID_MANAGER_H
#define STREAM_ID_MANAGER_H

#include <atomic>
#include <thread>

#include "cpp/mutex.h"
#include "isoundpool.h"
#include "media_dfx.h"
#include "audio_stream.h"
#include "sound_parser.h"
#include "thread_pool.h"

namespace OHOS {
namespace Media {
class CacheBuffer;
class AudioStream;

class StreamIDManager : public std::enable_shared_from_this<StreamIDManager> {
public:
    StreamIDManager(int32_t maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo,
        InterruptMode interruptMode = InterruptMode::SAME_SOUND_INTERRUPT);
    ~StreamIDManager();

    int32_t CreateAudioStream(int32_t soundID, int32_t &streamID,
        const std::shared_ptr<OHOS::Media::SoundParser> &soundParser);

    int32_t InitThreadPool();
    int32_t PlayWithSameSoundInterrupt(const std::shared_ptr<OHOS::Media::SoundParser> &soundParser,
        const PlayParams &playParameters);
    int32_t PlayWithNoInterrupt(const std::shared_ptr<OHOS::Media::SoundParser> &soundParser,
        const PlayParams &playParameters);
        
    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);

    int32_t ReorderStream(int32_t streamID, int32_t priority);
        
    int32_t GetStreamIDBySoundIDWithLock(int32_t soundID);
    std::shared_ptr<AudioStream> GetStreamByStreamIDWithLock(int32_t streamID);
    int32_t GetAvailableStreamIDBySoundID(int32_t soundID);

    void RemoveInvalidStreamsInInterruptMode();
    void RemoveInvalidStreamsInNoInterruptMode();
    void RemoveStreamByStreamIDInInterruptMode(int32_t soundID, int32_t streamID);
    void RemoveStreamByStreamIDInNoInterruptMode(int32_t soundID);
    int32_t ClearStreamIDInDeque(int32_t streamID, int32_t soundID);
    void PrintSoundID2MultiStreams();
    void PrintSoundID2Stream();
    void PrintPlayingStreams();

private:
    class AudioStreamCallBack : public ISoundPoolCallback {
    public:
        explicit AudioStreamCallBack(const std::weak_ptr<OHOS::Media::StreamIDManager> &streamIDManager)
            : streamIDManagerInner_(streamIDManager) {}
        virtual ~AudioStreamCallBack() = default;
        void OnLoadCompleted(int32_t soundID);
        void OnPlayFinished(int32_t streamID);
        void OnError(int32_t errorCode);

    private:
        std::weak_ptr<OHOS::Media::StreamIDManager> streamIDManagerInner_;
    };
    // audio render max concurrency count.
    static constexpr int32_t MAX_PLAY_STREAMS_NUMBER = 32;
    static constexpr int32_t MIN_PLAY_STREAMS_NUMBER = 1;
    static constexpr int32_t CACHE_BUFFER_THREAD_NUMBER = 1;
    static constexpr int32_t errorStreamId = -1;

    struct StreamIDAndPlayParamsInfo {
        int32_t streamID;
        PlayParams playParameters;
    };

    int32_t SetPlayWithSameSoundInterrupt(int32_t soundID, int32_t streamID, const PlayParams &playParameters);
    int32_t SetPlayWithNoInterrupt(int32_t soundID, int32_t streamID, const PlayParams &playParameters);
    int32_t AddPlayTask(int32_t streamID);
    int32_t AddStopTask(const std::shared_ptr<AudioStream> &stream);
    int32_t DoPlay(int32_t streamID);

    void OnPlayFinished(int32_t streamID);
    void QueueAndSortPlayingStreamID(int32_t freshStreamID);
    void QueueAndSortWillPlayStreamID(const StreamIDAndPlayParamsInfo &streamIDAndPlayParamsInfo);

    int32_t GetStreamIDBySoundID(int32_t soundID);
    std::shared_ptr<AudioStream> GetStreamByStreamID(int32_t streamID);

    ffrt::mutex streamIDManagerLock_;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;
    std::shared_ptr<ISoundPoolCallback> audioStreamCallback_ = nullptr;

    std::unordered_map<int32_t, std::shared_ptr<AudioStream>> soundID2Stream_;
    std::unordered_map<int32_t, std::list<std::shared_ptr<AudioStream>>> soundID2MultiStreams_;

    int32_t nextStreamID_ = 0;
    AudioStandard::AudioRendererInfo audioRendererInfo_;
    int32_t maxStreams_ = MIN_PLAY_STREAMS_NUMBER;

    std::atomic<bool> isStreamPlayingThreadPoolStarted_ = false;
    std::unique_ptr<ThreadPool> streamPlayingThreadPool_ = nullptr;
    std::atomic<bool> isStreamStopThreadPoolStarted_ = false;
    std::shared_ptr<ThreadPool> streamStopThreadPool_ = nullptr;

    std::deque<int32_t> playingStreamIDs_;
    std::deque<StreamIDAndPlayParamsInfo> willPlayStreamInfos_;
    InterruptMode interruptMode_ = InterruptMode::SAME_SOUND_INTERRUPT;
    std::atomic<int32_t> currentStreamsNum_;
};
} // namespace Media
} // namespace OHOS
#endif // STREAM_ID_MANAGER_H
