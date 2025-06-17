
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
#include "cache_buffer.h"
#include "isoundpool.h"
#include "sound_parser.h"
#include "thread_pool.h"
#include "cpp/mutex.h"
#include "media_dfx.h"

namespace OHOS {
namespace Media {
class CacheBuffer;
class SoundParser;

class StreamIDManager : public std::enable_shared_from_this<StreamIDManager> {
public:
    StreamIDManager(int32_t maxStreams, AudioStandard::AudioRendererInfo audioRenderInfo);
    ~StreamIDManager();

    int32_t GetGlobalId(int32_t soundId);
    void DelGlobalId(int32_t globalId);
    void SetGlobalId(int32_t soundId, int32_t globalId);
    void DelSoundId(int32_t soundId);
    int32_t InitThreadPool();
    int32_t Play(std::shared_ptr<OHOS::Media::SoundParser> &soundParser, PlayParams &playParameters);

    std::shared_ptr<CacheBuffer> FindCacheBufferLock(const int32_t streamID);

    int32_t GetStreamIDBySoundID(const int32_t soundID);

    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);

    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);

    int32_t ReorderStream(int32_t streamID, int32_t priority);

    int32_t ClearStreamIDInDeque(int32_t streamID, int32_t soundID);

private:
    class CacheBufferCallBack : public ISoundPoolCallback {
    public:
        explicit CacheBufferCallBack(const std::weak_ptr<OHOS::Media::StreamIDManager> &streamIDManager)
            : streamIDManagerInner_(streamIDManager) {}
        virtual ~CacheBufferCallBack() = default;
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

    int32_t SetPlay(const int32_t soundID, const int32_t streamID, const PlayParams playParameters);
    int32_t AddPlayTask(const int32_t streamID, const PlayParams playParameters);
    int32_t DoPlay(const int32_t streamID);
    int32_t GetFreshStreamID(const int32_t soundID, PlayParams playParameters);
    void OnPlayFinished();
    void QueueAndSortPlayingStreamID(int32_t streamID);
    void QueueAndSortWillPlayStreamID(StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo);
    std::shared_ptr<CacheBuffer> FindCacheBuffer(const int32_t streamID);

    // pair<int32_t, int32_t> is mapping between SoundId and GlobalId
    std::vector<std::pair<int32_t, int32_t>> globalIdVector_;
    std::mutex globalIdMutex_;
    std::shared_ptr<ISoundPoolCallback> cacheBufferCallback_ = nullptr;
    AudioStandard::AudioRendererInfo audioRendererInfo_;
    ffrt::mutex streamIDManagerLock_;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;
    std::map<int32_t, std::shared_ptr<CacheBuffer>> cacheBuffers_;
    int32_t nextStreamID_ = 0;
    int32_t maxStreams_ = MIN_PLAY_STREAMS_NUMBER;

    std::atomic<bool> isStreamPlayingThreadPoolStarted_ = false;
    std::unique_ptr<ThreadPool> streamPlayingThreadPool_;
    std::atomic<bool> isCacheBufferStopThreadPoolStarted_ = false;
    std::shared_ptr<ThreadPool> cacheBufferStopThreadPool_;

    std::deque<int32_t> streamIDs_;
    std::deque<StreamIDAndPlayParamsInfo> willPlayStreamInfos_;
    std::deque<int32_t> playingStreamIDs_;
};
} // namespace Media
} // namespace OHOS
#endif // STREAM_ID_MANAGER_H
