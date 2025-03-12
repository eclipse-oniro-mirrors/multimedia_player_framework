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
#ifndef PARALLEL_STREAM_MANAGER_H
#define PARALLEL_STREAM_MANAGER_H

#include <atomic>
#include <thread>
#include <vector>
#include "cache_buffer.h"
#include "stream.h"
#include "isoundpool.h"
#include "sound_parser.h"
#include "thread_pool.h"
#include "cpp/mutex.h"
#include "media_dfx.h"

namespace OHOS {
namespace Media {
class ParallelStreamManager : public std::enable_shared_from_this<ParallelStreamManager> {
public:
    ParallelStreamManager(int32_t maxStreams, AudioStandard::AudioRendererInfo audioRenderInfo);
    ~ParallelStreamManager();

    static int32_t GetGlobeId(int32_t soundId);
    static void DelGlobeId(int32_t globeId);
    static void SetGlobeId(int32_t soundId, int32_t globeId);
    int32_t InitThreadPool();
    int32_t Play(std::shared_ptr<SoundParser> soundParser, PlayParams playParameters);
    int32_t UnloadStream(int32_t soundId);
    void ReorderStream();
    std::shared_ptr<Stream> FindStreamLock(const int32_t streamId);
    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback);

private:
    class StreamCallBack : public ISoundPoolCallback {
    public:
        explicit StreamCallBack(const std::weak_ptr<ParallelStreamManager> parallelStreamManager)
            : parallelStreamManagerInner_(parallelStreamManager) {}
        virtual ~StreamCallBack() = default;
        void OnLoadCompleted(int32_t soundID);
        void OnPlayFinished(int32_t streamID);
        void OnError(int32_t errorCode);

    private:
        std::weak_ptr<ParallelStreamManager> parallelStreamManagerInner_;
    };

    int32_t PreparePlay(std::shared_ptr<Stream> stream, bool waitQueueFlag);
    int32_t DoPlay(int32_t streamId);
    void DealQueueAndAddTask(int32_t streamId, std::shared_ptr<Stream> stream, bool waitQueueFlag);
    void AddToPlayingDeque(int32_t streamId, std::shared_ptr<Stream> stream);
    void AddToWaitingDeque(int32_t streamId, std::shared_ptr<Stream> stream);
    void RemoveFromWaitingDeque(int32_t streamId);
    void OnPlayFinished(int32_t streamId);
    std::shared_ptr<Stream> FindStream(const int32_t streamId);

    static std::vector<std::pair<int32_t, int32_t>> globeIdVector_;
    static std::mutex globeIdMutex_;
    AudioStandard::AudioRendererInfo audioRendererInfo_;
    int32_t maxStreams_ = 1;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback_ = nullptr;
    std::deque<std::pair<int32_t, std::shared_ptr<Stream>>> playingStream_;
    std::deque<std::pair<int32_t, std::shared_ptr<Stream>>> waitingStream_;
    int32_t nextStreamId_ = 0;
    ffrt::mutex parallelStreamManagerLock_;
    std::shared_ptr<ThreadPool> streamPlayThreadPool_;
    std::shared_ptr<ThreadPool> streamStopThreadPool_;
    std::shared_ptr<ThreadPool> waitPlayThreadPool_;
};
} // namespace Media
} // namespace OHOS
#endif // PARALLEL_STREAM_MANAGER_H
