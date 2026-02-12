/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#ifndef DRAGGING_PLAYER_AGENT_H
#define DRAGGING_PLAYER_AGENT_H

#include <atomic>
#include "dragging_player.h"
#include "common/status.h"
#include "osal/task/task.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace Pipeline;

enum class DraggingMode : uint8_t {
    DRAGGING_NONE = 0,
    DRAGGING_CLOSEST = 1,
    DRAGGING_CONTINUOUS = 2,
};

class DraggingDelegator : public std::enable_shared_from_this<DraggingDelegator> {
public:
    DraggingDelegator(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId) : pipeline_(pipeline), demuxer_(demuxer), decoder_(decoder), playerId_(playerId) {};
    virtual ~DraggingDelegator() {};
    virtual Status Init() = 0;
    virtual void UpdateSeekPos(int64_t seekMs) = 0;
    virtual void Release() = 0;

    virtual void ConsumeVideoFrame(const shared_ptr<AVBuffer> avBuffer, uint32_t bufferIndex)
    {
        if (decoder_ != nullptr) {
            return decoder_->ConsumeVideoFrame(bufferIndex, true, -1);
        }
    }

    virtual bool IsVideoStreamDiscardable(const shared_ptr<AVBuffer> avBuffer)
    {
        (void)avBuffer;
        return false;
    }

    virtual void SetInterruptState() {};

protected:
    shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline_ {nullptr};
    shared_ptr<DemuxerFilter> demuxer_ {nullptr};
    shared_ptr<DecoderSurfaceFilter> decoder_ {nullptr};
    string playerId_ {};
};

class DraggingPlayerAgent : public enable_shared_from_this<DraggingPlayerAgent> {
public:
    static shared_ptr<DraggingPlayerAgent> Create(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    static bool IsDraggingSupported(const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder);

    using CreateFunc = DraggingPlayer *(*)();
    using DestroyFunc = void (*)(DraggingPlayer *);
    using CheckSupportedFunc = bool (*) (DemuxerFilter *, DecoderSurfaceFilter *);
    static CreateFunc createFunc_;
    static DestroyFunc destroyFunc_;
    static CheckSupportedFunc checkSupportedFunc_;
    DraggingPlayerAgent() {};
    DraggingPlayerAgent(const DraggingPlayerAgent &) = delete;
    DraggingPlayerAgent(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    DraggingPlayerAgent operator=(const DraggingPlayerAgent &) = delete;
    ~DraggingPlayerAgent();
    Status Init();
    void UpdateSeekPos(int64_t seekMs);
    void Release();
    mutex draggingMutex_ {};
    DraggingMode GetDraggingMode();
    void SetInterruptState();
 
private:
    static bool loaded_;
    static bool LoadSymbol();
    static void *LoadLibrary();
    static bool CheckSymbol(void *handler);
    static mutex mtx_;
    static void *handler_;
    shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline_ {nullptr};
    shared_ptr<DemuxerFilter> demuxer_ {nullptr};
    shared_ptr<DecoderSurfaceFilter> decoder_ {nullptr};
    string playerId_ {};
    shared_ptr<DraggingDelegator> delegator_ {nullptr};
    bool isReleased_ {false};
    DraggingMode draggingMode_ {DraggingMode::DRAGGING_CLOSEST};
};

class SeekContinuousDelegator : public DraggingDelegator {
public:
    static shared_ptr<SeekContinuousDelegator> Create(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    explicit SeekContinuousDelegator(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    ~SeekContinuousDelegator() override;
    Status Init() override;
    void UpdateSeekPos(int64_t seekMs) override;
    void Release() override;

    void ConsumeVideoFrame(const shared_ptr<AVBuffer> avBuffer, uint32_t bufferIndex) override;
    bool IsVideoStreamDiscardable(const shared_ptr<AVBuffer> avBuffer) override;
    void SetInterruptState() override;

private:
    void StopDragging(int64_t seekCnt);

    DraggingPlayer *draggingPlayer_ {nullptr};
    shared_ptr<VideoStreamReadyCallback> videoStreamReadyCb_ {nullptr};
    shared_ptr<VideoFrameReadyCallback> videoFrameReadyCb_ {nullptr};
    bool isReleased_ {false};
    unique_ptr<OHOS::Media::Task> monitorTask_;
    atomic<int64_t> seekCnt_ {0};
    mutex draggingMutex_ {};
    string threadName_ {};
};

class SeekClosestDelegator : public DraggingDelegator {
public:
    static shared_ptr<SeekClosestDelegator> Create(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    explicit SeekClosestDelegator(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId);
    ~SeekClosestDelegator() override;
    Status Init() override;
    void UpdateSeekPos(int64_t seekMs) override;
    void Release() override;

private:
    void SeekJob();
    void DoSeek(int64_t seekTimeMs);
    bool isReleased_ {false};
    string threadName_ {};
    unique_ptr<Task> seekTask_ {nullptr};
    mutex seekClosestMutex_ {};
    mutex queueMutex_ {};
    vector<int64_t> seekTimeMsQue_ {};
    int64_t curSeekTimeMs_ {-1};
};

class DraggingDelegatorFactory {
public:
    static shared_ptr<DraggingDelegator> CreateDelegator(
        const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
        const shared_ptr<DemuxerFilter> demuxer,
        const shared_ptr<DecoderSurfaceFilter> decoder,
        const string &playerId,
        DraggingMode &draggingMode);
};
} // namespace Media
} // namespace OHOS
#endif // DRAGGING_PLAYER_AGENT_H