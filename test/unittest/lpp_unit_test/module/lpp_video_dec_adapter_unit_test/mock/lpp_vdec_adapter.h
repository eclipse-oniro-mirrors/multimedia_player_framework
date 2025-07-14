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
#ifndef LPP_VDEC_ADAPTER_H
#define LPP_VDEC_ADAPTER_H

#include <string>
#include <deque>

#include "refbase.h"
#include "pipeline/pipeline.h"
#include "meta/format.h"
#include "video_decoder_adapter.h"
#include "lpp_video_data_manager.h"

#include "i_lpp_video_streamer.h"
#include "i_lpp_sync_manager.h"
#include "lpp_vdec_adapter.h"
#include "buffer/avbuffer_queue.h"
#include "avcodec_errors.h"

namespace OHOS {
namespace Media {
class LppVideoDecoderAdapter : public std::enable_shared_from_this<LppVideoDecoderAdapter> {
public:
    explicit LppVideoDecoderAdapter(const std::string &streamerId, bool isLpp);
    virtual ~LppVideoDecoderAdapter();
    virtual int32_t Init(const std::string &mime, bool &switchToCommon);
    int32_t Configure(const Format &param);
    int32_t SetVideoSurface(sptr<Surface> surface);
    int32_t Prepare();
    int32_t StartDecode();
    int32_t StartRender();
    int32_t Pause();
    int32_t Resume();
    int32_t Flush();
    int32_t Stop();
    int32_t Reset();
    int32_t SetParameter(const Format &param);
    int32_t SetCallback(const std::shared_ptr<MediaAVCodec::MediaCodecCallback> &callback);
    int32_t GetChannelId(int32_t &channelId);
    int32_t RenderFirstFrame();
    int32_t Release();

    void SetChannelIdDone();
    sptr<Media::AVBufferQueueProducer> GetInputBufferQueue();
    void OnQueueBufferAvailable();
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void OnOutputBufferBinded(std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap);
    void OnOutputBufferUnbinded();
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void OnOutputFormatChanged(const MediaAVCodec::Format &format);
    void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver);
    void SetSyncManager(std::shared_ptr<ILppSyncManager> syncMgr);
    void SetPlaybackSpeed(float speed);
    int32_t SetTargetPts(int64_t targetPts);

private:
    int32_t PrepareBufferQueue();
    void HandleQueueBufferAvailable();
    void ScheduleRenderFrameJob(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    bool HandleEosFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    bool HandleCommonFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void ProcessCommonFrame(int64_t renderTimeNs);
    bool HandleLppFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void ProcessLppFrame();
    void NotifyFirstFrameDecoded();
    bool PopHeadFrame(uint32_t &idx, int64_t renderTimeNs, bool cyclic);
    int64_t GetSysTimeNs();
    void CalcAnchorDiffTimeNs(int64_t pts, int64_t &diffTimeNs, bool &isCalclated);
    void CalcPreFrameDiffTimeNs(int64_t pts, int64_t &diffTimeNs, bool &isCalclated);
    void FlushTask();
    int64_t GeneratedJobIdx();
    bool IsJobFlushed(int64_t jobIdx);
    void DumpBufferIfNeeded(const std::string &fileName, const std::shared_ptr<AVBuffer>& buffer);

    std::string streamerId_{};
    bool isLppEnabled_ {true};
    std::atomic<bool> setChannelIdDone_ {false};
    std::weak_ptr<ILppSyncManager> syncMgr_;
    std::shared_ptr<MediaAVCodec::AVCodecVideoDecoder> videoDecoder_ {nullptr};
    std::shared_ptr<Media::AVBufferQueue> inputBufferQueue_ {nullptr};
    sptr<Media::AVBufferQueueConsumer> inputBufferQueueConsumer_;
    std::unique_ptr<OHOS::Media::Task> decodertask_ {nullptr};
    std::mutex jobIdxMutex_ {};
    int64_t jobIdx_ {0};
    int64_t jobIdxBase_ {0};
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};

    std::mutex inputMutex_ {};
    std::mutex outputMutex_ {};
    std::vector<std::shared_ptr<AVBuffer>> bufferVector_;
    std::deque<std::pair<int, std::shared_ptr<AVBuffer>>> outputBuffers_;
    bool firstFrameDecoded_ {false};
    bool firstFrameRenderred_ {false};
    bool renderStarted_ {false};

    std::atomic<int64_t> lastRenderTimeNs_ {0};
    std::atomic<int64_t> lastPts_ {0};

    std::atomic<bool> speed_ {1.0f};
    bool dumpBufferNeeded_ {false};
    std::string dumpFileNameOutput_ {};

    int64_t initTargetPts_ {-1};
    bool firstStarted_ {false};
};

}  // namespace Media
}  // namespace OHOS
#endif
