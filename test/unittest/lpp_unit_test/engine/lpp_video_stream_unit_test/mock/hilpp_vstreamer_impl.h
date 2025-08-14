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
#ifndef HILPP_VSTREAMER_IMPL_H
#define HILPP_VSTREAMER_IMPL_H
#include "i_lpp_video_streamer.h"
#include "i_lpp_sync_manager.h"
#include "pipeline/pipeline.h"
#include "lpp_video_data_manager.h"
#include "lpp_vdec_adapter.h"
#include "lpp_video_callback_looper.h"
#include "video_decoder_adapter.h"
#include "i_lpp_engine_manager.h"

namespace OHOS {
namespace Media {

class HiLppVideoStreamerImpl : public ILppVideoStreamerEngine,
                               public std::enable_shared_from_this<HiLppVideoStreamerImpl> {
public:
    HiLppVideoStreamerImpl();
    ~HiLppVideoStreamerImpl() override;
    int32_t Init(const std::string &mime) override;
    int32_t SetObs(const std::weak_ptr<ILppVideoStreamerEngineObs> &obs) override;
    int32_t SetParameter(const Format &param) override;
    int32_t Configure(const Format &param) override;
    int32_t SetVideoSurface(sptr<Surface> surface) override;
    int32_t Prepare() override;
    int32_t StartDecode() override;
    int32_t StartRender() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Flush() override;
    int32_t Stop() override;
    int32_t Reset() override;
    int32_t SetPlaybackSpeed(const float playbackSpeed) override;
    int32_t SetSyncAudioStreamer(int streamerId) override;
    int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) override;
    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;
    int32_t SetLppAudioStreamerId(std::string audioStreamerId) override;
    std::string GetStreamerId() override;
    std::shared_ptr<ILppSyncManager> GetLppSyncManager() override;
    int32_t RenderFirstFrame() override;
    void OnEvent(const Event &event);

private:
    void InitLppMode();
    void HandleDataNeededEvent(const Event &event);
    void HandleFirstFrameReadyEvent(const Event &event);
    void HandleRenderStartedEvent(const Event &event);
    void HandleCompleteEvent(const Event &event);
    void HandleResolutionChangeEvent(const Event &event);
    void HandleTargetArrivedEvent(const Event &event);
    int32_t EosPause();
    void HandleErrorEvent(const Event &event);

    bool isLpp_{false};
    std::string streamerId_{};
    int32_t channelId_{};
    int32_t shareBufferFd_{};
    sptr<Surface> surface_{nullptr};
    std::shared_ptr<LppVideoDataManager> dataMgr_{nullptr};
    std::shared_ptr<LppVideoDecoderAdapter> vdec_{nullptr};
    std::shared_ptr<ILppSyncManager> syncMgr_{nullptr};
    std::shared_ptr<LppVideoCallbackLooper> callbackLooper_{nullptr};
    std::string audioStreamerId_{};
    std::weak_ptr<ILppAudioStreamerEngine> audioStreamerEngine_;
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};

    bool isChannelSetDone_ {false};
    bool isPaused_ {false};
    std::mutex pauseMutex_ {};
};
}  // namespace Media
}  // namespace OHOS
#endif