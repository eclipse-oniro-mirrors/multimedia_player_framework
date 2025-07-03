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

#ifndef HILPP_ASTREAMER_IMPL_H
#define HILPP_ASTREAMER_IMPL_H
#include "i_lpp_audio_streamer.h"
#include "i_lpp_video_streamer.h"
#include "i_lpp_sync_manager.h"
#include "pipeline/pipeline.h"
#include "lpp_audio_data_manager.h"
#include "lpp_adec_adapter.h"
#include "lpp_audio_render_adapter.h"
#include "i_engine_factory.h"
#include "i_lpp_engine_manager.h"

namespace OHOS {
namespace Media {

class HiLppAudioStreamerImpl : public ILppAudioStreamerEngine,
                               public std::enable_shared_from_this<HiLppAudioStreamerImpl> {
public:
    HiLppAudioStreamerImpl();
    ~HiLppAudioStreamerImpl() override;
    int32_t Init(const std::string &mime) override;
    int32_t SetObs(const std::weak_ptr<ILppAudioStreamerEngineObs> &obs) override;
    int32_t Configure(const Format &param) override;
    int32_t Prepare() override;
    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Flush() override;
    int32_t Stop() override;
    int32_t Reset() override;
    int32_t SetVolume(const float volume) override;
    int32_t SetPlaybackSpeed(const float playbackSpeed) override;
    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;
    int32_t SetLppVideoStreamerId(std::string videoStreamerId) override;
    std::string GetStreamerId() override;
    int32_t GetCurrentPosition(int64_t &currentPosition) override;
    void OnEvent(const Event &event);

private:
    void InitLppMode();
    void HandleDataNeededEvent(const Event &event);
    void HandleAnchorUpdateEvent(const Event &event);
    void HandleCompleteEvent(const Event &event);
    void HandleInterruptEvent(const Event &event);
    void HandleDeviceChangeEvent(const Event &event);
    int32_t EosPause();
    void HandleErrorEvent(const Event &event);

    bool isLpp_{false};
    std::string streamerId_{};
    std::shared_ptr<LppAudioDataManager> dataMgr_{nullptr};
    std::shared_ptr<LppAudioDecoderAdapter> adec_{nullptr};
    std::shared_ptr<LppAudioRenderAdapter> aRender_{nullptr};
    std::shared_ptr<ILppSyncManager> syncMgr_{nullptr};
    std::shared_ptr<LppAudioCallbackLooper> callbackLooper_{nullptr};
    std::string videoStreamerId_{};
    std::shared_ptr<ILppVideoStreamerEngine> videoStreamerEngine_{nullptr};
    std::shared_ptr<EventReceiver> eventReceiver_;

    bool isPaused_ {false};
    std::mutex pauseMutex_ {};
};

}  // namespace Media
}  // namespace OHOS
#endif