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
#ifndef LPP_SYNC_MANAGER_ADAPTER_H
#define LPP_SYNC_MANAGER_ADAPTER_H

#include <map>
#include <memory>

#include "media_core.h"
#include "player.h"
#include "v1_0/ilow_power_player_factory.h"
#include "v1_0/ilpp_sync_manager_adapter.h"
#include "v1_0/ilpp_sync_manager_callback.h"
#include "pipeline/pipeline.h"

namespace PlayerHDI = OHOS::HDI::LowPowerPlayer::V1_0;

namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Base;

class LppSyncManagerAdapter : public std::enable_shared_from_this<LppSyncManagerAdapter> {
public:
    LppSyncManagerAdapter();
    ~LppSyncManagerAdapter();
    int32_t SetVideoChannelId(const uint32_t channelId);
    int32_t SetAudioChannelId(const uint32_t channelId);
    int32_t Init();
    int32_t StartRender();
    int32_t RenderNextFrame();
    int32_t Pause();
    int32_t Resume();
    int32_t Flush();
    int32_t Stop();
    int32_t Reset();
    int32_t SetTargetStartFrame(const uint64_t targetPts, uint32_t timeoutMs = 0);
    int32_t SetPlaybackSpeed(float speed);
    int32_t SetParameter(const std::map<std::string, std::string> &parameters);
    int32_t GetParameter(std::map<std::string, std::string> &parameters);
    int32_t UpdateTimeAnchor(const int64_t anchorPts, const int64_t anchorClk);
    int32_t LoadAdapter();
    int32_t UnloadAdapter();
    int32_t BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap);
    int32_t UnbindOutputBuffers();
    int32_t GetShareBuffer(int32_t &fd);
    int32_t SetTunnelId(uint64_t tunnelId);
    int32_t GetLatestPts(int64_t &pts);

    void OnError(const int32_t errorCode, const std::string &errorMsg);
    void OnTargetArrived(const int64_t targetPts, const bool isTimeout);
    void OnRenderStarted();
    void OnEos();
    void OnInfo(const int32_t infoCode, const std::string &infoMsg);
    void OnFirstFrameReady();
    void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver);
private:
    sptr<PlayerHDI::ILowPowerPlayerFactory> factory_{ nullptr };
    sptr<PlayerHDI::ILppSyncManagerAdapter> syncMgrAdapter_{ nullptr };
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};
};

class LowPowerPlayerFactory {
public:
    static int32_t CreateLppSyncManagerAdapter(std::shared_ptr<LppSyncManagerAdapter> &adapter);
    static int32_t DestroyLppSyncManagerAdapter(std::shared_ptr<LppSyncManagerAdapter> adapter);
};

}  // namespace Media
}  // namespace OHOS
#endif  // LPP_SYNC_MANAGER_ADAPTER_H