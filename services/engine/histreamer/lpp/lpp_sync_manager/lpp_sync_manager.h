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
#ifndef LPP_SYNC_MANAGER_H
#define LPP_SYNC_MANAGER_H

#include "i_lpp_sync_manager.h"
#include "lpp_sync_manager_adapter.h"
#include "osal/task/task.h"

namespace OHOS {
namespace Media {

class LppSyncManager : public ILppSyncManager, public std::enable_shared_from_this<LppSyncManager> {
public:
    explicit LppSyncManager(std::string videoStreamerId, bool isLpp);
    ~LppSyncManager() override;
    int32_t GetTimeAnchor(int64_t &anchorPts, int64_t &anchorClock) override;

    int32_t SetVideoChannelId(const uint32_t channelId) override;
    int32_t SetAudioChannelId(const uint32_t channelId) override;
    int32_t Init() override;
    int32_t Prepare() override;
    int32_t StartRender() override;
    int32_t RenderNextFrame() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Flush() override;
    int32_t Stop() override;
    int32_t Reset() override;
    int32_t SetTargetStartFrame(const uint64_t targetPts, uint32_t timeoutMs = 0) override;
    int32_t SetPlaybackSpeed(float speed) override;
    int32_t SetParameter(const std::map<std::string, std::string> &parameters) override;
    int32_t GetParameter(std::map<std::string, std::string> &parameters) override;
    int32_t UpdateTimeAnchor(const int64_t anchorPts, const int64_t anchorClk) override;
    int32_t BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap) override;
    int32_t UnbindOutputBuffers() override;
    int32_t GetShareBuffer(int32_t &fd) override;
    int32_t SetTunnelId(uint64_t tunnelId) override;
    int32_t SetAudioIsLpp(bool isLpp) override;
    void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver) override;
    int32_t GetLatestPts(int64_t &pts) override;

private:
    void ResetTimeAnchor();

    std::string videoStreamerId_ {};
    std::shared_ptr<LppSyncManagerAdapter> adapter_ {nullptr};
    bool videoIsLpp_ {true};
    bool audioIsLpp_ {false};
    std::mutex anchorMutex_{};
    int64_t localAnchorPts_{0};
    int64_t localAnchorClk_{0};
    std::unique_ptr<OHOS::Media::Task> synctask_ {nullptr};
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};
};

}  // namespace Media
}  // namespace OHOS

#endif