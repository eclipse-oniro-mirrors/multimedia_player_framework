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

#include "lpp_sync_manager_adapter.h"
#include "osal/task/task.h"

namespace OHOS {
namespace Media {

class LppSyncManager : public std::enable_shared_from_this<LppSyncManager> {
public:
    explicit LppSyncManager(std::string videoStreamerId, bool isLpp);
    ~LppSyncManager();
    int32_t GetTimeAnchor(int64_t &anchorPts, int64_t &anchorClock);

    int32_t SetVideoChannelId(const uint32_t channelId);
    int32_t SetAudioChannelId(const uint32_t channelId);
    int32_t Init();
    int32_t Prepare();
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
    int32_t BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap);
    int32_t UnbindOutputBuffers();
    int32_t GetShareBuffer(int32_t &fd);
    int32_t SetTunnelId(uint64_t tunnelId);
    int32_t SetAudioIsLpp(bool isLpp);
    void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver);

private:
    void ResetTimeAnchor();

    uint32_t adapterId_ {0};
    std::string videoStreamerId_ {};
    std::shared_ptr<LppSyncManagerAdapter> adapter_ {nullptr};
    bool videoIsLpp_ {true};
    bool audioIsLpp_ {false};
    std::mutex anchorMutex_{};
    uint64_t localAnchorPts_ {0};
    uint64_t localAnchorClk_ {0};
    std::unique_ptr<OHOS::Media::Task> synctask_ {nullptr};
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};
};

}  // namespace Media
}  // namespace OHOS

#endif