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
#ifndef I_LPP_SYNC_MANAGER_H
#define I_LPP_SYNC_MANAGER_H

#include <string>
#include <refbase.h>
#include "format.h"
#include "i_lpp_video_streamer.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {

class ILppSyncManager {
public:
    virtual ~ILppSyncManager() = default;
    virtual int32_t Init();
    virtual int32_t GetTimeAnchor(int64_t &anchorPts, int64_t &anchorClock) = 0;
    virtual int32_t SetVideoChannelId(const uint32_t channelId) = 0;
    virtual int32_t SetAudioChannelId(const uint32_t channelId) = 0;
    virtual int32_t Prepare() = 0;
    virtual int32_t StartRender() = 0;
    virtual int32_t RenderNextFrame() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Resume() = 0;
    virtual int32_t Flush() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t SetTargetStartFrame(const uint64_t targetPts, uint32_t timeoutMs = 0) = 0;
    virtual int32_t SetPlaybackSpeed(float speed) = 0;
    virtual int32_t SetParameter(const std::map<std::string, std::string> &parameters) = 0;
    virtual int32_t GetParameter(std::map<std::string, std::string> &parameters) = 0;
    virtual int32_t UpdateTimeAnchor(const int64_t anchorPts, const int64_t anchorClk) = 0;
    virtual int32_t BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap) = 0;
    virtual int32_t UnbindOutputBuffers() = 0;
    virtual int32_t GetShareBuffer(int32_t &fd) = 0;
    virtual int32_t SetTunnelId(uint64_t tunnelId) = 0;
    virtual int32_t SetAudioIsLpp(bool isLpp) = 0;
    virtual void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver) = 0;
    virtual int32_t GetLatestPts(int64_t &pts) = 0;
};

}
}

#endif