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
#ifndef I_LPP_VIDEO_STREAMER_H
#define I_LPP_VIDEO_STREAMER_H

#include <string>
#include <refbase.h>
#include "format.h"
#include "lpp_common.h"
#include "media_lpp_errors.h"
#ifndef SUPPORT_AUDIO_ONLY
#include "surface.h"
#endif
#include "i_lpp_sync_manager.h"

namespace OHOS {
class Surface;
class ILppSyncManager;
namespace Media {
class ILppVideoStreamerEngineObs : public std::enable_shared_from_this<ILppVideoStreamerEngineObs> {
public:
    virtual ~ILppVideoStreamerEngineObs() = default;
    virtual void OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum) = 0;
    virtual bool OnAnchorUpdateNeeded(int64_t &anchorPts, int64_t &anchorClk) = 0;
    virtual void OnError(const MediaServiceErrCode errCode, const std::string &errMsg) = 0;
    virtual void OnEos() = 0;
    virtual void OnRenderStarted() = 0;
    virtual void OnTargetArrived(const int64_t targetPts, const bool isTimeout) = 0;
    virtual void OnFirstFrameReady() = 0;
    virtual void OnStreamChanged(Format &format) = 0;
};

class ILppVideoStreamerEngine {
public:
    virtual ~ILppVideoStreamerEngine() = default;
    virtual int32_t Init(const std::string &mime) = 0;
    virtual int32_t SetObs(const std::weak_ptr<ILppVideoStreamerEngineObs> &obs) = 0;
    virtual int32_t SetParameter(const Format &param) = 0;
    virtual int32_t Configure(const Format &param) = 0;
    virtual int32_t SetVideoSurface(sptr<Surface> surface) = 0;
    virtual int32_t Prepare() = 0;
    virtual int32_t StartDecode() = 0;
    virtual int32_t StartRender() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Resume() = 0;
    virtual int32_t Flush() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t SetPlaybackSpeed(const float playbackSpeed) = 0;
    virtual int32_t SetSyncAudioStreamer(int streamerId) = 0;
    virtual int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) = 0;
    virtual int32_t ReturnFrames(sptr<LppDataPacket> framePacket) = 0;
    virtual int32_t SetLppAudioStreamerId(std::string audioStreamerId) = 0;
    virtual std::string GetStreamerId() = 0;
    virtual std::shared_ptr<ILppSyncManager> GetLppSyncManager() = 0;
    virtual int32_t RenderFirstFrame() = 0;
};
}  // namespace Media
}  // namespace OHOS
#endif  // I_LPP_VIDEO_STREAMER_H