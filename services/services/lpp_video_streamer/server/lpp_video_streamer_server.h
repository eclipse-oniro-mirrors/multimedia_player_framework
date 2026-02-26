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

#ifndef LPP_VIDEO_STREAMER_SERVICE_SERVER_H
#define LPP_VIDEO_STREAMER_SERVICE_SERVER_H

#include <atomic>
#include <mutex>

#include "i_lpp_video_streamer_service.h"
#include "i_lpp_video_streamer.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {

enum class VideoState : int32_t {
    CREATED = 0,
    INITIALIZED = 1,
    READY = 2,
    DECODING = 3,
    RENDERING = 4,
    PAUSED = 5,
    EOS = 6,
    STOPPED = 7,
    RELEASED = 8,
    ERROR = 32,
};

class LppLinkCallbackLooper;
class LppVideoStreamerServer : public ILppVideoStreamerService, public NoCopyable, public ILppVideoStreamerEngineObs {
public:
    static std::shared_ptr<ILppVideoStreamerService> Create();
    LppVideoStreamerServer();
    virtual ~LppVideoStreamerServer();

    int32_t Init(const std::string &mime) override;

    int32_t SetParameter(const Format &param) override;

    int32_t GetParameter(Format &param) override;

    int32_t Configure(const Format &param) override;

    int32_t Prepare() override;

    int32_t Start() override;

    int32_t Pause() override;

    int32_t Resume() override;

    int32_t Flush() override;

    int32_t Stop() override;

    int32_t Reset() override;

    int32_t Release() override;

    int32_t StartDecode() override;

    int32_t StartRender() override;

    int32_t SetOutputSurface(sptr<Surface> surface) override;

    int32_t SetSyncAudioStreamer(AudioStreamer *audioStreamer) override;

    int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) override;

    int32_t SetVolume(float volume) override;

    int32_t SetPlaybackSpeed(float speed) override;

    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;

    int32_t RegisterCallback() override;

    int32_t SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback) override;

    int32_t SetLppAudioStreamerId(const std::string audioStreamId) override;

    std::string GetStreamerId() override;

    int32_t RenderFirstFrame() override;

    int32_t GetLatestPts(int64_t &pts) override;

    void OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum) override;
    bool OnAnchorUpdateNeeded(int64_t &anchorPts, int64_t &anchorClk) override;
    void OnError(const MediaServiceErrCode errCode, const std::string &errMsg) override;
    void OnEos() override;
    void OnRenderStarted() override;
    void OnTargetArrived(const int64_t targetPts, const bool isTimeout) override;
    void OnFirstFrameReady() override;
    void OnStreamChanged(Format &format) override;

private:
    int32_t CreateStreamerEngine();
    bool StateEnter(VideoState targetState, const std::string funcName = "");
    bool StateCheck(VideoState curState);
    bool ErrorCheck(int32_t errorCode);

    std::shared_ptr<VideoStreamerCallback> callback_ = nullptr;

    std::string mime_ {};
    std::shared_ptr<ILppVideoStreamerEngine> streamerEngine_ = nullptr;
    uint32_t appTokenId_ = 0;
    int32_t appUid_ = 0;
    int32_t appPid_ = 0;
    std::string appName_ {};

    VideoState state_ {VideoState::CREATED};
    std::mutex stateMutex_ {};
    std::atomic<bool> isFirstFrameDecoded_ {false};
    std::atomic<bool> isFirstFrameRendered_ {false};
    Format param_ {};
};
}  // namespace Media
}  // namespace OHOS
#endif  // LPP_VIDEO_STREAMER_SERVICE_SERVER_H
