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

#ifndef VIDEO_STREAM_PLAYER_H
#define VIDEO_STREAM_PLAYER_H

#include <set>

#include "surface.h"
#include "meta/format.h"
#include "lpp_audio_streamer.h"
#include "lpp_common.h"
#include "lpp_capability.h"
namespace OHOS {
namespace Media {
class VideoStreamerKeys {
public:
    static constexpr std::string_view LPP_CURRENT_POSITION = "current_position";
    static constexpr std::string_view LPP_VIDEO_MAX_BUFFER_SIZE = "lpp_video_max_buffer_size";
    static constexpr std::string_view LPP_VIDEO_MAX_FRAME_NUM = "lpp_video_max_frame_num";
    static constexpr std::string_view LPP_VIDEO_TARGET_PTS = "lpp_video_target_pts";
    static constexpr std::string_view LPP_VIDEO_IS_TIMEOUT = "lpp_video_is_timeout";
};

enum VideoStreamerOnInfoType : int32_t {
    VIDEO_INFO_TYPE_LPP_DATA_NEEDED,
    VIDEO_INFO_TYPE_LPP_ANCHOR_UPDATED,
    VIDEO_INFO_TYPE_LPP_TARGET_ARRIVED,
    VIDEO_INFO_TYPE_LPP_RENDER_STARTED,
    VIDEO_INFO_TYPE_LPP_EOS,
    VIDEO_INFO_TYPE_LPP_FIRST_FRAME_READY,
    VIDEO_INFO_TYPE_LPP_STREAM_CHANGED,
};

class VideoStreamerCallback {
public:
    virtual ~VideoStreamerCallback() = default;

    virtual void OnError(int32_t errorCode, const std::string &errorMsg) = 0;

    virtual void OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody) = 0;
};

class VideoStreamer {
public:
    virtual ~VideoStreamer() = default;

    virtual int32_t SetParameter(const Format &param) = 0;

    virtual int32_t GetParameter(Format &param) = 0;

    virtual int32_t Configure(const Format &param) = 0;

    virtual int32_t SetOutputSurface(sptr<Surface> surface) = 0;

    virtual int32_t Prepare() = 0;

    virtual int32_t StartDecode() = 0;

    virtual int32_t StartRender() = 0;

    virtual int32_t Start() = 0;

    virtual int32_t Pause() = 0;

    virtual int32_t Resume() = 0;

    virtual int32_t Flush() = 0;

    virtual int32_t Stop() = 0;

    virtual int32_t Reset() = 0;

    virtual int32_t Release() = 0;

    virtual int32_t SetSyncAudioStreamer(std::shared_ptr<AudioStreamer> audioStreamer) = 0;

    virtual int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) = 0;

    virtual int32_t SetVolume(float volume) = 0;

    virtual int32_t SetPlaybackSpeed(float speed) = 0;

    virtual int32_t ReturnFrames(sptr<LppDataPacket> framePacket) = 0;

    virtual int32_t RegisterCallback() = 0;

    virtual int32_t SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback) = 0;

    virtual std::shared_ptr<VideoStreamerCallback> GetLppVideoStreamerCallback() = 0;

    virtual int32_t RenderFirstFrame() = 0;

    virtual std::string GetStreamerId() = 0;

    virtual int32_t GetLatestPts(int64_t &pts) = 0;
};

class __attribute__((visibility("default"))) VideoStreamerFactory {
public:
#ifdef UNSUPPORT_LPP_AUDIO_STRAMER
    static std::shared_ptr<VideoStreamer> CreateByMime(const std::string &mime)
    {
        (void)mime;
        return nullptr;
    }
    static LppAvCapabilityInfo *GetLppCapacity()
    {
        return nullptr;
    }
#else
    static std::shared_ptr<VideoStreamer> CreateByMime(const std::string &mime);
    static LppAvCapabilityInfo *GetLppCapacity();
#endif
    
private:
    VideoStreamerFactory() = default;
    ~VideoStreamerFactory() = default;
};
}  // namespace Media
}  // namespace OHOS
#endif  // VIDEO_STREAM_PLAYER_H
