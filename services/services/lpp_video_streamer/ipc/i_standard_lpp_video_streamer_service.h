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

#ifndef I_STANDARD_LPP_VIDEO_STREAMER_SERVICE_H
#define I_STANDARD_LPP_VIDEO_STREAMER_SERVICE_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "lpp_video_streamer.h"
#include "lpp_common.h"

namespace OHOS {
namespace Media {
class IStandardLppVideoStreamerService : public IRemoteBroker {
public:
    virtual ~IStandardLppVideoStreamerService() = default;
    // virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

    virtual int32_t Init(const std::string &mime) = 0;
    
    virtual int32_t SetParameter(const Format &param) = 0;

    virtual int32_t GetParameter(Format &param) = 0;

    virtual int32_t Configure(const Format &param) = 0;

    virtual int32_t Prepare() = 0;

    virtual int32_t Start() = 0;

    virtual int32_t Pause() = 0;

    virtual int32_t Resume() = 0;

    virtual int32_t Flush() = 0;

    virtual int32_t Stop() = 0;

    virtual int32_t Reset() = 0;

    virtual int32_t Release() = 0;

    virtual int32_t StartDecode() = 0;

    virtual int32_t StartRender() = 0;

    virtual int32_t SetOutputSurface(sptr<Surface> surface) = 0;

    virtual int32_t SetSyncAudioStreamer(AudioStreamer *audioStreamer) = 0;

    virtual int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) = 0;

    virtual int32_t SetVolume(float volume) = 0;

    virtual int32_t SetPlaybackSpeed(float speed) = 0;

    virtual int32_t ReturnFrames(sptr<LppDataPacket> framePacket) = 0;

    virtual int32_t RegisterCallback() = 0;

    virtual int32_t SetLppVideoStreamerCallback() = 0;

    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

    virtual int32_t SetLppAudioStreamerId(const std::string audioStreamId) = 0;

    virtual std::string GetStreamerId() = 0;

    virtual int32_t RenderFirstFrame() = 0;

    virtual int32_t GetLatestPts(int64_t &pts) = 0;

    /**
     * IPC code ID
     */
    enum PlayerServiceMsg {
        SET_PARAMETER = 0,
        CONFIGURE,
        INIT,
        PREPARE,
        START,
        PAUSE,
        RESUME,
        FLUSH,
        STOP,
        RESET,
        RELEASE,
        SET_VOLUME,
        SET_PLAYBACK_SPEED,
        RETURN_FRAMES,
        REGISTER_CALLBACK,
        SET_AUDIO_STREAM_CALLBACK,
        SET_LISTENER_OBJ,
        START_DECODE,
        START_RENDER,
        SET_OUTPUT_SURFACE,
        SET_SYNC_AUDIO_STREAMER,
        SET_TARGET_START_FRAME,
        GET_STREAM_ID,
        SET_AUDIO_STREAMER_ID,
        RENDER_FIRST_FRAME,
        GET_LATEST_PTS,
        GET_PARAMETER,
        MAX_IPC_ID,                   // all IPC codes should be added before MAX_IPC_ID
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardLppVideoStreamerService");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_PLAYER_SERVICE_H
