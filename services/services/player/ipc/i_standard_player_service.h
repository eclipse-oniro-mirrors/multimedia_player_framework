/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef I_STANDARD_PLAYER_SERVICE_H
#define I_STANDARD_PLAYER_SERVICE_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "player.h"

namespace OHOS {
namespace Media {
class IStandardPlayerService : public IRemoteBroker {
public:
    virtual ~IStandardPlayerService() = default;
    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;
    virtual int32_t SetSource(const std::string &url) = 0;
    virtual int32_t SetSource(const sptr<IRemoteObject> &object) = 0;
    virtual int32_t SetSource(int32_t fd, int64_t offset, int64_t size) = 0;
    virtual int32_t AddSubSource(const std::string &url) = 0;
    virtual int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) = 0;
    virtual int32_t Play() = 0;
    virtual int32_t Prepare() = 0;
    virtual int32_t SetRenderFirstFrame(bool display)
    {
        (void)display;
        return 0;
    }
    virtual int32_t SetPlayRange(int64_t start, int64_t end)
    {
        (void)start;
        (void)end;
        return 0;
    }
    virtual int32_t PrepareAsync() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t Release() = 0;
    virtual int32_t ReleaseSync() // Only client rewrite is required
    {
        return ERR_OK;
    }
    virtual int32_t SetVolume(float leftVolume, float rightVolume) = 0;
    virtual int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) = 0;
    virtual int32_t GetCurrentTime(int32_t &currentTime) = 0;
    virtual int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) = 0;
    virtual int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) = 0;
    virtual int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) = 0;
    virtual int32_t GetVideoWidth() = 0;
    virtual int32_t GetVideoHeight() = 0;
    virtual int32_t GetDuration(int32_t &duration) = 0;
    virtual int32_t SetPlaybackSpeed(PlaybackRateMode mode) = 0;
    virtual int32_t GetPlaybackSpeed(PlaybackRateMode &mode) = 0;
    virtual int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) = 0;
#ifdef SUPPORT_VIDEO
    virtual int32_t SetVideoSurface(sptr<Surface> surface) = 0;
#endif
    virtual bool IsPlaying() = 0;
    virtual bool IsLooping() = 0;
    virtual int32_t SetLooping(bool loop) = 0;
    virtual int32_t SetParameter(const Format &param) = 0;
    virtual int32_t DestroyStub() = 0;
    virtual int32_t SetPlayerCallback() = 0;
    virtual int32_t SelectBitRate(uint32_t bitRate) = 0;
    virtual int32_t SelectTrack(int32_t index, PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SMOOTH) = 0;
    virtual int32_t DeselectTrack(int32_t index) = 0;
    virtual int32_t GetCurrentTrack(int32_t trackType, int32_t &index) = 0;

    virtual int32_t SetDecryptConfig(const sptr<OHOS::DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp)
    {
        (void)keySessionProxy;
        (void)svp;
        return 0;
    }
    /**
     * IPC code ID
     */
    enum PlayerServiceMsg {
        SET_LISTENER_OBJ = 0,
        SET_SOURCE,
        SET_MEDIA_DATA_SRC_OBJ,
        SET_FD_SOURCE,
        ADD_SUB_SOURCE,
        ADD_SUB_FD_SOURCE,
        PLAY,
        PREPARE,
        SET_RENDER_FIRST_FRAME,
        SET_PLAY_RANGE,
        PREPAREASYNC,
        PAUSE,
        STOP,
        RESET,
        RELEASE,
        SET_VOLUME,
        SEEK,
        GET_CURRENT_TIME,
        GET_DURATION,
        SET_PLAYERBACK_SPEED,
        GET_PLAYERBACK_SPEED,
        SET_MEDIA_SOURCE,
        SET_VIDEO_SURFACE,
        IS_PLAYING,
        IS_LOOPING,
        SET_LOOPING,
        SET_RENDERER_DESC,
        DESTROY,
        SET_CALLBACK,
        GET_VIDEO_TRACK_INFO,
        GET_AUDIO_TRACK_INFO,
        GET_VIDEO_WIDTH,
        GET_VIDEO_HEIGHT,
        SELECT_BIT_RATE,
        SELECT_TRACK,
        DESELECT_TRACK,
        GET_CURRENT_TRACK,
        GET_SUBTITLE_TRACK_INFO,
        SET_DECRYPT_CONFIG,
        MAX_IPC_ID,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardPlayerService");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_PLAYER_SERVICE_H
