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
    virtual int32_t SetPlayerProducer(const PlayerProducer producer) = 0;
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
    virtual int32_t SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
    {
        (void)start;
        (void)end;
        (void)mode;
        return 0;
    }
    virtual int32_t SetSuperResolution(bool enabled)
    {
        (void)enabled;
        return 0;
    }
    virtual int32_t SetVideoWindowSize(int32_t width, int32_t height)
    {
        (void)width;
        (void)height;
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
    virtual int32_t SetVolumeMode(int32_t mode) = 0;
    virtual int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) = 0;
    virtual int32_t GetCurrentTime(int32_t &currentTime) = 0;
    virtual int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) = 0;
    virtual int32_t GetPlaybackInfo(Format &playbackInfo) = 0;
    virtual int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) = 0;
    virtual int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) = 0;
    virtual int32_t GetVideoWidth() = 0;
    virtual int32_t GetVideoHeight() = 0;
    virtual int32_t GetDuration(int32_t &duration) = 0;
    virtual int32_t SetPlaybackSpeed(PlaybackRateMode mode) = 0;
    virtual int32_t SetPlaybackRate(float rate) = 0;
    virtual int32_t GetPlaybackSpeed(PlaybackRateMode &mode) = 0;
    virtual int32_t SetSourceLoader(const sptr<IRemoteObject> &object) = 0;
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
    virtual int32_t SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
    {
        (void)playbackStrategy;
        return 0;
    }
    virtual int32_t SetMediaMuted(MediaType mediaType, bool isMuted)
    {
        (void)mediaType;
        (void)isMuted;
        return 0;
    }

    virtual int32_t GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics)
    {
        (void)playbackStatisticMetrics;
        return 0;
    }

    virtual int32_t GetPlaybackRate(float &rate)
    {
        (void)rate;
        return 0;
    }

    virtual int32_t SetDecryptConfig(const sptr<OHOS::DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp)
    {
        (void)keySessionProxy;
        (void)svp;
        return 0;
    }

    virtual int32_t SetMaxAmplitudeCbStatus(bool status)
    {
        (void)status;
        return 0;
    }

    virtual int32_t SetDeviceChangeCbStatus(bool status)
    {
        (void)status;
        return 0;
    }

    virtual int32_t GetApiVersion(int32_t &apiVersion)
    {
        (void)apiVersion;
        return 0;
    }

    virtual bool IsSeekContinuousSupported()
    {
        return false;
    }

    virtual int32_t GetPlaybackPosition(int32_t &playbackPosition)
    {
        (void)playbackPosition;
        return 0;
    }

    virtual int32_t SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
    {
        (void)status;
        (void)payloadTypes;
        return 0;
    }

    virtual int32_t SetStartFrameRateOptEnabled(bool enabled)
    {
        (void)enabled;
        return 0;
    }

    virtual int32_t SetReopenFd(int32_t fd)
    {
        (void)fd;
        return 0;
    }
 
    virtual int32_t EnableCameraPostprocessing()
    {
        return 0;
    }

    virtual int32_t SetCameraPostprocessing(bool isOpen)
    {
        (void)isOpen;
        return 0;
    }

    virtual int32_t EnableReportMediaProgress(bool enable)
    {
        (void)enable;
        return 0;
    }

    virtual int32_t EnableReportAudioInterrupt(bool enable)
    {
        (void)enable;
        return 0;
    }
    
    virtual int32_t ForceLoadVideo(bool /* enabled */)
    {
        return 0;
    }

    virtual int32_t SetLoudnessGain(float loudnessGain)
    {
        (void)loudnessGain;
        return 0;
    }
    
    virtual int32_t GetGlobalInfo(std::shared_ptr<Meta> &globalInfo)
    {
        (void)globalInfo;
        return 0;
    }
    
    virtual int32_t GetMediaDescription(Format &format)
    {
        (void)format;
        return 0;
    }

    virtual int32_t GetTrackDescription(Format &format, uint32_t trackIndex)
    {
        (void)format;
        (void)trackIndex;
        return 0;
    }

    /**
     * IPC code ID
     */
    enum PlayerServiceMsg {
        SET_LISTENER_OBJ = 0,
        SET_PLAYER_PRODUCER,
        SET_SOURCE,
        SET_MEDIA_DATA_SRC_OBJ,
        SET_FD_SOURCE,
        ADD_SUB_SOURCE,
        ADD_SUB_FD_SOURCE,
        PLAY,
        PREPARE,
        SET_RENDER_FIRST_FRAME,
        SET_PLAY_RANGE,
        SET_PLAY_RANGE_WITH_MODE,
        SET_SUPER_RESOLUTION,
        SET_VIDEO_WINDOW_SIZE,
        PREPAREASYNC,
        PAUSE,
        STOP,
        RESET,
        RELEASE,
        SET_VOLUME,
        SET_VOLUME_MODE,
        SEEK,
        GET_CURRENT_TIME,
        GET_PLAY_BACK_POSITION,
        GET_DURATION,
        SET_PLAYERBACK_SPEED,
        SET_PLAYERBACK_RATE,
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
        SET_PLAYBACK_STRATEGY,
        SET_MEDIA_MUTED,
        SET_MAX_AMPLITUDE_CB_STATUS,
        SET_SEI_MESSAGE_CB_STATUS,
        GET_PLAYBACK_INFO,
        SET_DEVICE_CHANGE_CB_STATUS,
        GET_API_VERSION,
        IS_SEEK_CONTINUOUS_SUPPORTED,
        SET_SOURCE_LOADER,
        SET_START_FRAME_RATE_OPT_ENABLED,
        SET_REOPEN_FD,
        ENABLE_CAMERA_POSTPROCESSING,
        ENABLE_REPORT_MEDIA_PROGRESS,
        ENABLE_REPORT_AUDIO_INTERRUPT,
        FORCE_LOAD_VIDEO,
        SET_LOUDNESSGAIN,
        SET_CAMERA_POST_POSTPROCESSING,
        GET_MEDIA_DESCRIPTION,
        GET_TRACK_DESCRIPTION,
        GET_PLAYBACK_STATISTIC_METRICS,
        MAX_IPC_ID,                   // all IPC codes should be added before MAX_IPC_ID
        GET_GLOBAL_INFO,
        GET_PLAYERBACK_RATE,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardPlayerService");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_PLAYER_SERVICE_H
