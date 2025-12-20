/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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
#ifndef I_PLAYER_ENGINE_H
#define I_PLAYER_ENGINE_H

#include <map>
#include <vector>
#include <cstdint>
#include <string>
#include <refbase.h>
#include "player.h"
#include "common/event.h"
#include "meta/video_types.h"
#include "nocopyable.h"

#ifdef SUPPORT_AVPLAYER_DRM
#include "imedia_key_session_service.h"
#endif

namespace OHOS {
class Surface;

namespace Media {
class IPlayerEngineObs : public std::enable_shared_from_this<IPlayerEngineObs> {
public:
    virtual ~IPlayerEngineObs() = default;
    virtual void OnError(PlayerErrorType errorType, int32_t errorCode, const std::string &description) = 0;
    virtual void OnErrorMessage(int32_t errorCode, const std::string &errorMsg)
    {
        (void)errorCode;
        (void)errorMsg;
    }
    virtual void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) = 0;
    virtual void OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason) = 0;
    virtual void OnDfxInfo(const DfxEvent &event)
    {
        (void)event;
    }
    virtual bool IsAudioPass(const char* mime)
    {
        (void)mime;
        return false;
    }
    virtual std::vector<std::string> GetList()
    {
        return {};
    }
};

class IPlayerEngine {
public:
    virtual ~IPlayerEngine() = default;

    virtual int32_t SetSource(const std::string &url) = 0;
    virtual int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) = 0;
    virtual int32_t SetObs(const std::weak_ptr<IPlayerEngineObs> &obs) = 0;
    virtual int32_t AddSubSource(const std::string &url)
    {
        (void)url;
        return 0;
    }
    virtual int32_t Play() = 0;
    virtual int32_t Prepare()
    {
        return 0;
    }
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
    virtual int32_t SetIsCalledBySystemApp(bool isCalledBySystemApp)
    {
        (void)isCalledBySystemApp;
        return 0;
    }
    virtual int32_t PrepareAsync() = 0;
    virtual int32_t Pause(bool isSystemOperation) = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t Freeze(bool &isNoNeedToFreeze) = 0;
    virtual int32_t UnFreeze() = 0;
    virtual int32_t PauseSourceDownload()
    {
        return 0;
    }
    virtual int32_t ResumeSourceDownload()
    {
        return 0;
    }
    virtual int32_t SetVolume(float leftVolume, float rightVolume) = 0;
    virtual int32_t SetVolumeMode(int32_t mode) = 0;
    virtual int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) = 0;
    virtual int32_t GetCurrentTime(int32_t &currentTime) = 0;
    virtual int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) = 0;
    virtual int32_t GetPlaybackInfo(Format &playbackInfo) = 0;
    virtual int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) = 0;
    virtual int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
    {
        (void)subtitleTrack;
        return 0;
    }
    virtual int32_t GetVideoWidth() = 0;
    virtual int32_t GetVideoHeight() = 0;
    virtual int32_t GetDuration(int32_t &duration) = 0;
    virtual int32_t SetPlaybackSpeed(PlaybackRateMode mode) = 0;
    virtual int32_t SetPlaybackRate(float rate) = 0;
    virtual int32_t GetPlaybackSpeed(PlaybackRateMode &mode) = 0;
    virtual int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) = 0;
    virtual int32_t SetVideoSurface(sptr<Surface> surface) = 0;
    virtual float GetMaxAmplitude() = 0;

    virtual int32_t SetDecryptConfig(const sptr<OHOS::DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp)
    {
        (void)keySessionProxy;
        (void)svp;
        return 0;
    }

    virtual int32_t GetPlaybackRate(float &rate)
    {
        (void)rate;
        return 0;
    }

    virtual int32_t SetLooping(bool loop) = 0;
    virtual int32_t SetParameter(const Format &param) = 0;
    virtual int32_t SelectBitRate(uint32_t bitRate, bool isAutoSelect)
    {
        (void)bitRate;
        (void)isAutoSelect;
        return 0;
    }
    virtual int32_t SetVideoScaleType(Plugins::VideoScaleType videoScaleType)
    {
        (void)videoScaleType;
        return 0;
    }
    virtual int32_t SetAudioRendererInfo(const int32_t contentType, const int32_t streamUsage,
        const int32_t rendererFlag, const int32_t volumeMode)
    {
        (void)contentType;
        (void)streamUsage;
        (void)rendererFlag;
        (void)volumeMode;
        return 0;
    }
    virtual int32_t SetAudioInterruptMode(const int32_t interruptMode)
    {
        (void)interruptMode;
        return 0;
    }

    virtual int32_t GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics)
    {
        (void)playbackStatisticMetrics;
        return 0;
    }

    virtual int32_t SelectTrack(int32_t index, PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SMOOTH)
    {
        (void)index;
        (void)mode;
        return 0;
    }
    virtual int32_t DeselectTrack(int32_t index)
    {
        (void)index;
        return 0;
    }
    virtual int32_t GetCurrentTrack(int32_t trackType, int32_t &index)
    {
        (void)trackType;
        (void)index;
        return 0;
    }
    virtual int32_t SetAudioEffectMode(const int32_t effectMode)
    {
        (void)effectMode;
        return 0;
    }
    virtual int32_t GetAudioEffectMode(int32_t &effectMode)
    {
        (void)effectMode;
        return 0;
    }
    virtual int32_t GetHEBCMode()
    {
        return 0;
    }
    virtual int32_t HandleCodecBuffers(bool enable)
    {
        (void)enable;
        return 0;
    }
    virtual int32_t SeekToCurrentTime(int32_t mSeconds, PlayerSeekMode mode)
    {
        (void)mSeconds;
        (void)mode;
        return 0;
    }
    virtual void SetInterruptState(bool isInterruptNeeded)
    {
        (void)isInterruptNeeded;
    }
    virtual void OnDumpInfo(int32_t fd)
    {
        (void)fd;
    }
    virtual void SetInstancdId(uint64_t instanceId)
    {
        (void)instanceId;
    }
    virtual void SetApiVersion(int32_t apiVersion)
    {
        (void)apiVersion;
    }

    virtual int64_t GetPlayRangeStartTime()
    {
        return 0;
    }

    virtual int64_t GetPlayRangeEndTime()
    {
        return 0;
    }

    virtual int32_t GetPlayRangeSeekMode()
    {
        return 0;
    }

    virtual int32_t PauseDemuxer()
    {
        return 0;
    }
    virtual int32_t ResumeDemuxer()
    {
        return 0;
    }
    virtual int32_t SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
    {
        (void)mediaType;
        (void)isMuted;
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

    virtual int32_t SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
    {
        (void)playbackStrategy;
        return 0;
    }
    virtual int32_t SeekContinous(int32_t mSeconds, int64_t seekContinousBatchNo)
    {
        (void)mSeconds;
        (void)seekContinousBatchNo;
        return 0;
    }
    virtual int32_t ExitSeekContinous(bool align, int64_t seekContinousBatchNo)
    {
        (void)align;
        (void)seekContinousBatchNo;
        return 0;
    }

    virtual int32_t SetMaxAmplitudeCbStatus(bool status)
    {
        (void)status;
        return 0;
    }

    virtual int32_t IsSeekContinuousSupported(bool &IsSeekContinuousSupported)
    {
        (void)IsSeekContinuousSupported;
        return 0;
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

    virtual bool IsNeedChangePlaySpeed(PlaybackRateMode &mode, bool &isXSpeedPlay)
    {
        (void)mode;
        (void)isXSpeedPlay;
        return false;
    }

    virtual bool IsPauseForTooLong(int64_t pauseTime)
    {
        (void)pauseTime;
        return false;
    }

    virtual void DoRestartLiveLink()
    {
    }

    virtual void SetPerfRecEnabled(bool isPerfRecEnabled)
    {
        (void)isPerfRecEnabled;
    }

    virtual bool IsLivingMaxDelayTimeValid()
    {
        return false;
    }

    virtual bool IsFlvLive()
    {
        return false;
    }

    virtual int32_t EnableReportMediaProgress(bool enable)
    {
        (void)enable;
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

    virtual int32_t ForceLoadVideo(bool /* enabled */)
    {
        return 0;
    }

    virtual int32_t NotifyMemoryExchange(bool /* status */)
    {
        return 0;
    }
    virtual void SetEosInLoopForFrozen(bool /* status */)
    {
        return ;
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
    virtual bool IsAudioPass(const char* mime)
    {
        (void)mime;
        return false;
    }
    virtual std::vector<std::string> GetList()
    {
        return {};
    }
};
} // namespace Media
} // namespace OHOS
#endif // I_PLAYER_ENGINE_H
