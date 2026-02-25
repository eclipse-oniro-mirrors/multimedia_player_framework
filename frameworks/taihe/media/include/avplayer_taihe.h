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
#ifndef AVPLAYER_TAIHE_H
#define AVPLAYER_TAIHE_H

#include <shared_mutex>
#include "audio_info.h"
#include "audio_effect.h"
#include "avmetadatahelper.h"
#include "avplayer_callback_taihe.h"
#include "common_taihe.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "player.h"
#include "taihe/runtime.hpp"
#include "media_data_source_callback_taihe.h"
#include "task_queue.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace ohos::multimedia::drm;
using TaskRet = std::pair<int32_t, std::string>;
using StateChangeCallback = void(string_view, ohos::multimedia::media::StateChangeReason);

struct AVPlayerContext {
    AVPlayerContext() = default;
    ~AVPlayerContext() = default;
    void SignError(int32_t code, const std::string &message);
    void CheckTaskResult(bool isTimeLimited = false, uint32_t milliseconds = 0)
    {
        if (asyncTask != nullptr) {
            auto result = isTimeLimited ? asyncTask->GetResultWithTimeLimit(milliseconds) : asyncTask->GetResult();
            if (result.HasResult() && result.Value().first != MSERR_EXT_API9_OK) {
                SignError(result.Value().first, result.Value().second);
            }
        }
    }
    std::shared_ptr<TaskHandler<TaskRet>> asyncTask = nullptr;
    std::vector<Format> trackInfoVec_;
};
struct AVPlayStrategyTmp {
    uint32_t preferredWidth;
    uint32_t preferredHeight;
    uint32_t preferredBufferDuration;
    bool preferredHdr;
    bool showFirstFrameOnPrepare;
    bool enableSuperResolution;
    int32_t mutedMediaType = static_cast<int32_t>(OHOS::Media::MediaType::MEDIA_TYPE_MAX_COUNT);
    std::string preferredAudioLanguage;
    std::string preferredSubtitleLanguage;
    double preferredBufferDurationForPlaying;
    double thresholdForAutoQuickPlay;
    bool isSetBufferDurationForPlaying {true};
    bool isSetThresholdForAutoQuickPlay {true};
};

namespace AVPlayerEvent {
    const std::string EVENT_STATE_CHANGE = "stateChange";
    const std::string EVENT_VOLUME_CHANGE = "volumeChange";
    const std::string EVENT_END_OF_STREAM = "endOfStream";
    const std::string EVENT_SEEK_DONE = "seekDone";
    const std::string EVENT_SPEED_DONE = "speedDone";
    const std::string EVENT_BITRATE_DONE = "bitrateDone";
    const std::string EVENT_TIME_UPDATE = "timeUpdate";
    const std::string EVENT_DURATION_UPDATE = "durationUpdate";
    const std::string EVENT_SUBTITLE_TEXT_UPDATE = "subtitleTextUpdate";
    const std::string EVENT_BUFFERING_UPDATE = "bufferingUpdate";
    const std::string EVENT_START_RENDER_FRAME = "startRenderFrame";
    const std::string EVENT_VIDEO_SIZE_CHANGE = "videoSizeChange";
    const std::string EVENT_AUDIO_INTERRUPT = "audioInterrupt";
    const std::string EVENT_AVAILABLE_BITRATES = "availableBitrates";
    const std::string EVENT_TRACKCHANGE = "trackChange";
    const std::string EVENT_TRACK_INFO_UPDATE = "trackInfoUpdate";
    const std::string EVENT_DRM_INFO_UPDATE = "mediaKeySystemInfoUpdate";
    const std::string EVENT_SET_DECRYPT_CONFIG_DONE = "setDecryptConfigDone";
    const std::string EVENT_AUDIO_DEVICE_CHANGE = "audioOutputDeviceChangeWithInfo";
    const std::string EVENT_SUBTITLE_UPDATE = "subtitleUpdate";
    const std::string EVENT_ERROR = "error";
    const std::string EVENT_AMPLITUDE_UPDATE = "amplitudeUpdate";
    const std::string EVENT_SUPER_RESOLUTION_CHANGED = "superResolutionChanged";
    const std::string EVENT_SEI_MESSAGE_INFO = "seiMessageReceived";
    const std::string EVENT_RATE_DONE = "playbackRateDone";
    const std::string EVENT_METRICS = "metricsEvent";
}

class AVPlayerImpl : public AVPlayerNotify {
public:
    AVPlayerImpl();

    optional<string> GetUrl();
    void SetUrl(optional_view<string> url);
    optional<ohos::multimedia::audio::AudioEffectMode> GetAudioEffectMode();
    void SetAudioEffectMode(optional_view<ohos::multimedia::audio::AudioEffectMode> audioEffectMode);
    int32_t GetWidth();
    int32_t GetHeight();
    string GetState();
    int32_t GetDuration();
    int32_t GetCurrentTime();
    void SetVolume(double volume);
    optional<ohos::multimedia::audio::AudioRendererInfo> GetAudioRendererInfo();
    void SetAudioRendererInfo(optional_view<ohos::multimedia::audio::AudioRendererInfo> audioRendererInfo);
    optional<::ohos::multimedia::audio::InterruptMode> GetAudioInterruptMode();
    void SetAudioInterruptMode(::ohos::multimedia::audio::InterruptMode audioInterruptMode);
    optional<AVDataSrcDescriptor> GetDataSrc();
    void SetDataSrc(optional_view<AVDataSrcDescriptor> dataSrc);
    optional<string> GetSurfaceId();
    void SetSurfaceId(optional_view<string> surfaceId);
    bool GetLoop();
    void SetLoop(bool loop);
    optional<ohos::multimedia::media::AVFileDescriptor> GetFdSrc();
    void SetFdSrc(optional_view<ohos::multimedia::media::AVFileDescriptor> fdSrc);
    void SetSpeed(PlaybackSpeed speed);
    void Seek(int32_t timeMs, optional_view<SeekMode> mode);
    optional<VideoScaleType> GetVideoScaleType();
    void SetVideoScaleType(optional_view<VideoScaleType> videoScaleType);
    bool IsSeekContinuousSupported();
    array<map<string, MediaDescriptionValue>> GetTrackDescriptionSync();
    int32_t GetPlaybackPosition();
    int64_t GetCurrentPresentationTimestamp();
    void SetBitrate(int32_t bitrate);
    void SetDecryptionConfig(ohos::multimedia::drm::weak::MediaKeySession mediaKeySession, bool secureVideoPath);
    ::taihe::array<MediaKeySystemInfo> GetMediaKeySystemInfos();
    void StopSync();
    void PlaySync();
    void ResetSync();
    void ReleaseSync();
    void PauseSync();
    void PrepareSync();
    void SetMediaSourceSync(ohos::multimedia::media::weak::MediaSource src, optional_view<PlaybackStrategy> strategy);
    void GetDefaultStrategy(AVPlayStrategyTmp &strategy);
    void GetPlayStrategy(AVPlayStrategyTmp &playStrategy, PlaybackStrategy strategy);
    void EnqueueMediaSourceTask(const std::shared_ptr<AVMediaSource> &mediaSource,
        const struct AVPlayStrategy &strategy);
    void AddSubtitleFromFdSync(int32_t fd, optional_view<int64_t> offset, optional_view<int64_t> length);
    array<int32_t> GetSelectedTracksSync();
    void SelectTrackSync(int32_t index, ::taihe::optional_view<::ohos::multimedia::media::SwitchMode> mode);
    void DeselectTrackSync(int32_t index);
    void AddSubtitleFromUrlSync(::taihe::string_view url);
    map<string, PlaybackInfoValue> GetPlaybackInfoSync();
    map<::ohos::multimedia::media::PlaybackMetricsKey, PlaybackMetricsValue> GetPlaybackStatisticMetricsSync();
    void SetVideoWindowSizeSync(int32_t width, int32_t height);
    void SetSuperResolutionSync(bool enabled);
    void SetPlaybackRangeSync(int32_t startTimeMs, int32_t endTimeMs,
        optional_view<::ohos::multimedia::media::SeekMode> mode);
    void SetMediaMutedSync(::ohos::multimedia::media::MediaType mediaType, bool muted);
    void SetPlaybackStrategySync(::ohos::multimedia::media::PlaybackStrategy const& strategy);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OnStateChange(callback_view<void(string_view, ohos::multimedia::media::StateChangeReason)> callback);
    void OnMediaKeySystemInfoUpdate(callback_view<void(array_view<MediaKeySystemInfo> data)> callback);
    void OnEndOfStream(callback_view<void(uintptr_t)> callback);
    void OnStartRenderFrame(callback_view<void(uintptr_t)> callback);
    void OnSeekDone(callback_view<void(int32_t)> callback);
    void OnDurationUpdate(callback_view<void(int32_t)> callback);
    void OnTimeUpdate(callback_view<void(int32_t)> callback);
    void OnVolumeChange(callback_view<void(double)> callback);
    void OnSpeedDone(callback_view<void(int32_t)> callback);
    void OnPlaybackRateDone(callback_view<void(double)> callback);
    void OnBitrateDone(callback_view<void(int32_t)> callback);
    void OnAvailableBitrates(callback_view<void(array_view<int32_t>)> callback);
    void OnAmplitudeUpdate(callback_view<void(array_view<double>)> callback);
    void OnBufferingUpdate(callback_view<void(ohos::multimedia::media::BufferingInfoType, int32_t)> callback);
    void OnVideoSizeChange(callback_view<void(int32_t, int32_t)> callback);
    void OnTrackChange(callback_view<void(int32_t, bool)> callback);
    void OnSubtitleUpdate(callback_view<void(SubtitleInfo const&)> callback);
    void OnSuperResolutionChanged(callback_view<void(bool)> callback);
    void OnTrackInfoUpdate(callback_view<void(array_view<map<string, MediaDescriptionValue>>)> callback);
    void OnSeiMessageReceived(array_view<int32_t> payloadTypes,
        callback_view<void(array_view<SeiMessage>, optional_view<int32_t>)> callback);
    void OnAudioInterrupt(callback_view<void(ohos::multimedia::audio::InterruptEvent const&)> callback);
    void OnAudioOutputDeviceChangeWithInfo(callback_view<void(
        ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)> callback);
    void OnMetricsEvent(callback_view<void(array_view<::ohos::multimedia::media::AVMetricsEvent> data)> callback);

    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OffStateChange(optional_view<callback<void(string_view,
            ohos::multimedia::media::StateChangeReason)>> callback);
    void OffMediaKeySystemInfoUpdate(optional_view<callback<void(array_view<MediaKeySystemInfo> data)>> callback);
    void OffEndOfStream(optional_view<callback<void(uintptr_t)>> callback);
    void OffStartRenderFrame(optional_view<callback<void(uintptr_t)>> callback);
    void OffSeekDone(optional_view<callback<void(int32_t)>> callback);
    void OffDurationUpdate(optional_view<callback<void(int32_t)>> callback);
    void OffTimeUpdate(optional_view<callback<void(int32_t)>> callback);
    void OffVolumeChange(optional_view<callback<void(double)>> callback);
    void OffSpeedDone(optional_view<callback<void(int32_t)>> callback);
    void OffBitrateDone(optional_view<callback<void(int32_t)>> callback);
    void OffAvailableBitrates(optional_view<callback<void(array_view<int32_t>)>> callback);
    void OffAmplitudeUpdate(optional_view<callback<void(array_view<double>)>> callback);
    void OffBufferingUpdate(optional_view<callback<void(ohos::multimedia::media::BufferingInfoType,
        int32_t)>> callback);
    void OffVideoSizeChange(optional_view<callback<void(int32_t, int32_t)>> callback);
    void OffTrackChange(optional_view<callback<void(int32_t, bool)>> callback);
    void OffSubtitleUpdate(optional_view<callback<void(SubtitleInfo const&)>> callback);
    void OffSuperResolutionChanged(optional_view<callback<void(bool)>> callback);
    void OffTrackInfoUpdate(optional_view<callback<void(array_view<map<string, int32_t>>)>> callback);
    void OffPlaybackRateDone(optional_view<callback<void(double)>> callback);
    void OffSeiMessageReceived(optional_view<array<int32_t>> payloadTypes,
        optional_view<callback<void(array_view<SeiMessage>, optional_view<int32_t>)>> callback);
    void OffAudioInterrupt(optional_view<callback<void(::ohos::multimedia::audio::InterruptEvent const&)>> callback);
    void OffAudioOutputDeviceChangeWithInfo(optional_view<callback<void(
        ::ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>> callback);
    void OffMetricsEvent(optional_view<callback<void(
        array_view<::ohos::multimedia::media::AVMetricsEvent> data)>> callback);
    bool GetIntArrayArgument(std::vector<int32_t> &vec, const std::vector<int32_t> &inputArray);
    void SeiMessageCallbackOff(std::string &callbackName, const std::vector<int32_t> &payloadTypes);
    void MaxAmplitudeCallbackOff(std::string callbackName);
    void ClearCallbackReference(const std::string &callbackName);
    void NotifyDuration(int32_t duration) override;
    void NotifyPosition(int32_t position) override;
    void NotifyState(OHOS::Media::PlayerStates state) override;
    void NotifyVideoSize(int32_t width, int32_t height) override;
    void NotifyIsLiveStream() override;
    void NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos) override;
    int32_t GetJsApiVersion() override;
    void EnqueueNetworkTask(const std::string url);
    void EnqueueFdTask(const int32_t fd);
    void SetSource(std::string url);
    void SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    PlayerSwitchMode TransferSwitchMode(int32_t mode);
    void GetAVPlayStrategyFromStrategyTmp(AVPlayStrategy &strategy, const AVPlayStrategyTmp &strategyTmp);
    void SetPlaybackRate(double rate);
    double GetPlaybackRateSync();
private:
    static bool IsSystemApp();
    void ResetUserParameters();
    void StopTaskQue();
    std::shared_ptr<TaskHandler<TaskRet>> PrepareTask();
    std::shared_ptr<TaskHandler<TaskRet>> PlayTask();
    std::shared_ptr<TaskHandler<TaskRet>> PauseTask();
    std::shared_ptr<TaskHandler<TaskRet>> StopTask();
    std::shared_ptr<TaskHandler<TaskRet>> ResetTask();
    std::shared_ptr<TaskHandler<TaskRet>> ReleaseTask();
    static void SeekEnqueueTask(AVPlayerImpl *jsPlayer, int32_t time, int32_t mode);
    static std::shared_ptr<AVMediaSource> GetAVMediaSource(ohos::multimedia::media::weak::MediaSource src,
        std::shared_ptr<AVMediaSourceTmp> &srcTmp);
    static PlayerSeekMode TransferSeekMode(int32_t mode);
    bool HandleParameter(ohos::multimedia::audio::AudioRendererInfo src,
        OHOS::AudioStandard::AudioRendererInfo &audioRendererInfo);
    void AddSubSource(std::string url);
    void SetSurface(const std::string &surfaceStr);
    void StartListenCurrentResource();
    void PauseListenCurrentResource();
    bool IsLiveSource() const;
    bool IsControllable();
    bool CanGetPlaybackStatisticMetrics();
    bool CanSetSuperResolution();
    bool IsRateValid(double rate);
    bool CanSetPlayRange();
    bool IsPalyingDurationValid(const AVPlayStrategyTmp &strategyTmp);
    void AddMediaStreamToAVMediaSource(
        const std::shared_ptr<AVMediaSourceTmp> &srcTmp, std::shared_ptr<AVMediaSource> &mediaSource);
    bool IsLivingMaxDelayTimeValid(const AVPlayStrategyTmp &strategyTmp);
    std::string GetCurrentState();
    std::shared_ptr<TaskHandler<TaskRet>> GetTrackDescriptionTask(const std::unique_ptr<AVPlayerContext> &Ctx);
    std::shared_ptr<TaskHandler<TaskRet>> SetVideoWindowSizeTask(int32_t width, int32_t height);
    std::shared_ptr<TaskHandler<TaskRet>> SetSuperResolutionTask(bool enable);
    std::shared_ptr<TaskHandler<TaskRet>> EqueueSetPlayRangeTask(int32_t start, int32_t end, int32_t mode);
    std::shared_ptr<TaskHandler<TaskRet>> SetMediaMutedTask(::OHOS::Media::MediaType type, bool isMuted);
    std::shared_ptr<TaskHandler<TaskRet>> SetPlaybackStrategyTask(AVPlayStrategy playStrategy);
    void HandleSelectTrack(int32_t index, optional_view<SwitchMode> mode);
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    std::condition_variable stopTaskQueCond_;
    bool taskQueStoped_ = false;
    std::shared_ptr<OHOS::Media::Player> player_ = nullptr;
    std::shared_ptr<AVPlayerCallback> playerCb_ = nullptr;
    std::atomic<bool> isReleased_ = false;
    OHOS::Media::PlayerStates state_ = OHOS::Media::PLAYER_IDLE;
    std::mutex mutex_;
    std::mutex taskMutex_;
    std::atomic<bool> isInterrupted_ = false;
    std::string url_ = "";
    struct OHOS::Media::AVFileDescriptor fileDescriptor_;
    std::atomic<bool> stopWait_;
    bool avplayerExit_ = false;
    std::condition_variable stateChangeCond_;
    bool isLiveStream_ = false;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    std::shared_mutex drmMutex_{};
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t duration_ = -1;
    int32_t position_ = -1;
    std::multimap<std::string, std::vector<uint8_t>> localDrmInfos_;
    std::shared_ptr<MediaDataSourceCallback> dataSrcCb_ = nullptr;
    struct DataSrcDescriptor dataSrcDescriptor_;
    int32_t audioEffectMode_ = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    std::unique_ptr<OHOS::Media::TaskQueue> taskQue_;
    bool loop_ = false;
    std::string surface_ = "";
    int32_t videoScaleType_ = 0;
    OHOS::AudioStandard::AudioRendererInfo audioRendererInfo_ = OHOS::AudioStandard::AudioRendererInfo {
        OHOS::AudioStandard::ContentType::CONTENT_TYPE_MUSIC,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA,
        0
    };
    OHOS::AudioStandard::InterruptMode interruptMode_ = OHOS::AudioStandard::InterruptMode::SHARE_MODE;
    Format playbackInfo_;
    Format playbackStatisticMetrics_;
    int32_t index_ = -1;
    int32_t mode_ = SWITCH_SMOOTH;
    std::mutex syncMutex_;
    bool getApiVersionFlag_ = true;
    bool calMaxAmplitude_ = false;
    bool seiMessageCallbackflag_ = false;
};
} // namespace ANI::Media
#endif //AVPLAYER_TAIHE_H