/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_AVPLAYER_H
#define CJ_AVPLAYER_H

#include "audio_effect.h"
#include "cj_avplayer_callback.h"
#include "cj_avplayer_utils.h"
#include "cj_common_ffi.h"
#include "cj_lambda.h"
#include "cj_media_data_source_callback.h"
#include "ffi_remote_data.h"
#include "media_data_source_callback.h"
#include "player.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {
class CJAVPlayer : public OHOS::FFI::FFIData, public CJAVPlayerNotify {
    DECL_TYPE(CJAVPlayer, OHOS::FFI::FFIData)
public:
    CJAVPlayer();
    ~CJAVPlayer() override;
    bool Constructor();

    void NotifyDuration(int32_t duration) override;
    void NotifyPosition(int32_t position) override;
    void NotifyState(PlayerStates state) override;
    void NotifyVideoSize(int32_t width, int32_t height) override;
    void NotifyIsLiveStream() override;
    void NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos) override;

    char *GetUrl();
    void SetUrl(char *url);
    CAVFileDescriptor GetAVFileDescriptor();
    void SetAVFileDescriptor(CAVFileDescriptor fileDescriptor);
    CAVDataSrcDescriptor GetDataSrc();
    void SetDataSrc(CAVDataSrcDescriptor dataSrcDescriptor);
    char *GetSurfaceID();
    void SetSurfaceID(char *surfaceId);
    bool GetLoop();
    void SetLoop(bool loop);
    int32_t GetVideoScaleType();
    void SetVideoScaleType(int32_t videoScaleType);
    int32_t GetAudioInterruptMode();
    void SetAudioInterruptMode(int32_t interruptMode);
    OHOS::AudioStandard::CAudioRendererInfo GetAudioRendererInfo();
    void SetAudioRendererInfo(OHOS::AudioStandard::CAudioRendererInfo info);
    int32_t GetAudioEffectMode();
    void SetAudioEffectMode(int32_t effectMode);
    char *GetState();
    int32_t GetCurrentTime();
    int32_t GetDuration();
    int32_t GetWidth();
    int32_t GetHeight();

    int32_t PrepareTask();
    int32_t Prepare();
    int32_t PlayTask();
    int32_t Play();
    int32_t PauseTask();
    int32_t Pause();
    int32_t StopTask();
    int32_t Stop();
    int32_t ResetTask();
    int32_t Reset();
    int32_t ReleaseTask();
    int32_t Release();
    void SeekTask(int32_t time, int32_t mode);
    void Seek(int32_t time, int32_t mode);

    int32_t OnStateChange(int64_t callbackId);
    int32_t OffStateChange(int64_t callbackId);
    int32_t OffStateChangeAll();
    int32_t OnError(int64_t callbackId);
    int32_t OffError(int64_t callbackId);
    int32_t OffErrorAll();
    int32_t OnSeekDone(int64_t callbackId);
    int32_t OffSeekDone(int64_t callbackId);
    int32_t OffSeekDoneAll();
    int32_t OnSpeedDone(int64_t callbackId);
    int32_t OffSpeedDone(int64_t callbackId);
    int32_t OffSpeedDoneAll();
    int32_t OnBitRateDone(int64_t callbackId);
    int32_t OffBitRateDone(int64_t callbackId);
    int32_t OffBitRateDoneAll();
    int32_t OnAvailableBitrates(int64_t callbackId);
    int32_t OffAvailableBitrates(int64_t callbackId);
    int32_t OffAvailableBitratesAll();
    int32_t OnMediaKeySystemInfoUpdate(int64_t callbackId);
    int32_t OffMediaKeySystemInfoUpdate(int64_t callbackId);
    int32_t OffMediaKeySystemInfoUpdateAll();
    int32_t OnVolumeChange(int64_t callbackId);
    int32_t OffVolumeChange(int64_t callbackId);
    int32_t OffVolumeChangeAll();
    int32_t OnEndOfStream(int64_t callbackId);
    int32_t OffEndOfStream(int64_t callbackId);
    int32_t OffEndOfStreamAll();
    int32_t OnTimeUpdate(int64_t callbackId);
    int32_t OffTimeUpdate(int64_t callbackId);
    int32_t OffTimeUpdateAll();
    int32_t OnDurationUpdate(int64_t callbackId);
    int32_t OffDurationUpdate(int64_t callbackId);
    int32_t OffDurationUpdateAll();
    int32_t OnBufferingUpdate(int64_t callbackId);
    int32_t OffBufferingUpdate(int64_t callbackId);
    int32_t OffBufferingUpdateAll();
    int32_t OnStartRenderFrame(int64_t callbackId);
    int32_t OffStartRenderFrame(int64_t callbackId);
    int32_t OffStartRenderFrameAll();
    int32_t OnVideoSizeChange(int64_t callbackId);
    int32_t OffVideoSizeChange(int64_t callbackId);
    int32_t OffVideoSizeChangeAll();
    int32_t OnAudioInterrupt(int64_t callbackId);
    int32_t OffAudioInterrupt(int64_t callbackId);
    int32_t OffAudioInterruptAll();
    int32_t OnAudioDeviceChange(int64_t callbackId);
    int32_t OffAudioDeviceChange(int64_t callbackId);
    int32_t OffAudioDeviceChangeAll();
    int32_t OnSubtitleUpdate(int64_t callbackId);
    int32_t OffSubtitleUpdate(int64_t callbackId);
    int32_t OffSubtitleUpdateAll();
    int32_t OnTrackChange(int64_t callbackId);
    int32_t OffTrackChange(int64_t callbackId);
    int32_t OffTrackChangeAll();
    int32_t OnTrackInfoUpdate(int64_t callbackId);
    int32_t OffTrackInfoUpdate(int64_t callbackId);
    int32_t OffTrackInfoUpdateAll();
    int32_t OnAmplitudeUpdate(int64_t callbackId);
    int32_t OffAmplitudeUpdate(int64_t callbackId);
    int32_t OffAmplitudeUpdateAll();

    std::string GetCurrentState();
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    void StartListenCurrentResource();
    void SetSource(std::string url);
    void EnqueueNetworkTask(const std::string url);
    void EnqueueFdTask(const int32_t fd);
    void QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    bool IsLiveSource() const;
    bool IsControllable();
    void PauseListenCurrentResource();
    void ResetUserParameters();
    PlayerSeekMode TransferSeekMode(int32_t mode);
    int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy);
    int32_t SetPlaybackStrategy(AVPlayStrategy strategy);
    int32_t SetMediaMuted(int32_t mediaType, bool muted);
    int32_t GetSelectedTracks(std::vector<int32_t> &trackIndex);
    int32_t SelectTrack(int32_t index, int32_t mode);
    int32_t DeselectTrack(int32_t index);
    std::multimap<std::string, std::vector<uint8_t>> GetMediaKeySystemInfos();
    void SetSpeed(int32_t speed);
    void SetBitrate(int32_t bitrate);
    void SetVolume(float volume);
    int32_t AddSubtitleFromFd(int32_t fd, int64_t offset, int64_t length);
    int32_t AddSubtitleFromUrl(std::string url);
    int32_t GetPlaybackInfo(Format &format);
    int32_t GetTrackDescription(std::vector<Format> &trackInfos);
    bool HandleParameter(OHOS::AudioStandard::CAudioRendererInfo info);
    void SetSurface(const std::string &surfaceStr);

private:
    std::shared_ptr<Player> player_ = nullptr;
    std::shared_ptr<CJAVPlayerCallback> playerCb_ = nullptr;
    std::shared_ptr<CJMediaDataSourceCallback> dataSrcCb_ = nullptr;
    std::atomic<bool> isReleased_ = false;
    std::atomic<bool> isInterrupted_ = false;
    std::string url_ = "";
    struct AVFileDescriptor fileDescriptor_;
    std::string surface_ = "";
    bool loop_ = false;
    int32_t videoScaleType_ = 0;
    OHOS::AudioStandard::InterruptMode interruptMode_ = AudioStandard::InterruptMode::SHARE_MODE;
    OHOS::AudioStandard::AudioRendererInfo audioRendererInfo_ = OHOS::AudioStandard::AudioRendererInfo{
        OHOS::AudioStandard::ContentType::CONTENT_TYPE_MUSIC, OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA, 0};
    int32_t audioEffectMode_ = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    std::mutex mutex_;
    std::mutex taskMutex_;
    PlayerStates state_ = PLAYER_IDLE;
    std::condition_variable stateChangeCond_;
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t position_ = -1;
    int32_t duration_ = -1;
    bool isLiveStream_ = false;
    std::multimap<std::string, std::vector<uint8_t>> localDrmInfos_;
    std::mutex syncMutex_;
};

} // namespace Media
} // namespace OHOS
#endif