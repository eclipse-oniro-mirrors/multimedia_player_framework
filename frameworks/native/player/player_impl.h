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

#ifndef PLAYER_IMPL_H
#define PLAYER_IMPL_H

#include "player.h"
#include "nocopyable.h"
#include "osal/task/autolock.h"
#include "i_player_service.h"
#include "hitrace/tracechain.h"
#include "hiappevent_agent.h"
#include "common/fdsan_fd.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
class PlayerImpl : public Player, public NoCopyable, public std::enable_shared_from_this<PlayerImpl> {
public:
    PlayerImpl();
    ~PlayerImpl();

    int32_t SetSource(const std::string &url) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    int32_t Prepare() override;
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size) override;
    int32_t Pause() override;
    int32_t Play() override;
    int32_t Reset() override;
    int32_t SetRenderFirstFrame(bool display) override;
    int32_t SetPlayRange(int64_t start, int64_t end) override;
    int32_t SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode = SEEK_PREVIOUS_SYNC) override;
    int32_t SetPlayRangeUsWithMode(int64_t start, int64_t end, PlayerSeekMode mode = SEEK_PREVIOUS_SYNC) override;
    int32_t PrepareAsync() override;
    int32_t AddSubSource(const std::string &url) override;
    int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t ReleaseSync() override;
    int32_t SetVolume(float leftVolume, float rightVolume) override;
    int32_t SetVolumeMode(int32_t mode) override;
    int32_t GetCurrentTime(int32_t &currentTime) override;
    int32_t GetPlaybackPosition(int32_t &playbackPosition) override;
    int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) override;
    int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) override;
    int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) override;
    int32_t GetPlaybackInfo(Format &playbackInfo) override;
    int32_t GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics) override;
    int32_t GetVideoWidth() override;
    int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) override;
    int32_t GetVideoHeight() override;
    int32_t SetPlaybackSpeed(PlaybackRateMode mode) override;
    int32_t SetPlaybackRate(float rate) override;
    int32_t GetDuration(int32_t &duration) override;
    int32_t GetApiVersion(int32_t &apiVersion) override;
    int32_t GetPlaybackSpeed(PlaybackRateMode &mode) override;
    int32_t GetPlaybackRate(float &rate) override;
    int32_t SetLooping(bool loop) override;
#ifdef SUPPORT_VIDEO
    int32_t SetVideoSurface(sptr<Surface> surface) override;
#endif
    bool IsPlaying() override;
    int32_t SetParameter(const Format &param) override;
    bool IsLooping() override;
    int32_t SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback) override;
    int32_t SelectBitRate(uint32_t bitRate) override;
    int32_t SelectTrack(int32_t index, PlayerSwitchMode mode) override;
    int32_t DeselectTrack(int32_t index) override;
    int32_t GetCurrentTrack(int32_t trackType, int32_t &index) override;
    int32_t SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp) override;
    int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) override;
    int32_t Init(const PlayerProducer producer = PlayerProducer::INNER);
    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody);
    int32_t SetPlaybackStrategy(AVPlayStrategy playbackStrategy) override;
    int32_t SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted) override;
    int32_t SetSuperResolution(bool enabled) override;
    int32_t SetVideoWindowSize(int32_t width, int32_t height) override;
    int32_t SetMaxAmplitudeCbStatus(bool status) override;
    int32_t SetDeviceChangeCbStatus(bool status) override;
    bool IsSeekContinuousSupported() override;
    int32_t SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes) override;
    int32_t EnableReportMediaProgress(bool enable) override;
    int32_t EnableReportAudioInterrupt(bool enable) override;
    int32_t SetStartFrameRateOptEnabled(bool enabled) override;
    bool ReleaseClientListener() override;
    HiviewDFX::HiTraceId GetTraceId();
    int32_t SetReopenFd(int32_t fd) override;
    int32_t EnableCameraPostprocessing() override;
    int32_t SetCameraPostprocessing(bool isOpen) override;
    void TraceApiEvent(int errCode, const std::string& message, time_t startTime);
    int32_t ForceLoadVideo(bool status) override;
    int32_t SetLoudnessGain(float loudnessGain) override;
    int32_t GetGlobalInfo(std::shared_ptr<Meta> &globalInfo) override;
    int32_t GetMediaDescription(Format &format) override;
    int32_t GetTrackDescription(Format &format, uint32_t trackIndex) override;
    int32_t RegisterDeviceCapability(IsAudioPassthrough callback, GetDolbyList getDolbyList) override;
private:
    void ResetSeekVariables();
    void HandleSeekDoneInfo(PlayerOnInfoType type, int32_t extra);
    int32_t SetSourceTask(int32_t fd, int64_t offset, int64_t size);
    std::recursive_mutex recMutex_;
    int32_t mCurrentPosition = INT32_MIN;
    PlayerSeekMode mCurrentSeekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    int32_t mSeekPosition = INT32_MIN;
    PlayerSeekMode mSeekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    std::atomic<bool> isSeeking_{false};
    int32_t prevTrackIndex_ = INT32_MIN;
    std::shared_ptr<PlayerCallback> callback_;
    std::unique_ptr<FdsanFd> fdsanFd_ = nullptr;

    std::shared_ptr<IPlayerService> playerService_ = nullptr;
    sptr<Surface> surface_ = nullptr;
    HiviewDFX::HiTraceId traceId_;
    std::mutex cbMutex_;
    std::shared_ptr<HiAppEventAgent> hiAppEventAgent_ = nullptr;
    int64_t prepareStartTimeMs_ = -1;
};

class PlayerImplCallback : public PlayerCallback {
public:
    PlayerImplCallback(const std::shared_ptr<PlayerCallback> playerCb, std::shared_ptr<PlayerImpl> player);
    ~PlayerImplCallback() = default;

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody);
    void OnError(int32_t errorCode, const std::string &errorMsg);
private:
    std::shared_ptr<PlayerCallback> playerCb_;
    std::weak_ptr<PlayerImpl> player_;
    std::mutex playerImplCbMutex_;
    bool getApiVersionFlag_ = true;
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_IMPL_H
