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

#ifndef CJ_AVPLAYER_CALLBACK_H
#define CJ_AVPLAYER_CALLBACK_H

#include <map>
#include <mutex>
#include "cj_avplayer_utils.h"
#include "multimedia_audio_common.h"
#include "multimedia_audio_ffi.h"
#include "player.h"

namespace OHOS {
namespace Media {
namespace AVPlayerState {
const std::string STATE_IDLE = "idle";
const std::string STATE_INITIALIZED = "initialized";
const std::string STATE_PREPARED = "prepared";
const std::string STATE_PLAYING = "playing";
const std::string STATE_PAUSED = "paused";
const std::string STATE_STOPPED = "stopped";
const std::string STATE_RELEASED = "released";
const std::string STATE_ERROR = "error";
const std::string STATE_COMPLETED = "completed";
} // namespace AVPlayerState

class CJAVPlayerNotify {
public:
    CJAVPlayerNotify() = default;
    virtual ~CJAVPlayerNotify() = default;
    virtual void NotifyDuration(int32_t duration) = 0;
    virtual void NotifyPosition(int32_t position) = 0;
    virtual void NotifyState(PlayerStates state) = 0;
    virtual void NotifyVideoSize(int32_t width, int32_t height) = 0;
    virtual void NotifyIsLiveStream() = 0;
    virtual void NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos) = 0;
};
using OnInfoFunc = std::function<void(const int32_t, const Format &)>;
class CJAVPlayerCallback : public PlayerCallback {
public:
    explicit CJAVPlayerCallback(CJAVPlayerNotify *listener);
    virtual ~CJAVPlayerCallback();
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    void Start();
    void Pause();
    void Release();

    std::atomic<bool> isSetVolume_ = false;

    void OnStartRenderFrameCb() const;
    void OnStateChangeCb(const int32_t extra, const Format &infoBody);
    void OnVolumeChangeCb(const int32_t extra, const Format &infoBody);
    void OnSeekDoneCb(const int32_t extra, const Format &infoBody);
    void OnSpeedDoneCb(const int32_t extra, const Format &infoBody);
    void OnBitRateDoneCb(const int32_t extra, const Format &infoBody);
    void OnPositionUpdateCb(const int32_t extra, const Format &infoBody);
    void OnDurationUpdateCb(const int32_t extra, const Format &infoBody);
    void OnBufferingUpdateCb(const int32_t extra, const Format &infoBody);
    void OnMessageCb(const int32_t extra, const Format &infoBody);
    void OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody);
    void OnAudioInterruptCb(const int32_t extra, const Format &infoBody);
    void OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody);
    void OnBitRateCollectedCb(const int32_t extra, const Format &infoBody);
    void OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody);
    void OnSubtitleInfoCb(const int32_t extra, const Format &infoBody);
    void OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody);

    void OnEosCb(const int32_t extra, const Format &infoBody);
    void OnTrackChangedCb(const int32_t extra, const Format &infoBody);
    void OnTrackInfoUpdate(const int32_t extra, const Format &infoBody);
    bool IsValidState(PlayerStates state, std::string &stateStr);
    int32_t SetDrmInfoData(const uint8_t *drmInfoAddr, int32_t infoCount,
                           std::multimap<std::string, std::vector<uint8_t>> &drmInfoMap);

    int64_t stateChangeCallbackId = -1;
    std::function<void(std::string &stateStr, int32_t reason)> stateChangeCallback = nullptr;
    int64_t errorCallbackId = -1;
    std::function<void(int32_t errorCode, const std::string &errorMsg)> errorCallback = nullptr;
    int64_t seekDoneCallbackId = -1;
    std::function<void(int32_t currentPositon)> seekDoneCallback = nullptr;
    int64_t speedDoneCallbackId = -1;
    std::function<void(int32_t speedMode)> speedDoneCallback = nullptr;
    int64_t bitRateDoneCallbackId = -1;
    std::function<void(int32_t bitRate)> bitRateDoneCallback = nullptr;
    int64_t mediaKeySystemInfoUpdateCallbackId = -1;
    std::function<void(CArrCMediaKeySystemInfo drmInfoMap)> mediaKeySystemInfoUpdateCallback = nullptr;
    int64_t availableBitratesCallbackId = -1;
    std::function<void(std::vector<int32_t> bitrateVec)> availableBitratesCallback = nullptr;
    int64_t volumeChangeCallbackId = -1;
    std::function<void(float volumeLevel)> volumeChangeCallback = nullptr;
    int64_t endOfStreamCallbackId = -1;
    std::function<void()> endOfStreamCallback = nullptr;
    int64_t timeUpdateCallbackId = -1;
    std::function<void(int32_t position)> timeUpdateCallback = nullptr;
    int64_t durationUpdateCallbackId = -1;
    std::function<void(int32_t duration)> durationUpdateCallback = nullptr;
    int64_t bufferingUpdateCallbackId = -1;
    std::function<void(int32_t bufferingType, int32_t val)> bufferingUpdateCallback = nullptr;
    int64_t startRenderFrameCallbackId = -1;
    std::function<void()> startRenderFrameCallback = nullptr;
    int64_t videoSizeChangeCallbackId = -1;
    std::function<void(int32_t width, int32_t height)> videoSizeChangeCallback = nullptr;
    int64_t audioInterruptCallbackId = -1;
    std::function<void(int32_t eventType, int32_t forceType, int32_t hintType)> audioInterruptCallback = nullptr;
    int64_t audioDeviceChangeCallbackId = -1;
    std::function<void(AudioStandard::AudioDeviceDescriptor deviceInfo, int32_t reason)> audioDeviceChangeCallback =
        nullptr;
    int64_t subtitleUpdateCallbackId = -1;
    std::function<void(std::string text, int32_t pts, int32_t duration)> subtitleUpdateCallback = nullptr;
    int64_t trackChangeCallbackId = -1;
    std::function<void(int32_t index, int32_t isSelect)> trackChangeCallback = nullptr;
    int64_t trackInfoUpdateCallbackId = -1;
    std::function<void(CArrCMediaDescription trackInfo)> trackInfoUpdateCallback = nullptr;
    int64_t amplitudeUpdateCallbackId = -1;
    std::function<void(std::vector<float> MaxAmplitudeVec)> amplitudeUpdateCallback = nullptr;

private:
    std::mutex mutex_;
    CJAVPlayerNotify *listener_ = nullptr;
    std::atomic<bool> isloaded_ = false;
    PlayerStates state_ = PLAYER_IDLE;
    std::map<uint32_t, OnInfoFunc> onInfoFuncs_;
};

} // namespace Media
} // namespace OHOS
#endif // CJ_AVPLAYER_CALLBACK_H
