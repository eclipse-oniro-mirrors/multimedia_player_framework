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
#ifndef AVPLAYER_CALLBACK_TAIHE_H
#define AVPLAYER_CALLBACK_TAIHE_H

#include <map>
#include <mutex>
#include <ani.h>
#include "media_errors.h"
#include "player.h"
#include "event_handler.h"
#include "audio_info.h"
#include "audio_effect.h"
#include "audio_device_descriptor.h"
#include "common_taihe.h"

namespace ANI {
namespace Media {
using namespace OHOS::Media;

extern OHOS::AudioStandard::InterruptEvent interruptEvent_;
class AVPlayerNotify {
public:
    AVPlayerNotify() = default;
    virtual ~AVPlayerNotify() = default;
    virtual void NotifyDuration(int32_t duration) = 0;
    virtual void NotifyPosition(int32_t position) = 0;
    virtual void NotifyState(PlayerStates state) = 0;
    virtual void NotifyVideoSize(int32_t width, int32_t height) = 0;
    virtual void NotifyIsLiveStream() = 0;
    virtual void NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos) = 0;
    virtual int32_t GetJsApiVersion();
};

using OnInfoFunc = std::function<void(const int32_t, const Format &)>;
class AVPlayerCallback : public PlayerCallback, public std::enable_shared_from_this<AVPlayerCallback> {
public:
    AVPlayerCallback(AVPlayerNotify *listener);
    virtual ~AVPlayerCallback();
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;
    bool IsValidState(PlayerStates state, std::string &stateStr);
    void NotifyIsLiveStream(const int32_t extra, const Format &infoBody);
    void OnStateChangeCb(const int32_t extra, const Format &infoBody);
    void OnSeekDoneCb(const int32_t extra, const Format &infoBody);
    void OnSpeedDoneCb(const int32_t extra, const Format &infoBody);
    void OnPlaybackRateDoneCb(const int32_t extra, const Format &infoBody);
    void OnBitRateDoneCb(const int32_t extra, const Format &infoBody);
    void OnVolumeChangeCb(const int32_t extra, const Format &infoBody);
    void OnPositionUpdateCb(const int32_t extra, const Format &infoBody);
    void OnDurationUpdateCb(const int32_t extra, const Format &infoBody);
    void OnBufferingUpdateCb(const int32_t extra, const Format &infoBody);
    void OnMessageCb(const int32_t extra, const Format &infoBody);
    void OnStartRenderFrameCb() const;
    void OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody);
    void OnBitRateCollectedCb(const int32_t extra, const Format &infoBody);
    void OnEosCb(const int32_t extra, const Format &infoBody);
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    void OnSetDecryptConfigDoneCb(const int32_t extra, const Format &infoBody);
    void OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody);
    void OnTrackInfoUpdate(const int32_t extra, const Format &infoBody);
    void OnTrackChangedCb(const int32_t extra, const Format &infoBody);
    void OnAudioInterruptCb(const int32_t extra, const Format &infoBody);
    void OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody);
    void OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody);
    void OnSuperResolutionChangedCb(const int32_t extra, const Format &infoBody);
    void OnSeiInfoCb(const int32_t extra, const Format &infoBody);
    void OnSubtitleInfoCb(const int32_t extra, const Format &infoBody);
    void OnMetricsEventCb(const int32_t extra, const Format &infoBody);
    int32_t SetDrmInfoData(const uint8_t *drmInfoAddr, int32_t infoCount,
        std::multimap<std::string, std::vector<uint8_t>> &drmInfoMap);
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void ClearCallbackReference(const std::string &name);
    void Start();
    void Pause();
    void Release();
    std::atomic<bool> isSetVolume_ = false;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
private:
    std::mutex mutex_;
    std::atomic<bool> isLoaded_ = false;
    AVPlayerNotify *listener_ = nullptr;
    std::map<uint32_t, OnInfoFunc> onInfoFuncs_;
    PlayerStates state_ = PLAYER_IDLE;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};
} // namespace Media
} // namespace ANI
#endif // AVPLAYER_CALLBACK_TAIHE_H