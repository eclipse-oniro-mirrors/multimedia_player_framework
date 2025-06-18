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

#include <map>
#include <ani.h>
#include <thread>
#include <sstream>
#include <iomanip>
#include "avplayer_callback_taihe.h"
#include "media_errors.h"
#include "media_log.h"
#include "avplayer_taihe.h"
#include "media_taihe_utils.h"
#include "audio_device_descriptor.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerCallback" };
}

namespace ANI {
namespace Media {

OHOS::AudioStandard::InterruptEvent interruptEvent_ = OHOS::AudioStandard::InterruptEvent {
    OHOS::AudioStandard::InterruptType::INTERRUPT_TYPE_BEGIN,
    OHOS::AudioStandard::InterruptForceType::INTERRUPT_FORCE,
    OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE,
};

class AniCallback {
public:
    struct Base {
        std::weak_ptr<AutoRef> callback;
        std::string callbackName = "unknown";
        Base() = default;
        virtual ~Base() = default;
        virtual void UvWork()
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "ref is nullptr");
            auto func = ref->callbackRef_;
            uintptr_t undefined = MediaTaiheUtils::GetUndefined(get_env());
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            (*cacheCallback)(static_cast<uintptr_t>(undefined));
        }

        virtual void JsCallback()
        {
            UvWork();
            delete this;
        }
    };

    struct Error : public Base {
        std::string errorMsg = "unknown";
        MediaServiceExtErrCodeAPI9 errorCode = MSERR_EXT_API9_UNSUPPORT_FORMAT;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> errorRef = callback.lock();
            CHECK_AND_RETURN_LOG(errorRef != nullptr, "ref is nullptr");
            auto func = errorRef->callbackRef_;
            auto err = MediaTaiheUtils::ToBusinessError(get_env(), errorCode, errorMsg);
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
        }
    };

    struct Int : public Base {
        int32_t value = 0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intRef = callback.lock();
            CHECK_AND_RETURN_LOG(intRef != nullptr, "ref is nullptr");
            auto func = intRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
            (*cacheCallback)(value);
        }
    };

    struct IntVecEnum : public Base {
        std::vector<uint32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr, "ref is nullptr");
            int32_t firstValueAsDouble = static_cast<int32_t>(valueVec[0]);
            int32_t val = 0;
            auto func = intVecRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(ohos::multimedia::media::BufferingInfoType, int32_t)>>
                cacheCallback = std::reinterpret_pointer_cast<taihe::callback<void
                    (ohos::multimedia::media::BufferingInfoType, int32_t)>>(func);
            ohos::multimedia::media::BufferingInfoType::key_t key;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::BufferingInfoType>(firstValueAsDouble, key);
            (*cacheCallback)(ohos::multimedia::media::BufferingInfoType(key), val);
        }
    };

    struct IntVec : public Base {
        std::vector<uint32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr, "ref is nullptr");
            int32_t firstValueAsDouble = static_cast<int32_t>(valueVec[0]);
            int32_t secondValueAsDouble = static_cast<int32_t>(valueVec[1]);
            auto func = intVecRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(int32_t, int32_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t, int32_t)>>(func);
            (*cacheCallback)(firstValueAsDouble, secondValueAsDouble);
        }
    };
    struct IntArray : public Base {
        std::vector<int32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr, "ref is nullptr");
            auto func = intVecRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(array_view<int32_t>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<int32_t>)>>(func);
            (*cacheCallback)(valueVec);
        }
    };

    struct Double :public Base {
        double value = 0.0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stateChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(stateChangeRef != nullptr, "ref is nullptr");
            auto func = stateChangeRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(double)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(double)>>(func);
            (*cacheCallback)(value);
        }
    };

    struct FloatArray : public Base {
        std::vector<float> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            CHECK_AND_RETURN_LOG(floatArrayRef != nullptr, "ref is nullptr");
            auto func = floatArrayRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(array_view<float>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<float>)>>(func);
            std::vector<float> floatVec(valueVec.begin(), valueVec.end());
            (*cacheCallback)(array_view<float>(floatVec));
        }
    };

    struct TrackInfoUpdate : public Base {
        std::vector<Format> trackInfo;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            CHECK_AND_RETURN_LOG(floatArrayRef != nullptr, "ref is nullptr");
            auto func = floatArrayRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(array_view<map<string, MediaDescriptionValue>>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void
                    (array_view<map<string, MediaDescriptionValue>>)>>(func);
            std::vector<taihe::map<taihe::string, MediaDescriptionValue>> trackInfoMaps;
            for (uint32_t i = 0; i < trackInfo.size(); i++) {
                trackInfoMaps.push_back(MediaTaiheUtils::CreateFormatBuffer(trackInfo[i]));
            }
            array_view<map<string, MediaDescriptionValue>> trackInfoView(trackInfoMaps);
            (*cacheCallback)(trackInfoView);
        }
    };

    struct TrackChange : public Base {
        int32_t number = 0;
        bool isSelect = false;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr, "ref is nullptr");
            auto func = intVecRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(int32_t, bool)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t, bool)>>(func);
            (*cacheCallback)(number, isSelect);
        }
    };

    struct StateChange : public Base {
        std::string state = "";
        int32_t reason = 0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stateChangeRef = callback.lock();
            std::shared_ptr<taihe::callback<StateChangeCallback>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<StateChangeCallback>>(stateChangeRef->callbackRef_);
            ohos::multimedia::media::StateChangeReason::key_t key;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::StateChangeReason>(reason, key);
            (*cacheCallback)(taihe::string_view(state), ohos::multimedia::media::StateChangeReason(key));
        }
    };

    struct Bool : public Base {
        bool value = false;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> boolRef = callback.lock();
            CHECK_AND_RETURN_LOG(boolRef != nullptr, "ref is nullptr");
            auto func = boolRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(bool)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(bool)>>(func);
            (*cacheCallback)(value);
        }
    };

    struct SeiInfoUpadte : public Base {
        int32_t playbackPosition;
        std::vector<Format> payloadGroup;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> seiInfoRef = callback.lock();
            CHECK_AND_RETURN_LOG(seiInfoRef != nullptr, "ref is nullptr");
            auto func = seiInfoRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(array_view<SeiMessage>, optional_view<int32_t>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<SeiMessage>,
                    optional_view<int32_t>)>>(func);
            std::vector<SeiMessage> seiMessages;
            for (const auto& format : payloadGroup) {
                uint8_t* bufferData = nullptr;
                size_t bufferLen = 0;
                ::taihe::array<uint8_t> payload(0);

                if (format.GetBuffer("payload", &bufferData, bufferLen)) {
                    payload = ::taihe::array<uint8_t>(::taihe::copy_data_t{}, bufferData, bufferLen);
                }
                SeiMessage seiMessage {
                    .payloadType = 0,
                    .payload = std::move(payload)
                };

                int32_t payloadType = 0;
                if (format.GetIntValue("payloadType", payloadType)) {
                    seiMessage.payloadType = payloadType;
                }
                seiMessages.push_back(seiMessage);
            }
            array_view<SeiMessage> seiMessageView(seiMessages);
            (*cacheCallback)(seiMessageView, optional_view<int32_t>(&playbackPosition));
        }
    };

    struct ObjectArray : public Base {
        std::multimap<std::string, std::vector<uint8_t>> infoMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> mapRef = callback.lock();
            CHECK_AND_RETURN_LOG(mapRef != nullptr, "ref is nullptr");
            auto func = mapRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            ANI::Media::MediaKeySystemInfo mediaKeySystemInfo;
            ani_object aniObject = MediaTaiheUtils::CreateMediaKeySystemInfo(get_env(), mediaKeySystemInfo);
            uintptr_t objectArray = reinterpret_cast<uintptr_t>(&aniObject);
            (*cacheCallback)(objectArray);
        }
    };

    struct SubtitleInfo : public Base {
        struct SubtitleParam {
            std::string text;
            int32_t pts;
            int32_t duration;
        } valueMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> subtitleRef = callback.lock();
            CHECK_AND_RETURN_LOG(subtitleRef != nullptr, "ref is nullptr");
            auto func = subtitleRef->callbackRef_;
            std::shared_ptr<taihe::callback<void(::ohos::multimedia::media::SubtitleInfo const&)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void
                    (::ohos::multimedia::media::SubtitleInfo const&)>>(func);
            ::ohos::multimedia::media::SubtitleInfo subtitleInfo;
            subtitleInfo.text = ::taihe::optional<taihe::string>(std::in_place_t{}, valueMap.text);
            subtitleInfo.startTime = taihe::optional<int>(std::in_place_t{}, valueMap.pts);
            subtitleInfo.duration = taihe::optional<int>(std::in_place_t{}, valueMap.duration);
            (*cacheCallback)(subtitleInfo);
        }
    };

    static void CompleteCallback(AniCallback::Base *aniCb, const AVPlayerCallback *aVPlayerCallback)
    {
        auto task = [aniCb]() {
            if (aniCb) {
                aniCb->UvWork();
            }
        };
        if (!aVPlayerCallback) {
            MEDIA_LOGE("aVPlayerCallback is null");
            return;
        }
        aVPlayerCallback->mainHandler_->PostTask(task, "On", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    }
};

bool AVPlayerCallback::IsValidState(PlayerStates state, std::string &stateStr)
{
    switch (state) {
        case PLAYER_IDLE:
            stateStr = AVPlayerState::STATE_IDLE;
            break;
        case PLAYER_INITIALIZED:
            stateStr = AVPlayerState::STATE_INITIALIZED;
            break;
        case PLAYER_PREPARED:
            stateStr = AVPlayerState::STATE_PREPARED;
            break;
        case PLAYER_STARTED:
            stateStr = AVPlayerState::STATE_PLAYING;
            break;
        case PLAYER_PAUSED:
            stateStr = AVPlayerState::STATE_PAUSED;
            break;
        case PLAYER_STOPPED:
            stateStr = AVPlayerState::STATE_STOPPED;
            break;
        case PLAYER_PLAYBACK_COMPLETE:
            stateStr = AVPlayerState::STATE_COMPLETED;
            break;
        case PLAYER_RELEASED:
            stateStr = AVPlayerState::STATE_RELEASED;
            break;
        case PLAYER_STATE_ERROR:
            stateStr = AVPlayerState::STATE_ERROR;
            break;
        default:
            return false;
    }
    return true;
}

AVPlayerCallback::AVPlayerCallback(AVPlayerNotify *listener)
    : listener_(listener)
{
    onInfoFuncs_ = {
        { INFO_TYPE_STATE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnStateChangeCb(extra, infoBody); } },
        { INFO_TYPE_VOLUME_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVolumeChangeCb(extra, infoBody); } },
        { INFO_TYPE_SEEKDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSeekDoneCb(extra, infoBody); } },
        { INFO_TYPE_SPEEDDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSpeedDoneCb(extra, infoBody); } },
        { INFO_TYPE_BITRATEDONE,
            [this](const int32_t extra, const Format &infoBody) { OnBitRateDoneCb(extra, infoBody); } },
        { INFO_TYPE_POSITION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnPositionUpdateCb(extra, infoBody); } },
        { INFO_TYPE_DURATION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnDurationUpdateCb(extra, infoBody); } },
        { INFO_TYPE_BUFFERING_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnBufferingUpdateCb(extra, infoBody); } },
        { INFO_TYPE_MESSAGE,
            [this](const int32_t extra, const Format &infoBody) { OnMessageCb(extra, infoBody);} },
        { INFO_TYPE_RESOLUTION_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVideoSizeChangedCb(extra, infoBody); } },
        { INFO_TYPE_BITRATE_COLLECT,
             [this](const int32_t extra, const Format &infoBody) { OnBitRateCollectedCb(extra, infoBody); } },
        { INFO_TYPE_EOS,
            [this](const int32_t extra, const Format &infoBody) { OnEosCb(extra, infoBody); } },
        { INFO_TYPE_IS_LIVE_STREAM,
            [this](const int32_t extra, const Format &infoBody) {NotifyIsLiveStream(extra, infoBody); } },
        { INFO_TYPE_TRACKCHANGE,
             [this](const int32_t extra, const Format &infoBody) { OnTrackChangedCb(extra, infoBody); } },
        { INFO_TYPE_TRACK_INFO_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnTrackInfoUpdate(extra, infoBody); } },
         { INFO_TYPE_SET_DECRYPT_CONFIG_DONE,
            [this](const int32_t extra, const Format &infoBody) { OnSetDecryptConfigDoneCb(extra, infoBody); } },
        { INFO_TYPE_MAX_AMPLITUDE_COLLECT,
             [this](const int32_t extra, const Format &infoBody) { OnMaxAmplitudeCollectedCb(extra, infoBody); } },
        // { INFO_TYPE_INTERRUPT_EVENT,
        //     [this](const int32_t extra, const Format &infoBody) { OnAudioInterruptCb(extra, infoBody); } },
        // { INFO_TYPE_AUDIO_DEVICE_CHANGE,
        //     [this](const int32_t extra, const Format &infoBody) { OnAudioDeviceChangeCb(extra, infoBody); } },
        { INFO_TYPE_DRM_INFO_UPDATED,
            [this](const int32_t extra, const Format &infoBody) { OnDrmInfoUpdatedCb(extra, infoBody); } },
        { INFO_TYPE_SUPER_RESOLUTION_CHANGED,
            [this](const int32_t extra, const Format &infoBody) { OnSuperResolutionChangedCb(extra, infoBody); } },
        { INFO_TYPE_SEI_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSeiInfoCb(extra, infoBody); } },
        { INFO_TYPE_SUBTITLE_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSubtitleInfoCb(extra, infoBody); } },
    };
}

void AVPlayerCallback::NotifyIsLiveStream(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    (void)infoBody;
    if (listener_ != nullptr) {
        listener_->NotifyIsLiveStream();
    }
}

void AVPlayerCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
{
    PlayerStates state = static_cast<PlayerStates>(extra);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instance OnStateChanged is called, current state: %{public}d",
        FAKE_POINTER(this), state);

    if (listener_ != nullptr) {
        listener_->NotifyState(state);
    }

    if (state_ != state) {
        state_ = state;
        std::string stateStr;
        if (IsValidState(state, stateStr)) {
            if (refMap_.find(AVPlayerEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
                MEDIA_LOGW("no stateChange cb");
                return;
            }
            AniCallback::StateChange *cb = new(std::nothrow) AniCallback::StateChange();
            CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new StateChange");

            int32_t reason = OHOS::Media::StateChangeReason::USER;
            if (infoBody.ContainKey(PlayerKeys::PLAYER_STATE_CHANGED_REASON)) {
                (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, reason);
            }
            cb->callback = refMap_.at(AVPlayerEvent::EVENT_STATE_CHANGE);
            cb->callbackName = AVPlayerEvent::EVENT_STATE_CHANGE;
            cb->state = stateStr;
            cb->reason = reason;
            AniCallback::CompleteCallback(cb, this);
        }
    }
}

void AVPlayerCallback::OnSeekDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t currentPositon = extra;
    MEDIA_LOGI("seekDone %{public}d", currentPositon);
    if (refMap_.find(AVPlayerEvent::EVENT_SEEK_DONE) == refMap_.end()) {
        MEDIA_LOGW(" can not find seekdone callback!");
        return;
    }
    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SEEK_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SEEK_DONE;
    cb->value = currentPositon;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnSpeedDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t speedMode = extra;
    MEDIA_LOGI("SpeedDone %{public}d", speedMode);
    if (refMap_.find(AVPlayerEvent::EVENT_SPEED_DONE) == refMap_.end()) {
        MEDIA_LOGW(" can not find speeddone callback!");
        return;
    }

    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SPEED_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SPEED_DONE;
    cb->value = speedMode;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnBitRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t bitRate = extra;
    MEDIA_LOGI("Bitrate %{public}d", bitRate);
    if (refMap_.find(AVPlayerEvent::EVENT_BITRATE_DONE) == refMap_.end()) {
        MEDIA_LOGW(" can not find bitrate callback!");
        return;
    }

    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_BITRATE_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_BITRATE_DONE;
    cb->value = bitRate;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnPositionUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t position = extra;
    MEDIA_LOGI("OnPositionUpdate %{public}d", position);

    if (listener_ != nullptr) {
        listener_->NotifyPosition(position);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_TIME_UPDATE) == refMap_.end()) {
        MEDIA_LOGW(" can not find timeupdate callback!");
        return;
    }

    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TIME_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_TIME_UPDATE;
    cb->value = position;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t duration = extra;
    MEDIA_LOGI("OnPositionUpdate %{public}d", duration);

    if (listener_ != nullptr) {
        listener_->NotifyDuration(duration);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_DURATION_UPDATE) == refMap_.end()) {
        MEDIA_LOGW(" can not find timeupdate callback!");
        return;
    }

    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_DURATION_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_DURATION_UPDATE;
    cb->value = duration;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnVolumeChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    float volumeLevel = 0.0;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_VOLUME_LEVEL, volumeLevel);

    isSetVolume_ = false;
    MEDIA_LOGI("OnVolumeChangeCb in volume=%{public}f", volumeLevel);
    if (refMap_.find(AVPlayerEvent::EVENT_VOLUME_CHANGE) == refMap_.end()) {
        MEDIA_LOGI("can not find vol change callback!");
        return;
    }

    AniCallback::Double *cb = new(std::nothrow) AniCallback::Double();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Double");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_VOLUME_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_VOLUME_CHANGE;
    cb->value = static_cast<double>(volumeLevel);
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnBufferingUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_BUFFERING_UPDATE) == refMap_.end()) {
        MEDIA_LOGI("can not find buffering update callback!");
        return;
    }

    int32_t val = 0;
    int32_t bufferingType = -1;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_START))) {
        bufferingType = BUFFERING_START;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_START), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_END))) {
        bufferingType = BUFFERING_END;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_END), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT))) {
        bufferingType = BUFFERING_PERCENT;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_CACHED_DURATION))) {
        bufferingType = CACHED_DURATION;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_CACHED_DURATION), val);
    } else {
        return;
    }

    MEDIA_LOGD("OnBufferingUpdateCb is called, buffering type: %{public}d value: %{public}d", bufferingType, val);
    AniCallback::IntVecEnum *cb = new(std::nothrow) AniCallback::IntVecEnum();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntVecEnum");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_BUFFERING_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_BUFFERING_UPDATE;
    cb->valueVec.push_back(bufferingType);
    cb->valueVec.push_back(val);
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnMessageCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    MEDIA_LOGI("OnMessageCb is called, extra: %{public}d", extra);
    if (extra == PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START) {
        AVPlayerCallback::OnStartRenderFrameCb();
    }
}

void AVPlayerCallback::OnStartRenderFrameCb() const
{
    MEDIA_LOGI("OnStartRenderFrameCb is called");
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_START_RENDER_FRAME) == refMap_.end()) {
        MEDIA_LOGW("can not find start render callback!");
        return;
    }

    AniCallback::Base *cb = new(std::nothrow) AniCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_START_RENDER_FRAME);
    cb->callbackName = AVPlayerEvent::EVENT_START_RENDER_FRAME;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t width = 0;
    int32_t height = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_WIDTH, width);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_HEIGHT, height);
    MEDIA_LOGI("sizeChange w %{public}d h %{public}d", width, height);

    if (listener_ != nullptr) {
        listener_->NotifyVideoSize(width, height);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find video size changed callback!");
        return;
    }
    AniCallback::IntVec *cb = new(std::nothrow) AniCallback::IntVec();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntVec");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE;
    cb->valueVec.push_back(width);
    cb->valueVec.push_back(height);
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnBitRateCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AVAILABLE_BITRATES) == refMap_.end()) {
        MEDIA_LOGW("can not find bitrate collected callback!");
        return;
    }

    std::vector<int32_t> bitrateVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES))) {
        uint8_t *addr = nullptr;
        size_t size  = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "bitrate addr is nullptr");

        MEDIA_LOGI("bitrate size = %{public}zu", size / sizeof(uint32_t));
        while (size > 0) {
            if (size < sizeof(uint32_t)) {
                break;
            }

            uint32_t bitrate = *(static_cast<uint32_t *>(static_cast<void *>(addr)));
            MEDIA_LOGI("bitrate = %{public}u", bitrate);
            addr += sizeof(uint32_t);
            size -= sizeof(uint32_t);
            bitrateVec.push_back(static_cast<int32_t>(bitrate));
        }
    }

    AniCallback::IntArray *cb = new(std::nothrow) AniCallback::IntArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AVAILABLE_BITRATES);
    cb->callbackName = AVPlayerEvent::EVENT_AVAILABLE_BITRATES;
    cb->valueVec = bitrateVec;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnTrackInfoUpdate(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    std::vector<Format> trackInfo;
    (void)infoBody.GetFormatVector(std::string(PlayerKeys::PLAYER_TRACK_INFO), trackInfo);
    MEDIA_LOGI("OnTrackInfoUpdate callback");

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE) != refMap_.end(),
        "can not find trackInfoUpdate callback!");

    AniCallback::TrackInfoUpdate *cb = new(std::nothrow) AniCallback::TrackInfoUpdate();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new TrackInfoUpdate");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_TRACK_INFO_UPDATE;
    cb->trackInfo = trackInfo;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnTrackChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t index = -1;
    int32_t isSelect = -1;
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), index);
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_IS_SELECT), isSelect);
    MEDIA_LOGI("OnTrackChangedCb index %{public}d, isSelect = %{public}d", index, isSelect);

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_TRACKCHANGE) != refMap_.end(),
        "can not find trackChange callback!");

    AniCallback::TrackChange *cb = new(std::nothrow) AniCallback::TrackChange();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new TrackChange");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TRACKCHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_TRACKCHANGE;
    cb->number = index;
    cb->isSelect = isSelect ? true : false;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnEosCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t isLooping = extra;
    MEDIA_LOGI("OnEndOfStream is called, isloop: %{public}d", isLooping);
    if (refMap_.find(AVPlayerEvent::EVENT_END_OF_STREAM) == refMap_.end()) {
        MEDIA_LOGW("can not find EndOfStream callback!");
        return;
    }

    AniCallback::Base *cb = new(std::nothrow) AniCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_END_OF_STREAM);
    cb->callbackName = AVPlayerEvent::EVENT_END_OF_STREAM;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGD("OnInfo %{public}d", type);
    if (onInfoFuncs_.count(type) > 0) {
        onInfoFuncs_[type](extra, infoBody);
    } else {
        MEDIA_LOGD(" OnInfo: %{public}d no member func supporting", type);
    }
}

AVPlayerCallback::~AVPlayerCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instance destroy", FAKE_POINTER(this));
}

void AVPlayerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    if (errorCodeApi9 == MSERR_EXT_API9_NO_PERMISSION ||
        errorCodeApi9 == MSERR_EXT_API9_NO_MEMORY ||
        errorCodeApi9 == MSERR_EXT_API9_TIMEOUT ||
        errorCodeApi9 == MSERR_EXT_API9_SERVICE_DIED ||
        errorCodeApi9 == MSERR_EXT_API9_UNSUPPORT_FORMAT) {
        Format infoBody;
        AVPlayerCallback::OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, infoBody);
    }
    AVPlayerCallback::OnErrorCb(errorCodeApi9, errorMsg);
}

void AVPlayerCallback::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::string message = MSExtAVErrorToString(errorCode) + errorMsg;
    MEDIA_LOGE("OnErrorCb:errorCode %{public}d, errorMsg %{public}s", errorCode, message.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVPlayerEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find error callback!", FAKE_POINTER(this));
        return;
    }

    AniCallback::Error *cb = new(std::nothrow) AniCallback::Error();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Error");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_ERROR);
    cb->callbackName = AVPlayerEvent::EVENT_ERROR;
    cb->errorCode = errorCode;
    cb->errorMsg = message;

    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnSetDecryptConfigDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    MEDIA_LOGI("AVPlayerCallback OnSetDecryptConfigDoneCb is called");
    if (refMap_.find(AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE) == refMap_.end()) {
        MEDIA_LOGW("can not find SetDecryptConfig Done callback!");
        return;
    }

    AniCallback::Base *cb = new(std::nothrow) AniCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("can not find max amplitude collected callback!");
        return;
    }

    std::vector<float> MaxAmplitudeVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE))) {
        uint8_t *addr = nullptr;
        size_t size  = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "max amplitude addr is nullptr");

        MEDIA_LOGD("max amplitude size = %{public}zu", size / sizeof(float));
        while (size > 0) {
            if (size < sizeof(float)) {
                break;
            }

            float maxAmplitude = *(static_cast<float *>(static_cast<void *>(addr)));
            MEDIA_LOGD("maxAmplitude = %{public}f", maxAmplitude);
            addr += sizeof(float);
            size -= sizeof(float);
            MaxAmplitudeVec.push_back(static_cast<float>(maxAmplitude));
        }
    }

    AniCallback::FloatArray *cb = new(std::nothrow) AniCallback::FloatArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_AMPLITUDE_UPDATE;
    cb->valueVec = MaxAmplitudeVec;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    MEDIA_LOGI("AVPlayerCallback OnDrmInfoUpdatedCb is called");
    if (refMap_.find(AVPlayerEvent::EVENT_DRM_INFO_UPDATE) == refMap_.end()) {
        MEDIA_LOGI("can not find drm info updated callback!");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR))) {
        MEDIA_LOGI("there's no drminfo-update drm_info_addr key");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT))) {
        MEDIA_LOGI("there's no drminfo-update drm_info_count key");
        return;
    }

    uint8_t *drmInfoAddr = nullptr;
    size_t size  = 0;
    int32_t infoCount = 0;
    infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR), &drmInfoAddr, size);
    CHECK_AND_RETURN_LOG(drmInfoAddr != nullptr && size > 0, "get drminfo buffer failed");
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT), infoCount);
    CHECK_AND_RETURN_LOG(infoCount > 0, "get drminfo count is illegal");

    std::multimap<std::string, std::vector<uint8_t>> drmInfoMap;
    int32_t ret = SetDrmInfoData(drmInfoAddr, infoCount, drmInfoMap);
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "SetDrmInfoData err");
    AniCallback::ObjectArray *cb = new(std::nothrow) AniCallback::ObjectArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new ObjectArray");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_DRM_INFO_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_DRM_INFO_UPDATE;
    cb->infoMap = drmInfoMap;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnSuperResolutionChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t enabled = 0;
    (void)infoBody.GetIntValue(PlayerKeys::SUPER_RESOLUTION_ENABLED, enabled);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnSuperResolutionChangedCb is called, enabled = %{public}d",
        FAKE_POINTER(this), enabled);

    if (refMap_.find(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED) == refMap_.end()) {
        MEDIA_LOGI("can not find super resolution changed callback!");
        return;
    }
    AniCallback::Bool *cb = new(std::nothrow) AniCallback::Bool();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Bool");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED);
    cb->callbackName = AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED;
    cb->value = enabled ? true : false;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnSeiInfoCb(const int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN_LOG(
        refMap_.find(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO) != refMap_.end(), "can not find on sei message callback!");

    (void)extra;
    int32_t playbackPosition = 0;
    bool res = infoBody.GetIntValue(Tag::AV_PLAYER_SEI_PLAYBACK_POSITION, playbackPosition);
    CHECK_AND_RETURN_LOG(res, "get playback position failed");

    std::vector<Format> formatVec;
    res = infoBody.GetFormatVector(Tag::AV_PLAYER_SEI_PLAYBACK_GROUP, formatVec);
    CHECK_AND_RETURN_LOG(res, "get sei payload group failed");

    AniCallback::SeiInfoUpadte *cb = new(std::nothrow) AniCallback::SeiInfoUpadte();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO);
    cb->callbackName = AVPlayerEvent::EVENT_SEI_MESSAGE_INFO;
    cb->playbackPosition = playbackPosition;
    cb->payloadGroup = formatVec;
    AniCallback::CompleteCallback(cb, this);
}

void AVPlayerCallback::OnSubtitleInfoCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    int32_t pts = -1;
    int32_t duration = -1;
    std::string text;
    infoBody.GetStringValue(PlayerKeys::SUBTITLE_TEXT, text);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_PTS), pts);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_DURATION), duration);
    MEDIA_LOGI("OnSubtitleInfoCb pts %{public}d, duration = %{public}d", pts, duration);

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_SUBTITLE_UPDATE) != refMap_.end(),
        "can not find Subtitle callback!");

    AniCallback::SubtitleInfo *cb = new(std::nothrow) AniCallback::SubtitleInfo();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Subtitle");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SUBTITLE_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_SUBTITLE_UPDATE;
    cb->valueMap.text = text;
    cb->valueMap.pts = pts;
    cb->valueMap.duration = duration;

    AniCallback::CompleteCallback(cb, this);
}

int32_t AVPlayerCallback::SetDrmInfoData(const uint8_t *drmInfoAddr, int32_t infoCount,
    std::multimap<std::string, std::vector<uint8_t>> &drmInfoMap)
{
    DrmInfoItem *drmInfos = reinterpret_cast<DrmInfoItem*>(const_cast<uint8_t *>(drmInfoAddr));
    if (drmInfos == nullptr) {
        MEDIA_LOGI("cast drmInfos nullptr");
        return MSERR_INVALID_VAL;
    }
    for (int32_t i = 0; i < infoCount; i++) {
        DrmInfoItem temp = drmInfos[i];
        std::stringstream ssConverter;
        std::string uuid;
        for (uint32_t index = 0; index < DrmConstant::DRM_MAX_M3U8_DRM_UUID_LEN; index++) {
            int32_t singleUuid = static_cast<int32_t>(temp.uuid[index]);
            ssConverter << std::hex << std::setfill('0') << std::setw(2) << singleUuid; // 2:w
            uuid = ssConverter.str();
        }
        std::vector<uint8_t> pssh(temp.pssh, temp.pssh + temp.psshLen);
        drmInfoMap.insert({ uuid, pssh });
    }

    if (listener_ != nullptr) {
        listener_->NotifyDrmInfoUpdated(drmInfoMap);
    }
    return MSERR_OK;
}

void AVPlayerCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
}

void AVPlayerCallback::ClearCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.erase(name);
}

void AVPlayerCallback::Start()
{
    isLoaded_ = true;
}

void AVPlayerCallback::Pause()
{
    isLoaded_ = false;
}

} // namespace Media
} // namespace ANI
