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
constexpr int32_t ARGS_TWO = 2;
constexpr int32_t ARGS_THREE = 3;
constexpr int32_t ARGS_FOUR = 4;
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

    static ohos::multimedia::audio::AudioDeviceDescriptor GetDeviceInfo(
        OHOS::AudioStandard::AudioDeviceDescriptor deviceInfo)
    {
        ohos::multimedia::audio::DeviceRole::key_t deviceRoleKey;
        MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceRole>(
            deviceInfo.deviceRole_, deviceRoleKey);
        ohos::multimedia::audio::DeviceType::key_t deviceTypeKey;
        MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceType>(
            deviceInfo.deviceType_, deviceTypeKey);
        taihe::string name = MediaTaiheUtils::ToTaiheString(deviceInfo.deviceName_);
        taihe::string address = MediaTaiheUtils::ToTaiheString(deviceInfo.macAddress_);
        std::vector<int32_t> samplingRateVec(
            deviceInfo.audioStreamInfo_.front().samplingRate.begin(),
            deviceInfo.audioStreamInfo_.front().samplingRate.end());
        std::vector<int32_t> channelsVec(deviceInfo.audioStreamInfo_.front().channelLayout.begin(),
            deviceInfo.audioStreamInfo_.front().channelLayout.end());
        taihe::string networkId = MediaTaiheUtils::ToTaiheString(deviceInfo.networkId_);
        taihe::string displayName = MediaTaiheUtils::ToTaiheString(
            deviceInfo.displayName_);
        ohos::multimedia::audio::AudioEncodingType::key_t audioEncodingTypeKey;
        MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEncodingType>(
            deviceInfo.audioStreamInfo_.front().encoding, audioEncodingTypeKey);
        std::vector<int32_t> channelMasks;
        channelMasks.push_back(deviceInfo.channelMasks_);
        std::vector<ohos::multimedia::audio::AudioEncodingType> audioEncodingType;
        audioEncodingType.push_back(audioEncodingTypeKey);

        ohos::multimedia::audio::AudioDeviceDescriptor descriptor {
            std::move(ohos::multimedia::audio::DeviceRole(deviceRoleKey)),
            std::move(ohos::multimedia::audio::DeviceType(deviceTypeKey)),
            std::move(deviceInfo.deviceId_),
            std::move(name),
            std::move(address),
            array<int32_t>(samplingRateVec),
            array<int32_t>(channelsVec),
            array<int32_t>(channelMasks),
            std::move(networkId),
            std::move(deviceInfo.interruptGroupId_),
            std::move(deviceInfo.volumeGroupId_),
            std::move(displayName),
            optional<::taihe::array<ohos::multimedia::audio::AudioEncodingType>>(
                std::in_place_t{}, array<ohos::multimedia::audio::AudioEncodingType>(audioEncodingType)),
            optional<bool>(std::nullopt),
            optional<int32_t>(std::nullopt),
        };
        return descriptor;
    }
    struct Base {
        std::weak_ptr<AutoRef> callback;
        std::string callbackName = "unknown";
        Base() = default;
        virtual ~Base() = default;
        virtual void UvWork()
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = ref->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(errorRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = errorRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(intRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = intRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(intVecRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            CHECK_AND_RETURN_LOG(valueVec.size() > 0, "valueVec is empty");
            int32_t firstValueAsDouble = static_cast<int32_t>(valueVec[0]);
            int32_t val = 0;
            auto func = intVecRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(intVecRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            CHECK_AND_RETURN_LOG(valueVec.size() > 1, "valueVec size is less than 2");
            auto func = intVecRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(int32_t, int32_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t, int32_t)>>(func);
            (*cacheCallback)(valueVec[0], valueVec[1]);
        }
    };
    struct IntArray : public Base {
        std::vector<int32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = intVecRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(array_view<int32_t>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<int32_t>)>>(func);
            (*cacheCallback)(valueVec);
        }
    };

    struct Double :public Base {
        double value = 0.0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> doubleRef = callback.lock();
            CHECK_AND_RETURN_LOG(doubleRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = doubleRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(floatArrayRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = floatArrayRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(array_view<double>)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<double>)>>(func);
            std::vector<double> floatVec(valueVec.begin(), valueVec.end());
            (*cacheCallback)(array_view<double>(floatVec));
        }
    };

    struct TrackInfoUpdate : public Base {
        std::vector<Format> trackInfo;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            CHECK_AND_RETURN_LOG(floatArrayRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = floatArrayRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            std::shared_ptr<AutoRef> trackChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(trackChangeRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = trackChangeRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(stateChangeRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = stateChangeRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<StateChangeCallback>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<StateChangeCallback>>(func);
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
            CHECK_AND_RETURN_LOG(boolRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = boolRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            CHECK_AND_RETURN_LOG(seiInfoRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = seiInfoRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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
            (*cacheCallback)(seiMessageView, optional<int32_t>::make(playbackPosition));
        }
    };
    struct PropertyInt : public Base {
        std::map<std::string, int32_t> valueMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> propertyIntRef = callback.lock();
            CHECK_AND_RETURN_LOG(propertyIntRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            auto func = propertyIntRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(ohos::multimedia::audio::InterruptEvent const&)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(
                    ohos::multimedia::audio::InterruptEvent const&)>>(func);

            ohos::multimedia::audio::InterruptEvent interruptEvent = {
                .eventType = ohos::multimedia::audio::InterruptType(static_cast<
                    ohos::multimedia::audio::InterruptType::key_t>(valueMap["eventType"])),
                .forceType = ohos::multimedia::audio::InterruptForceType(static_cast<
                    ohos::multimedia::audio::InterruptForceType::key_t>(valueMap["forceType"])),
                .hintType = ohos::multimedia::audio::InterruptHint(static_cast<
                    ohos::multimedia::audio::InterruptHint::key_t>(valueMap["hintType"])),
            };

            (*cacheCallback)(interruptEvent);
        }
    };

    struct DeviceChangeAni : public Base {
        OHOS::AudioStandard::AudioDeviceDescriptor deviceInfo =
            OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::AudioDeviceDescriptor::DEVICE_INFO);
        int32_t reason;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> deviceChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(deviceChangeRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            auto func = deviceChangeRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>>
                cacheCallback = std::reinterpret_pointer_cast<
                    taihe::callback<void(ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>>(func);

            std::vector<ohos::multimedia::audio::AudioDeviceDescriptor> audioDeviceDescriptor;
            audioDeviceDescriptor.push_back(GetDeviceInfo(deviceInfo));

            ohos::multimedia::audio::AudioStreamDeviceChangeReason::key_t changeReasonKey;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioStreamDeviceChangeReason>(
                reason, changeReasonKey);
            ohos::multimedia::audio::AudioStreamDeviceChangeReason changeReason =
                static_cast<ohos::multimedia::audio::AudioStreamDeviceChangeReason>(changeReasonKey);

            ohos::multimedia::audio::AudioStreamDeviceChangeInfo audioStreamDeviceChangeInfo = {
                array<ohos::multimedia::audio::AudioDeviceDescriptor>(audioDeviceDescriptor),
                std::move(changeReason),
            };

            (*cacheCallback)(audioStreamDeviceChangeInfo);
        }
    };
    struct ObjectArray : public Base {
        std::multimap<std::string, std::vector<uint8_t>> infoMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> mapRef = callback.lock();
            CHECK_AND_RETURN_LOG(mapRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            auto func = mapRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(array_view<MediaKeySystemInfo> data)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(array_view<MediaKeySystemInfo> data)>>(func);
            std::vector<MediaKeySystemInfo> infoArray;
            for (auto item : infoMap) {
                MediaKeySystemInfo info{
                    item.first,
                    array<uint8_t>(copy_data_t{}, item.second.data(), item.second.size())
                };
                infoArray.push_back(info);
            }
            (*cacheCallback)(array<MediaKeySystemInfo>(copy_data_t{}, infoArray.data(), infoArray.size()));
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
            CHECK_AND_RETURN_LOG(subtitleRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());
            auto func = subtitleRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
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

    struct MetricsEvent : public Base {
        std::vector<int64_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stallingRef = callback.lock();
            CHECK_AND_RETURN_LOG(stallingRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            auto func = stallingRef->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<taihe::callback<void(
                array_view<::ohos::multimedia::media::AVMetricsEvent> data)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(
                    array_view<::ohos::multimedia::media::AVMetricsEvent> data)>>(func);

            int32_t aVMetricsEventType = static_cast<int32_t>(valueVec[0]);
            ohos::multimedia::media::AVMetricsEventType::key_t aVMetricsEventTypeKey;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::AVMetricsEventType>(
                aVMetricsEventType, aVMetricsEventTypeKey);
            std::map<std::string, int64_t> detailMap = {{"media_type", valueVec[ARGS_FOUR]},
                {"duration", valueVec[ARGS_THREE]}};
            map<string, int64_t> taiheHeader;
            for (const auto& [key, value] : detailMap) {
                taiheHeader.emplace(taihe::string(key), value);
            }
            ::ohos::multimedia::media::AVMetricsEvent aVMetricsEvent {
                .event = ohos::multimedia::media::AVMetricsEventType(aVMetricsEventTypeKey),
                .timeStamp = valueVec[1],
                .playbackPosition = valueVec[ARGS_TWO],
                .details = taiheHeader,
            };
            std::vector<::ohos::multimedia::media::AVMetricsEvent> infoArray;
            infoArray.push_back(aVMetricsEvent);
            (*cacheCallback)(array<::ohos::multimedia::media::AVMetricsEvent>(copy_data_t{},
                infoArray.data(), infoArray.size()));
        }
    };

    static void CompleteCallback(AniCallback::Base *aniCb, std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler)
    {
        CHECK_AND_RETURN_LOG(aniCb != nullptr, "aniCb is nullptr");
        CHECK_AND_RETURN_LOG(mainHandler != nullptr, "callback failed, mainHandler is nullptr!");
        auto task = [aniCb]() {
            if (aniCb) {
                aniCb->UvWork();
                delete aniCb;
            }
        };
        bool ret = mainHandler->PostTask(task, "On", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
        if (!ret) {
            MEDIA_LOGE("Failed to PostTask!");
            delete aniCb;
        }
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
        { INFO_TYPE_RATEDONE,
            [this](const int32_t extra, const Format &infoBody) {OnPlaybackRateDoneCb(extra, infoBody); } },
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
        { INFO_TYPE_DRM_INFO_UPDATED,
            [this](const int32_t extra, const Format &infoBody) { OnDrmInfoUpdatedCb(extra, infoBody); } },
        { INFO_TYPE_SUPER_RESOLUTION_CHANGED,
            [this](const int32_t extra, const Format &infoBody) { OnSuperResolutionChangedCb(extra, infoBody); } },
        { INFO_TYPE_SEI_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSeiInfoCb(extra, infoBody); } },
        { INFO_TYPE_SUBTITLE_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSubtitleInfoCb(extra, infoBody); } },
        { INFO_TYPE_INTERRUPT_EVENT,
            [this](const int32_t extra, const Format &infoBody) { OnAudioInterruptCb(extra, infoBody); } },
        { INFO_TYPE_AUDIO_DEVICE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnAudioDeviceChangeCb(extra, infoBody); } },
        { INFO_TYPE_EOS, [this](const int32_t extra, const Format &infoBody) { OnEosCb(extra, infoBody); } },
        { INFO_TYPE_SEEKDONE, [this](const int32_t extra, const Format &infoBody) { OnSeekDoneCb(extra, infoBody); } },
        { INFO_TYPE_METRICS_EVENT,
            [this](const int32_t extra, const Format &infoBody) { OnMetricsEventCb(extra, infoBody); } },
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
            AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
}

void AVPlayerCallback::OnPlaybackRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    float speedRate = 0.0f;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_PLAYBACK_RATE, speedRate);
    MEDIA_LOGI("OnPlaybackRateDoneCb is called, speedRate: %{public}f", speedRate);
    if (refMap_.find(AVPlayerEvent::EVENT_RATE_DONE) == refMap_.end()) {
        MEDIA_LOGW(" can not find ratedone callback!");
        return;
    }

    AniCallback::Double *cb = new(std::nothrow) AniCallback::Double();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new float");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_RATE_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_RATE_DONE;
    cb->value = static_cast<double>(speedRate);
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
}

void AVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    int32_t duration = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnDurationUpdateCb is called, duration: %{public}d",
        FAKE_POINTER(this), duration);

    if (listener_ != nullptr) {
        listener_->NotifyDuration(duration);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_DURATION_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find duration update callback!", FAKE_POINTER(this));
        return;
    }

    AniCallback::Int *cb = new(std::nothrow) AniCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_DURATION_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_DURATION_UPDATE;
    cb->value = duration;
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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

    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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
    AniCallback::CompleteCallback(cb, mainHandler_);
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

    AniCallback::CompleteCallback(cb, mainHandler_);
}

void AVPlayerCallback::OnAudioInterruptCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AUDIO_INTERRUPT) == refMap_.end()) {
        MEDIA_LOGI("can not find audio interrupt callback!");
        return;
    }

    AniCallback::PropertyInt *cb = new(std::nothrow) AniCallback::PropertyInt();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new PropertyInt");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AUDIO_INTERRUPT);
    cb->callbackName = AVPlayerEvent::EVENT_AUDIO_INTERRUPT;
    int32_t eventType = 0;
    int32_t forceType = 0;
    int32_t hintType = 0;
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    MEDIA_LOGI("OnAudioInterruptCb is called, eventType = %{public}d, forceType = %{public}d, hintType = %{public}d",
        eventType, forceType, hintType);
    // ohos.multimedia.audio.d.ts interface InterruptEvent
    cb->valueMap["eventType"] = eventType;
    cb->valueMap["forceType"] = forceType;
    cb->valueMap["hintType"] = hintType;
    AniCallback::CompleteCallback(cb, mainHandler_);
}

void AVPlayerCallback::OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE) == refMap_.end()) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " can not find audio AudioDeviceChange callback!", FAKE_POINTER(this));
        return;
    }

    AniCallback::DeviceChangeAni *cb = new(std::nothrow) AniCallback::DeviceChangeAni();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new DeviceChangeTaihe");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE;

    uint8_t *parcelBuffer = nullptr;
    size_t parcelSize;
    infoBody.GetBuffer(PlayerKeys::AUDIO_DEVICE_CHANGE, &parcelBuffer, parcelSize);
    OHOS::Parcel parcel;
    parcel.WriteBuffer(parcelBuffer, parcelSize);
    OHOS::AudioStandard::AudioDeviceDescriptor deviceInfo(OHOS::AudioStandard::AudioDeviceDescriptor::DEVICE_INFO);
    deviceInfo.UnmarshallingSelf(parcel);

    int32_t reason;
    infoBody.GetIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, reason);

    cb->deviceInfo = deviceInfo;
    cb->reason = reason;

    AniCallback::CompleteCallback(cb, mainHandler_);
}

void AVPlayerCallback::OnMetricsEventCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isLoaded_.load(), "current source is unready");
    
    // Extract stalling event information from infoBody
    int32_t stallingEventType = 0;
    int64_t stallingTimestamp = 0;
    int64_t stallingTimeline = 0;
    int64_t stallingDuration = 0;
    int32_t stallingMediaType = 0;

    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_METRICS_EVENT_TYPE, stallingEventType);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_TIMESTAMP, stallingTimestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_TIMELINE, stallingTimeline);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_DURATION, stallingDuration);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STALLING_MEDIA_TYPE, stallingMediaType);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb is called, timestamp = %{public}" PRId64
        ", timeline = %{public}" PRId64 ", duration = %{public}" PRId64 ", mediaType = %{public}" PRId32,
        FAKE_POINTER(this), stallingTimestamp, stallingTimeline, stallingDuration, stallingMediaType);

    if (refMap_.find(AVPlayerEvent::EVENT_METRICS) == refMap_.end()) {
        MEDIA_LOGW("can not find metrics event callback!");
        return;
    }
    
    AniCallback::MetricsEvent *cb = new(std::nothrow) AniCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(stallingEventType);
    cb->valueVec.push_back(stallingTimestamp);
    cb->valueVec.push_back(stallingTimeline);
    cb->valueVec.push_back(stallingDuration);
    cb->valueVec.push_back(static_cast<int64_t>(stallingMediaType));
    AniCallback::CompleteCallback(cb, mainHandler_);
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
        if (temp.psshLen > 0 && temp.psshLen <= DrmConstant::DRM_MAX_M3U8_DRM_PSSH_LEN) {
            std::vector<uint8_t> pssh(temp.pssh, temp.pssh + temp.psshLen);
            drmInfoMap.insert({ uuid, pssh });
        }
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
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
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

void AVPlayerCallback::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);

    Format infoBody;
    AVPlayerCallback::OnStateChangeCb(PlayerStates::PLAYER_RELEASED, infoBody);
    listener_ = nullptr;
}

} // namespace Media
} // namespace ANI
