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
#include "media_log.h"
#include <thread>
#include "ani_avplayer_callback.h"
#include "media_ani_utils.h"
#include "media_errors.h"
#include "avplayer_ani.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerCallback" };
}

namespace OHOS {
namespace Media {

static const std::map<StateChangeReason, int32_t> ANI_STATECHANGEREASON_INDEX_MAP = {
    { StateChangeReason::USER, 0 },
    { StateChangeReason::BACKGROUND, 1 },
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
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> baseRef = callback.lock();
            int res = baseRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(baseRef->cb_);
            const std::string state = "";

            std::vector<ani_ref> args = {};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
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
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> errorRef = callback.lock();
            CHECK_AND_RETURN_LOG(errorRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            int res = errorRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(errorRef->cb_);
            ani_object arg1 = {};
            MediaAniUtils::CreateError(errorRef->env_, errorCode, errorMsg, arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct Int : public Base {
        int32_t value = 0;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> intRef = callback.lock();
            int res = intRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(intRef->cb_);
            ani_int arg1 = {};
            MediaAniUtils::ToAniInt(intRef->env_, value, arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct IntVec : public Base {
        std::vector<uint32_t> valueVec;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            int res = intVecRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(intVecRef->cb_);
            const int32_t state = 0;
            ani_int arg1 = {};
            MediaAniUtils::ToAniInt(intVecRef->env_, state, arg1);

            const int32_t reason = 0;
            ani_int arg2 = {};
            MediaAniUtils::ToAniInt(intVecRef->env_, reason, arg2);
            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(arg1), reinterpret_cast<ani_ref>(arg2)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct IntArray : public Base {
        std::vector<int32_t> valueVec;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            int res = intVecRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(intVecRef->cb_);
            ani_object arg1 = {};
            MediaAniUtils::ToAniInt32Array(intVecRef->env_, valueVec, arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct Double :public Base {
        double value = 0.0;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> stateChangeRef = callback.lock();
            int res = stateChangeRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(stateChangeRef->cb_);
            ani_double arg1 = {};
            MediaAniUtils::ToAniDouble(stateChangeRef->env_, value, arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct FloatArray : public Base {
        std::vector<float> valueVec;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            int res = floatArrayRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(floatArrayRef->cb_);
            ani_object arg1 = {};
            MediaAniUtils::ToAniFloatArray(floatArrayRef->env_, valueVec, arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct TrackInfoUpdate : public Base {
        std::vector<Format> trackInfo;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            int res = floatArrayRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(floatArrayRef->cb_);

            ani_class cls {};
            static const std::string className = "escompat.Array";
            floatArrayRef->env_->FindClass(className.c_str(), &cls);
            ani_string str = nullptr;
            const char *utf8String = std::to_string(trackInfo.size()).c_str();
            const ani_size stringLength = strlen(utf8String);
            floatArrayRef->env_->String_NewUTF8(utf8String, stringLength, &str);
            ani_array_ref arg1 = nullptr;
            floatArrayRef->env_->Array_New_Ref(cls, stringLength, str, &arg1);

            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(&arg1)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct TrackChange : public Base {
        int32_t number = 0;
        bool isSelect = false;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            int res = intVecRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }
            auto fnObject = reinterpret_cast<ani_fn_object>(intVecRef->cb_);

            ani_int arg1 = {};
            MediaAniUtils::ToAniInt(intVecRef->env_, number, arg1);

            ani_boolean arg2 = isSelect ? ANI_TRUE : ANI_FALSE;
            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(arg1), reinterpret_cast<ani_ref>(arg2)};

            ani_ref result;
            if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
                return;
            }

            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    struct StateChange : public Base {
        std::string state = "";
        int32_t reason = 0;
        void UvWork() override
        {
            ani_vm *etsVm;
            ani_env *etsEnv;
            std::shared_ptr<AutoRef> stateChangeRef = callback.lock();
            int res = stateChangeRef->env_->GetVM(&etsVm);
            if (res != ANI_OK) {
                return;
            }
            ani_option interopEnabled {"--interop=disable", nullptr};
            ani_options aniArgs {1, &interopEnabled};
            if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
                return;
            }

            ani_string arg1 = {};
            MediaAniUtils::ToAniString(stateChangeRef->env_, state, arg1);

            static const char *className = "@ohos.multimedia.media.media.StateChangeReason";
            ani_enum_item aniEnumItem;
            ani_enum aniEnum {};
            if (ANI_OK != etsEnv->FindEnum(className, &aniEnum)) {
                MEDIA_LOGI("sunyu  FindEnum");
            }
            auto it = ANI_STATECHANGEREASON_INDEX_MAP.find(static_cast<StateChangeReason>(reason));
            auto errorcode = etsEnv->Enum_GetEnumItemByIndex(aniEnum, (ani_int)it->second, &aniEnumItem);
            if (ANI_OK != errorcode) {
                MEDIA_LOGI("sunyu  Enum_GetEnumItemByIndex: %{public}d, %{public}d", errorcode, reason);
            }
            std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(arg1), reinterpret_cast<ani_ref>(aniEnumItem)};

            ani_ref result;
            if (ANI_OK!=etsEnv->FunctionalObject_Call((ani_fn_object)stateChangeRef->cb_,
                args.size(), args.data(), &result)) {
                return;
            }
            if (ANI_OK != etsVm->DetachCurrentThread()) {
                return;
            }
        }
    };

    static void CompleteCallback([[maybe_unused]] ani_env *env, AniCallback::Base *aniCb)
    {
        auto t1 = std::thread([aniCb]() {
            aniCb->UvWork();
        });
        t1.join();
    }
};

bool AniAVPlayerCallback::IsValidState(PlayerStates state, std::string &stateStr)
{
    switch (state) {
        case PlayerStates::PLAYER_IDLE:
            stateStr = AVPlayerState::STATE_IDLE;
            break;
        case PlayerStates::PLAYER_INITIALIZED:
            stateStr = AVPlayerState::STATE_INITIALIZED;
            break;
        case PlayerStates::PLAYER_PREPARED:
            stateStr = AVPlayerState::STATE_PREPARED;
            break;
        case PlayerStates::PLAYER_STARTED:
            stateStr = AVPlayerState::STATE_PLAYING;
            break;
        case PlayerStates::PLAYER_PAUSED:
            stateStr = AVPlayerState::STATE_PAUSED;
            break;
        case PlayerStates::PLAYER_STOPPED:
            stateStr = AVPlayerState::STATE_STOPPED;
            break;
        case PlayerStates::PLAYER_PLAYBACK_COMPLETE:
            stateStr = AVPlayerState::STATE_COMPLETED;
            break;
        case PlayerStates::PLAYER_RELEASED:
            stateStr = AVPlayerState::STATE_RELEASED;
            break;
        case PlayerStates::PLAYER_STATE_ERROR:
            stateStr = AVPlayerState::STATE_ERROR;
            break;
        default:
            return false;
    }
    return true;
}

AniAVPlayerCallback::AniAVPlayerCallback(ani_env *env, ANIAVPlayerNotify *listener)
    : env_(env), listener_(listener)
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
    };
}

void AniAVPlayerCallback::NotifyIsLiveStream(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    (void)infoBody;
    if (listener_ != nullptr) {
        listener_->NotifyIsLiveStream();
    }
}

void AniAVPlayerCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
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

            int32_t reason = StateChangeReason::USER;
            if (infoBody.ContainKey(PlayerKeys::PLAYER_STATE_CHANGED_REASON)) {
                (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, reason);
            }
            cb->callback = refMap_.at(AVPlayerEvent::EVENT_STATE_CHANGE);
            cb->callbackName = AVPlayerEvent::EVENT_STATE_CHANGE;
            cb->state = stateStr;
            cb->reason = reason;
            AniCallback::CompleteCallback(env_, cb);
        }
    }
}

void AniAVPlayerCallback::OnSeekDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnSpeedDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnBitRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnPositionUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnVolumeChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnBufferingUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::IntVec *cb = new(std::nothrow) AniCallback::IntVec();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntVec");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_BUFFERING_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_BUFFERING_UPDATE;
    cb->valueVec.push_back(bufferingType);
    cb->valueVec.push_back(val);
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnMessageCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    MEDIA_LOGI("OnMessageCb is called, extra: %{public}d", extra);
    if (extra == PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START) {
        AniAVPlayerCallback::OnStartRenderFrameCb();
    }
}

void AniAVPlayerCallback::OnStartRenderFrameCb() const
{
    MEDIA_LOGI("OnStartRenderFrameCb is called");
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_START_RENDER_FRAME) == refMap_.end()) {
        MEDIA_LOGW("can not find start render callback!");
        return;
    }

    AniCallback::Base *cb = new(std::nothrow) AniCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_START_RENDER_FRAME);
    cb->callbackName = AVPlayerEvent::EVENT_START_RENDER_FRAME;
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnBitRateCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnTrackInfoUpdate(const int32_t extra, const Format &infoBody)
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnTrackChangedCb(const int32_t extra, const Format &infoBody)
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnEosCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGD("OnInfo %{public}d", type);
    if (onInfoFuncs_.count(type) > 0) {
        onInfoFuncs_[type](extra, infoBody);
    } else {
        MEDIA_LOGD(" OnInfo: %{public}d no member func supporting", type);
    }
}

AniAVPlayerCallback::~AniAVPlayerCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instance destroy", FAKE_POINTER(this));
}

void AniAVPlayerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    if (errorCodeApi9 == MSERR_EXT_API9_NO_PERMISSION ||
        errorCodeApi9 == MSERR_EXT_API9_NO_MEMORY ||
        errorCodeApi9 == MSERR_EXT_API9_TIMEOUT ||
        errorCodeApi9 == MSERR_EXT_API9_SERVICE_DIED ||
        errorCodeApi9 == MSERR_EXT_API9_UNSUPPORT_FORMAT) {
        Format infoBody;
        AniAVPlayerCallback::OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, infoBody);
    }
    AniAVPlayerCallback::OnErrorCb(errorCodeApi9, errorMsg);
}

void AniAVPlayerCallback::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnSetDecryptConfigDoneCb(const int32_t extra, const Format &infoBody)
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
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
    AniCallback::CompleteCallback(env_, cb);
}

void AniAVPlayerCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void AniAVPlayerCallback::ClearCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.erase(name);
}

void AniAVPlayerCallback::Start()
{
    isloaded_ = true;
}

void AniAVPlayerCallback::Pause()
{
    isloaded_ = false;
}

} // namespace Media
} // namespace OHOS
