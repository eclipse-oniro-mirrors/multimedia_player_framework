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

#include "system_tone_player_taihe.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "common_taihe.h"
#include "ipc_skeleton.h"
#include "media_core.h"
#include "ringtone_common_taihe.h"
#include "system_sound_log.h"
#include "tokenid_kit.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerTaihe"};

const double DOUBLE_ZERO = 0.0;
const int32_t INVALID_HAPTICS_FEATURE = -1;
const int32_t INVALID_STREAM_ID = -1;
const int32_t ALL_STREAMID = 0;
const std::string PLAY_FINISHED_CALLBACK_NAME = "playFinished";
const std::string ERROR_CALLBACK_NAME = "error";
}

using namespace ANI::Media;

namespace ANI::Media {

SystemTonePlayerImpl::SystemTonePlayerImpl(std::shared_ptr<OHOS::Media::SystemTonePlayer> systemTonePlayer)
{
    if (systemTonePlayer != nullptr) {
        systemTonePlayer_ = systemTonePlayer;
        if (systemTonePlayer_ != nullptr && callbackTaihe_ == nullptr) {
            callbackTaihe_ = std::make_shared<SystemTonePlayerCallbackTaihe>();
            if (callbackTaihe_ == nullptr) {
                CommonTaihe::ThrowError("No memory");
                return;
            }
            int32_t ret = systemTonePlayer_->SetSystemTonePlayerFinishedAndErrorCallback(callbackTaihe_);
            MEDIA_LOGI("SetSystemTonePlayerFinishedAndErrorCallback %{public}s", ret == 0 ? "success" : "failed");
        }
    }
}

SystemTonePlayer SystemTonePlayerImpl::GetSystemTonePlayerInstance(
    std::shared_ptr<OHOS::Media::SystemTonePlayer> &systemTonePlayer)
{
    return make_holder<SystemTonePlayerImpl, SystemTonePlayer>(systemTonePlayer);
}

::taihe::string SystemTonePlayerImpl::GetTitleSync()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError(OHOS::Media::MSERR_INVALID_STATE, "GetTitleSync: The system tone player is nullptr!");
        return {};
    }

    return systemTonePlayer_->GetTitle();
}

void SystemTonePlayerImpl::SetAudioVolumeScale(double scale)
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError("SetAudioVolumeScale: systemTonePlayer_ is nullptr!");
        return;
    }

    int32_t ret = systemTonePlayer_->SetAudioVolume(scale);
    if (ret != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(ret, "SetAudioVolumeScale: Operation is not supported or failed");
    }
}

double SystemTonePlayerImpl::GetAudioVolumeScale()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError("GetAudioVolumeScale: systemTonePlayer_ is nullptr!");
        return DOUBLE_ZERO;
    }

    float volume;
    int32_t ret = systemTonePlayer_->GetAudioVolume(volume);
    if (ret != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(ret, "GetAudioVolumeScale: Operation is not supported or failed");
        return DOUBLE_ZERO;
    }
    return static_cast<double>(volume);
}

taihe::array<ToneHapticsFeature> SystemTonePlayerImpl::GetSupportedHapticsFeaturesSync()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError("GetSupportedHapticsFeaturesSync: systemTonePlayer_ is nullptr!");
        return {};
    }

    std::vector<OHOS::Media::ToneHapticsFeature> toneHapticsFeatures;
    int32_t status = systemTonePlayer_->GetSupportHapticsFeatures(toneHapticsFeatures);
    if (status != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(status, "GetSupportHapticsFeatures Error: Operation is not supported or failed");
        return {};
    }

    std::vector<ToneHapticsFeature> result;
    for (auto feature : toneHapticsFeatures) {
        result.emplace_back(ToneHapticsFeature::from_value(static_cast<int32_t>(feature)));
    }
    return taihe::array<ToneHapticsFeature>(result);
}

void SystemTonePlayerImpl::SetHapticsFeature(ToneHapticsFeature hapticsFeature)
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError("SetHapticsFeature: systemTonePlayer_ is nullptr!");
        return;
    }
    int32_t status = systemTonePlayer_->SetHapticsFeature(
        static_cast<OHOS::Media::ToneHapticsFeature>(hapticsFeature.get_value()));
    if (status != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(status, "SetHapticsFeature Error: Operation is not supported or failed");
    }
}

ToneHapticsFeature SystemTonePlayerImpl::GetHapticsFeature()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError("GetHapticsFeature: systemTonePlayer_ is nullptr!");
        return ToneHapticsFeature::from_value(INVALID_HAPTICS_FEATURE);
    }
    OHOS::Media::ToneHapticsFeature toneHapticsFeature;
    int32_t status = systemTonePlayer_->GetHapticsFeature(toneHapticsFeature);
    if (status != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(status, "GetHapticsFeature Error: Operation is not supported or failed");
        return ToneHapticsFeature::from_value(INVALID_HAPTICS_FEATURE);
    }
    return ToneHapticsFeature::from_value(static_cast<int32_t>(toneHapticsFeature));
}

void SystemTonePlayerImpl::PrepareSync()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError(OHOS::Media::MSERR_INVALID_STATE, "PrepareSync: systemTonePlayer_ is nullptr!");
        return;
    }

    int32_t status = systemTonePlayer_->Prepare();
    if (status) {
        CommonTaihe::ThrowError(status, "PrepareSync: Operation is not supported or failed");
        return;
    }
}

int32_t SystemTonePlayerImpl::StartSync(optional_view<SystemToneOptions> toneOptions)
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError(OHOS::Media::MSERR_INVALID_STATE, "StartSync: systemTonePlayer_ is nullptr!");
        return INVALID_STREAM_ID;
    }

    OHOS::Media::SystemToneOptions systemToneOptions {false, false};
    if (toneOptions.has_value()) {
        systemToneOptions.muteAudio = toneOptions->muteAudio.value_or(false);
        systemToneOptions.muteHaptics = toneOptions->muteHaptics.value_or(false);
    }

    int32_t streamID = systemTonePlayer_->Start(systemToneOptions);
    std::shared_ptr<SystemTonePlayerCallbackTaihe> cb =
        std::static_pointer_cast<SystemTonePlayerCallbackTaihe>(callbackTaihe_);
    if (cb) {
        cb->RemovePlayFinishedCallbackReference(streamID);
    }
    return streamID;
}

void SystemTonePlayerImpl::StopSync(int32_t id)
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError(OHOS::Media::MSERR_INVALID_STATE, "StopSync: systemTonePlayer_ is nullptr!");
        return;
    }

    int32_t status = systemTonePlayer_->Stop(id);
    if (status) {
        CommonTaihe::ThrowError(status, "StopSync: Operation is not supported or failed");
        return;
    }
}

void SystemTonePlayerImpl::ReleaseSync()
{
    if (systemTonePlayer_ == nullptr) {
        CommonTaihe::ThrowError(OHOS::Media::MSERR_INVALID_STATE, "ReleaseSync: systemTonePlayer_ is nullptr!");
        return;
    }

    int32_t status = systemTonePlayer_->Release();
    if (status) {
        CommonTaihe::ThrowError(status, "ReleaseSync: Operation is not supported or failed");
        return;
    }
}

void SystemTonePlayerImpl::OnPlayFinished(int32_t streamId, callback_view<void(int32_t)> callback)
{
    if (systemTonePlayer_ == nullptr || callbackTaihe_ == nullptr) {
        MEDIA_LOGE("OnPlayFinished: systemTonePlayer_ or callbackTaihe_ is nullptr!");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return;
    }

    if (!(systemTonePlayer_->IsStreamIdExist(streamId) || streamId == ALL_STREAMID)) {
        MEDIA_LOGE("streamId is not exists");
        CommonTaihe::ThrowError(TAIHE_ERR_PARAM_CHECK_ERROR, TAIHE_ERR_PARAM_CHECK_ERROR_INFO);
        return;
    }

    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);
    callbackTaihe_->SavePlayFinishedCallbackReference(PLAY_FINISHED_CALLBACK_NAME, autoRef, streamId);
}

void SystemTonePlayerImpl::OffPlayFinished(optional_view<callback<void(int32_t)>> callback)
{
    if (systemTonePlayer_ == nullptr || callbackTaihe_ == nullptr) {
        MEDIA_LOGE("OffPlayFinished: systemTonePlayer_ or callbackTaihe_ is nullptr!");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return;
    }

    std::shared_ptr<AutoRef> autoRef = nullptr;
    if (callback.has_value()) {
        std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback.value());
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);
    }
    callbackTaihe_->RemoveCallbackReference(PLAY_FINISHED_CALLBACK_NAME, autoRef);
}

void SystemTonePlayerImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    if (systemTonePlayer_ == nullptr || callbackTaihe_ == nullptr) {
        MEDIA_LOGE("OnError: systemTonePlayer_ or callbackTaihe_ is nullptr!");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return;
    }

    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);
    callbackTaihe_->SaveCallbackReference(ERROR_CALLBACK_NAME, autoRef);
}

void SystemTonePlayerImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    if (systemTonePlayer_ == nullptr || callbackTaihe_ == nullptr) {
        MEDIA_LOGE("OffError: systemTonePlayer_ or callbackTaihe_ is nullptr!");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return;
    }

    std::shared_ptr<AutoRef> autoRef = nullptr;
    if (callback.has_value()) {
        std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback.value());
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);
    }
    callbackTaihe_->RemoveCallbackReference(ERROR_CALLBACK_NAME, autoRef);
}
} // namespace ANI::Media