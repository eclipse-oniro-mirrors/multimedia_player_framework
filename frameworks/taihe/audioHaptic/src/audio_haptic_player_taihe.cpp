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

#include "audio_haptic_common_taihe.h"
#include "audio_haptic_log.h"
#include "audio_haptic_player_taihe.h"

namespace {
const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";
const std::string END_OF_STREAM_CALLBACK_NAME = "endOfStream";

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AudioHapticPlayerTaihe"};
}

namespace ANI::Media {

AudioHapticPlayerImpl::AudioHapticPlayerImpl()
{
}

AudioHapticPlayerImpl::AudioHapticPlayerImpl(std::shared_ptr<OHOS::Media::AudioHapticPlayer> &audioHapticPlayer)
{
    if (audioHapticPlayer == nullptr) {
        MEDIA_LOGE("%{public}s: Failed to create AudioHapticPlayer instance.", __func__);
        return;
    }

    audioHapticPlayer_ = std::move(audioHapticPlayer);
    if (audioHapticPlayer_ != nullptr && callbackTaihe_ == nullptr) {
        callbackTaihe_ = std::make_shared<AudioHapticPlayerCallbackTaihe>();
        if (callbackTaihe_ == nullptr) {
            CommonTaihe::ThrowError("No memory");
            return;
        }
        int32_t ret = audioHapticPlayer_->SetAudioHapticPlayerCallback(callbackTaihe_);
        MEDIA_LOGI("Constructor: SetAudioHapticPlayerCallback %{public}s",
            ret == 0 ? "succeess" : "failed");
    }
}

AudioHapticPlayerImpl::~AudioHapticPlayerImpl()
{
}

AudioHapticPlayer AudioHapticPlayerImpl::CreatePlayerInstance(
    std::shared_ptr<OHOS::Media::AudioHapticPlayer> &audioHapticPlayer)
{
    return make_holder<AudioHapticPlayerImpl, AudioHapticPlayer>(audioHapticPlayer);
}

bool AudioHapticPlayerImpl::IsMuted(AudioHapticType audioHapticType)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return false;
    }

    if (!IsLegalAudioHapticType(audioHapticType.get_value())) {
        MEDIA_LOGE("IsMuted: the param type mismatch");
        CommonTaihe::ThrowError(NAPI_ERR_INPUT_INVALID,
            "parameter verification failed: The param of type must be enum AudioHapticType");
        return false;
    }
    return audioHapticPlayer_->IsMuted(OHOS::Media::AudioHapticType(audioHapticType.get_value()));
}

bool AudioHapticPlayerImpl::IsLegalAudioHapticType(int32_t audioHapticType)
{
    switch (audioHapticType) {
        case OHOS::Media::AUDIO_HAPTIC_TYPE_AUDIO:
        case OHOS::Media::AUDIO_HAPTIC_TYPE_HAPTIC:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioHapticType: audioHapticType %{public}d is invalid", audioHapticType);
    return false;
}

void AudioHapticPlayerImpl::StartSync()
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    bool status = audioHapticPlayer_->Start();
    if (status) {
        MEDIA_LOGE("Start: Failed to start audio haptic player");
        CommonTaihe::ThrowError("Error: Operation is not supported or failed");
    }
}

void AudioHapticPlayerImpl::StopSync()
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    bool status = audioHapticPlayer_->Stop();
    if (status) {
        MEDIA_LOGE("Stop: Failed to stop audio haptic player");
        CommonTaihe::ThrowError("Error: Operation is not supported or failed");
    }
}

void AudioHapticPlayerImpl::ReleaseSync()
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    bool status = audioHapticPlayer_->Release();
    if (status) {
        MEDIA_LOGE("Release: Failed to release audio haptic player");
        CommonTaihe::ThrowError("Error: Operation is not supported or failed");
    }
}

bool AudioHapticPlayerImpl::RegisterCallback(const std::string &callbackName,
    callback_view<void(uintptr_t)> callback)
{
    if (callbackTaihe_ == nullptr) {
        CommonTaihe::ThrowError(NAPI_ERR_OPERATE_NOT_ALLOWED, "RegisterCallback: Failed to get callbackTaihe_");
        return false;
    }
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);
    callbackTaihe_->SaveCallbackReference(callbackName, autoRef);
    return true;
}

bool AudioHapticPlayerImpl::UnregisterCallback(const std::string &callbackName)
{
    if (callbackTaihe_ == nullptr) {
        CommonTaihe::ThrowError(NAPI_ERR_OPERATE_NOT_ALLOWED, "UnregisterCallback: Failed to get callbackTaihe_");
        return false;
    }
    callbackTaihe_->RemoveCallbackReference(callbackName);
    return true;
}

void AudioHapticPlayerImpl::OnAudioInterrupt(callback_view<void(uintptr_t)> callback)
{
    RegisterCallback(AUDIO_INTERRUPT_CALLBACK_NAME, callback);
}

void AudioHapticPlayerImpl::OffAudioInterrupt(optional_view<callback<void(uintptr_t)>> callback)
{
    UnregisterCallback(AUDIO_INTERRUPT_CALLBACK_NAME);
}

void AudioHapticPlayerImpl::OnEndOfStream(callback_view<void(uintptr_t)> callback)
{
    RegisterCallback(END_OF_STREAM_CALLBACK_NAME, callback);
}

void AudioHapticPlayerImpl::OffEndOfStream(optional_view<callback<void(uintptr_t)>> callback)
{
    UnregisterCallback(END_OF_STREAM_CALLBACK_NAME);
}

} // namespace ANI::Media