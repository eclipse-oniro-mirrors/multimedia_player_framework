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

#include "audio_haptic_player_taihe.h"

#include "audio_haptic_common_taihe.h"
#include "audio_haptic_log.h"

namespace {
const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";
const std::string END_OF_STREAM_CALLBACK_NAME = "endOfStream";
const double PRECISION = 100.00;

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
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID,
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

bool AudioHapticPlayerImpl::IsLegalVolumeOrIntensity(double number)
{
    return number >= 0.0 && number <= 1.0;
}

bool AudioHapticPlayerImpl::JudgeVolume(double &volume)
{
    if (!IsLegalVolumeOrIntensity(volume)) {
        MEDIA_LOGE("SetVolume: the param is invalid");
        return false;
    }

    volume = static_cast<float>(std::round(volume * PRECISION) / PRECISION);
    return true;
}

bool AudioHapticPlayerImpl::JudgeIntensity(double &intensity)
{
    if (!IsLegalVolumeOrIntensity(intensity)) {
        MEDIA_LOGE("SetIntensity: the param is invalid");
        return false;
    }

    intensity = static_cast<float>(std::round(intensity * PRECISION) / PRECISION);
    return true;
}

bool AudioHapticPlayerImpl::JudgeRamp(int duration, double &startIntensity, double &endIntensity)
{
    int32_t notLessThanDurationMs = 100;
    if (duration < notLessThanDurationMs) {
        MEDIA_LOGE("SetHapticsRamp: the duration is invalid, duration not less than 100 ms");
        return false;
    }

    if (!IsLegalVolumeOrIntensity(startIntensity)) {
        MEDIA_LOGE("SetHapticsRamp: startIntensity is invalid, startIntensity's value ranges from 0.00 to 1.00");
        return false;
    }
    startIntensity = static_cast<float>(std::round(startIntensity * PRECISION) / PRECISION);

    if (!IsLegalVolumeOrIntensity(endIntensity)) {
        MEDIA_LOGE("SetHapticsRamp: endIntensity is invalid, endIntensity's value ranges from 0.00 to 1.00");
        return false;
    }
    endIntensity = static_cast<float>(std::round(endIntensity * PRECISION) / PRECISION);

    return true;
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

void AudioHapticPlayerImpl::SetVolumeSync(double volume)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    if (!JudgeVolume(volume)) {
        CommonTaihe::ThrowError(TAIHE_ERR_PARAM_OUT_OF_RANGE, TAIHE_ERR_PARAM_OUT_OF_RANGE_INFO);
        return;
    }

    int32_t result = audioHapticPlayer_->SetVolume(volume);
    if (result != 0) {
        CommonTaihe::ThrowError(result, "Failed to set volume");
    }
}

void AudioHapticPlayerImpl::SetHapticsIntensitySync(double intensity)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    if (!AudioHapticCommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return;
    }

    if (!JudgeIntensity(intensity)) {
        CommonTaihe::ThrowError(TAIHE_ERR_PARAM_OUT_OF_RANGE, TAIHE_ERR_PARAM_OUT_OF_RANGE_INFO);
        return;
    }

    int32_t result = audioHapticPlayer_->SetHapticIntensity(intensity * PRECISION);
    if (result != 0) {
        CommonTaihe::ThrowError(result, "Failed to set haptics intensity");
    }
}

void AudioHapticPlayerImpl::EnableHapticsInSilentMode(bool enable)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    if (!AudioHapticCommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return;
    }

    int32_t result = audioHapticPlayer_->EnableHapticsInSilentMode(enable);
    if (result == TAIHE_ERR_OPERATE_NOT_ALLOWED) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, "Failed to enable haptics in silent mode");
    }
}

bool AudioHapticPlayerImpl::IsHapticsIntensityAdjustmentSupported()
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return false;
    }

    if (!AudioHapticCommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return false;
    }

    bool isSupported = audioHapticPlayer_->IsHapticsIntensityAdjustmentSupported();
    return isSupported;
}

void AudioHapticPlayerImpl::SetLoopSync(bool loop)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    int32_t result = audioHapticPlayer_->SetLoop(loop);
    if (result != 0) {
        CommonTaihe::ThrowError(result, "Failed to set loop");
    }
}

void AudioHapticPlayerImpl::SetHapticsRampSync(int32_t duration, double startIntensity, double endIntensity)
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return;
    }

    if (!AudioHapticCommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return;
    }

    if (!JudgeRamp(duration, startIntensity, endIntensity)) {
        CommonTaihe::ThrowError(TAIHE_ERR_PARAM_OUT_OF_RANGE, TAIHE_ERR_PARAM_OUT_OF_RANGE_INFO);
        return;
    }

    int32_t result = audioHapticPlayer_->SetHapticsRamp(duration, startIntensity * PRECISION, endIntensity * PRECISION);
    if (result != 0) {
        CommonTaihe::ThrowError(result, "Failed to set haptics ramp");
    }
}

bool AudioHapticPlayerImpl::IsHapticsRampSupported()
{
    if (audioHapticPlayer_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticPlayer_ is nullptr");
        return false;
    }

    if (!AudioHapticCommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return false;
    }

    bool isSupported = audioHapticPlayer_->IsHapticsRampSupported();
    return isSupported;
}

bool AudioHapticPlayerImpl::RegisterCallback(const std::string &callbackName,
    callback_view<void(uintptr_t)> callback)
{
    if (callbackTaihe_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, "RegisterCallback: Failed to get callbackTaihe_");
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
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, "UnregisterCallback: Failed to get callbackTaihe_");
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