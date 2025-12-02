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

#include "audio_haptic_manager_taihe.h"

#include "audio_haptic_common_taihe.h"
#include "audio_haptic_log.h"
#include "audio_haptic_player.h"
#include "audio_haptic_player_taihe.h"
#include "common_taihe.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticManagerTaihe"};
constexpr int32_t INVALID_ID = -1;
constexpr int32_t ERROR = -1;
constexpr int32_t SUCCESS = 0;
}

namespace ANI::Media {

AudioHapticManagerImpl::AudioHapticManagerImpl()
{
    audioHapticMgrClient_ = OHOS::Media::AudioHapticManagerFactory::CreateAudioHapticManager();
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: Failed to create audioHapticManager");
    }
}

AudioHapticManagerImpl::~AudioHapticManagerImpl()
{
}

int32_t AudioHapticManagerImpl::RegisterSourceSync(string_view audioUri, string_view hapticUri)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return INVALID_ID;
    }

    return audioHapticMgrClient_->RegisterSource(audioUri.c_str(), hapticUri.c_str());
}

void AudioHapticManagerImpl::UnregisterSourceSync(int32_t id)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return;
    }

    int32_t status = audioHapticMgrClient_->UnregisterSource(id);
    if (status != OHOS::Media::MSERR_OK) {
        CommonTaihe::ThrowError(status, "Error: UnregisterSource failed");
    }
}

void AudioHapticManagerImpl::SetAudioLatencyMode(int32_t id, AudioLatencyMode latencyMode)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return;
    }

    if (!IsLegalAudioLatencyMode(latencyMode.get_value())) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID,
            "SetAudioLatencyMode: the value of latencyMode is invalid");
        return;
    }

    int32_t setResult = audioHapticMgrClient_->SetAudioLatencyMode(
        id, OHOS::Media::AudioLatencyMode(latencyMode.get_value()));
    if (setResult != SUCCESS) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED,
            "SetAudioLatencyMode: Failed to set audio latency mode");
    }
}

bool AudioHapticManagerImpl::IsLegalAudioLatencyMode(int32_t latencyMode)
{
    switch (latencyMode) {
        case OHOS::Media::AUDIO_LATENCY_MODE_NORMAL:
        case OHOS::Media::AUDIO_LATENCY_MODE_FAST:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioLatencyMode: latencyMode %{public}d is invalid", latencyMode);
    return false;
}

bool AudioHapticManagerImpl::IsLegalAudioStreamUsage(int32_t streamUsage)
{
    switch (streamUsage) {
        case OHOS::AudioStandard::STREAM_USAGE_MUSIC:
        case OHOS::AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION:
        case OHOS::AudioStandard::STREAM_USAGE_VOICE_ASSISTANT:
        case OHOS::AudioStandard::STREAM_USAGE_ALARM:
        case OHOS::AudioStandard::STREAM_USAGE_VOICE_MESSAGE:
        case OHOS::AudioStandard::STREAM_USAGE_RINGTONE:
        case OHOS::AudioStandard::STREAM_USAGE_NOTIFICATION:
        case OHOS::AudioStandard::STREAM_USAGE_ACCESSIBILITY:
        case OHOS::AudioStandard::STREAM_USAGE_SYSTEM:
        case OHOS::AudioStandard::STREAM_USAGE_MOVIE:
        case OHOS::AudioStandard::STREAM_USAGE_GAME:
        case OHOS::AudioStandard::STREAM_USAGE_AUDIOBOOK:
        case OHOS::AudioStandard::STREAM_USAGE_NAVIGATION:
        case OHOS::AudioStandard::STREAM_USAGE_DTMF:
        case OHOS::AudioStandard::STREAM_USAGE_ENFORCED_TONE:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioStreamUsage: streamUsage %{public}d is invalid", streamUsage);
    return false;
}

void AudioHapticManagerImpl::SetStreamUsage(int32_t id, uintptr_t usage)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return;
    }

    int32_t streamUsage = 0;
    ani_status status = CommonTaihe::EnumGetValueInt32(::taihe::get_env(),
        reinterpret_cast<ani_enum_item>(usage), streamUsage);
    if (status != ANI_OK) {
        CommonTaihe::ThrowError("SetStreamUsage: Get parameter streamUsage failed!");
        return;
    }

    if (!IsLegalAudioStreamUsage(streamUsage)) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID,
            "SetStreamUsage: the value of streamUsage is invalid");
        return;
    }

    int32_t setResult = audioHapticMgrClient_->SetStreamUsage(
        id, static_cast<OHOS::AudioStandard::StreamUsage>(streamUsage));
    if (setResult != SUCCESS) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED,
            "SetStreamUsage: Failed to set stream usage");
    }
}

int32_t AudioHapticManagerImpl::RegisterSourceFromFdSync(AudioHapticFileDescriptor const& audioFd,
    AudioHapticFileDescriptor const& hapticFd)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return 0;
    }

    OHOS::Media::AudioHapticFileDescriptor audioHapticFd;
    if (GetAudioHapticFileDescriptorValue(audioFd, audioHapticFd) != SUCCESS) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, "Invalid first parameter");
        return 0;
    }

    OHOS::Media::AudioHapticFileDescriptor audioHapticFileDescriptor;
    if (GetAudioHapticFileDescriptorValue(hapticFd, audioHapticFileDescriptor) != SUCCESS) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, "Invalid second parameter");
        return 0;
    }

    int32_t sourceID;
    if (audioHapticFd.fd == -1 || audioHapticFileDescriptor.fd == -1) {
        sourceID = ERROR;
    } else {
        sourceID = audioHapticMgrClient_->RegisterSourceFromFd(audioHapticFd, audioHapticFileDescriptor);
    }

    if (sourceID <= ERROR) {
        CommonTaihe::ThrowError(sourceID, "RegisterSourceFromFd Error: Operation is not supported or failed");
        return 0;
    }
    return sourceID;
}

int32_t AudioHapticManagerImpl::GetAudioHapticFileDescriptorValue(AudioHapticFileDescriptor const& audioFd,
    OHOS::Media::AudioHapticFileDescriptor& audioHapticFd)
{
    audioHapticFd.fd = audioFd.fd;
    if (audioFd.length.has_value()) {
        audioHapticFd.length = audioFd.length.value();
    }
    if (audioFd.offset.has_value()) {
        audioHapticFd.offset = audioFd.offset.value();
    }
    return SUCCESS;
}

void AudioHapticManagerImpl::CreatePlayerExecute(std::unique_ptr<AudioHapticManagerTaiheContext> &taiheContext)
{
    std::shared_ptr<OHOS::Media::AudioHapticPlayer> audioHapticPlayer =
        audioHapticMgrClient_->CreatePlayer(taiheContext->sourceID, taiheContext->playerOptions);

    if (audioHapticPlayer != nullptr) {
        int32_t result = audioHapticPlayer->Prepare();
        if (result == OHOS::Media::MSERR_OK) {
            taiheContext->audioHapticPlayer = audioHapticPlayer;
            taiheContext->status = SUCCESS;
            return;
        }
        // Fail to prepare the audio haptic player. Throw err.
        if (result == OHOS::Media::MSERR_OPEN_FILE_FAILED) {
            taiheContext->errCode = TAIHE_ERR_IO_ERROR;
        } else if (result == OHOS::Media::MSERR_UNSUPPORT_FILE) {
            taiheContext->errCode = TAIHE_ERR_UNSUPPORTED_FORMAT;
        } else {
            taiheContext->errCode = TAIHE_ERR_OPERATE_NOT_ALLOWED;
        }
    } else {
        taiheContext->errCode = TAIHE_ERR_OPERATE_NOT_ALLOWED;
    }
    taiheContext->audioHapticPlayer = nullptr;
    taiheContext->status = ERROR;
    taiheContext->errMessage = AudioHapticCommonTaihe::GetMessageByCode(taiheContext->errCode);
}

AudioHapticPlayerOrNull AudioHapticManagerImpl::CreatePlayerComplete(
    std::unique_ptr<AudioHapticManagerTaiheContext> &taiheContext)
{
    if (taiheContext->audioHapticPlayer == nullptr) {
        CommonTaihe::ThrowError(taiheContext->errCode, taiheContext->errMessage);
        return AudioHapticPlayerOrNull::make_type_null();
    }
    if (::taihe::has_error()) {
        CommonTaihe::ThrowError("CreatePlayer Error: Operation is not supported or failed");
        return AudioHapticPlayerOrNull::make_type_null();
    }
    return AudioHapticPlayerOrNull::make_type_audioHapticPlayer(AudioHapticPlayerImpl::CreatePlayerInstance(
        taiheContext->audioHapticPlayer));
}

AudioHapticPlayerOrNull AudioHapticManagerImpl::CreatePlayerSync(int32_t id,
    optional_view<AudioHapticPlayerOptions> options)
{
    if (audioHapticMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("Error: audioHapticMgrClient_ is nullptr");
        return AudioHapticPlayerOrNull::make_type_null();
    }

    std::unique_ptr<AudioHapticManagerTaiheContext> taiheContext = std::make_unique<AudioHapticManagerTaiheContext>();
    if (taiheContext == nullptr) {
        CommonTaihe::ThrowError("No memory");
        return AudioHapticPlayerOrNull::make_type_null();
    }
    taiheContext->sourceID = id;
    if (options.has_value()) {
        taiheContext->playerOptions.muteAudio = options->muteAudio.value_or(false);
        taiheContext->playerOptions.muteHaptics = options->muteHaptics.value_or(false);
    }

    CreatePlayerExecute(taiheContext);
    return CreatePlayerComplete(taiheContext);
}

AudioHapticManager GetAudioHapticManager()
{
    return taihe::make_holder<AudioHapticManagerImpl, AudioHapticManager>();
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_GetAudioHapticManager(ANI::Media::GetAudioHapticManager);