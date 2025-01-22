/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cj_audio_haptic_manager.h"

#include "audio_haptic_log.h"
#include "cj_audio_haptic_player.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "CJAudioHapticManager"};
}

namespace OHOS {
namespace Media {

CjAudioHapticManager::CjAudioHapticManager()
    : audioHapticMgrClient_(AudioHapticManagerFactory::CreateAudioHapticManager()) {}

CjAudioHapticManager::~CjAudioHapticManager() = default;

int32_t CjAudioHapticManager::RegisterSource(const char* audioUri, const char* hapticUri, int32_t& resId)
{
    if (!audioUri || !hapticUri) {
        return ERR_INVALID_ARG;
    }
    resId = audioHapticMgrClient_->RegisterSource(audioUri, hapticUri);
    return SUCCESS;
}

int32_t CjAudioHapticManager::UnregisterSource(int32_t id)
{
    return audioHapticMgrClient_->UnregisterSource(id);
}

int32_t CjAudioHapticManager::SetAudioLatencyMode(int32_t id, int32_t latencyMode)
{
    if (!IsLegalAudioLatencyMode(latencyMode)) {
        MEDIA_LOGE("SetAudioLatencyMode: the value of latencyMode is invalid");
        return ERR_INVALID_ARG;
    }

    int32_t ret = audioHapticMgrClient_->SetAudioLatencyMode(id, static_cast<AudioLatencyMode>(latencyMode));
    if (ret != SUCCESS) {
        MEDIA_LOGE("SetAudioLatencyMode: Failed to set audio latency mode");
        return ERR_OPERATE_NOT_ALLOWED;
    }
    return ret;
}

bool CjAudioHapticManager::IsLegalAudioLatencyMode(int32_t latencyMode)
{
    switch (latencyMode) {
        case AUDIO_LATENCY_MODE_NORMAL:
        case AUDIO_LATENCY_MODE_FAST:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioLatencyMode: latencyMode %{public}d is invalid", latencyMode);
    return false;
}

int32_t CjAudioHapticManager::SetStreamUsage(int32_t id, int32_t streamUsage)
{
    if (!IsLegalAudioStreamUsage (streamUsage)) {
        MEDIA_LOGE("SetStreamUsage: the value of streamUsage is invalid");
        return ERR_INVALID_ARG;
    }
    int32_t ret = audioHapticMgrClient_->SetStreamUsage(id, static_cast<AudioStandard::StreamUsage>(streamUsage));
    if (ret != SUCCESS) {
        MEDIA_LOGE("SetStreamUsage: Failed to set audio stream usage");
        return ERR_OPERATE_NOT_ALLOWED;
    }
    return ret;
}

bool CjAudioHapticManager::IsLegalAudioStreamUsage(int32_t streamUsage)
{
    switch (streamUsage) {
        case AudioStandard::STREAM_USAGE_MUSIC:
        case AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION:
        case AudioStandard::STREAM_USAGE_VOICE_ASSISTANT:
        case AudioStandard::STREAM_USAGE_ALARM:
        case AudioStandard::STREAM_USAGE_VOICE_MESSAGE:
        case AudioStandard::STREAM_USAGE_RINGTONE:
        case AudioStandard::STREAM_USAGE_NOTIFICATION:
        case AudioStandard::STREAM_USAGE_ACCESSIBILITY:
        case AudioStandard::STREAM_USAGE_SYSTEM:
        case AudioStandard::STREAM_USAGE_MOVIE:
        case AudioStandard::STREAM_USAGE_GAME:
        case AudioStandard::STREAM_USAGE_AUDIOBOOK:
        case AudioStandard::STREAM_USAGE_NAVIGATION:
        case AudioStandard::STREAM_USAGE_DTMF:
        case AudioStandard::STREAM_USAGE_ENFORCED_TONE:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioStreamUsage: streamUsage %{public}d is invalid", streamUsage);
    return false;
}

int64_t CjAudioHapticManager::CreatePlayer(int32_t id, bool muteAudio, bool muteHaptics, int32_t &errCode)
{
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer =
        audioHapticMgrClient_->CreatePlayer(id, AudioHapticPlayerOptions {muteAudio, muteHaptics});
    if (audioHapticPlayer != nullptr) {
        int32_t result = audioHapticPlayer->Prepare();
        if (result == MSERR_OK) {
            errCode = SUCCESS;
            auto instance = FFIData::Create<CjAudioHapticPlayer>(audioHapticPlayer);
            return instance == nullptr ? INVALID_OBJ : instance->GetID();
        }
        // Fail to prepare the audio haptic player. Throw err.
        if (result == MSERR_OPEN_FILE_FAILED) {
            errCode = ERR_IO_ERROR;
        } else if (result == MSERR_UNSUPPORT_FILE) {
            errCode = ERR_UNSUPPORTED_FORMAT;
        } else {
            errCode = ERR_OPERATE_NOT_ALLOWED;
        }
    } else {
        errCode = ERR_OPERATE_NOT_ALLOWED;
    }
    return INVALID_OBJ;
}
} // OHOS
} // Media