/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "audio_haptic_manager_impl.h"

#include "audio_haptic_player_impl.h"

#include "media_log.h"
#include "media_errors.h"

#include "isoundpool.h"
#include "player.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "AudioHapticManagerImpl"};
}

namespace OHOS {
namespace Media {
const std::int32_t MAX_PLAYER_NUM = 32;

std::unique_ptr<AudioHapticManager> AudioHapticManagerFactory::CreateAudioHapticManager()
{
    std::unique_ptr<AudioHapticManagerImpl> audioHapticMgr = std::make_unique<AudioHapticManagerImpl>();
    CHECK_AND_RETURN_RET_LOG(audioHapticMgr != nullptr, nullptr, "Failed to create audio haptic manager object");

    return audioHapticMgr;
}

AudioHapticManagerImpl::AudioHapticManagerImpl()
{
    audioHapticPlayerMap_.clear();
    curPlayerIndex_ = 0;
    curPlayerCount_ = 0;
}

AudioHapticManagerImpl::~AudioHapticManagerImpl()
{
    audioHapticPlayerMap_.clear();
    curPlayerIndex_ = 0;
    curPlayerCount_ = 0;
}

int32_t AudioHapticManagerImpl::RegisterSource(const std::string &audioUri, const std::string &hapticUri)
{
    if (curPlayerCount_ >= MAX_PLAYER_NUM) {
        MEDIA_LOGE("RegisterSource failed curPlayerCount_: %{public}d", curPlayerCount_);
        return -1;
    }
    curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    while (audioHapticPlayerMap_[curPlayerIndex_] != nullptr) {
        curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    }
    int32_t sourceID = curPlayerIndex_;
    audioHapticPlayerMap_[sourceID] = std::make_shared<AudioHapticPlayerInfo>(audioUri, hapticUri,
        AUDIO_LATENCY_MODE_NORMAL, AudioStandard::StreamUsage::STREAM_USAGE_MUSIC, nullptr);
    curPlayerCount_ += 1;
    return sourceID;
}

int32_t AudioHapticManagerImpl::UnregisterSource(const int32_t &sourceID)
{
    if (audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("UnregisterSource failed sourceID: %{public}d", sourceID);
        return MSERR_INVALID_VAL;
    }
    curPlayerCount_ -= 1;

    return MSERR_OK;
}

bool AudioHapticManagerImpl::CheckAudioLatencyMode(const AudioLatencyMode &latencyMode)
{
    return latencyMode == AUDIO_LATENCY_MODE_NORMAL || latencyMode == AUDIO_LATENCY_MODE_FAST;
}

int32_t AudioHapticManagerImpl::SetAudioLatencyMode(const int32_t &sourceID, const AudioLatencyMode &latencyMode)
{
    if (audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("SetAudioLatencyMode: failed for invalid sourceID: %{public}d", sourceID);
        return MSERR_INVALID_VAL;
    }
    if (!CheckAudioLatencyMode(latencyMode)) {
        MEDIA_LOGE("SetAudioLatencyMode: failed for invalid latencyMode: %{public}d", latencyMode);
        return MSERR_INVALID_VAL;
    }

    std::shared_ptr<AudioHapticPlayerInfo> audioHapticPlayerInfo = audioHapticPlayerMap_[sourceID];
    audioHapticPlayerInfo->latencyMode_ = latencyMode;
    return MSERR_OK;
}

bool AudioHapticManagerImpl::CheckAudioStreamUsage(const AudioStandard::StreamUsage &streamUsage)
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
    MEDIA_LOGE("CheckAudioStreamUsage: streamUsage %{public}d is invalid", streamUsage);
    return false;
}

int32_t AudioHapticManagerImpl::SetStreamUsage(const int32_t &sourceID, const AudioStandard::StreamUsage &streamUsage)
{
    if (audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("SetStreamUsage: failed for invalid sourceID: %{public}d", sourceID);
        return MSERR_INVALID_VAL;
    }
    if (!CheckAudioStreamUsage(streamUsage)) {
        MEDIA_LOGE("SetStreamUsage: failed for invalid latencyMode: %{public}d", streamUsage);
        return MSERR_INVALID_VAL;
    }
    std::shared_ptr<AudioHapticPlayerInfo> audioHapticPlayerInfo = audioHapticPlayerMap_[sourceID];
    audioHapticPlayerInfo->streamUsage_ = streamUsage;
    return MSERR_OK;
}

std::shared_ptr<AudioHapticPlayer> AudioHapticManagerImpl::CreatePlayer(const int32_t &sourceID,
    const AudioHapticPlayerOptions &audioHapticPlayerOptions)
{
    if (audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("CreatePlayer failed for sourceID: %{public}d", sourceID);
        return nullptr;
    }
    if (audioHapticPlayerMap_[sourceID]->audioHapticPlayer_ != nullptr) {
        audioHapticPlayerMap_[sourceID]->audioHapticPlayer_->Release();
        audioHapticPlayerMap_[sourceID]->audioHapticPlayer_ = nullptr;
    }

    std::shared_ptr<AudioHapticPlayerInfo> audioHapticPlayerInfo = audioHapticPlayerMap_[sourceID];
    std::shared_ptr<AudioHapticPlayerImpl> audioHapticPlayer = std::make_shared<AudioHapticPlayerImpl>();
    audioHapticPlayer->SetPlayerOptions(audioHapticPlayerOptions.muteAudio, audioHapticPlayerOptions.muteHaptics);
    audioHapticPlayer->SetPlayerSource(audioHapticPlayerInfo->audioUri_, audioHapticPlayerInfo->hapticUri_);
    audioHapticPlayer->SetPlayerStreamUsage(audioHapticPlayerInfo->streamUsage_);
    AudioLatencyMode latencyMode = audioHapticPlayerInfo->latencyMode_;

    // load audio player
    if (latencyMode == AUDIO_LATENCY_MODE_NORMAL) {
        audioHapticPlayer->SetPlayerType(AUDIO_HAPTIC_TYPE_NORMAL);
        audioHapticPlayer->LoadAVPlayer();
    } else if (latencyMode == AUDIO_LATENCY_MODE_FAST) {
        audioHapticPlayer->SetPlayerType(AUDIO_HAPTIC_TYPE_FAST);
        audioHapticPlayer->LoadSoundPoolPlayer();
    }
    // load vibrator
    audioHapticPlayer->LoadVibratorSource();
    
    audioHapticPlayerInfo->audioHapticPlayer_ = audioHapticPlayer;
    return audioHapticPlayer;
}
} // namesapce AudioStandard
} // namespace OHOS