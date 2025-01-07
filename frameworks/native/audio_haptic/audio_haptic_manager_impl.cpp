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

#include "audio_haptic_log.h"
#include "media_errors.h"

#include "isoundpool.h"
#include "player.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticManagerImpl"};
}

namespace OHOS {
namespace Media {
const std::int32_t MAX_PLAYER_NUM = 128;
const int32_t ERROR = -1;
const std::string FDHEAD = "fd://";

std::shared_ptr<AudioHapticManager> AudioHapticManagerFactory::audioHapticManager_ = nullptr;
std::mutex AudioHapticManagerFactory::audioHapticManagerMutex_;

static int32_t ExtractFd(const std::string& uri)
{
    if (uri.size() <= FDHEAD.size() || uri.substr(0, FDHEAD.length()) != FDHEAD) {
        return ERROR;
    }

    std::string numberPart = uri.substr(FDHEAD.length());
    for (char c : numberPart) {
        if (!std::isdigit(c)) {
            MEDIA_LOGE("ExtractFd: The part after the FDHEAD is not all digits.");
            return ERROR;
        }
    }

    int32_t fd = atoi(numberPart.c_str());
    return fd > 0 ? fd : ERROR;
}

static std::string DupFdFromUri(const std::string &uri)
{
    MEDIA_LOGI("DupFdFromUri uri: %{public}s", uri.c_str());
    if (uri.find(FDHEAD) == std::string::npos) {
        return uri;
    }

    int32_t fd = ExtractFd(uri);
    if (fd == ERROR) {
        MEDIA_LOGE("DupFdFromUri ExtractFd failed");
        return "";
    }

    int32_t dupFd = dup(fd);
    if (dupFd == ERROR) {
        MEDIA_LOGE("DupFdFromUri failed. uri: %{public}s", uri.c_str());
        return "";
    }
    return FDHEAD + std::to_string(dupFd);
}

std::shared_ptr<AudioHapticManager> AudioHapticManagerFactory::CreateAudioHapticManager()
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);
    if (audioHapticManager_ == nullptr) {
        audioHapticManager_ = std::make_shared<AudioHapticManagerImpl>();
    }
    CHECK_AND_RETURN_RET_LOG(audioHapticManager_ != nullptr, nullptr, "Failed to create audio haptic manager object");

    return audioHapticManager_;
}

AudioHapticManagerImpl::AudioHapticManagerImpl()
{
    audioHapticPlayerMap_.clear();
    curPlayerIndex_ = 0;
    curPlayerCount_ = 0;
}

AudioHapticManagerImpl::~AudioHapticManagerImpl()
{
    for (auto &[sourceId, info] : audioHapticPlayerMap_) {
        (void)sourceId;
        if (!info->audioUri_.empty()) {
            int32_t fd = ExtractFd(info->audioUri_);
            if (fd != ERROR) {
                close(fd);
            }
        }
        if (!info->hapticSource_.hapticUri.empty()) {
            int32_t fd = ExtractFd(info->hapticSource_.hapticUri);
            if (fd != ERROR) {
                close(fd);
            }
        }
    }
    audioHapticPlayerMap_.clear();
    curPlayerIndex_ = 0;
    curPlayerCount_ = 0;
}

int32_t AudioHapticManagerImpl::RegisterSourceWithEffectId(const std::string &audioUri, const std::string &effectId)
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);
    if (effectId == "") {
        MEDIA_LOGE("RegisterSourceWithEffectId failed. The effectId is empty!");
        return -1;
    }
    if (curPlayerCount_ >= MAX_PLAYER_NUM) {
        MEDIA_LOGE("RegisterSourceWithEffectId failed. curPlayerCount_: %{public}d", curPlayerCount_);
        return -1;
    }
    curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    while (audioHapticPlayerMap_[curPlayerIndex_] != nullptr) {
        curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    }
    int32_t sourceId = curPlayerIndex_;
    HapticSource sourceUri = {"", effectId};
    audioHapticPlayerMap_[sourceId] = std::make_shared<AudioHapticPlayerInfo>(audioUri, sourceUri,
        AUDIO_LATENCY_MODE_FAST, AudioStandard::StreamUsage::STREAM_USAGE_MUSIC);
    curPlayerCount_ += 1;
    MEDIA_LOGI("Finish to RegisterSourceWithEffectId. effectId: %{public}s, sourceId: %{public}d",
        effectId.c_str(), sourceId);
    return sourceId;
}

int32_t AudioHapticManagerImpl::RegisterSource(const std::string &audioUri, const std::string &hapticUri)
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);

    if (curPlayerCount_ >= MAX_PLAYER_NUM) {
        MEDIA_LOGE("RegisterSource failed curPlayerCount_: %{public}d", curPlayerCount_);
        return -1;
    }
    curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    while (audioHapticPlayerMap_[curPlayerIndex_] != nullptr) {
        curPlayerIndex_ = (curPlayerIndex_ + 1) % MAX_PLAYER_NUM;
    }
    std::string audioUriStr = DupFdFromUri(audioUri);
    std::string hapticUriStr = DupFdFromUri(hapticUri);

    int32_t sourceId = curPlayerIndex_;
    HapticSource sourceUri = {hapticUriStr, ""};
    audioHapticPlayerMap_[sourceId] = std::make_shared<AudioHapticPlayerInfo>(audioUriStr, sourceUri,
        AUDIO_LATENCY_MODE_NORMAL, AudioStandard::StreamUsage::STREAM_USAGE_MUSIC);
    curPlayerCount_ += 1;
    MEDIA_LOGI("Finish to RegisterSource. audioUri: %{public}s, hapticUri: %{public}s, sourceId: %{public}d",
        audioUriStr.c_str(), hapticUriStr.c_str(), sourceId);
    return sourceId;
}

int32_t AudioHapticManagerImpl::UnregisterSource(const int32_t &sourceID)
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);

    if (audioHapticPlayerMap_.count(sourceID) == 0 || audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("UnregisterSource failed sourceID: %{public}d", sourceID);
        return MSERR_INVALID_VAL;
    }

    std::shared_ptr<AudioHapticPlayerInfo> info = audioHapticPlayerMap_[sourceID];
    if (!info->audioUri_.empty()) {
        int32_t fd = ExtractFd(info->audioUri_);
        if (fd != ERROR) {
            close(fd);
        }
    }
    if (!info->hapticSource_.hapticUri.empty()) {
        int32_t fd = ExtractFd(info->hapticSource_.hapticUri);
        if (fd != ERROR) {
            close(fd);
        }
    }

    audioHapticPlayerMap_[sourceID] = nullptr;
    audioHapticPlayerMap_.erase(sourceID);
    curPlayerCount_ -= 1;
    MEDIA_LOGI("Finish to UnregisterSource. sourceId: %{public}d", sourceID);
    return MSERR_OK;
}

bool AudioHapticManagerImpl::CheckAudioLatencyMode(const int32_t &sourceId, const AudioLatencyMode &latencyMode)
{
    if (latencyMode != AUDIO_LATENCY_MODE_NORMAL && latencyMode != AUDIO_LATENCY_MODE_FAST) {
        MEDIA_LOGE("The AudioLatencyMode %{public}d is invalid!", latencyMode);
        return false;
    }

    // effectId can only be used for low latency mode.
    HapticSource source = audioHapticPlayerMap_[sourceId]->hapticSource_;
    if (source.effectId != "" && latencyMode != AUDIO_LATENCY_MODE_FAST) {
        MEDIA_LOGE("The effectId source can only be used for low latency mode!");
        return false;
    }

    return true;
}

int32_t AudioHapticManagerImpl::SetAudioLatencyMode(const int32_t &sourceId, const AudioLatencyMode &latencyMode)
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);
    if (audioHapticPlayerMap_.count(sourceId) == 0 || audioHapticPlayerMap_[sourceId] == nullptr) {
        MEDIA_LOGE("SetAudioLatencyMode: failed for invalid sourceID: %{public}d", sourceId);
        return MSERR_INVALID_VAL;
    }
    if (!CheckAudioLatencyMode(sourceId, latencyMode)) {
        MEDIA_LOGE("SetAudioLatencyMode: failed for invalid latencyMode: %{public}d", latencyMode);
        return MSERR_INVALID_VAL;
    }
    audioHapticPlayerMap_[sourceId]->latencyMode_ = latencyMode;
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
        case AudioStandard::STREAM_USAGE_VOICE_RINGTONE:
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
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);
    if (audioHapticPlayerMap_.count(sourceID) == 0 || audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("SetStreamUsage: failed for invalid sourceID: %{public}d", sourceID);
        return MSERR_INVALID_VAL;
    }
    if (!CheckAudioStreamUsage(streamUsage)) {
        MEDIA_LOGE("SetStreamUsage: failed for invalid latencyMode: %{public}d", streamUsage);
        return MSERR_INVALID_VAL;
    }
    audioHapticPlayerMap_[sourceID]->streamUsage_ = streamUsage;
    return MSERR_OK;
}

std::shared_ptr<AudioHapticPlayer> AudioHapticManagerImpl::CreatePlayer(const int32_t &sourceID,
    const AudioHapticPlayerOptions &audioHapticPlayerOptions)
{
    std::lock_guard<std::mutex> lock(audioHapticManagerMutex_);
    if (audioHapticPlayerMap_.count(sourceID) == 0 || audioHapticPlayerMap_[sourceID] == nullptr) {
        MEDIA_LOGE("CreatePlayer failed for sourceID: %{public}d", sourceID);
        return nullptr;
    }

    std::shared_ptr<AudioHapticPlayerInfo> audioHapticPlayerInfo = audioHapticPlayerMap_[sourceID];
    AudioHapticPlayerParam param = AudioHapticPlayerParam(audioHapticPlayerOptions,
        audioHapticPlayerInfo->audioUri_, audioHapticPlayerInfo->hapticSource_,
        audioHapticPlayerInfo->latencyMode_, audioHapticPlayerInfo->streamUsage_);
    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer = AudioHapticPlayerFactory::CreateAudioHapticPlayer(param);

    if (audioHapticPlayer == nullptr) {
        MEDIA_LOGE("CreatePlayer failed for sourceID: %{public}d", sourceID);
        return nullptr;
    }
    return audioHapticPlayer;
}
} // namesapce AudioStandard
} // namespace OHOS
