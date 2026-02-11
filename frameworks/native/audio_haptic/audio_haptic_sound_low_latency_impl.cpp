/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "audio_haptic_sound_low_latency_impl.h"

#include <fcntl.h>

#include "isoundpool.h"
#include "audio_haptic_log.h"
#include "directory_ex.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticSoundLowLatencyImpl"};
}

namespace OHOS {
namespace Media {
const int32_t MAX_SOUND_POOL_STREAMS = 1; // ensure that only one stream for sound pool is playing.
const int32_t LOAD_WAIT_SECONDS = 2;

AudioHapticSoundLowLatencyImpl::AudioHapticSoundLowLatencyImpl(const AudioSource& audioSource, const bool &muteAudio,
    const AudioStandard::StreamUsage &streamUsage, const bool &parallelPlayFlag)
    : audioSource_(audioSource),
      muteAudio_(muteAudio),
      parallelPlayFlag_(parallelPlayFlag),
      streamUsage_(streamUsage)
{
}

AudioHapticSoundLowLatencyImpl::~AudioHapticSoundLowLatencyImpl()
{
    if (soundPoolPlayer_ != nullptr) {
        (void)ReleaseSoundInternal();
    }
}

int32_t AudioHapticSoundLowLatencyImpl::LoadSoundPoolPlayer()
{
    MEDIA_LOGI("Enter LoadSoundPoolPlayer()");

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = streamUsage_;
    audioRendererInfo.rendererFlags = 1;

    soundPoolPlayer_ = SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_VAL,
        "Failed to create sound pool player instance");

    soundPoolCallback_ = std::make_shared<AHSoundLowLatencyCallback>(shared_from_this());
    CHECK_AND_RETURN_RET_LOG(soundPoolCallback_ != nullptr, MSERR_INVALID_VAL, "Failed to create callback object");
    soundPoolPlayer_->SetSoundPoolCallback(soundPoolCallback_);

    firstFrameCallback_ = std::make_shared<AHSoundFirstFrameCallback>(shared_from_this());
    CHECK_AND_RETURN_RET_LOG(firstFrameCallback_ != nullptr, MSERR_INVALID_VAL, "Failed to create callback object");
    soundPoolPlayer_->SetSoundPoolFrameWriteCallback(firstFrameCallback_);

    configuredAudioSource_ = {};
    playerState_ = AudioHapticPlayerState::STATE_NEW;
    return MSERR_OK;
}

int32_t AudioHapticSoundLowLatencyImpl::OpenAudioSource()
{
    if (fileDes_ != -1) {
        (void)close(fileDes_);
        fileDes_ = -1;
    }

    auto audioUri = audioSource_.audioUri;
    auto audioFd = audioSource_.fd;
    MEDIA_LOGI("Set audio source to soundpool. audioUri [%{public}s], audioFd [%{public}d]",
        audioUri.c_str(), audioFd);
    CHECK_AND_RETURN_RET_LOG(!audioUri.empty() || audioFd > FILE_DESCRIPTOR_INVALID, MSERR_OPEN_FILE_FAILED,
        "AudioUri is empty or invalid audioFd.");

    if (!audioUri.empty()) {
        const std::string fdHead = "fd://";
        int32_t oldFd = ExtractFd(audioUri);
        if (oldFd != FILE_DESCRIPTOR_INVALID) {
            fileDes_ = dup(oldFd);
            MEDIA_LOGI("fileDes_ == %{public}d", fileDes_);
        } else {
            std::string absFilePath;
            CHECK_AND_RETURN_RET_LOG(PathToRealPath(audioUri, absFilePath), MSERR_OPEN_FILE_FAILED,
                "file is not real path, file path: %{private}s", audioUri.c_str());
            CHECK_AND_RETURN_RET_LOG(!absFilePath.empty(), MSERR_OPEN_FILE_FAILED,
                "Failed to obtain the canonical path for source path %{public}d %{private}s",
                errno, audioUri.c_str());
            fileDes_ = open(absFilePath.c_str(), O_RDONLY | O_CLOEXEC);
        }
    } else {
        fileDes_ = dup(audioFd);
    }
    MEDIA_LOGI("AudioHapticSoundLowLatencyImpl::OpenAudioSource fileDes_: %{public}d", fileDes_);
    CHECK_AND_RETURN_RET_LOG(fileDes_ > FILE_DESCRIPTOR_INVALID, MSERR_OPEN_FILE_FAILED,
        "AudioHapticSoundLowLatencyImpl::OpenAudioSource: Failed to open the audio source for sound pool.");
    // If an audio player is created through a file descriptor (FD)
    // the length information is required, otherwise SoundPool will return a failure
    if (audioUri.empty() && audioSource_.length == 0) {
        struct stat64 statbuf = { 0 };
        CHECK_AND_RETURN_RET_LOG(fstat64(fileDes_, &statbuf) == 0, MSERR_OPEN_FILE_FAILED,
            "AudioHapticSoundLowLatencyImpl::OpenAudioSource: Failed to open the audio source for sound pool.");
        audioSource_.length = statbuf.st_size;
    }
    return MSERR_OK;
}

int32_t AudioHapticSoundLowLatencyImpl::PrepareSound()
{
    MEDIA_LOGI("Enter PrepareSound with sound pool");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    int32_t result = LoadSoundPoolPlayer();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK && soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE,
        "Audio haptic player(soundpool) instance is null");

    if (!configuredAudioSource_.empty() && configuredAudioSource_ == audioSource_) {
        MEDIA_LOGI("Prepare: The audioSource_ has been loaded. Return directly.");
        return MSERR_OK;
    }

    result = OpenAudioSource();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "Failed to open audio source.");

    int32_t soundID = -1;
    if (!audioSource_.audioUri.empty()) {
        std::string uri = "fd://" + std::to_string(fileDes_);
        soundID = soundPoolPlayer_->Load(uri);
    } else {
        soundID = soundPoolPlayer_->Load(fileDes_, audioSource_.offset, audioSource_.length);
    }
    if (soundID < 0) {
        MEDIA_LOGE("Prepare: Failed to load soundPool uri.");
        return MSERR_OPEN_FILE_FAILED;
    }
    std::unique_lock<std::mutex> lockPrepare(prepareMutex_);
    prepareCond_.wait_for(lockPrepare, std::chrono::seconds(LOAD_WAIT_SECONDS),
        [this]() { return isPrepared_ || isReleased_ || isUnsupportedFile_; });
    CHECK_AND_RETURN_RET_LOG(!isReleased_, MSERR_INVALID_OPERATION, "The sound pool is released when it is preparing.");
    CHECK_AND_RETURN_RET_LOG(!isUnsupportedFile_, MSERR_UNSUPPORT_FILE,
        "Failed to load audio uri: report unsupported file err when loading source for sound pool.");
    CHECK_AND_RETURN_RET_LOG(isPrepared_, MSERR_OPEN_FILE_FAILED, "Failed to load audio uri: time out.");

    // The audio source has been loaded for sound pool
    soundID_ = soundID;
    configuredAudioSource_ = audioSource_;
    playerState_ = AudioHapticPlayerState::STATE_PREPARED;

    return MSERR_OK;
}

int32_t AudioHapticSoundLowLatencyImpl::StartSound(const int32_t &audioHapticSyncId)
{
    MEDIA_LOGI("Enter StartSound with sound pool");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    if (playerState_ != AudioHapticPlayerState::STATE_PREPARED &&
        playerState_ != AudioHapticPlayerState::STATE_RUNNING &&
        playerState_ != AudioHapticPlayerState::STATE_STOPPED) {
        MEDIA_LOGE("SoundPoolPlayer not Prepared");
        return MSERR_START_FAILED;
    }
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "Sound pool player instance is null");

    audioHapticSyncId_ = audioHapticSyncId;
    MEDIA_LOGI("AudioHapticSoundLowLatencyImpl::StartSound start sound with syncId %{public}d", audioHapticSyncId_);
    PlayParams playParams {
        .loop = (loop_ ? -1 : 0),
        .rate = 0, // default AudioRendererRate::RENDER_RATE_NORMAL
        .leftVolume = volume_ * (muteAudio_ ? 0 : 1),
        .rightVolume = volume_ * (muteAudio_ ? 0 : 1),
        .priority = 0,
        .parallelPlayFlag = parallelPlayFlag_,
        .audioHapticsSyncId = audioHapticSyncId,
    };
    streamID_ = soundPoolPlayer_->Play(soundID_, playParams);
    playerState_ = AudioHapticPlayerState::STATE_RUNNING;

    return MSERR_OK;
}

int32_t AudioHapticSoundLowLatencyImpl::StopSound()
{
    MEDIA_LOGI("Enter StopSound with sound pool");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "Sound pool player instance is null");

    (void)soundPoolPlayer_->Stop(streamID_);
    playerState_ = AudioHapticPlayerState::STATE_STOPPED;

    return MSERR_OK;
}

int32_t AudioHapticSoundLowLatencyImpl::ReleaseSound()
{
    MEDIA_LOGI("Enter ReleaseSound with sound pool");
    return ReleaseSoundInternal();
}

int32_t AudioHapticSoundLowLatencyImpl::ReleaseSoundInternal()
{
    MEDIA_LOGI("Enter ReleaseSoundInternal().");
    {
        std::lock_guard<std::mutex> lockPrepare(prepareMutex_);
        isReleased_ = true;
        prepareCond_.notify_one();
    }
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(playerState_ != AudioHapticPlayerState::STATE_RELEASED, MSERR_OK,
        "The audio haptic player has been released.");
    ReleaseSoundPoolPlayer();
    playerState_ = AudioHapticPlayerState::STATE_RELEASED;

    return MSERR_OK;
}

void AudioHapticSoundLowLatencyImpl::ReleaseSoundPoolPlayer()
{
    if (soundPoolPlayer_ != nullptr) {
        (void)soundPoolPlayer_->Release();
        soundPoolPlayer_ = nullptr;
    }
    soundPoolCallback_ = nullptr;
    if (fileDes_ != -1) {
        (void)close(fileDes_);
        fileDes_ = -1;
    }
}

int32_t AudioHapticSoundLowLatencyImpl::SetVolume(float volume)
{
    MEDIA_LOGI("AudioHapticSoundLowLatencyImpl::SetVolume %{public}f", volume);
    if (volume < 0.0f || volume > 1.0f) {
        MEDIA_LOGE("SetVolume: the volume value is invalid.");
        return MSERR_INVALID_VAL;
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    int32_t result = MSERR_OK;
    volume_ = volume;

    if (playerState_ != AudioHapticPlayerState::STATE_PREPARED &&
        playerState_ != AudioHapticPlayerState::STATE_RUNNING) {
        MEDIA_LOGI("Audio haptic player is not prepared or running. No need to modify player");
        return result;
    }
    if (streamID_ != -1) {
        float actualVolume = volume_ * (muteAudio_ ? 0 : 1);
        result = soundPoolPlayer_->SetVolume(streamID_, actualVolume, actualVolume);
    }
    return result;
}

int32_t AudioHapticSoundLowLatencyImpl::SetLoop(bool loop)
{
    MEDIA_LOGI("AudioHapticSoundLowLatencyImpl::SetLoop %{public}d", loop);
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    int32_t result = MSERR_OK;
    loop_ = loop;

    if (playerState_ != AudioHapticPlayerState::STATE_PREPARED &&
        playerState_ != AudioHapticPlayerState::STATE_RUNNING) {
        MEDIA_LOGI("Audio haptic player is not prepared or running. No need to modify player");
        return result;
    }
    if (streamID_ != -1) {
        int32_t loopCount = loop_ ? -1 : 0;
        result = soundPoolPlayer_->SetLoop(streamID_, loopCount);
    }
    return result;
}

int32_t AudioHapticSoundLowLatencyImpl::GetAudioCurrentTime()
{
    MEDIA_LOGE("GetAudioCurrentTime is unsupported for sound pool.");
    return -1;
}

int32_t AudioHapticSoundLowLatencyImpl::SetAudioHapticSoundCallback(
    const std::shared_ptr<AudioHapticSoundCallback> &callback)
{
    if (callback == nullptr) {
        MEDIA_LOGE("The audio haptic player callback is nullptr.");
        return MSERR_INVALID_VAL;
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    audioHapticPlayerCallback_ = callback;
    return MSERR_OK;
}

void AudioHapticSoundLowLatencyImpl::NotifyPreparedEvent()
{
    std::lock_guard<std::mutex> lockPrepare(prepareMutex_);
    isPrepared_ = true;
    prepareCond_.notify_one();
}

void AudioHapticSoundLowLatencyImpl::NotifyErrorEvent(int32_t errorCode)
{
    MediaServiceErrCode mediaErr = static_cast<MediaServiceErrCode>(errorCode);
    if (mediaErr == MSERR_UNSUPPORT_FILE) {
        std::lock_guard<std::mutex> lockPrepare(prepareMutex_);
        isUnsupportedFile_ = true;
        prepareCond_.notify_one();
    }

    std::shared_ptr<AudioHapticSoundCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyFirstFrameEvent for audio haptic player");
        cb->OnError(errorCode);
    } else {
        MEDIA_LOGE("NotifyFirstFrameEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

void AudioHapticSoundLowLatencyImpl::NotifyFirstFrameEvent(uint64_t latency)
{
    std::shared_ptr<AudioHapticSoundCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyFirstFrameEvent for audio haptic player");
        cb->OnFirstFrameWriting(latency);
    } else {
        MEDIA_LOGE("NotifyFirstFrameEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

void AudioHapticSoundLowLatencyImpl::NotifyEndOfStreamEvent()
{
    MEDIA_LOGI("NotifyEndOfStreamEvent");
    playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    std::shared_ptr<AudioHapticSoundCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyEndOfStreamEvent for audio haptic player");
        cb->OnEndOfStream();
    } else {
        MEDIA_LOGE("NotifyEndOfStreamEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

int32_t AudioHapticSoundLowLatencyImpl::ExtractFd(const std::string& audioUri)
{
    const std::string prefix = "fd://";
    if (audioUri.size() <= prefix.size() || audioUri.substr(0, prefix.length()) != prefix) {
        MEDIA_LOGW("ExtractFd: Input does not start with the required prefix.");
        return FILE_DESCRIPTOR_INVALID;
    }

    std::string numberPart = audioUri.substr(prefix.length());
    for (char c : numberPart) {
        if (!std::isdigit(c)) {
            MEDIA_LOGE("ExtractFd: The part after the prefix is not all digits.");
            return FILE_DESCRIPTOR_INVALID;
        }
    }

    int32_t fd = atoi(numberPart.c_str());
    return fd > FILE_DESCRIPTOR_INVALID ? fd : FILE_DESCRIPTOR_INVALID;
}

// Callback class symbols
AHSoundLowLatencyCallback::AHSoundLowLatencyCallback(
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl)
    : soundLowLatencyImpl_(soundLowLatencyImpl) {}

void AHSoundLowLatencyCallback::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("OnLoadCompleted reported from sound pool.");
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl = soundLowLatencyImpl_.lock();
    if (soundLowLatencyImpl == nullptr) {
        MEDIA_LOGE("The audio haptic player for low latency mode has been released.");
        return;
    }
    soundLowLatencyImpl->NotifyPreparedEvent();
}

void AHSoundLowLatencyCallback::OnPlayFinished(int32_t streamID)
{
    (void)streamID;
    MEDIA_LOGI("OnPlayFinished reported from sound pool.");
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl = soundLowLatencyImpl_.lock();
    if (soundLowLatencyImpl == nullptr) {
        MEDIA_LOGE("The audio haptic player for low latency mode has been released.");
        return;
    }
    soundLowLatencyImpl->NotifyEndOfStreamEvent();
}

void AHSoundLowLatencyCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGE("OnError reported from sound pool: %{public}d", errorCode);
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl = soundLowLatencyImpl_.lock();
    if (soundLowLatencyImpl == nullptr) {
        MEDIA_LOGE("The audio haptic player for low latency mode has been released.");
        return;
    }
    soundLowLatencyImpl->NotifyErrorEvent(errorCode);
}

AHSoundFirstFrameCallback::AHSoundFirstFrameCallback(
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl)
    : soundLowLatencyImpl_(soundLowLatencyImpl) {}

void AHSoundFirstFrameCallback::OnFirstAudioFrameWritingCallback(uint64_t &latency)
{
    MEDIA_LOGI("OnFirstAudioFrameWritingCallback from Soundpool. Latency %{public}" PRIu64 "", latency);
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> soundLowLatencyImpl = soundLowLatencyImpl_.lock();
    if (soundLowLatencyImpl == nullptr) {
        MEDIA_LOGE("The audio haptic player for low latency mode has been released.");
        return;
    }
    soundLowLatencyImpl->NotifyFirstFrameEvent(latency);
}
} // namesapce AudioStandard
} // namespace OHOS
