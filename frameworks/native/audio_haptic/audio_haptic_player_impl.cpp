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

#include "audio_haptic_player_impl.h"

#include <fcntl.h>

#include "isoundpool.h"
#include "media_log.h"
#include "media_errors.h"
#include "player.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "AudioHapticManagerImpl"};
}

namespace OHOS {
namespace Media {
const int32_t MAX_SOUND_POOL_STREAMS = 1; // ensure that only one system tone is playing.
const int32_t LOAD_WAIT_SECONDS = 2;

AudioHapticPlayerImpl::AudioHapticPlayerImpl()
    : playerType_(AUDIO_HAPTIC_TYPE_DEFAULT),
      muteAudio_(false),
      muteHaptic_(false),
      audioUri_(""),
      hapticUri_(""),
      configuredAudioUri_(""),
      callback_(nullptr)
{
}

AudioHapticPlayerImpl::~AudioHapticPlayerImpl()
{
    if (soundPoolPlayer_ != nullptr) {
        soundPoolPlayer_->Release();
        soundPoolPlayer_ = nullptr;
    }
    if (avPlayer_ != nullptr) {
        avPlayer_->Release();
        avPlayer_ = nullptr;
    }
    if (callback_ != nullptr) {
        callback_ = nullptr;
    }
    if (audioHapticVibrator_ != nullptr) {
        audioHapticVibrator_->Release();
        audioHapticVibrator_ = nullptr;
    }

    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
        vibrateThread_ = nullptr;
    }
}

void AudioHapticPlayerImpl::SetPlayerOptions(const bool &muteAudio, const bool &muteHaptic)
{
    muteAudio_ = muteAudio;
    muteHaptic_ = muteHaptic;
}

int32_t AudioHapticPlayerImpl::SetPlayerType(const AudioHapticPlayerType &audioHapticPlayerType)
{
    playerType_ = audioHapticPlayerType;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::SetPlayerStreamUsage(const AudioStandard::StreamUsage &streamUsage)
{
    streamUsage_ = streamUsage;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::SetPlayerSource(const std::string audioUri, const std::string hapticUri)
{
    audioUri_ = audioUri;
    hapticUri_ = hapticUri;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::StartVibrate()
{
    if (muteHaptic_) {
        MEDIA_LOGI("StartVibrate: muteHaptic is true. No need to vibrate");
        return MSERR_OK;
    }

    MEDIA_LOGI("Enter StartVibrate()");
    std::unique_lock<std::mutex> lockWait(waitStartVibrateMutex_);
    bool waitResult = condStartVibrate_.wait_for(lockWait, std::chrono::seconds(LOAD_WAIT_SECONDS),
        [this]() { return isAudioPlayFirstFrame_; });
    if (!waitResult) {
        MEDIA_LOGE("StartVibrate: Failed to start vibrate (time out).");
        return MSERR_INVALID_OPERATION;
    }
    isAudioPlayFirstFrame_ = false;

    if (!isRelease_) {
        int hapticDelay = audioHapticVibrator_->GetDelayTime();
        int delay = (this->audioLatency_ - hapticDelay) > 0 ? this->audioLatency_ - hapticDelay : 0;
        waitResult = condStartVibrate_.wait_for(lockWait, std::chrono::milliseconds(delay),
            [this]() { return isRelease_; });
        if (!isRelease_) {
            AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_NORMAL;
            if (playerType_ == AUDIO_HAPTIC_TYPE_FAST) {
                latencyMode = AUDIO_LATENCY_MODE_FAST;
            }
            audioHapticVibrator_->StartVibrate(latencyMode);
        }
    }
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::LoadVibratorSource()
{
    audioHapticVibrator_ = AudioHapticVibrator::CreateAudioHapticVibrator(*this);
    CHECK_AND_RETURN_RET_LOG(audioHapticVibrator_ != nullptr, MSERR_INVALID_OPERATION,
        "Failed to create audio haptic vibrator instance");

    return audioHapticVibrator_->PreLoad(hapticUri_);
}

int32_t AudioHapticPlayerImpl::LoadSoundPoolPlayer()
{
    MEDIA_LOGI("Enter LoadSoundPoolPlayer()");

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = streamUsage_;
    audioRendererInfo.rendererFlags = 1;

    soundPoolPlayer_ = SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_VAL,
        "Failed to create sound pool player instance");

    callback_ = std::make_shared<AudioHapticPlayerNativeCallback>(*this);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "Failed to create callback object");
    soundPoolPlayer_->SetSoundPoolCallback(callback_);

    firstFrameCb_ = std::make_shared<AudioHapticFirstFrameCb>(*this);
    CHECK_AND_RETURN_RET_LOG(firstFrameCb_ != nullptr, MSERR_INVALID_VAL, "Failed to create callback object");
    soundPoolPlayer_->SetSoundPoolFrameWriteCallback(firstFrameCb_);

    configuredAudioUri_ = "";

    PrepareSoundPoolSource();

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::PrepareSoundPoolSource()
{
    MEDIA_LOGI("Enter PrepareSoundPoolSource()");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "soundpool player instance is null");

    if (!configuredAudioUri_.empty() && configuredAudioUri_ == audioUri_) {
        MEDIA_LOGI("Prepare: The audioUri_ uri has been loaded. Return directly.");
        return MSERR_OK;
    }

    fileDes_ = open(audioUri_.c_str(), O_RDONLY);
    if (fileDes_ == -1) {
        // open file failed, return.
        return MSERR_OPEN_FILE_FAILED;
    }
    std::string uri = "fd://" + std::to_string(fileDes_);

    int32_t soundID = soundPoolPlayer_->Load(uri);
    if (soundID < 0) {
        MEDIA_LOGE("Prepare: Failed to load soundPool uri.");
        return MSERR_OPEN_FILE_FAILED;
    }
    std::unique_lock<std::mutex> lockWait(loadUriMutex_);
    bool waitResult = condLoadUri_.wait_for(lockWait, std::chrono::seconds(LOAD_WAIT_SECONDS),
        [this]() { return loadCompleted_; });
    if (!waitResult) {
        MEDIA_LOGE("Prepare: Failed to load soundpool uri (time out).");
        return MSERR_OPEN_FILE_FAILED;
    }

    soundID_ = soundID;
    configuredAudioUri_ = audioUri_;

    playerState_ = STATE_PREPARED;

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::StartSoundPoolPlayer()
{
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    MEDIA_LOGI("Enter StartSoundPoolPlayer()");
    if (playerState_ != STATE_PREPARED && playerState_ != STATE_RUNNING && playerState_ != STATE_STOPPED) {
        MEDIA_LOGE("SoundPoolPlayer not Prepared");
        return MSERR_START_FAILED;
    }
    if (vibrateThread_ == nullptr) {
        vibrateThread_ = std::make_shared<std::thread>([this] { StartVibrate(); });
    }
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "Sound pool player instance is null");

    PlayParams playParams {
        .loop = 0,
        .rate = 0, // default AudioRendererRate::RENDER_RATE_NORMAL
        .leftVolume = 1.0,
        .rightVolume = 1.0,
        .priority = 0,
        .parallelPlayFlag = false,
    };

    int32_t streamID = soundPoolPlayer_->Play(soundID_, playParams);
    streamID_ = streamID;
    if (muteAudio_) {
        soundPoolPlayer_->SetVolume(streamID_, 0, 0);
    }
    playerState_ = STATE_RUNNING;

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::StopSoundPoolPlayer()
{
    MEDIA_LOGI("Enter StopSoundPoolPlayer()");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "Sound pool player instance is null");

    (void)soundPoolPlayer_->Stop(streamID_);
    audioHapticVibrator_->StopVibrate();

    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
        vibrateThread_.reset();
    }

    playerState_ = STATE_STOPPED;

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::ReleaseSoundPoolPlayer()
{
    MEDIA_LOGI("Enter Release()");
    {
        std::lock_guard<std::mutex> lockStatus(loadUriMutex_);
        loadCompleted_ = false;
        condLoadUri_.notify_one();
    }
    audioHapticVibrator_->Release();
    {
        // When player is releasing，notify vibrate thread immediately
        std::lock_guard<std::mutex> lockVibrate(waitStartVibrateMutex_);
        isAudioPlayFirstFrame_ = true;
        isRelease_ = true;
        condStartVibrate_.notify_one();
    }
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(soundPoolPlayer_ != nullptr, MSERR_INVALID_STATE, "Sound pool player instance is null");

    (void)soundPoolPlayer_->Release();
    soundPoolPlayer_ = nullptr;
    if (fileDes_ != -1) {
        (void)close(fileDes_);
        fileDes_ = -1;
    }
    callback_ = nullptr;

    playerState_ = STATE_RELEASED;

    return MSERR_OK;
}


bool AudioHapticPlayerImpl::IsMuted(const AudioHapticType &audioHapticType) const
{
    if (audioHapticType == AUDIO_HAPTIC_TYPE_AUDIO) {
        return muteAudio_;
    } else if (audioHapticType == AUDIO_HAPTIC_TYPE_HAPTIC) {
        return muteHaptic_;
    }
    MEDIA_LOGE("IsMuted: invalid audioHapticType %{public}d", audioHapticType);
    return false;
}

int32_t AudioHapticPlayerImpl::Start()
{
    if (playerType_ == AUDIO_HAPTIC_TYPE_NORMAL) {
        StartAVPlayer();
    } else if (playerType_ == AUDIO_HAPTIC_TYPE_FAST) {
        StartSoundPoolPlayer();
    }
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::Stop()
{
    if (playerType_ == AUDIO_HAPTIC_TYPE_NORMAL) {
        StopAVPlayer();
    } else if (playerType_ == AUDIO_HAPTIC_TYPE_FAST) {
        StopSoundPoolPlayer();
    }
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::Release()
{
    if (playerType_ == AUDIO_HAPTIC_TYPE_NORMAL) {
        ReleaseAVPlayer();
    } else if (playerType_ == AUDIO_HAPTIC_TYPE_FAST) {
        ReleaseSoundPoolPlayer();
    }
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::SetAudioHapticPlayerCallback(
    const std::shared_ptr<AudioHapticPlayerCallback> &playerCallback)
{
    napiCallback_ = playerCallback;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::GetAudioCurrentTime()
{
    if (avPlayer_ == nullptr) {
        MEDIA_LOGE("GetAudioCurrentTime: avPlayer_ is nullptr. This function is only usable for avPlayer.");
        return -1;
    }
    int32_t currentTime = -1;
    (void)avPlayer_->GetCurrentTime(currentTime);
    return currentTime;
}

void AudioHapticPlayerImpl::NotifySoundPoolSourceLoadCompleted()
{
    std::lock_guard<std::mutex> lockUri(loadUriMutex_);
    loadCompleted_ = true;
    condLoadUri_.notify_one();
}

int32_t AudioHapticPlayerImpl::LoadAVPlayer()
{
    avPlayer_ = PlayerFactory::CreatePlayer();
    CHECK_AND_RETURN_RET_LOG(avPlayer_ != nullptr, MSERR_INVALID_VAL, "Failed to create AvPlayer instance");

    callback_ = std::make_shared<AudioHapticPlayerNativeCallback>(*this);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "Failed to create callback object");

    avPlayer_->SetPlayerCallback(callback_);
    playerState_ = STATE_NEW;
    configuredAudioUri_ = "";

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::PrepareAVPlayer(bool isReInitNeeded)
{
    MEDIA_LOGI("PrepareAVPlayer");
    CHECK_AND_RETURN_RET_LOG(avPlayer_ != nullptr, MSERR_INVALID_VAL, "Audio haptic player instance is null");

    if (audioUri_.empty()) {
        // if audioUri_ == "", try to use default path.
        MEDIA_LOGI("The audio uri is empty");
        return MSERR_INVALID_VAL;
    }

    // If uri is different from from configure uri, reset the player
    if (audioUri_ != configuredAudioUri_ || isReInitNeeded) {
        (void)avPlayer_->Reset();

        int32_t ret = avPlayer_->SetSource(audioUri_);
        if (ret != MSERR_OK) {
            // failed to set source, try to use default path.
        }
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Set source failed %{public}d", ret);

        Format format;
        format.PutIntValue(PlayerKeys::CONTENT_TYPE, AudioStandard::CONTENT_TYPE_UNKNOWN);
        format.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage_);
        ret = avPlayer_->SetParameter(format);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Set stream usage to AVPlayer failed %{public}d", ret);

        ret = avPlayer_->PrepareAsync();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Prepare failed %{public}d", ret);

        configuredAudioUri_ = audioUri_;
        playerState_ = STATE_NEW;
    }

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::StartAVPlayer()
{
    MEDIA_LOGI("StartAVPlayer");

    CHECK_AND_RETURN_RET_LOG(avPlayer_ != nullptr && playerState_ != STATE_INVALID, MSERR_INVALID_VAL,
        "StartAVPlayer: no available AVPlayer_");

    if (avPlayer_->IsPlaying() || isStartQueued_) {
        MEDIA_LOGE("Play in progress, cannot start now");
        return MSERR_START_FAILED;
    }

    // Player doesn't support play in stopped state. Hence reinitialise player for making start<-->stop to work
    if (playerState_ == STATE_STOPPED) {
        (void)PrepareAVPlayer(true);
    } else {
        (void)PrepareAVPlayer(false);
    }

    if (muteAudio_) {
        avPlayer_->SetVolume(0, 0);
    }

    if (vibrateThread_ == nullptr) {
        vibrateThread_ = std::make_shared<std::thread>([this] { StartVibrate(); });
    }
    if (playerState_ == STATE_NEW) {
        MEDIA_LOGI("Start received before AVPlayer is prepared. Wait for callback");
        isStartQueued_ = true;
        return MSERR_OK;
    }

    auto ret = avPlayer_->Play();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_START_FAILED, "Start failed %{public}d", ret);

    playerState_ = STATE_RUNNING;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::StopAVPlayer()
{
    MEDIA_LOGI("StopAVPlayer");
    CHECK_AND_RETURN_RET_LOG(avPlayer_ != nullptr && playerState_ != STATE_INVALID, MSERR_INVALID_VAL,
        "StopAVPlayer: no available AVPlayer_");

    if (playerState_ != STATE_STOPPED && avPlayer_->IsPlaying()) {
        (void)avPlayer_->Stop();
        audioHapticVibrator_->StopVibrate();
    }
    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
        vibrateThread_.reset();
    }

    playerState_ = STATE_STOPPED;
    isStartQueued_ = false;

    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::ReleaseAVPlayer()
{
    MEDIA_LOGI("ReleaseAVPlayer");

    audioHapticVibrator_->Release();
    {
        // When player is releasing，notify vibrate thread immediately
        std::lock_guard<std::mutex> lockVibrate(waitStartVibrateMutex_);
        isAudioPlayFirstFrame_ = true;
        isRelease_ = true;
        condStartVibrate_.notify_one();
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);

    if (playerState_ != STATE_STOPPED) {
        StopAVPlayer();
    }

    if (avPlayer_ != nullptr) {
        (void)avPlayer_->Release();
    }

    playerState_ = STATE_RELEASED;
    avPlayer_ = nullptr;
    callback_ = nullptr;

    return MSERR_OK;
}


void AudioHapticPlayerImpl::SetAVPlayerState(AudioHapticPlayerState playerState)
{
    CHECK_AND_RETURN_LOG(avPlayer_ != nullptr, "AVPlayer instance is null");

    if (playerState_ != AudioHapticPlayerState::STATE_RELEASED) {
        playerState_ = playerState;
    }

    if (playerState_ == AudioHapticPlayerState::STATE_PREPARED) {
        MEDIA_LOGI("Player prepared callback received. Start now");
        if (isStartQueued_) {
            auto ret = avPlayer_->Play();
            isStartQueued_ = false;
            CHECK_AND_RETURN_LOG(ret == MSERR_OK, "Play failed %{public}d", ret);
            playerState_ = AudioHapticPlayerState::STATE_RUNNING;
        }
    }
}

void AudioHapticPlayerImpl::NotifyInterruptEvent(AudioStandard::InterruptEvent &interruptEvent)
{
    if (napiCallback_ != nullptr) {
        MEDIA_LOGI("NotifyInterruptEvent for napi object");
        napiCallback_->OnInterrupt(interruptEvent);
    } else {
        MEDIA_LOGE("NotifyInterruptEvent: napiCallback_ is nullptr");
    }
}

void AudioHapticPlayerImpl::NotifyEndOfStreamEvent()
{
    audioHapticVibrator_->StopVibrate();
    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
        vibrateThread_.reset();
    }

    playerState_ = STATE_STOPPED;

    if (napiCallback_ != nullptr) {
        MEDIA_LOGI("NotifyEndOfStreamEvent for napi object");
        napiCallback_->OnEndOfStream();
    } else {
        MEDIA_LOGE("NotifyEndOfStreamEvent: napiCallback_ is nullptr");
    }
}

void AudioHapticPlayerImpl::NotifyStartVibrate(uint64_t latency)
{
    std::lock_guard<std::mutex> lock(this->waitStartVibrateMutex_);
    this->isAudioPlayFirstFrame_ = true;
    this->audioLatency_ = latency;
    this->condStartVibrate_.notify_one();
}

void AudioHapticPlayerImpl::SetAudioLatency(const uint64_t &latency)
{
    audioLatency_ = latency;
}

// Callback class symbols
AudioHapticPlayerNativeCallback::AudioHapticPlayerNativeCallback(AudioHapticPlayerImpl &audioHapticPlayerImpl)
    : audioHapticPlayerImpl_(audioHapticPlayerImpl) {}

// SoundPool callback
void AudioHapticPlayerNativeCallback::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("OnLoadCompleted reported from sound pool.");
    audioHapticPlayerImpl_.NotifySoundPoolSourceLoadCompleted();
}

void AudioHapticPlayerNativeCallback::OnPlayFinished()
{
    MEDIA_LOGI("OnPlayFinished reported from sound pool.");
    audioHapticPlayerImpl_.NotifyEndOfStreamEvent();
}

void AudioHapticPlayerNativeCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGE("Error reported from sound pool: %{public}d", errorCode);
}

// AVPlayer callback
void AudioHapticPlayerNativeCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("Error reported from AVPlayer: %{public}d", errorCode);
}

void AudioHapticPlayerNativeCallback::OnInfo(Media::PlayerOnInfoType type, int32_t extra, const Media::Format &infoBody)
{
    if (type == INFO_TYPE_STATE_CHANGE) {
        MEDIA_LOGI("OnInfo: state change reported from AVPlayer.");
        HandleStateChangeEvent(extra, infoBody);
    } else if (type == INFO_TYPE_INTERRUPT_EVENT) {
        MEDIA_LOGI("OnInfo: interrupt event reported from AVPlayer.");
        HandleAudioInterruptEvent(extra, infoBody);
    } else if (type == INFO_TYPE_AUDIO_FIRST_FRAME) {
        MEDIA_LOGI("OnInfo: first frame event reported from AVPlayer.");
        HandleAudioFirstFrameEvent(extra, infoBody);
    } else {
        return;
    }
}

void AudioHapticPlayerNativeCallback::HandleStateChangeEvent(int32_t extra, const Format &infoBody)
{
    MEDIA_LOGI("HandleStateChangeEvent from AVPlayer");
    PlayerStates avPlayerState = static_cast<PlayerStates>(extra);
    switch (avPlayerState) {
        case PLAYER_STATE_ERROR:
            playerState_ = STATE_INVALID;
            break;
        case PLAYER_IDLE:
        case PLAYER_INITIALIZED:
        case PLAYER_PREPARING:
            playerState_ = STATE_NEW;
            break;
        case PLAYER_PREPARED:
            playerState_ = STATE_PREPARED;
            break;
        case PLAYER_STARTED:
            playerState_ = STATE_RUNNING;
            break;
        case PLAYER_PAUSED:
            playerState_ = STATE_PAUSED;
            break;
        case PLAYER_STOPPED:
        case PLAYER_PLAYBACK_COMPLETE:
            playerState_ = STATE_STOPPED;
            break;
        default:
            break;
    }
    audioHapticPlayerImpl_.SetAVPlayerState(playerState_);
    if (avPlayerState == PLAYER_PLAYBACK_COMPLETE) {
        audioHapticPlayerImpl_.NotifyEndOfStreamEvent();
    }
}

void AudioHapticPlayerNativeCallback::HandleAudioInterruptEvent(int32_t extra, const Format &infoBody)
{
    MEDIA_LOGI("HandleAudioInterruptEvent from AVPlayer");
    AudioStandard::InterruptEvent interruptEvent;
    int32_t eventTypeValue = 0;
    int32_t forceTypeValue = 0;
    int32_t hintTypeValue = 0;
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventTypeValue);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceTypeValue);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintTypeValue);
    interruptEvent.eventType = static_cast<AudioStandard::InterruptType>(eventTypeValue);
    interruptEvent.forceType = static_cast<AudioStandard::InterruptForceType>(forceTypeValue);
    interruptEvent.hintType = static_cast<AudioStandard::InterruptHint>(hintTypeValue);
    audioHapticPlayerImpl_.NotifyInterruptEvent(interruptEvent);
}

void AudioHapticPlayerNativeCallback::HandleAudioFirstFrameEvent(int32_t extra, const Format &infoBody)
{
    MEDIA_LOGI("HandleAudioFirstFrameEvent from AVPlayer");
    int64_t value = 0;
    (void)infoBody.GetLongValue(PlayerKeys::AUDIO_FIRST_FRAME, value);
    uint64_t latency = static_cast<uint64_t>(value);
    audioHapticPlayerImpl_.NotifyStartVibrate(latency);
}

AudioHapticFirstFrameCb::AudioHapticFirstFrameCb(AudioHapticPlayerImpl &audioHapticPlayerImpl)
    : audioHapticPlayerImpl_(audioHapticPlayerImpl) {}

void AudioHapticFirstFrameCb::OnFirstAudioFrameWritingCallback(uint64_t &latency)
{
    MEDIA_LOGI("OnFirstAudioFrameWritingCallback from Sound pool");
    audioHapticPlayerImpl_.NotifyStartVibrate(latency);
}
} // namesapce AudioStandard
} // namespace OHOS