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
#include "audio_haptic_sound_low_latency_impl.h"
#include "audio_haptic_sound_normal_impl.h"

#include "audio_haptic_log.h"
#include "media_errors.h"
#include "media_monitor_manager.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticPlayerImpl"};
constexpr int32_t INVALID_FD = -1;
}

namespace OHOS {
namespace Media {
const int32_t LOAD_WAIT_SECONDS = 2;
const int32_t LOAD_WAIT_SECONDS_FOR_LOOP = 40;

std::mutex AudioHapticPlayerFactory::createPlayerMutex_;

std::shared_ptr<AudioHapticPlayer> AudioHapticPlayerFactory::CreateAudioHapticPlayer(
    const AudioHapticPlayerParam &param)
{
    std::lock_guard<std::mutex> lock(createPlayerMutex_);
    // Create audio haptic player using the param.
    std::shared_ptr<AudioHapticPlayerImpl> audioHapticPlayer = std::make_shared<AudioHapticPlayerImpl>();
    audioHapticPlayer->SetPlayerParam(param);
    audioHapticPlayer->LoadPlayer();
    return audioHapticPlayer;
}

std::mutex AudioHapticSound::createAudioHapticSoundMutex_;

std::shared_ptr<AudioHapticSound> AudioHapticSound::CreateAudioHapticSound(
    const AudioLatencyMode &latencyMode, const AudioSource& audioSource, const bool &muteAudio,
    const AudioStandard::StreamUsage &streamUsage, const bool &parallelPlayFlag)
{
    if (latencyMode != AUDIO_LATENCY_MODE_NORMAL && latencyMode != AUDIO_LATENCY_MODE_FAST) {
        MEDIA_LOGE("Invalid param: the latency mode %{public}d is unsupported.", latencyMode);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(createAudioHapticSoundMutex_);
    std::shared_ptr<AudioHapticSound> audioHapticSound = nullptr;
    switch (latencyMode) {
        case AUDIO_LATENCY_MODE_NORMAL:
            audioHapticSound = std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);
            break;
        case AUDIO_LATENCY_MODE_FAST:
            audioHapticSound = std::make_shared<AudioHapticSoundLowLatencyImpl>(
                audioSource, muteAudio, streamUsage, parallelPlayFlag);
            break;
        default:
            MEDIA_LOGE("Invalid param: the latency mode %{public}d is unsupported.", latencyMode);
            break;
    }
    return audioHapticSound;
}

AudioHapticPlayerImpl::AudioHapticPlayerImpl()
    : latencyMode_(AUDIO_LATENCY_MODE_NORMAL),
      muteAudio_(false),
      muteHaptic_(false)
{
}

AudioHapticPlayerImpl::~AudioHapticPlayerImpl()
{
    if (playerState_ != AudioHapticPlayerState::STATE_RELEASED) {
        ReleaseVibrator();
        ReleaseSound();
    }
}

void AudioHapticPlayerImpl::SetPlayerParam(const AudioHapticPlayerParam &param)
{
    muteAudio_ = param.options.muteAudio;
    muteHaptic_ = param.options.muteHaptics;
    parallelPlayFlag_ = param.options.parallelPlayFlag;
    audioSource_ = param.audioSource;
    hapticSource_ = param.hapticSource;
    latencyMode_ = param.latencyMode;
    streamUsage_ = param.streamUsage;
}

void AudioHapticPlayerImpl::LoadPlayer()
{
    // Load audio player
    audioHapticSound_ = AudioHapticSound::CreateAudioHapticSound(
        latencyMode_, audioSource_, muteAudio_, streamUsage_, parallelPlayFlag_);
    CHECK_AND_RETURN_LOG(audioHapticSound_ != nullptr, "Failed to create audio haptic sound instance");
    soundCallback_ = std::make_shared<AudioHapticSoundCallbackImpl>(shared_from_this());
    (void)audioHapticSound_->SetAudioHapticSoundCallback(soundCallback_);

    // Load vibrator
    audioHapticVibrator_ = AudioHapticVibrator::CreateAudioHapticVibrator(*this);
    CHECK_AND_RETURN_LOG(audioHapticVibrator_ != nullptr, "Failed to create audio haptic vibrator instance");
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

int32_t AudioHapticPlayerImpl::Prepare()
{
    int32_t result = MSERR_OK;
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(audioHapticSound_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic sound is nullptr");
    CHECK_AND_RETURN_RET_LOG(audioSource_.audioUri != "" || audioSource_.fd > INVALID_FD,
        MSERR_OPEN_FILE_FAILED, "Invalid val: audioSource");
    result = audioHapticSound_->PrepareSound();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "Failed to load audio file");

    CHECK_AND_RETURN_RET_LOG(audioHapticVibrator_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic vibrator is nullptr");
    result = audioHapticVibrator_->PreLoad(hapticSource_, streamUsage_);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "Failed to load vobration file");

    playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::Start()
{
    int32_t result = MSERR_OK;
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);

    CHECK_AND_RETURN_RET_LOG(audioHapticVibrator_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic vibrator is nullptr");

    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
        vibrateThread_.reset();
    }
    if (vibrateThread_ == nullptr) {
        ResetVibrateState();
        vibrateThread_ = std::make_shared<std::thread>([this] { StartVibrate(); });
    }

    CHECK_AND_RETURN_RET_LOG(audioHapticSound_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic sound is nullptr");
    result = audioHapticSound_->StartSound();
    SendHapticPlayerEvent(MSERR_OK, "START_HAPTIC_PLAYER");
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "Failed to start sound.");
    MEDIA_LOGW("StartSound() has been executed successfully!");
    playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    return result;
}

int32_t AudioHapticPlayerImpl::Stop()
{
    int32_t result = MSERR_OK;
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);

    CHECK_AND_RETURN_RET_LOG(audioHapticVibrator_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic vibrator is nullptr");
    StopVibrate();

    CHECK_AND_RETURN_RET_LOG(audioHapticSound_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic sound is nullptr");
    result = audioHapticSound_->StopSound();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "Failed to stop sound.");

    playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    return result;
}

int32_t AudioHapticPlayerImpl::Release()
{
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(playerState_ != AudioHapticPlayerState::STATE_RELEASED, MSERR_OK,
        "The audio haptic player has been released.");

    CHECK_AND_RETURN_RET_LOG(audioHapticVibrator_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic vibrator is nullptr");
    ReleaseVibrator();

    CHECK_AND_RETURN_RET_LOG(audioHapticSound_ != nullptr, MSERR_INVALID_OPERATION,
        "Audio haptic sound is nullptr");
    ReleaseSound();

    playerState_ = AudioHapticPlayerState::STATE_RELEASED;
    return MSERR_OK;
}

void AudioHapticPlayerImpl::ReleaseVibrator()
{
    if (audioHapticVibrator_ != nullptr) {
        audioHapticVibrator_->StopVibrate();
    }
    {
        // When player is releasing，notify vibrate thread immediately
        std::lock_guard<std::mutex> lockVibrate(waitStartVibrateMutex_);
        isAudioPlayFirstFrame_ = true;
        isVibrationStopped_ = true;
        condStartVibrate_.notify_one();
    }
    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
    }
    vibrateThread_.reset();
    if (audioHapticVibrator_ != nullptr) {
        (void)audioHapticVibrator_->Release();
        audioHapticVibrator_ = nullptr;
    }
}

void AudioHapticPlayerImpl::ReleaseSound()
{
    if (audioHapticSound_ != nullptr) {
        (void)audioHapticSound_->ReleaseSound();
        audioHapticSound_ = nullptr;
    }
    soundCallback_ = nullptr;
}

int32_t AudioHapticPlayerImpl::SetVolume(float volume)
{
    MEDIA_LOGI("AudioHapticPlayerImpl::SetVolume %{public}f", volume);
    if (volume < 0.0f || volume > 1.0f) {
        MEDIA_LOGE("SetVolume: the volume value is invalid.");
        return MSERR_INVALID_VAL;
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    int32_t result = MSERR_OK;
    volume_ = volume;
    if (audioHapticSound_ == nullptr) {
        MEDIA_LOGW("Audio haptic sound is nullptr!");
        return result;
    }
    float actualVolume = volume_ * (muteAudio_ ? 0 : 1);
    result = audioHapticSound_->SetVolume(actualVolume);

    if (latencyMode_ == AUDIO_LATENCY_MODE_NORMAL &&
        (streamUsage_ == AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE ||
        streamUsage_ == AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE) &&
        playerState_ == AudioHapticPlayerState::STATE_RUNNING &&
        std::abs(volume_ - 0.0f) <= std::numeric_limits<float>::epsilon()) {
        // only for the call manager ringtone
        StopVibrate();
    }

    return result;
}

bool AudioHapticPlayerImpl::IsVibrationIntensityAdjustmentSupported()
{
    MEDIA_LOGI("AudioHapticPlayerImpl::IsVibrationIntensityAdjustmentSupported");
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    if (audioHapticVibrator_ != nullptr) {
        return audioHapticVibrator_->IsHdHapticSupported();
    }
    return false;
}

void AudioHapticPlayerImpl::EnableHapticsInSlientMode(bool enable)
{
    MEDIA_LOGI("AudioHapticPlayerImpl::EnableHapticsInSlientMode %{public}d", enable);
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    if (audioHapticVibrator_ != nullptr) {
        audioHapticVibrator_->EnableHapticsInSlientMode(enable);
    }
}

int32_t AudioHapticPlayerImpl::SetHapticIntensity(float intensity)
{
    MEDIA_LOGI("AudioHapticPlayerImpl::SetHapticIntensity %{public}f", intensity);
    if (intensity < 1.0f || intensity > 100.0f) {
        MEDIA_LOGE("SetHapticIntensity: the intensity value is invalid.");
        return MSERR_INVALID_VAL;
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    return audioHapticVibrator_->SetHapticIntensity(intensity);
}

int32_t AudioHapticPlayerImpl::SetLoop(bool loop)
{
    MEDIA_LOGI("AudioHapticPlayerImpl::SetLoop %{public}d", loop);
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    int32_t result = MSERR_OK;
    loop_ = loop;
    if (audioHapticSound_ == nullptr) {
        MEDIA_LOGW("Audio haptic sound is nullptr!");
        return result;
    }
    result = audioHapticSound_->SetLoop(loop);
    return result;
}

HapticsMode AudioHapticPlayerImpl::GetHapticsMode() const
{
    return hapticsMode_;
}

void AudioHapticPlayerImpl::SetHapticsMode(HapticsMode hapticsMode)
{
    MEDIA_LOGI("AudioHapticPlayerImpl::SetHapticsMode %{public}d", hapticsMode);
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    hapticsMode_ = hapticsMode;
}

int32_t AudioHapticPlayerImpl::SetAudioHapticPlayerCallback(
    const std::shared_ptr<AudioHapticPlayerCallback> &playerCallback)
{
    if (playerCallback == nullptr) {
        MEDIA_LOGE("The audio haptic player callback is nullptr.");
        return MSERR_INVALID_VAL;
    }

    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    audioHapticPlayerCallback_ = playerCallback;
    return MSERR_OK;
}

int32_t AudioHapticPlayerImpl::GetAudioCurrentTime()
{
    CHECK_AND_RETURN_RET_LOG(audioHapticSound_ != nullptr, -1, "Audio haptic sound is nullptr");
    return audioHapticSound_->GetAudioCurrentTime();
}

int32_t AudioHapticPlayerImpl::StartVibrate()
{
    if (muteHaptic_) {
        MEDIA_LOGI("StartVibrate: muteHaptic is true. No need to vibrate");
        SendHapticPlayerEvent(MSERR_OK, "NO_NEED_VIBRATE");
        return MSERR_OK;
    }

    MEDIA_LOGI("Enter StartVibrate()");
    std::unique_lock<std::mutex> lockWait(waitStartVibrateMutex_);
    do {
        int32_t waitTime = loop_ ? LOAD_WAIT_SECONDS_FOR_LOOP : LOAD_WAIT_SECONDS;
        bool waitResult = condStartVibrate_.wait_for(lockWait, std::chrono::seconds(waitTime),
            [this]() { return isAudioPlayFirstFrame_ || isVibrationStopped_; });
        if (!waitResult) {
            MEDIA_LOGE("StartVibrate: Failed to start vibrate (time out).");
            SendHapticPlayerEvent(MSERR_INVALID_OPERATION, "VIBRATE_TIME_OUT");
            return MSERR_INVALID_OPERATION;
        }
        if (isVibrationStopped_) {
            MEDIA_LOGI("StartVibrate: audio haptic player has been stopped.");
            SendHapticPlayerEvent(MSERR_OK, "HAPTIC_PLAYER_STOP");
            return MSERR_OK;
        }

        isAudioPlayFirstFrame_ = false; // reset for next time.

        int32_t hapticDelay = audioHapticVibrator_->GetDelayTime();
        int32_t delay = (static_cast<int32_t>(this->audioLatency_) - hapticDelay) > 0 ?
            static_cast<int32_t>(this->audioLatency_) - hapticDelay : 0;
        waitResult = condStartVibrate_.wait_for(lockWait, std::chrono::milliseconds(delay),
            [this]() { return isVibrationStopped_.load(); });
        if (isVibrationStopped_) {
            MEDIA_LOGI("StartVibrate: audio haptic player has been stopped.");
            SendHapticPlayerEvent(MSERR_OK, "HAPTIC_PLAYER_STOP");
            return MSERR_OK;
        }
        MEDIA_LOGI("The first frame of audio is about to start. Triggering the vibration.");
        isVibrationRunning_.store(true);
        audioHapticVibrator_->StartVibrate(latencyMode_);
        isVibrationRunning_.store(false);
    } while (loop_ && !isVibrationStopped_);

    SendHapticPlayerEvent(MSERR_OK, "START_VIBRATE");
    return MSERR_OK;
}

void AudioHapticPlayerImpl::StopVibrate()
{
    MEDIA_LOGI("Stop vibrate for audio haptic player right now.");
    if (audioHapticVibrator_ != nullptr) {
        audioHapticVibrator_->StopVibrate();
    } else {
        MEDIA_LOGW("The audio haptic vibrator is nullptr!");
    }
    {
        std::lock_guard<std::mutex> lockVibrate(waitStartVibrateMutex_);
        isVibrationStopped_ = true;
        condStartVibrate_.notify_one();
    }
    if (vibrateThread_ != nullptr && vibrateThread_->joinable()) {
        vibrateThread_->join();
    }
    vibrateThread_.reset();
}

void AudioHapticPlayerImpl::ResetVibrateState()
{
    isVibrationStopped_ = false;
    if (audioHapticVibrator_ != nullptr) {
        audioHapticVibrator_->ResetStopState();
    } else {
        MEDIA_LOGW("The audio haptic vibrator is nullptr!");
    }
}

void AudioHapticPlayerImpl::NotifyInterruptEvent(const AudioStandard::InterruptEvent &interruptEvent)
{
    std::shared_ptr<AudioHapticPlayerCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyInterruptEvent for napi object or caller");
        cb->OnInterrupt(interruptEvent);
    } else {
        MEDIA_LOGE("NotifyInterruptEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

void AudioHapticPlayerImpl::NotifyEndOfStreamEvent()
{
    MEDIA_LOGI("NotifyEndOfStreamEvent");
    std::thread (HandleEndOfStreamEventThreadFunc, shared_from_this()).detach();
    std::shared_ptr<AudioHapticPlayerCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyEndOfStreamEvent for napi object or caller");
        cb->OnEndOfStream();
    } else {
        MEDIA_LOGE("NotifyEndOfStreamEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

void AudioHapticPlayerImpl::HandleEndOfStreamEventThreadFunc(std::weak_ptr<AudioHapticPlayerImpl> player)
{
    std::shared_ptr<AudioHapticPlayerImpl> playerPtr = player.lock();
    if (playerPtr != nullptr) {
        playerPtr->HandleEndOfStreamEvent();
    }
}

void AudioHapticPlayerImpl::HandleEndOfStreamEvent()
{
    std::lock_guard<std::mutex> lock(audioHapticPlayerLock_);
    if (playerState_ == AudioHapticPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("The audio haptic player has been released!");
        return;
    }
    StopVibrate();
    playerState_ = AudioHapticPlayerState::STATE_STOPPED;
}

void AudioHapticPlayerImpl::NotifyErrorEvent(int32_t errCode)
{
    std::shared_ptr<AudioHapticPlayerCallback> cb = audioHapticPlayerCallback_.lock();
    if (cb != nullptr) {
        MEDIA_LOGI("NotifyErrorEvent for napi object or caller. errCode: %{public}d", errCode);
        cb->OnError(errCode);
    } else {
        MEDIA_LOGE("NotifyErrorEvent: audioHapticPlayerCallback_ is nullptr");
    }
}

void AudioHapticPlayerImpl::NotifyStartVibrate(const uint64_t &latency)
{
    if (isVibrationRunning_.load() &&
        (hapticsMode_ == HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE ||
        hapticsMode_ == HapticsMode::HAPTICS_MODE_NON_SYNC)) {
        MEDIA_LOGI("The non sync vibration is already running.");
        return;
    }
    std::lock_guard<std::mutex> lock(this->waitStartVibrateMutex_);
    this->isAudioPlayFirstFrame_ = true;
    this->audioLatency_ = latency;
    this->condStartVibrate_.notify_one();
}

void AudioHapticPlayerImpl::SendHapticPlayerEvent(const int32_t &errorCode, const std::string &strEvent)
{
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::ModuleId::AUDIO, Media::MediaMonitor::EventId::HAPTIC_PLAYER,
        Media::MediaMonitor::EventType::HAPTIC_PLAYER_EVENT);
    bean->Add("ERROR_CODE", errorCode);
    bean->Add("ERROR_REASON", strEvent);
    Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
}

// Callback class symbols
AudioHapticSoundCallbackImpl::AudioHapticSoundCallbackImpl(std::shared_ptr<AudioHapticPlayerImpl> audioHapticPlayerImpl)
    : audioHapticPlayerImpl_(audioHapticPlayerImpl) {}

void AudioHapticSoundCallbackImpl::OnEndOfStream()
{
    MEDIA_LOGI("OnEndOfStream reported from audio haptic sound.");
    std::shared_ptr<AudioHapticPlayerImpl> player = audioHapticPlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyEndOfStreamEvent();
}

void AudioHapticSoundCallbackImpl::OnError(int32_t errorCode)
{
    MEDIA_LOGE("OnError reported from audio haptic sound: %{public}d", errorCode);
    std::shared_ptr<AudioHapticPlayerImpl> player = audioHapticPlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyErrorEvent(errorCode);
}

void AudioHapticSoundCallbackImpl::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("OnInterrupt from audio haptic sound. hintType: %{public}d", interruptEvent.hintType);
    std::shared_ptr<AudioHapticPlayerImpl> player = audioHapticPlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyInterruptEvent(interruptEvent);
}

void AudioHapticSoundCallbackImpl::OnFirstFrameWriting(uint64_t latency)
{
    MEDIA_LOGI("OnFirstFrameWriting from audio haptic sound. Latency %{public}" PRIu64 "", latency);
    std::shared_ptr<AudioHapticPlayerImpl> player = audioHapticPlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyStartVibrate(latency);
}
} // namesapce AudioStandard
} // namespace OHOS
