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
#include "audio_haptic_vibrator_impl.h"

#include <fcntl.h>
#include <sys/stat.h>

#include "audio_haptic_log.h"
#include "directory_ex.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticVibratorImpl"};
#ifdef SUPPORT_VIBRATOR
constexpr int32_t MIN_WAITING_TIME_FOR_VIBRATOR = 1200; // ms
constexpr uint64_t MILLISECONDS_FOR_ONE_SECOND = 1000; // ms
constexpr int32_t PLAYER_BUFFER_TIME = 50; // ms
constexpr int32_t MAX_WAITING_LOOP_COUNT = 10;
#endif
}

namespace OHOS {
namespace Media {
#ifdef SUPPORT_VIBRATOR
static const std::unordered_map<AudioStandard::StreamUsage, VibratorUsage> USAGE_MAP = {
    {AudioStandard::StreamUsage::STREAM_USAGE_MEDIA, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_MUSIC, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION, VibratorUsage::USAGE_COMMUNICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_VOICE_ASSISTANT, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_ALARM, VibratorUsage::USAGE_ALARM},
    {AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MESSAGE, VibratorUsage::USAGE_COMMUNICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION_RINGTONE, VibratorUsage::USAGE_RING},
    {AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE, VibratorUsage::USAGE_RING},
    {AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE, VibratorUsage::USAGE_RING},
    {AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION, VibratorUsage::USAGE_NOTIFICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_ACCESSIBILITY, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_SYSTEM, VibratorUsage::USAGE_NOTIFICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_MOVIE, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_GAME, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_AUDIOBOOK, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_NAVIGATION, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_DTMF, VibratorUsage::USAGE_NOTIFICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_ENFORCED_TONE, VibratorUsage::USAGE_NOTIFICATION},
    {AudioStandard::StreamUsage::STREAM_USAGE_ULTRASONIC, VibratorUsage::USAGE_MEDIA},
    {AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION, VibratorUsage::USAGE_COMMUNICATION},
};
#endif
const int ERROR = -1;

AudioHapticVibratorImpl::AudioHapticVibratorImpl(AudioHapticPlayer &audioHapticPlayer)
    : audioHapticPlayer_(audioHapticPlayer)
{
    if (audioHapticPlayer_.IsMuted(AUDIO_HAPTIC_TYPE_HAPTIC)) {
        MEDIA_LOGW("The muteHaptic value of audioHapticPlayer_ is true. No need to vibrate.");
    }
}

AudioHapticVibratorImpl::~AudioHapticVibratorImpl() {}

std::mutex AudioHapticVibrator::createVibratorMutex_;

std::shared_ptr<AudioHapticVibrator> AudioHapticVibrator::CreateAudioHapticVibrator(
    AudioHapticPlayer &audioHapticPlayer)
{
    std::lock_guard<std::mutex> lock(createVibratorMutex_);
    auto audioHapticVibrator = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayer);
    return audioHapticVibrator;
}

void AudioHapticVibratorImpl::SetIsSupportEffectId(bool isSupport)
{
#ifdef SUPPORT_VIBRATOR
    isSupportEffectId_ = isSupport;
#endif
}

int32_t AudioHapticVibratorImpl::ExtractFd(const std::string& hapticsUri)
{
    const std::string prefix = "fd://";
    if (hapticsUri.size() <= prefix.size() || hapticsUri.substr(0, prefix.length()) != prefix) {
        MEDIA_LOGW("ExtractFd: Input does not start with the required prefix.");
        return ERROR;
    }

    std::string numberPart = hapticsUri.substr(prefix.length());
    for (char c : numberPart) {
        if (!std::isdigit(c)) {
            MEDIA_LOGE("ExtractFd: The part after the prefix is not all digits.");
            return ERROR;
        }
    }

    int32_t fd = atoi(numberPart.c_str());
    return fd > 0 ? fd : ERROR;
}

int32_t AudioHapticVibratorImpl::OpenHapticFile(const std::string &hapticUri)
{
#ifdef SUPPORT_VIBRATOR
    int32_t newFd = -1;
    int32_t oldFd = ExtractFd(hapticUri);
    if (oldFd != ERROR) {
        newFd = dup(oldFd);
        if (newFd == ERROR) {
            MEDIA_LOGE("OpenHapticFile: dup failed, file path: %{public}s", hapticUri.c_str());
            return MSERR_OPEN_FILE_FAILED;
        }
    } else {
        MEDIA_LOGW("OpenHapticFile: hapticUri is not new format.");

        std::string absFilePath;
        if (!PathToRealPath(hapticUri, absFilePath)) {
            MEDIA_LOGE("file is not real path, file path: %{private}s", hapticUri.c_str());
            return ERROR;
        }
        if (absFilePath.empty()) {
            MEDIA_LOGE("Failed to obtain the canonical path for source path %{public}d %{private}s",
                errno, hapticUri.c_str());
            return ERROR;
        }

        newFd = open(hapticUri.c_str(), O_RDONLY);
        if (newFd == ERROR) {
            // open file failed, return.
            MEDIA_LOGE("OpenHapticFile: open file failed, file path: %{public}s", hapticUri.c_str());
            return MSERR_OPEN_FILE_FAILED;
        }
    }

    vibratorFD_ = std::make_shared<VibratorFileDescription>();
    CHECK_AND_RETURN_RET_LOG(vibratorFD_ != nullptr, ERROR, "vibratorFD_ is null");
    vibratorPkg_ = std::make_shared<VibratorPackage>();
    CHECK_AND_RETURN_RET_LOG(vibratorPkg_ != nullptr, ERROR, "vibratorPkg_ is null");

    struct stat64 statbuf = { 0 };
    if (fstat64(newFd, &statbuf) == 0) {
        vibratorFD_->fd = newFd;
        vibratorFD_->offset = 0;
        vibratorFD_->length = statbuf.st_size;
        return MSERR_OK;
    } else {
        close(newFd);
        return MSERR_OPEN_FILE_FAILED;
    }
#endif
    return MSERR_OK;
}

int32_t AudioHapticVibratorImpl::PreLoad(const HapticSource &hapticSource,
    const AudioStandard::StreamUsage &streamUsage)
{
    MEDIA_LOGI("PreLoad with hapticUri [%{public}s], effectId [%{public}s], streamUsage [%{public}d]",
        hapticSource.hapticUri.c_str(), hapticSource.effectId.c_str(), streamUsage);
    streamUsage_ = streamUsage;
#ifdef SUPPORT_VIBRATOR
    if (audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NONE) {
        MEDIA_LOGI("The hapticdMopde value of audioHapticPlayer_ is NONE. No need to vibrate.");
        return MSERR_OK;
    }
    auto iterator = USAGE_MAP.find(streamUsage_);
    if (iterator != USAGE_MAP.end()) {
        vibratorUsage_ = iterator->second;
    } else {
        MEDIA_LOGW("Invalid stream usage! Use the default usage (USAGE_MEDIA).");
        vibratorUsage_ = VibratorUsage::USAGE_MEDIA;
    }
    hapticSource_ = hapticSource;
    if (hapticSource.hapticUri == "") {
        bool isSupported = false;
        int32_t effectResult = Sensors::IsSupportEffect(hapticSource.effectId.c_str(), &isSupported);
        if (effectResult == 0 && isSupported) {
            SetIsSupportEffectId(true);
            MEDIA_LOGI("The effectId is supported. Vibrator has been prepared.");
            return MSERR_OK;
        } else {
            MEDIA_LOGE("The effectId is not supported!");
            return MSERR_UNSUPPORT_FILE;
        }
    }

    if (OpenHapticFile(hapticSource.hapticUri) != MSERR_OK) {
        return MSERR_OPEN_FILE_FAILED;
    }

    int32_t result = Sensors::PreProcess(*vibratorFD_, *vibratorPkg_);
    if (result != 0) {
        return MSERR_UNSUPPORT_FILE;
    }
#endif
    return MSERR_OK;
}

int32_t AudioHapticVibratorImpl::SetHapticIntensity(float intensity)
{
    MEDIA_LOGI("SetHapticIntensity for effectId source. intensity: %{public}f", intensity);
    std::lock_guard<std::mutex> lock(vibrateMutex_);
#ifdef SUPPORT_VIBRATOR
    vibrateIntensity_ = intensity;
#endif
    return MSERR_OK;
}

int32_t AudioHapticVibratorImpl::Release()
{
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    isStopped_ = true;
#ifdef SUPPORT_VIBRATOR
    int32_t result = Sensors::Cancel();
    if (result != 0) {
        MEDIA_LOGE("Failed to stop vibrator: result %{public}d", result);
    }
    vibrateCV_.notify_one();

    if (vibratorPkg_ != nullptr) {
        Sensors::FreeVibratorPackage(*vibratorPkg_);
        vibratorPkg_ = nullptr;
    }
    vibratorFD_ = nullptr;

#endif
    return MSERR_OK;
}

void AudioHapticVibratorImpl::ResetStopState()
{
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    isStopped_ = false;
}

int32_t AudioHapticVibratorImpl::StartVibrate(const AudioLatencyMode &latencyMode)
{
    MEDIA_LOGI("StartVibrate: for latency mode %{public}d", latencyMode);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NONE) {
        return result;
    } else if (audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NON_SYNC) {
        return StartNonSyncVibration();
    } else if (audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE) {
        return StartNonSyncOnceVibration();
    }
    if (latencyMode == AUDIO_LATENCY_MODE_NORMAL) {
        return StartVibrateForAVPlayer();
    } else if (latencyMode == AUDIO_LATENCY_MODE_FAST) {
        if (isSupportEffectId_) {
            return StartVibrateWithEffect();
        } else {
            return StartVibrateForSoundPool();
        }
    } else {
        return MSERR_INVALID_OPERATION;
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StartVibrateWithEffect()
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    (void)Sensors::SetUsage(vibratorUsage_);
    MEDIA_LOGI("PlayPrimitiveEffect with effectId: %{public}s", hapticSource_.effectId.c_str());
    result = Sensors::PlayPrimitiveEffect(hapticSource_.effectId.c_str(), vibrateIntensity_);
    if (result != 0) {
        MEDIA_LOGE("Failed to PlayPrimitiveEffect with effectId: %{public}s, result: %{public}d",
            hapticSource_.effectId.c_str(), result);
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StartVibrateForSoundPool()
{
    std::unique_lock<std::mutex> lock(vibrateMutex_);
    if (isStopped_) {
        MEDIA_LOGW("Vibrator has been stopped. Return ok immediately");
        AudioHapticPlayerImpl::SendHapticPlayerEvent(MSERR_OK, "VIBRATOR_STOP");
        return MSERR_OK;
    }

    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (vibratorPkg_ == nullptr || vibratorFD_ == nullptr) {
        MEDIA_LOGE("Vibration source file is not prepared. Can not start vibrating");
        AudioHapticPlayerImpl::SendHapticPlayerEvent(MSERR_INVALID_OPERATION, "VIBRATOR_NOT_PREPARE");
        return MSERR_INVALID_OPERATION;
    }
    int32_t vibrateTime = 0; // record the pattern time which has been played
    for (int32_t i = 0; i < vibratorPkg_->patternNum; ++i) {
        int32_t patternTime = vibratorPkg_->patterns[i].time - vibrateTime; // calculate the time of single pattern
        vibrateTime = vibratorPkg_->patterns[i].time;
        (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(patternTime),
            [this]() { return isStopped_; });
        CHECK_AND_RETURN_RET_LOG(!isStopped_, result,
            "StartVibrateForSoundPool: Stop() is call when waiting");
        (void)Sensors::SetUsage(vibratorUsage_);
        MEDIA_LOGI("PlayPattern for SoundPool.");
        result = Sensors::PlayPattern(vibratorPkg_->patterns[i]);
        if (result != 0) {
            MEDIA_LOGE("Failed to PlayPattern for SoundPool. Error %{public}d", result);
            return result;
        }
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::RunVibrationPatterns(std::unique_lock<std::mutex> &lock)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    int32_t vibrateTime = 0; // record the pattern time which has been played
    for (int32_t i = 0; i < vibratorPkg_->patternNum; ++i) {
        int32_t patternTime = vibratorPkg_->patterns[i].time - vibrateTime; // calculate the time of single pattern
        vibrateTime = vibratorPkg_->patterns[i].time;
        (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(patternTime),
            [this]() { return isStopped_; });
        CHECK_AND_RETURN_RET_LOG(!isStopped_, result,
            "RunVibrationPatterns: Stop() is call when waiting");
        (void)Sensors::SetUsage(vibratorUsage_);
        MEDIA_LOGI("PlayPattern for NonSyncVibration");
        result = Sensors::PlayPattern(vibratorPkg_->patterns[i]);
        if (result != 0) {
            MEDIA_LOGE("Failed to PlayPattern for NonSyncVibration. Error %{public}d", result);
            return result;
        }
        if (i == vibratorPkg_->patternNum - 1) {
            int32_t lastPatternDuration = vibratorPkg_->patterns[i].patternDuration;
            (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(lastPatternDuration),
                [this]() { return isStopped_; });
            CHECK_AND_RETURN_RET_LOG(!isStopped_, result,
                "RunVibrationPatterns: Stop() is call when waiting");
        }
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StartNonSyncVibration()
{
    std::unique_lock<std::mutex> lock(vibrateMutex_);
    if (isStopped_) {
        MEDIA_LOGW("Vibrator has been stopped. Return ok immediately");
        return MSERR_OK;
    }

    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (vibratorPkg_ == nullptr || vibratorFD_ == nullptr) {
        MEDIA_LOGE("Vibration source file is not prepared. Can not start vibrating");
        return MSERR_INVALID_OPERATION;
    }
    while (!isStopped_) {
        result = RunVibrationPatterns(lock);
        if (result != MSERR_OK) {
            MEDIA_LOGI("StartNonSyncVibration: RunVibrationPatterns fail.");
            return result;
        }
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StartNonSyncOnceVibration()
{
    std::unique_lock<std::mutex> lock(vibrateMutex_);
    if (isStopped_) {
        MEDIA_LOGW("Vibrator has been stopped. Return ok immediately");
        return MSERR_OK;
    }

    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (vibratorPkg_ == nullptr || vibratorFD_ == nullptr) {
        MEDIA_LOGE("Vibration source file is not prepared. Can not start vibrating");
        return MSERR_INVALID_OPERATION;
    }
    result = RunVibrationPatterns(lock);
    if (result != MSERR_OK) {
        MEDIA_LOGI("StartNonSyncOnceVibration: RunVibrationPatterns fail.");
        return result;
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StartVibrateForAVPlayer()
{
    std::unique_lock<std::mutex> lock(vibrateMutex_);
    if (isStopped_) {
        MEDIA_LOGW("Vibrator has been stopped. Return ok immediately");
        return MSERR_OK;
    }

    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (vibratorPkg_ == nullptr || vibratorFD_ == nullptr) {
        MEDIA_LOGE("Vibration source file is not prepared. Can not start vibrating");
        return MSERR_INVALID_OPERATION;
    }
    int32_t vibrateTime = 0; // record the pattern time which has been played
    for (int32_t i = 0; i < vibratorPkg_->patternNum; ++i) {
        // the delay time of first frame has been handled in audio haptic player
        int32_t patternTime = vibratorPkg_->patterns[i].time - vibrateTime; // calculate the time of single pattern
        (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(patternTime),
            [this]() { return isStopped_; });
        CHECK_AND_RETURN_RET_LOG(!isStopped_, result,
            "StartVibrateForAVPlayer: Stop() is call when waiting");
        (void)Sensors::SetUsage(vibratorUsage_);
        MEDIA_LOGI("PlayPattern for AVPlayer successfully!");
        result = Sensors::PlayPattern(vibratorPkg_->patterns[i]);
        AudioHapticPlayerImpl::SendHapticPlayerEvent(result, "PLAY_PATTERN_AVPLAYER");
        CHECK_AND_RETURN_RET_LOG(result == 0, result,
            "Failed to PlayPattern for AVPlayer. Error %{public}d", result);

        // get the audio time every second and handle the delay time
        if (i + 1 >= vibratorPkg_->patternNum) {
            // the last pattern has been played, break.
            break;
        }
        int32_t nextVibratorTime = vibratorPkg_->patterns[i + 1].time;
        vibrateTime = audioHapticPlayer_.GetAudioCurrentTime() - PLAYER_BUFFER_TIME + GetDelayTime();
        int32_t count = 0;
        while (nextVibratorTime - vibrateTime > MIN_WAITING_TIME_FOR_VIBRATOR && count < MAX_WAITING_LOOP_COUNT) {
            (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(MILLISECONDS_FOR_ONE_SECOND),
                [this]() { return isStopped_; });
            CHECK_AND_RETURN_RET_LOG(!isStopped_, result,
                "StartVibrateForAVPlayer: Stop() is call when waiting");
            vibrateTime = audioHapticPlayer_.GetAudioCurrentTime() - PLAYER_BUFFER_TIME + GetDelayTime();
            count++;
        }
        if (count == MAX_WAITING_LOOP_COUNT) {
            MEDIA_LOGE("StartVibrateForAVPlayer: loop count has reached the max value.");
            return MSERR_INVALID_OPERATION;
        }
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::StopVibrate()
{
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    isStopped_ = true;
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    vibrateCV_.notify_one();
    result = Sensors::Cancel();
    MEDIA_LOGI("StopVibrate: %{public}d", result);
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::GetDelayTime()
{
    int32_t delayTime = 0;
#ifdef SUPPORT_VIBRATOR
    (void)Sensors::GetDelayTime(delayTime);
#endif
    return delayTime;
}
} // namesapce Media
} // namespace OHOS