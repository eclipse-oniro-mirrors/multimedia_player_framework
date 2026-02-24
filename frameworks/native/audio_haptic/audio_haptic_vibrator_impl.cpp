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
#include <thread>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "audio_haptic_log.h"
#include "directory_ex.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticVibratorImpl"};
#ifdef SUPPORT_VIBRATOR
constexpr int32_t MIN_WAITING_TIME_FOR_VIBRATOR = 1200; // ms
constexpr uint64_t MILLISECONDS_FOR_ONE_SECOND = 1000; // ms
constexpr int32_t PLAYER_BUFFER_TIME = 30; // ms
constexpr int32_t PATTERN_DEFAULT_COUNT = 10;
constexpr int32_t PATTERN_MAX_COUNT = 200;
constexpr int32_t WAIT_VIBRATOR_CANCEL_TIME_MS = 50; // ms
constexpr int32_t DURATION_AT_LEAST = 100; // ms
constexpr int32_t FREQUENCY_THIRTY_THREE = 33;
constexpr int32_t PATTERNDURATION_TIME_MS = 800; //ms

void CopyPoint(const VibratorCurvePoint &strongPoint, VibratorCurvePoint &weakPoint)
{
    weakPoint.time = strongPoint.time;
    weakPoint.intensity = strongPoint.intensity;
    weakPoint.frequency = strongPoint.frequency;
}

void CopyEvent(const VibratorEvent &strongEvent, VibratorEvent &weakEvent)
{
    // Copy event type
    weakEvent.type = strongEvent.type;
    // Copy event time
    weakEvent.time = strongEvent.time;
    // Copy event frequency to 33
    weakEvent.frequency = FREQUENCY_THIRTY_THREE;
    // Copy event index
    weakEvent.index = strongEvent.index;
    // intensity keep same
    weakEvent.intensity = strongEvent.intensity;
    // duration keep same
    weakEvent.duration = strongEvent.duration;

    // Handle pointNum and points
    if (strongEvent.pointNum > 0 && strongEvent.points != nullptr) {
        // Allocate new points array
        weakEvent.points = new VibratorCurvePoint[strongEvent.pointNum];
        
        for (int32_t i = 0; i < strongEvent.pointNum; ++i) {
            CopyPoint(strongEvent.points[i], weakEvent.points[i]);
        }
    }
}

void CopyPattern(const VibratorPattern &strongPattern, VibratorPattern &weakPattern)
{
    // Copy pattern basic properties
    weakPattern.time = strongPattern.time;
    weakPattern.eventNum = strongPattern.eventNum;
    weakPattern.patternDuration = strongPattern.patternDuration;

    // Allocate and copy events array
    if (strongPattern.eventNum > 0 && strongPattern.events != nullptr) {
        weakPattern.events = new VibratorEvent[strongPattern.eventNum];

        for (int32_t i = 0; i < strongPattern.eventNum; ++i) {
            CopyEvent(strongPattern.events[i], weakPattern.events[i]);
        }
    }
}

void convertToWeakVibratorPackage(const std::shared_ptr<VibratorPackage> &strongPackage,
                                  std::shared_ptr<VibratorPackage> &weakPackage)
{
    if (strongPackage == nullptr || weakPackage == nullptr) {
        return;
    }

    // Copy basic properties
    weakPackage->patternNum = strongPackage->patternNum;
    weakPackage->packageDuration = strongPackage->packageDuration;

    // Allocate and copy patterns array
    if (strongPackage->patternNum > 0 && strongPackage->patterns != nullptr) {
        weakPackage->patterns = new VibratorPattern[strongPackage->patternNum];

        // Handle each pattern
        for (int32_t i = 0; i < strongPackage->patternNum; ++i) {
            CopyPattern(strongPackage->patterns[i], weakPackage->patterns[i]);
        }
    }
}
#endif

int64_t GetCurrentTimeMillis()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}
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
};
#endif
const int ERROR = -1;

bool IsSelfSystemCaller()
{
    Security::AccessToken::FullTokenID selfTokenID = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID);
}

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
    return fd > FILE_DESCRIPTOR_INVALID ? fd : ERROR;
}

int32_t AudioHapticVibratorImpl::OpenHapticSource(const HapticSource& hapticSource, int32_t& fd)
{
#ifdef SUPPORT_VIBRATOR
    std::string hapticUri = hapticSource.hapticUri;
    int32_t hapticFd = hapticSource.fd;
    MEDIA_LOGI("OpenHapticSource. hapticUri [%{public}s], hapticFd [%{public}d]",
        hapticUri.c_str(), hapticFd);
    CHECK_AND_RETURN_RET_LOG(!hapticUri.empty() || hapticFd > FILE_DESCRIPTOR_INVALID, MSERR_OPEN_FILE_FAILED,
        "hapticUri is empty or invalid hapticFd.");

    if (!hapticUri.empty()) {
        int32_t oldFd = ExtractFd(hapticUri);
        if (oldFd != ERROR) {
            fd = dup(oldFd);
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

            fd = open(hapticUri.c_str(), O_RDONLY | O_CLOEXEC);
        }
    } else {
        fd = dup(hapticFd);
    }

    CHECK_AND_RETURN_RET_LOG(fd > FILE_DESCRIPTOR_INVALID, MSERR_OPEN_FILE_FAILED,
        "OpenHapticSource: open source failed, file path: %{public}s, fd: %{public}d", hapticUri.c_str(), hapticFd);
#endif
    return MSERR_OK;
}

int32_t AudioHapticVibratorImpl::OpenHapticFile(const HapticSource& hapticSource)
{
#ifdef SUPPORT_VIBRATOR
    int32_t newFd = FILE_DESCRIPTOR_INVALID;
    int32_t ret = OpenHapticSource(hapticSource, newFd);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "OpenHapticFile: open file failed");

    vibratorFD_ = std::make_shared<VibratorFileDescription>();
    CHECK_AND_RETURN_RET_LOG(vibratorFD_ != nullptr, ERROR, "vibratorFD_ is null");
    vibratorPkg_ = std::make_shared<VibratorPackage>();
    CHECK_AND_RETURN_RET_LOG(vibratorPkg_ != nullptr, ERROR, "vibratorPkg_ is null");

    struct stat64 statbuf = { 0 };
    if (fstat64(newFd, &statbuf) == 0) {
        vibratorFD_->fd = newFd;
        vibratorFD_->offset = hapticSource.offset;
        vibratorFD_->length = hapticSource.length > 0 ? hapticSource.length : statbuf.st_size;
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
    if (hapticSource.hapticUri == "" && hapticSource.fd == FILE_DESCRIPTOR_INVALID) {
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

    if (OpenHapticFile(hapticSource) != MSERR_OK) {
        return MSERR_OPEN_FILE_FAILED;
    }

    CHECK_AND_RETURN_RET_LOG(vibratorFD_ != nullptr, ERROR, "vibratorFD_ is null.");
    int32_t fd = vibratorFD_->fd;
    int32_t result = Sensors::PreProcess(*vibratorFD_, *vibratorPkg_);
    if (result != 0) {
        close(fd);
        return MSERR_UNSUPPORT_FILE;
    }
    close(fd);
#endif
    return MSERR_OK;
}

int32_t AudioHapticVibratorImpl::SetHapticIntensity(float intensity)
{
    MEDIA_LOGI("SetHapticIntensity for effectId source. intensity: %{public}f", intensity);
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (hapticSource_.hapticUri == "" && hapticSource_.fd == FILE_DESCRIPTOR_INVALID) {
        vibrateIntensity_ = intensity;
    } else {
        if (isRunning_) {
            if (isIntensityChanged_) {
                result = ERR_OPERATE_NOT_ALLOWED;
            } else {
                result = SeekAndRestart();
            }
        }
        CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result,
            "AudioHapticVibratorImpl::SetHapticIntensity failed. result: %{public}d", result);
        vibratorParameter_.intensity = intensity;
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::SetHapticsFeature(const HapticsFeature &feature)
{
    MEDIA_LOGI("AudioHapticVibratorImpl::SetHapticsFeature %{public}d", feature);
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (vibratorPkg_ == nullptr) {
        return ERR_OPERATE_NOT_ALLOWED;
    }
    if (feature == HapticsFeature::GENTLE_HAPTICS) {
        auto gentlePkg = std::make_shared<VibratorPackage>();
        if (modulatePkg_ != nullptr) {
            convertToWeakVibratorPackage(modulatePkg_, gentlePkg);
            Sensors::FreeVibratorPackage(*modulatePkg_);
            modulatePkg_ = nullptr;
            rampEndIntensity_ = -1.0f;
        } else {
            convertToWeakVibratorPackage(vibratorPkg_, gentlePkg);
        }

        std::swap(vibratorPkg_, gentlePkg);

        if (gentlePkg != nullptr) {
            Sensors::FreeVibratorPackage(*gentlePkg);
            gentlePkg = nullptr;
        }

        if (isRunning_) {
            result = SeekAndRestart();
        }
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::SetHapticsRamp(int32_t duration, float startIntensity, float endIntensity)
{
    MEDIA_LOGI("AudioHapticVibratorImpl::SetHapticsRamp %{public}d, %{public}f, %{public}f",
        duration, startIntensity, endIntensity);
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (isRunning_.load() || vibratorPkg_ == nullptr) {
        return ERR_OPERATE_NOT_ALLOWED;
    }
    // duration not less than 100ms and not larger than haptics package duration
    auto lastPattern = vibratorPkg_->patterns[vibratorPkg_->patternNum - 1];
    int32_t packageDuration = lastPattern.time + lastPattern.patternDuration;
    int32_t actualDuration = duration;
    if (duration > packageDuration) {
        actualDuration = packageDuration;
    }
    if (actualDuration < DURATION_AT_LEAST) {
        MEDIA_LOGE("AudioHapticVibratorImpl::SetHapticsRamp error, duration %{public}d, packageDuration %{public}d",
            actualDuration, packageDuration);
        return MSERR_INVALID_VAL;
    }

    if (startIntensity < 1.0f || startIntensity > 100.0f) {
        MEDIA_LOGE("AudioHapticVibratorImpl::SetHapticsRamp: the startIntensity value is invalid.");
        return MSERR_INVALID_VAL;
    }

    if (endIntensity < 1.0f || endIntensity > 100.0f) {
        MEDIA_LOGE("AudioHapticVibratorImpl::SetHapticsRamp: the endIntensity value is invalid.");
        return MSERR_INVALID_VAL;
    }

    // four points will be enough
    int32_t numPoints = 4;
    VibratorCurvePoint points[numPoints];
    int32_t timeIntervalMs = actualDuration / numPoints;
    int32_t intensityStep = (endIntensity - startIntensity) / numPoints;

    for (int i = 0; i < numPoints; ++i) {
        points[i].time = i * timeIntervalMs;
        points[i].intensity = startIntensity + i * intensityStep;
    }

    modulatePkg_ = std::make_shared<VibratorPackage>();
    result = Sensors::ModulatePackage(points, numPoints, packageDuration, *vibratorPkg_, *modulatePkg_);
    MEDIA_LOGI("AudioHapticVibratorImpl::SetHapticsRamp ModulatePackage result %{public}d", result);
    if (result == MSERR_OK) {
        std::swap(vibratorPkg_, modulatePkg_);
        rampEndIntensity_ = endIntensity;
    }
#endif
    return result;
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
    if (seekVibratorPkg_ != nullptr) {
        Sensors::FreeVibratorPackage(*seekVibratorPkg_);
        seekVibratorPkg_ = nullptr;
    }
    if (modulatePkg_ != nullptr) {
        Sensors::FreeVibratorPackage(*modulatePkg_);
        modulatePkg_ = nullptr;
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
    vibrationTimeElapsed_ = 0;
    patternStartTime_ = GetCurrentTimeMillis();
    vibratorTime_.store(0);
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
    (void)Sensors::SetUsage(vibratorUsage_, enableInSilentMode_.load());
    MEDIA_LOGI("PlayPrimitiveEffect with effectId: %{public}s", hapticSource_.effectId.c_str());
    result = Sensors::PlayPrimitiveEffect(hapticSource_.effectId.c_str(), vibrateIntensity_);
    if (result != 0) {
        MEDIA_LOGE("Failed to PlayPrimitiveEffect with effectId: %{public}s, result: %{public}d",
            hapticSource_.effectId.c_str(), result);
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::PlayVibrateForSoundPool(
    const std::shared_ptr<VibratorPackage>& vibratorPkg,
    std::unique_lock<std::mutex>& lock
)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    // record the pattern time which has been played
    int32_t vibrateTime = vibratorTime_.load();
    for (int32_t i = 0; i < vibratorPkg->patternNum; ++i) {
        result = PlayVibrationPattern(vibratorPkg, i, vibrateTime, lock);
        CHECK_AND_RETURN_RET_LOG(result == 0, result, "AudioHapticVibratorImpl::PlayVibrateForSoundPool failed.");
        if (isStopped_) {
            return result;
        }
        if (isNeedRestart_) {
            break;
        }
    }

    if (isNeedRestart_ && seekVibratorPkg_ != nullptr) {
        isNeedRestart_ = false;
        MEDIA_LOGI("AudioHapticVibratorImpl::PlayVibrateForSoundPool change intensity and restart.");
        result = PlayVibrateForSoundPool(seekVibratorPkg_, lock);
        if (Sensors::FreeVibratorPackage(*seekVibratorPkg_) == MSERR_OK) {
            seekVibratorPkg_ = nullptr;
        }
    }
#endif
    return result;
}

void AudioHapticVibratorImpl::ResumeModulePackge()
{
    if (modulatePkg_ != nullptr) {
        std::swap(modulatePkg_, vibratorPkg_);
        Sensors::FreeVibratorPackage(*modulatePkg_);
        modulatePkg_ = nullptr;
        vibratorParameter_.intensity = rampEndIntensity_;
        rampEndIntensity_ = -1.0f;
    }
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
    isRunning_.store(true);
    result = PlayVibrateForSoundPool(vibratorPkg_, lock);
    ResumeModulePackge();
    isRunning_.store(false);
    isIntensityChanged_.store(false);
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::RunVibrationPatterns(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                                      std::unique_lock<std::mutex> &lock)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    // record the pattern time which has been played
    int32_t vibrateTime = vibratorTime_.load();
    for (int32_t i = 0; i < vibratorPkg->patternNum; ++i) {
        result = PlayVibrationPattern(vibratorPkg, i, vibrateTime, lock);
        CHECK_AND_RETURN_RET_LOG(result == 0, result, "AudioHapticVibratorImpl::PlayVibrateForSoundPool failed.");
        if (isStopped_) {
            return result;
        }
        if (isNeedRestart_) {
            break;
        }
    }
    if (isNeedRestart_ && seekVibratorPkg_ != nullptr) {
        isNeedRestart_ = false;
        MEDIA_LOGI("AudioHapticVibratorImpl::RunVibrationPatterns change intensity and restart.");
        result = RunVibrationPatterns(seekVibratorPkg_, lock);
        if (Sensors::FreeVibratorPackage(*seekVibratorPkg_) == MSERR_OK) {
            seekVibratorPkg_ = nullptr;
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

    isRunning_ = true;
    patternduratiomTime_ = PATTERNDURATION_TIME_MS;
    while (!isStopped_) {
        vibrationTimeElapsed_ = 0;
        patternStartTime_ = GetCurrentTimeMillis();
        result = RunVibrationPatterns(vibratorPkg_, lock);
        ResumeModulePackge();
        if (result != MSERR_OK) {
            MEDIA_LOGI("StartNonSyncVibration: RunVibrationPatterns fail.");
            return result;
        }
    }
    isRunning_ = false;
    isIntensityChanged_ = false;
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
    isRunning_ = true;
    result = RunVibrationPatterns(vibratorPkg_, lock);
    ResumeModulePackge();
    isRunning_ = false;
    isIntensityChanged_ = false;
    if (result != MSERR_OK) {
        MEDIA_LOGI("StartNonSyncOnceVibration: RunVibrationPatterns fail.");
        return result;
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::PlayVibrationPattern(
    const std::shared_ptr<VibratorPackage>& vibratorPkg,
    int32_t patternIndex,
    int32_t& vibrateTime,
    std::unique_lock<std::mutex>& lock
)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (patternIndex >= vibratorPkg->patternNum) {
        return result;
    }

    // the delay time of first frame has been handled in audio haptic player
    // calculate the time of single pattern
    MEDIA_LOGI("AudioHapticVibratorImpl::PlayVibrationPattern pattern time %{public}d",
        vibratorPkg->patterns[patternIndex].time);
    int32_t patternTime = vibratorPkg->patterns[patternIndex].time - vibrateTime;
    vibrateTime = vibratorPkg->patterns[patternIndex].time;
    
    (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(patternTime < 0 ? 0 : patternTime),
        [this]() { return isStopped_ || isNeedRestart_; });
    CHECK_AND_RETURN_RET_LOG(!isStopped_ && !isNeedRestart_, result,
        "AudioHapticVibratorImpl::PlayVibrationPattern: Stop() is call when waiting");
    (void)Sensors::SetUsage(vibratorUsage_, enableInSilentMode_.load());
    (void)Sensors::SetParameters(vibratorParameter_);
    MEDIA_LOGI("AudioHapticVibratorImpl::PlayVibrationPattern.");
    patternStartTime_ = GetCurrentTimeMillis();
    vibrationTimeElapsed_ = vibratorPkg->patterns[patternIndex].time;
    if (audioHapticSyncId_ > 0 && !IsNonSync()) {
        result = Sensors::PlayPatternBySessionId(audioHapticSyncId_, vibratorPkg->patterns[patternIndex]);
    } else {
        result = Sensors::PlayPattern(vibratorPkg->patterns[patternIndex]);
    }
    CHECK_AND_RETURN_RET_LOG(result == 0, result,
        "AudioHapticVibratorImpl::PlayVibrationPattern: Failed to PlayPattern. Error %{public}d", result);

    // last pattern need to wait
    if (patternIndex == vibratorPkg->patternNum - 1) {
        int32_t lastPatternDuration = vibratorPkg->patterns[patternIndex].patternDuration + patternduratiomTime_;
        (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(lastPatternDuration),
            [this]() { return isStopped_ || isNeedRestart_; });
        CHECK_AND_RETURN_RET_LOG(!isStopped_ && !isNeedRestart_, result,
            "AudioHapticVibratorImpl::PlayVibrationPattern: Stop() is call when waiting");
    }
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::PlayVibrateForAVPlayer(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                                        std::unique_lock<std::mutex>& lock)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    // record the pattern time which has been played
    int32_t vibrateTime = vibratorTime_.load();
    MEDIA_LOGI("AudioHapticVibratorImpl::PlayVibrateForAVPlayer: now: %{public}d", vibrateTime);
    int32_t patternDuration = IsSelfSystemCaller() ? PATTERN_MAX_COUNT : PATTERN_DEFAULT_COUNT;
    for (int32_t i = 0; i < vibratorPkg->patternNum; ++i) {
        result = PlayVibrationPattern(vibratorPkg, i, vibrateTime, lock);
        AudioHapticPlayerImpl::SendHapticPlayerEvent(result, "PLAY_PATTERN_AVPLAYER");
        CHECK_AND_RETURN_RET_LOG(result == 0, result, "AudioHapticVibratorImpl::PlayVibrateForAVPlayer failed.");
        if (isStopped_) {
            return result;
        }
        // get the audio time every second and handle the delay time unless DSP do sync work(syncId > 0)
        if (isNeedRestart_ || i + 1 >= vibratorPkg->patternNum) {
            break;
        }
        if (audioHapticSyncId_ > 0) {
            continue;
        }
        int32_t nextVibratorTime = vibratorPkg->patterns[i + 1].time;
        vibrateTime = audioHapticPlayer_.GetAudioCurrentTime() + PLAYER_BUFFER_TIME + GetDelayTime();
        int32_t count = 0;
        while (nextVibratorTime - vibrateTime > MIN_WAITING_TIME_FOR_VIBRATOR && count < patternDuration) {
            (void)vibrateCV_.wait_for(lock, std::chrono::milliseconds(MILLISECONDS_FOR_ONE_SECOND),
                [this]() { return isStopped_ || isNeedRestart_; });
            CHECK_AND_RETURN_RET_LOG(!isStopped_, result, "PlayVibrateForAVPlayer: Stop() is call when waiting");
            if (isNeedRestart_) {
                break;
            }
            vibrateTime = audioHapticPlayer_.GetAudioCurrentTime() + PLAYER_BUFFER_TIME + GetDelayTime();
            count++;
        }
        if (count == patternDuration) {
            MEDIA_LOGE("PlayVibrateForAVPlayer: loop count has reached the max value.");
            return MSERR_INVALID_OPERATION;
        }
    }
    if (isNeedRestart_ && seekVibratorPkg_ != nullptr) {
        isNeedRestart_ = false;
        MEDIA_LOGI("AudioHapticVibratorImpl::PlayVibrateForAVPlayer change intensity and restart.");
        result = PlayVibrateForAVPlayer(seekVibratorPkg_, lock);
        if (Sensors::FreeVibratorPackage(*seekVibratorPkg_) == MSERR_OK) {
            seekVibratorPkg_ = nullptr;
        }
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
    isRunning_.store(true);
    patternduratiomTime_ = 0;
    result = PlayVibrateForAVPlayer(vibratorPkg_, lock);
    ResumeModulePackge();
    isRunning_.store(false);
    isIntensityChanged_.store(false);
#endif
    return result;
}

int32_t AudioHapticVibratorImpl::SeekAndRestart()
{
    if (patternStartTime_ == 0) {
        return MSERR_OK;
    }

    seekVibratorPkg_ = std::make_shared<VibratorPackage>();
    auto duration = GetCurrentTimeMillis() - patternStartTime_;
    MEDIA_LOGI("AudioHapticVibratorImpl::SeekAndRestart vibrationTimeElapsed_: %{public}d duration: %{public}" PRId64,
        vibrationTimeElapsed_.load(), duration);
    int32_t result = Sensors::SeekTimeOnPackage(vibrationTimeElapsed_ + duration + WAIT_VIBRATOR_CANCEL_TIME_MS,
        *vibratorPkg_, *seekVibratorPkg_);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result,
        "AudioHapticVibratorImpl::SeekAndRestart SeekTimeOnPackage error");
    isNeedRestart_ = true;
    isIntensityChanged_ = true;
    vibratorTime_.store(vibrationTimeElapsed_ + duration);
    // cancel is async, so should wait for 50ms then restart
    (void)Sensors::Cancel();
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_VIBRATOR_CANCEL_TIME_MS));
    vibrateCV_.notify_one();
    return MSERR_OK;
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

bool AudioHapticVibratorImpl::IsHapticsCustomSupported()
{
    std::lock_guard<std::mutex> lock(vibrateMutex_);
    int32_t result = false;
#ifdef SUPPORT_VIBRATOR
    result = Sensors::IsSupportVibratorCustom();
    MEDIA_LOGI("AudioHapticVibratorImpl::IsHapticsCustomSupported: %{public}d", result);
#endif
    return result;
}

bool AudioHapticVibratorImpl::IsNonSync()
{
    return audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NON_SYNC ||
        audioHapticPlayer_.GetHapticsMode() == HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE;
}
} // namesapce Media
} // namespace OHOS