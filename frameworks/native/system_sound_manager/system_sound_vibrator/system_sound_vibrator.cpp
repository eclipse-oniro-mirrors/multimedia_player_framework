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

#include "system_sound_vibrator.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef SUPPORT_VIBRATOR
#include "vibrator_agent.h"
#endif

#include "media_errors.h"
#include "system_sound_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundVibrator"};
}

namespace OHOS {
namespace Media {
const std::string PREFIX = "fd://";
#ifdef SUPPORT_VIBRATOR
constexpr int32_t PATTERNDURATION_TIME_MS = 800; //ms

const std::unordered_map<VibrationType, VibratorUsage> VIBRATOR_USAGE_MAP = {
    {VibrationType::VIBRATION_RINGTONE, USAGE_RING},
    {VibrationType::VIBRATION_SYSTEM_TONE, USAGE_NOTIFICATION},
};

const std::unordered_map<VibrationType, int32_t> LOOP_COUNT_MAP = {
    // Default loop count. Ringtone need be repeated.
    {VibrationType::VIBRATION_RINGTONE, 10},
    {VibrationType::VIBRATION_SYSTEM_TONE, 1},
};

const std::unordered_map<VibrationType, std::string> EFFECT_ID_MAP = {
    // Default effectId
    {VibrationType::VIBRATION_RINGTONE, "haptic.ringtone.Dream_It_Possible"},
    {VibrationType::VIBRATION_SYSTEM_TONE, "haptic.pattern.type4"},
};
#endif

// static variables
std::mutex SystemSoundVibrator::g_vibrateMutex;
std::string SystemSoundVibrator::g_hapticUri = "";
std::condition_variable SystemSoundVibrator::g_vibrateCV;
std::shared_ptr<std::thread> SystemSoundVibrator::g_vibrateThread = nullptr;
bool SystemSoundVibrator::g_isRunning = false;

int32_t SystemSoundVibrator::StartVibrator(VibrationType type)
{
    std::lock_guard<std::mutex> lock(g_vibrateMutex);
    MEDIA_LOGI("StartVibrator: for vibration type %{public}d", type);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    bool setUsageRet = Sensors::SetUsage(VIBRATOR_USAGE_MAP.at(type));
    bool setLoopRet = Sensors::SetLoopCount(LOOP_COUNT_MAP.at(type));
    result = Sensors::StartVibrator(EFFECT_ID_MAP.at(type).c_str());
    MEDIA_LOGI("StartVibrator: setUsageRet %{public}d, setLoopRet %{public}d, startRet %{public}d",
        setUsageRet, setLoopRet, result);
#endif
    return result;
}

int32_t SystemSoundVibrator::StartVibratorForSystemTone(const std::string &hapticUri)
{
    std::lock_guard<std::mutex> lock(g_vibrateMutex);
    MEDIA_LOGI("Start vibrator with hapticUri [%{public}s] for system tone", hapticUri.c_str());
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    if (!(Sensors::IsSupportVibratorCustom())) {
        MEDIA_LOGE("Custom vibration is not supported for this device!");
        return MSERR_INVALID_OPERATION;
    }
    int32_t fd = ExtractFd(hapticUri);
    if (fd == -1) {
        MEDIA_LOGI("hapticUri is not fd. Try to open it");
        char realPathRes[PATH_MAX + 1] = {'\0'};
        CHECK_AND_RETURN_RET_LOG((strlen(hapticUri.c_str()) < PATH_MAX) &&
            (realpath(hapticUri.c_str(), realPathRes) != nullptr), MSERR_OPEN_FILE_FAILED, "Invalid file path length");
        std::string realPathStr(realPathRes);
        fd = open(realPathStr.c_str(), O_RDONLY);
        if (fd == -1) {
            MEDIA_LOGE("Failed to open hapticUri!");
            return MSERR_OPEN_FILE_FAILED;
        }
    }

    struct stat64 statbuf = { 0 };
    if (fstat64(fd, &statbuf) != 0) {
        MEDIA_LOGE("Failed to open fd and get size.");
        close(fd);
        return MSERR_OPEN_FILE_FAILED;
    }
    Sensors::SetUsage(USAGE_NOTIFICATION);
    Sensors::SetLoopCount(1);
    result = Sensors::PlayVibratorCustom(fd, 0, statbuf.st_size);
    close(fd);
#endif

    return result;
}

int32_t SystemSoundVibrator::ExtractFd(const std::string &hapticsUri)
{
    if (hapticsUri.size() <= PREFIX.size() || hapticsUri.substr(0, PREFIX.length()) != PREFIX) {
        MEDIA_LOGW("ExtractFd: Input does not start with the required PREFIX.");
        return -1;
    }

    std::string numberPart = hapticsUri.substr(PREFIX.length());
    for (char c : numberPart) {
        if (!std::isdigit(c)) {
            MEDIA_LOGE("ExtractFd: The part after the PREFIX is not all digits.");
            return -1;
        }
    }
    return std::stoi(numberPart);
}

int32_t SystemSoundVibrator::StartVibratorForFastMode()
{
    std::lock_guard<std::mutex> lock(g_vibrateMutex);
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    const int32_t DURATION = 2000; // ms. The duration of vibration for fast mode.
    bool setUsageRet = Sensors::SetUsage(USAGE_RING);
    result = Sensors::StartVibratorOnce(DURATION);
    MEDIA_LOGI("StartVibrator for fast mode: setUsageRet %{public}d, startRet %{public}d", setUsageRet, result);
#endif
    return result;
}

int32_t SystemSoundVibrator::StartVibratorForRingtone(const std::string &hapticUri)
{
    if (hapticUri == "") {
        MEDIA_LOGI("hapticUri is empty. No need to start vibrator. Return success!");
        return MSERR_OK;
    }

    std::lock_guard<std::mutex> lock(g_vibrateMutex);
    MEDIA_LOGI("Start vibrator with hapticUri [%{public}s] for ringtone", hapticUri.c_str());
    if (g_isRunning) {
        MEDIA_LOGE("Vibrator is already running!");
        return MSERR_INVALID_OPERATION;
    }
    if (g_vibrateThread != nullptr) {
        MEDIA_LOGE("g_vibrateThread is not nullptr!");
        return MSERR_INVALID_OPERATION;
    }
    g_isRunning = true;
    g_hapticUri = hapticUri;
    g_vibrateThread = std::make_shared<std::thread>(
        [] { SystemSoundVibrator::VibrateForRingtone(g_hapticUri); });
    return MSERR_OK;
}

int32_t SystemSoundVibrator::VibrateForRingtone(const std::string hapticUri)
{
    std::unique_lock<std::mutex> lock(g_vibrateMutex);
    MEDIA_LOGI("VibrateForRingtone with hapticUri [%{public}s] for ringtone", hapticUri.c_str());
    if (!g_isRunning) {
        MEDIA_LOGE("Vibrator is already stopped. No need to start!");
        return MSERR_INVALID_OPERATION;
    }

    int32_t fd = ExtractFd(hapticUri);
    if (fd == -1) {
        MEDIA_LOGI("hapticUri is not fd. Try to open it");
        char realPathRes[PATH_MAX + 1] = {'\0'};
        CHECK_AND_RETURN_RET_LOG((strlen(hapticUri.c_str()) < PATH_MAX) &&
            (realpath(hapticUri.c_str(), realPathRes) != nullptr), MSERR_OPEN_FILE_FAILED, "Invalid file path length");
        std::string realPathStr(realPathRes);
        fd = open(realPathStr.c_str(), O_RDONLY);
        if (fd == -1) {
            MEDIA_LOGE("Failed to open hapticUri!");
            return MSERR_OPEN_FILE_FAILED;
        }
    }

    int32_t result = VibrateLoopFunc(lock, fd);
    if (result != MSERR_OK) {
        close(fd);
        MEDIA_LOGE("Failed to start vibrator!");
        return MSERR_INVALID_OPERATION;
    }
    close(fd);
    return result;
}

int32_t SystemSoundVibrator::VibrateLoopFunc(std::unique_lock<std::mutex> &lock, int32_t fd)
{
    int32_t result = MSERR_OK;
#ifdef SUPPORT_VIBRATOR
    std::shared_ptr<VibratorFileDescription> vibratorFd = std::make_shared<VibratorFileDescription>();
    CHECK_AND_RETURN_RET_LOG(vibratorFd != nullptr, MSERR_OPEN_FILE_FAILED, "vibratorFd is null");
    std::shared_ptr<VibratorPackage> vibratorPkg = std::make_shared<VibratorPackage>();
    CHECK_AND_RETURN_RET_LOG(vibratorPkg != nullptr, MSERR_OPEN_FILE_FAILED, "vibratorPkg is null");

    struct stat64 statbuf = { 0 };
    if (fstat64(fd, &statbuf) == 0) {
        vibratorFd->fd = fd;
        vibratorFd->offset = 0;
        vibratorFd->length = statbuf.st_size;
    } else {
        return MSERR_OPEN_FILE_FAILED;
    }

    result = Sensors::PreProcess(*vibratorFd, *vibratorPkg);
    CHECK_AND_RETURN_RET_LOG(result == 0, MSERR_UNSUPPORT_FILE, "Failed to PreProcess haptic file!");

    while (g_isRunning) {
        int32_t vibrateTime = 0; // record the pattern time which has been played
        for (int32_t i = 0; i < vibratorPkg->patternNum; ++i) {
            int32_t patternTime = vibratorPkg->patterns[i].time - vibrateTime; // calculate the time of single pattern
            vibrateTime = vibratorPkg->patterns[i].time;
            (void)g_vibrateCV.wait_for(lock, std::chrono::milliseconds(patternTime),
                []() { return !g_isRunning; });
            CHECK_AND_RETURN_RET_LOG(g_isRunning, result, "RunVibrationPatterns: Stop() is call when waiting");
            (void)Sensors::SetUsage(USAGE_RING);
            MEDIA_LOGI("PlayPattern for NonSyncVibration");
            result = Sensors::PlayPattern(vibratorPkg->patterns[i]);
            CHECK_AND_RETURN_RET_LOG(result == 0, result,
                "Failed to PlayPattern for NonSyncVibration. Error %{public}d", result);
        }
        // wait for the last pattern
        int32_t lastPatternDuration = vibratorPkg->patterns[vibratorPkg->patternNum - 1].patternDuration +
            PATTERNDURATION_TIME_MS;
        (void)g_vibrateCV.wait_for(lock, std::chrono::milliseconds(lastPatternDuration),
            []() { return !g_isRunning; });
        CHECK_AND_RETURN_RET_LOG(g_isRunning, result, "RunVibrationPatterns: Stop() is call when waiting");
    }
#endif
    return result;
}

int32_t SystemSoundVibrator::StopVibrator()
{
    std::unique_lock<std::mutex> lock(g_vibrateMutex);
    int32_t result = MSERR_OK;
    if (g_isRunning) {
        g_isRunning = false;
        g_vibrateCV.notify_all();
    }
    if (g_vibrateThread != nullptr && g_vibrateThread->joinable()) {
        g_vibrateThread->detach();
        g_vibrateThread = nullptr;
    }
    g_hapticUri = "";

#ifdef SUPPORT_VIBRATOR
    result = Sensors::Cancel();
    MEDIA_LOGI("StopVibrator: %{public}d", result);
#endif
    return result;
}

int32_t SystemSoundVibrator::GetVibratorDuration(const std::string &hapticUri)
{
    int32_t ret = -1;
#ifdef SUPPORT_VIBRATOR
    int32_t fd = ExtractFd(hapticUri);
    if (fd == -1) {
        MEDIA_LOGI("hapticUri is not fd. Try to open it");
        char realPathRes[PATH_MAX + 1] = {'\0'};
        CHECK_AND_RETURN_RET_LOG((strlen(hapticUri.c_str()) < PATH_MAX) &&
            (realpath(hapticUri.c_str(), realPathRes) != nullptr), MSERR_OPEN_FILE_FAILED, "Invalid file path length");
        std::string realPathStr(realPathRes);
        fd = open(realPathStr.c_str(), O_RDONLY);
        if (fd == -1) {
            MEDIA_LOGE("Failed to open hapticUri!");
            return ret;
        }
    }

    VibratorFileDescription vibratorFD{};
    VibratorPackage vibratorPkg{};
    struct stat64 statbuf = { 0 };
    if (fstat64(fd, &statbuf) == 0) {
        vibratorFD.fd = fd;
        vibratorFD.offset = 0;
        vibratorFD.length = statbuf.st_size;
    } else {
        close(fd);
        MEDIA_LOGE("Failed to get file size!");
        return ret;
    }

    int32_t result = Sensors::PreProcess(vibratorFD, vibratorPkg);
    if (result != 0) {
        close(fd);
        MEDIA_LOGE("Failed to pre-process hapticUri!");
        return ret;
    }
    int32_t delayTime = 0;
    (void)Sensors::GetDelayTime(delayTime);
    int32_t patternMaxIndex = vibratorPkg.patternNum - 1;
    int32_t eventMaxIndex = vibratorPkg.patterns[patternMaxIndex].eventNum - 1;
    ret = delayTime + vibratorPkg.patterns[patternMaxIndex].time +
        vibratorPkg.patterns[patternMaxIndex].events[eventMaxIndex].time +
        vibratorPkg.patterns[patternMaxIndex].events[eventMaxIndex].duration;
    Sensors::FreeVibratorPackage(vibratorPkg);
    close(fd);
#endif
    return ret;
}
} // namesapce AudioStandard
} // namespace OHOS
