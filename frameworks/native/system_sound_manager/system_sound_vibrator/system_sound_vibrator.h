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

#ifndef SYSTEM_SOUND_VIBRATOR_H
#define SYSTEM_SOUND_VIBRATOR_H

#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace OHOS {
namespace Media {
enum class VibrationType {
    VIBRATION_RINGTONE = 0,
    VIBRATION_SYSTEM_TONE,
};

class SystemSoundVibrator {
public:
    static int32_t StartVibrator(VibrationType type);
    static int32_t StartVibratorForSystemTone(const std::string &hapticUri);
    static int32_t StartVibratorForRingtone(const std::string &hapticUri);
    static int32_t StopVibrator();

private:
    static int32_t ExtractFd(const std::string &hapticsUri);
    static int32_t VibrateForRingtone(const std::string &hapticUri);
    static int32_t VibrateLoopFunc(std::unique_lock<std::mutex> &lock, int32_t fd);

    static std::mutex g_vibrateMutex;
    static std::string g_hapticUri;
    static std::shared_ptr<std::thread> g_vibrateThread;
    static bool g_isRunning;
    static std::condition_variable g_vibrateCV;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_SOUND_VIBRATOR_H
