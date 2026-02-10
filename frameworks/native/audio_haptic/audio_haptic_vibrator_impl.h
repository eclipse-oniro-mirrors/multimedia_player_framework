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

#ifndef AUDIO_HAPTIC_VIBRATOR_IMPL_H
#define AUDIO_HAPTIC_VIBRATOR_IMPL_H

#include "audio_haptic_vibrator.h"

#include <cstdint>
#include <string>

#ifdef SUPPORT_VIBRATOR
#include "vibrator_agent.h"
#endif

namespace OHOS {
namespace Media {

class AudioHapticVibratorImpl : public AudioHapticVibrator {
public:
    explicit AudioHapticVibratorImpl(AudioHapticPlayer &audioHapticPlayer);
    ~AudioHapticVibratorImpl();

    int32_t PreLoad(const HapticSource &hapticSource, const AudioStandard::StreamUsage &streamUsage) override;
    int32_t SetHapticIntensity(float intensity) override;
    int32_t Release() override;
    void ResetStopState() override;
    int32_t StartVibrate(const AudioLatencyMode &latencyMode) override;
    int32_t StopVibrate() override;
    int32_t GetDelayTime() override;
    void SetIsSupportEffectId(bool isSupport);
    bool IsHapticsCustomSupported() override;
    void EnableHapticsInSilentMode(bool enable) override
    {
        enableInSilentMode_.store(enable);
    }
    int32_t SetHapticsRamp(int32_t duration, float startIntensity, float endIntensity) override;
    int32_t SetHapticsFeature(const HapticsFeature &feature) override;
    void SetAudioHapticSyncId(const int32_t &audioHapticSyncId) override
    {
        audioHapticSyncId_ = audioHapticSyncId;
    }
private:
    int32_t StartVibrateForSoundPool();
    int32_t StartVibrateWithEffect();
    int32_t StartVibrateForAVPlayer();
    int32_t StartNonSyncVibration();
    int32_t StartNonSyncOnceVibration();
    int32_t RunVibrationPatterns(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                 std::unique_lock<std::mutex> &lock);
    int32_t OpenHapticSource(const HapticSource& hapticSource, int32_t& fd);
    int32_t OpenHapticFile(const HapticSource& hapticSource);
    int32_t ExtractFd(const std::string& hapticsUri);
    int32_t PlayVibrationPattern(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                 int32_t patternIndex,
                                 int32_t& vibrateTime,
                                 std::unique_lock<std::mutex>& lock);
    int32_t PlayVibrateForAVPlayer(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                   std::unique_lock<std::mutex>& lock);
    int32_t PlayVibrateForSoundPool(const std::shared_ptr<VibratorPackage>& vibratorPkg,
                                    std::unique_lock<std::mutex>& lock);
    int32_t SeekAndRestart();
    void ResumeModulePackge();
    bool IsNonSync();

    AudioHapticPlayer &audioHapticPlayer_;

#ifdef SUPPORT_VIBRATOR
    VibratorUsage vibratorUsage_ = VibratorUsage::USAGE_UNKNOWN;
    std::shared_ptr<VibratorFileDescription> vibratorFD_ = nullptr;
    std::shared_ptr<VibratorPackage> vibratorPkg_ = nullptr;
    std::shared_ptr<VibratorPackage> seekVibratorPkg_ = nullptr;
    std::shared_ptr<VibratorPackage> modulatePkg_ = nullptr;
    std::condition_variable vibrateCV_;
    float vibrateIntensity_ = 1.0f;
    bool isSupportEffectId_ = false;
    HapticSource hapticSource_;
    std::atomic<bool> enableInSilentMode_ = false;
    float rampEndIntensity_ = -1.0f;
    int32_t audioHapticSyncId_ = 0;
#endif
    std::mutex vibrateMutex_;
    AudioStandard::StreamUsage streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool isStopped_ = false;
    int32_t patternduratiomTime_ = 0;
    std::atomic<int32_t> vibrationTimeElapsed_ = 0;
    std::atomic<int64_t> patternStartTime_ = 0;
    std::atomic<int32_t> vibratorTime_ = 0;
    VibratorParameter vibratorParameter_;
    std::atomic<bool> isRunning_ = false;
    std::atomic<bool> isIntensityChanged_ = false;
    std::atomic<bool> isNeedRestart_ = false;
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_HAPTIC_VIBRATOR_IMPL_H
