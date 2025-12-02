/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef AUDIO_HAPTIC_PLAYER_TAIHE_H
#define AUDIO_HAPTIC_PLAYER_TAIHE_H

#include "ohos.multimedia.audioHaptic.audioHaptic.proj.hpp"
#include "ohos.multimedia.audioHaptic.audioHaptic.impl.hpp"
#include "taihe/runtime.hpp"

#include "audio_haptic_player.h"
#include "audio_haptic_player_callback_taihe.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::audioHaptic::audioHaptic;

class AudioHapticPlayerImpl {
public:
    AudioHapticPlayerImpl();
    AudioHapticPlayerImpl(std::shared_ptr<OHOS::Media::AudioHapticPlayer> &audioHapticPlayer);
    ~AudioHapticPlayerImpl();
    static AudioHapticPlayer CreatePlayerInstance(std::shared_ptr<OHOS::Media::AudioHapticPlayer> &audioHapticPlayer);

    bool IsMuted(AudioHapticType audioHapticType);
    void StartSync();
    void StopSync();
    void ReleaseSync();
    void SetVolumeSync(double volume);
    void SetHapticsIntensitySync(double intensity);
    void EnableHapticsInSilentMode(bool enable);
    bool IsHapticsIntensityAdjustmentSupported();
    void SetLoopSync(bool loop);
    void SetHapticsRampSync(int32_t duration, double startIntensity, double endIntensity);
    bool IsHapticsRampSupported();
    void OnAudioInterrupt(callback_view<void(uintptr_t)> callback);
    void OffAudioInterrupt(optional_view<callback<void(uintptr_t)>> callback);
    void OnEndOfStream(callback_view<void(uintptr_t)> callback);
    void OffEndOfStream(optional_view<callback<void(uintptr_t)>> callback);

private:
    bool IsLegalAudioHapticType(int32_t audioHapticType);
    bool IsLegalVolumeOrIntensity(double volume);
    bool JudgeVolume(double &volume);
    bool JudgeIntensity(double &intensity);
    bool JudgeRamp(int duration, double &startIntensity, double &endIntensity);
    bool RegisterCallback(const std::string &callbackName, callback_view<void(uintptr_t)> callback);
    bool UnregisterCallback(const std::string &callbackName);

private:
    std::shared_ptr<OHOS::Media::AudioHapticPlayer> audioHapticPlayer_ = nullptr;
    std::shared_ptr<AudioHapticPlayerCallbackTaihe> callbackTaihe_ = nullptr;
};
} // namespace ANI::Media
#endif // AUDIO_HAPTIC_PLAYER_TAIHE_H