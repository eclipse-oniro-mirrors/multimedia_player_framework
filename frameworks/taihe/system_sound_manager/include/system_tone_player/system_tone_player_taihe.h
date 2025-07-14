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

#ifndef SYSTEM_TONE_PLAYER_TAIHE_H
#define SYSTEM_TONE_PLAYER_TAIHE_H

#include "systemTonePlayer.proj.hpp"
#include "systemTonePlayer.impl.hpp"
#include "taihe/runtime.hpp"

#include "system_tone_callback_taihe.h"
#include "system_tone_player.h"

namespace ANI::Media {
using namespace taihe;
using namespace systemTonePlayer;
using ToneHapticsFeature = ::ohos::multimedia::systemSoundManager::ToneHapticsFeature;

class SystemTonePlayerImpl {
public:
    static SystemTonePlayer GetSystemTonePlayerInstance(
        std::shared_ptr<OHOS::Media::SystemTonePlayer> &systemTonePlayer);

    SystemTonePlayerImpl() = default;
    SystemTonePlayerImpl(std::shared_ptr<OHOS::Media::SystemTonePlayer> systemTonePlayer);
    ~SystemTonePlayerImpl() = default;

    ::taihe::string GetTitleSync();
    void SetAudioVolumeScale(double scale);
    double GetAudioVolumeScale();
    ::taihe::array<ToneHapticsFeature> GetSupportedHapticsFeaturesSync();
    void SetHapticsFeature(ToneHapticsFeature hapticsFeature);
    ToneHapticsFeature GetHapticsFeature();
    void PrepareSync();
    int32_t StartSync(optional_view<SystemToneOptions> toneOptions);
    void StopSync(int32_t id);
    void ReleaseSync();
    void OnPlayFinished(int32_t streamId, callback_view<void(int32_t)> callback);
    void OffPlayFinished(optional_view<callback<void(int32_t)>> callback);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);

private:
    std::shared_ptr<OHOS::Media::SystemTonePlayer> systemTonePlayer_ = nullptr;
    std::shared_ptr<SystemTonePlayerCallbackTaihe> callbackTaihe_ = nullptr;
};

} // namespace ANI::Media
#endif // SYSTEM_TONE_PLAYER_TAIHE_H