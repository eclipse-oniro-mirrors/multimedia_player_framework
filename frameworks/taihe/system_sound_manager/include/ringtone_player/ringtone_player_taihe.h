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

#ifndef RINGTONE_PLAYER_TAIHE_H
#define RINGTONE_PLAYER_TAIHE_H

#include <map>

#include "audio_info.h"
#include "media_errors.h"
#include "ringtone_common_taihe.h"
#include "ringtone_player.h"
#include "ringtone_player_callback_taihe.h"
#include "ringtonePlayer.proj.hpp"
#include "ringtonePlayer.impl.hpp"
#include "system_sound_log.h"
#include "taihe/runtime.hpp"

namespace ANI::Media {
static const std::string RINGTONE_PLAYER_TAIHE_CLASS_NAME = "RingtonePlayer";

class RingtonePlayerImpl {
public:
    RingtonePlayerImpl() = default;
    RingtonePlayerImpl(std::shared_ptr<OHOS::Media::RingtonePlayer> ringtonePlayer);
    ~RingtonePlayerImpl() = default;

    ::taihe::string GetState();
    ::taihe::string GetTitleSync();
    uintptr_t GetAudioRendererInfoSync();
    void ConfigureSync(::ringtonePlayer::RingtoneOptions const& options);
    void StartSync();
    void StopSync();
    void ReleaseSync();
    void OnAudioInterrupt(::taihe::callback_view<void(uintptr_t)> callback);
    void OffAudioInterrupt();

private:
    std::shared_ptr<OHOS::Media::RingtonePlayer> ringtonePlayer_;
    std::shared_ptr<OHOS::Media::RingtonePlayerInterruptCallback> callbackTaihe_ = nullptr;
};
} // namespace ANI::Media
#endif // RINGTONE_PLAYER_TAIHE_H