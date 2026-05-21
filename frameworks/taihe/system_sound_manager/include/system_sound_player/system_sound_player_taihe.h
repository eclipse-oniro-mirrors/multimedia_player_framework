/*
* Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef SYSTEM_SOUND_PLAYER_TAIHE_H
#define SYSTEM_SOUND_PLAYER_TAIHE_H

#include <map>

#include "system_sound_player.h"
#include "audio_info.h"
#include "media_errors.h"
#include "system_sound_log.h"
#include "SystemSoundPlayer.proj.hpp"
#include "SystemSoundPlayer.impl.hpp"
#include "system_sound_log.h"
#include "taihe/runtime.hpp"

namespace ANI::Media {
using namespace taihe;
using namespace SystemSoundPlayer;
using SystemSoundTypeTaihe = ::ohos::multimedia::systemSoundManager::SystemSoundType;
class SystemSoundPlayerImpl {
public:
    SystemSoundPlayerImpl() = default;
    SystemSoundPlayerImpl(std::unique_ptr<SystemSoundPlayerImpl> obj);
    ~SystemSoundPlayerImpl();

    void LoadSync(SystemSoundTypeTaihe soundType);
    void PlaySync(SystemSoundTypeTaihe soundType);
    void UnloadSync(SystemSoundTypeTaihe soundType);
    void ReleaseSync();

    void SetSystemSoundPlayer(const std::shared_ptr<OHOS::Media::SystemSoundPlayer>& player);
    std::shared_ptr<OHOS::Media::SystemSoundPlayer> GetSystemSoundPlayer();

private:
    std::shared_ptr<OHOS::Media::SystemSoundPlayer> systemSoundPlayer_;
};
} // namespace ANI::Media
#endif // SYSTEM_SOUND_PLAYER_TAIHE_H