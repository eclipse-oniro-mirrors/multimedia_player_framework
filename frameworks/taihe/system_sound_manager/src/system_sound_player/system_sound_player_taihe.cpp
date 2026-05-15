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

#include "common_taihe.h"
#include "system_sound_player_taihe.h"
#include "system_sound_log.h"

using namespace ANI::Media;
namespace {

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundPlayerTaihe"};

}

namespace ANI::Media {

SystemSoundPlayerImpl::SystemSoundPlayerImpl(std::unique_ptr<SystemSoundPlayerImpl> obj)
{
    MEDIA_LOGI("SystemSoundPlayerImpl in.");
    if (obj != nullptr) {
        systemSoundPlayer_ = obj->systemSoundPlayer_;
    } else {
        MEDIA_LOGE("Failed to create systemSoundPlayer instance.");
    }
}

SystemSoundPlayerImpl::~SystemSoundPlayerImpl()
{
    MEDIA_LOGI("SystemSoundPlayerImpl destroyed.");
}

void SystemSoundPlayerImpl::LoadSync(SystemSoundTypeTaihe soundType)
{
    if (systemSoundPlayer_ == nullptr) {
        taihe::set_error("Failed to create systemSoundPlayer instance.");
        return;
    }
    int32_t systemSoundType = soundType.get_value();
    MEDIA_LOGI("LoadSync systemSoundType = %{public}d", systemSoundType);
    int32_t resultLoad = systemSoundPlayer_->Load(static_cast<OHOS::Media::SystemSoundType>(systemSoundType));
    if (resultLoad < 0) {
        CommonTaihe::ThrowError(resultLoad, "LoadSync: Operation is not supported or failed");
        return;
    }
}

void SystemSoundPlayerImpl::PlaySync(SystemSoundTypeTaihe soundType)
{
    if (systemSoundPlayer_ == nullptr) {
        taihe::set_error("Failed to create systemSoundPlayer instance.");
        return;
    }
    int32_t systemSoundType = soundType.get_value();
    MEDIA_LOGI("PlaySync systemSoundType = %{public}d", systemSoundType);
    int32_t resultPlay = systemSoundPlayer_->Play(static_cast<OHOS::Media::SystemSoundType>(systemSoundType));
    if (resultPlay < 0) {
        CommonTaihe::ThrowError(resultPlay, "PlaySync: Operation is not supported or failed");
        return;
    }
}

void SystemSoundPlayerImpl::UnloadSync(SystemSoundTypeTaihe soundType)
{
    if (systemSoundPlayer_ == nullptr) {
        taihe::set_error("Failed to create systemSoundPlayer instance.");
        return;
    }
    int32_t systemSoundType = soundType.get_value();
    MEDIA_LOGI("UnloadSync systemSoundType = %{public}d", systemSoundType);
    int32_t resultUnload = systemSoundPlayer_->Unload(static_cast<OHOS::Media::SystemSoundType>(systemSoundType));
    if (resultUnload < 0) {
        CommonTaihe::ThrowError(resultUnload, "UnloadSync: Operation is not supported or failed");
        return;
    }
}

void SystemSoundPlayerImpl::ReleaseSync()
{
    MEDIA_LOGI("ReleaseSync in.");
    if (systemSoundPlayer_ == nullptr) {
        taihe::set_error("Failed to create systemSoundPlayer instance.");
        return;
    }
    int32_t resultRelease = systemSoundPlayer_->Release();
    if (resultRelease < 0) {
        CommonTaihe::ThrowError(resultRelease, "ReleaseSync: Operation is not supported or failed");
        return;
    }
}

void SystemSoundPlayerImpl::SetSystemSoundPlayer(const std::shared_ptr<OHOS::Media::SystemSoundPlayer>& player)
{
    systemSoundPlayer_ = player;
}

std::shared_ptr<OHOS::Media::SystemSoundPlayer> SystemSoundPlayerImpl::GetSystemSoundPlayer()
{
    return systemSoundPlayer_;
}
} // namespace ANI::Media
