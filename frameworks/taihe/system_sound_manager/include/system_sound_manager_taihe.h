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

#ifndef SYSTEM_SOUND_MANAGER_TAIHE_H
#define SYSTEM_SOUND_MANAGER_TAIHE_H

#include "ability_context.h"
#include "ani_base_context.h"
#include "ohos.multimedia.systemSoundManager.proj.hpp"
#include "ohos.multimedia.systemSoundManager.impl.hpp"
#include "ringtone_common_taihe.h"
#include "system_sound_manager.h"
#include "system_tone_player_taihe.h"
#include "taihe/runtime.hpp"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::systemSoundManager;
using RingtoneTypeTaihe = ::ohos::multimedia::systemSoundManager::RingtoneType;
using SystemSoundManagerTaihe = ::ohos::multimedia::systemSoundManager::SystemSoundManager;
using SystemToneTypeTaihe = ::ohos::multimedia::systemSoundManager::SystemToneType;
using ToneAttrsTaihe = ::ohos::multimedia::systemSoundManager::ToneAttrs;
using ToneHapticsAttrsTaihe = ::ohos::multimedia::systemSoundManager::ToneHapticsAttrs;
using ToneHapticsSettings = ::ohos::multimedia::systemSoundManager::ToneHapticsSettings;
using ToneHapticsTypeTaihe = ::ohos::multimedia::systemSoundManager::ToneHapticsType;
using WeakToneAttrsTaihe = ::ohos::multimedia::systemSoundManager::weak::ToneAttrs;
using SystemSoundErrorTaihe = ::ohos::multimedia::systemSoundManager::SystemSoundError;

class SystemSoundManagerImpl {
public:
    SystemSoundManagerImpl();
    explicit SystemSoundManagerImpl(std::unique_ptr<SystemSoundManagerImpl> obj);
    ~SystemSoundManagerImpl();

    string GetSystemToneUriSync(uintptr_t context, SystemToneType type);
    ToneHapticsSettings GetToneHapticsSettingsSync(uintptr_t context, ToneHapticsType type);
    ::systemTonePlayer::SystemTonePlayer GetSystemTonePlayerSync(uintptr_t context, SystemToneType type);

    void CloseSync(int32_t fd);
    ToneAttrsTaihe GetDefaultRingtoneAttrsSync(uintptr_t context, RingtoneTypeTaihe type);
    ::taihe::array<ToneAttrsTaihe> GetAlarmToneAttrListSync(uintptr_t context);
    void RemoveCustomizedToneSync(uintptr_t context, ::taihe::string_view uri);
    ::taihe::array<ToneAttrsTaihe> GetSystemToneAttrListSync(uintptr_t context, SystemToneTypeTaihe type);
    ::taihe::string AddCustomizedToneByUriSync(
        uintptr_t context, WeakToneAttrsTaihe toneAttr, ::taihe::string_view externalUri);
    ::taihe::string AddCustomizedToneByFdSync(
        uintptr_t context, WeakToneAttrsTaihe toneAttr, int32_t fd, ::taihe::optional_view<int64_t> offset,
        ::taihe::optional_view<int64_t> length);
    int32_t OpenAlarmToneSync(uintptr_t context, ::taihe::string_view uri);
    ToneAttrsTaihe GetDefaultSystemToneAttrsSync(uintptr_t context, SystemToneTypeTaihe type);
    ::taihe::array<ToneAttrsTaihe> GetRingtoneAttrListSync(uintptr_t context, RingtoneTypeTaihe type);
    void SetAlarmToneUriSync(uintptr_t context, ::taihe::string_view uri);
    ::taihe::string GetAlarmToneUriSync(uintptr_t context);
    ToneAttrsTaihe GetDefaultAlarmToneAttrsSync(uintptr_t context);
    ::taihe::array<ToneHapticsAttrsTaihe> GetToneHapticsListSync(uintptr_t context, bool isSynced);
    void SetToneHapticsSettingsSync(
        uintptr_t context, ToneHapticsTypeTaihe type, const ToneHapticsSettings& settings);
    ToneHapticsAttrsTaihe GetHapticsAttrsSyncedWithToneSync(uintptr_t context, ::taihe::string_view toneUri);
    int32_t OpenToneHapticsSync(uintptr_t context, ::taihe::string_view hapticsUri);
    void SetSystemToneUriSync(uintptr_t context, ::taihe::string_view uri, SystemToneTypeTaihe type);
    ::ringtonePlayer::RingtonePlayer GetRingtonePlayerSync(uintptr_t context, RingtoneTypeTaihe type);
    ::taihe::string GetRingtoneUriSync(uintptr_t context, RingtoneTypeTaihe type);
    void SetRingtoneUriSync(uintptr_t context, ::taihe::string_view uri, RingtoneTypeTaihe type);
    ToneAttrsTaihe GetCurrentRingtoneAttributeSync(RingtoneTypeTaihe type);
    ::taihe::array<uintptr_t> RemoveCustomizedToneListSync(::taihe::array_view<::taihe::string> uriList);
    ::taihe::array<uintptr_t> OpenToneListSync(::taihe::array_view<::taihe::string> uriList);

    friend SystemSoundManagerTaihe GetSystemSoundManager();

private:
    static bool CheckResultUriAndThrowError(std::string uri);
    static bool CheckToneHapticsResultAndThrowError(int32_t result);
    static bool CheckToneHapticsResultAndThrowErrorExt(int32_t result);
    static void GetToneHapticsSettingsFromTaihe(
        const ToneHapticsSettings& settings, OHOS::Media::ToneHapticsSettings& innerSettings);

    static array<ToneAttrsTaihe> ReturnErrToneAttrsTaiheArray();
    static array<ToneHapticsAttrsTaihe> ReturnErrToneHapticsAttrsTaiheArray();
    static array<ToneAttrsTaihe> ToToneAttrsTaiheArray(
        std::vector<std::shared_ptr<OHOS::Media::ToneAttrs>> &src);
    static array<ToneHapticsAttrsTaihe> ToToneHapticsAttrsTaiheArray(
        std::vector<std::shared_ptr<OHOS::Media::ToneHapticsAttrs>> &src);
    static std::shared_ptr<OHOS::AbilityRuntime::Context> GetAbilityContext(ani_env* env, uintptr_t contextArg);

    std::shared_ptr<OHOS::Media::SystemSoundManager> sysSoundMgrClient_ = nullptr;
};
} // namespace ANI::Media
#endif // SYSTEM_SOUND_MANAGER_TAIHE_H