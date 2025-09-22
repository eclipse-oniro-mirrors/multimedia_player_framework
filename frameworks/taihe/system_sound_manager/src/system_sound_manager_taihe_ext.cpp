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

#include "system_sound_manager_taihe.h"

#include "common_taihe.h"
#include "system_sound_log.h"
#include "tone_haptics_attrs_taihe.h"
#include "tone_haptics_settings_taihe.h"

namespace {
const int UNSUPPORTED_ERROR = -5;
const int OPERATION_ERROR = -4;
const int IO_ERROR = -3;
const int ERROR = -1;
const int INVALID_TONE_HAPTICS_TYPE = -1;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerTaihe"};
}

using namespace ANI::Media;

namespace ANI::Media {
void SystemSoundManagerImpl::GetToneHapticsSettingsFromTaihe(
    const ToneHapticsSettings& settings, OHOS::Media::ToneHapticsSettings& innerSettings)
{
    if (settings.hapticsUri.has_value()) {
        innerSettings.hapticsUri = std::string(settings.hapticsUri.value());
    }
    innerSettings.mode = static_cast<OHOS::Media::ToneHapticsMode>(settings.mode.get_value());
}

array<ToneHapticsAttrsTaihe> SystemSoundManagerImpl::ReturnErrToneHapticsAttrsTaiheArray()
{
    std::vector<ToneHapticsAttrsTaihe> emptyVec;
    return array<ToneHapticsAttrsTaihe>(emptyVec);
}

array<ToneHapticsAttrsTaihe> SystemSoundManagerImpl::ToToneHapticsAttrsTaiheArray(
    std::vector<std::shared_ptr<OHOS::Media::ToneHapticsAttrs>> &src)
{
    std::vector<ToneHapticsAttrsTaihe> vec;
    for (auto &item : src) {
        vec.emplace_back(make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>(item));
    }
    return array<ToneHapticsAttrsTaihe>(vec);
}

bool SystemSoundManagerImpl::CheckToneHapticsResultAndThrowError(int32_t result)
{
    if (result == IO_ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return false;
    } else if (result == UNSUPPORTED_ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_UNSUPPORTED_OPERATION, TAIHE_ERR_UNSUPPORTED_OPERATION_INFO);
        return false;
    }
    return true;
}

bool SystemSoundManagerImpl::CheckToneHapticsResultAndThrowErrorExt(int32_t result)
{
    if (result == OPERATION_ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO);
        return false;
    }
    return CheckToneHapticsResultAndThrowError(result);
}

ToneHapticsSettings SystemSoundManagerImpl::GetToneHapticsSettingsSync(
    uintptr_t context, ToneHapticsTypeTaihe type)
{
    ToneHapticsSettings settings = {
        .mode = ToneHapticsMode::from_value(INVALID_TONE_HAPTICS_TYPE),
        .hapticsUri = optional<string>(std::in_place_t{}, ""),
    };
    if (!CommonTaihe::VerifySelfSystemPermission()) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return settings;
    }

    auto abilityContext = GetAbilityContext(get_env(), context);
    int32_t toneHapticsType = type.get_value();
    MEDIA_LOGI("GetToneHapticsSettings toneHapticsType : %{public}d", toneHapticsType);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return settings;
    }

    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError("sysSoundMgrClient_ is nullptr.");
        return settings;
    }

    OHOS::Media::ToneHapticsSettings toneHapticsSettings;
    int32_t result = sysSoundMgrClient_->GetToneHapticsSettings(abilityContext,
        static_cast<OHOS::Media::ToneHapticsType>(toneHapticsType), toneHapticsSettings);
    if (!result) {
        settings = ToneHapticsSettingsTaihe::NewInstance(toneHapticsSettings);
    } else if (result == IO_ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    } else if (result == UNSUPPORTED_ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_UNSUPPORTED_OPERATION, TAIHE_ERR_UNSUPPORTED_OPERATION_INFO);
    }
    return settings;
}

::taihe::array<ToneHapticsAttrsTaihe> SystemSoundManagerImpl::GetToneHapticsListSync(uintptr_t context, bool isSynced)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ReturnErrToneHapticsAttrsTaiheArray();
    }

    bool isSyncedInner = isSynced == ANI_TRUE;
    MEDIA_LOGI("GetToneHapticsList isSynced : %{public}s", isSyncedInner ? "true" : "false");
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneHapticsAttrsTaiheArray();
    }
    if (sysSoundMgrClient_ == nullptr) {
        return ReturnErrToneHapticsAttrsTaiheArray();
    }

    std::vector<std::shared_ptr<OHOS::Media::ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = sysSoundMgrClient_->GetToneHapticsList(abilityContext, isSyncedInner, toneHapticsAttrsArray);
    if (!CheckToneHapticsResultAndThrowError(result)) {
        return ReturnErrToneHapticsAttrsTaiheArray();
    }
    return ToToneHapticsAttrsTaiheArray(toneHapticsAttrsArray);
}

void SystemSoundManagerImpl::SetToneHapticsSettingsSync(
    uintptr_t context, ToneHapticsTypeTaihe type, const ToneHapticsSettings& settings)
{
    CHECK_AND_RETURN_RET_LOG(CommonTaihe::VerifySelfSystemPermission(),
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO), "No system permission");

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    CHECK_AND_RETURN_RET_LOG(abilityContext != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO),
        "invalid arguments");
    CHECK_AND_RETURN_RET_NOLOG(sysSoundMgrClient_ != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));

    OHOS::Media::ToneHapticsSettings settingsInner;
    GetToneHapticsSettingsFromTaihe(settings, settingsInner);
    int32_t result = sysSoundMgrClient_->SetToneHapticsSettings(
        abilityContext, static_cast<OHOS::Media::ToneHapticsType>(type.get_value()), settingsInner);
    CheckToneHapticsResultAndThrowErrorExt(result);
}

ToneHapticsAttrsTaihe SystemSoundManagerImpl::GetHapticsAttrsSyncedWithToneSync(
    uintptr_t context, ::taihe::string_view toneUri)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>();
    }

    MEDIA_LOGI("GetHapticsAttrsSyncedWithTone toneUri : %{public}s", std::string(toneUri).c_str());
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        return make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>();
    }

    std::shared_ptr<OHOS::Media::ToneHapticsAttrs> toneHapticsAttrs;
    int32_t result = sysSoundMgrClient_->GetHapticsAttrsSyncedWithTone(
        abilityContext, std::string(toneUri), toneHapticsAttrs);
    if (!CheckToneHapticsResultAndThrowErrorExt(result)) {
        return make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>();
    }
    return make_holder<ToneHapticsAttrsImpl, ToneHapticsAttrsTaihe>(toneHapticsAttrs);
}

int32_t SystemSoundManagerImpl::OpenToneHapticsSync(uintptr_t context, ::taihe::string_view hapticsUri)
{
    if (!CommonTaihe::VerifySelfSystemPermission()) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ERROR;
    }

    MEDIA_LOGI("OpenToneHaptics hapticsUri : %{public}s", std::string(hapticsUri).c_str());
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERROR;
    }
    if (sysSoundMgrClient_ == nullptr) {
        return ERROR;
    }

    int32_t fd = sysSoundMgrClient_->OpenToneHaptics(abilityContext, std::string(hapticsUri));
    if (!CheckToneHapticsResultAndThrowErrorExt(fd)) {
        return ERROR;
    }
    return fd;
}
} // namespace ANI::Media