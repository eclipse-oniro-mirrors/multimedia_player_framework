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
#include "system_sound_manager.h"
#include "tone_attrs_taihe.h"
#include "tone_haptics_attrs_taihe.h"
#include "tone_haptics_settings_taihe.h"

namespace {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

const int UNSUPPORTED_ERROR = -5;
const int OPERATION_ERROR = -4;
const int IO_ERROR = -3;
const int ERROR = -1;
const int INVALID_TONE_HAPTICS_TYPE = -1;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerTaihe"};
constexpr char ENUM_SYSTEM_SOUND_ERROR[] = "@ohos.multimedia.systemSoundManager.systemSoundManager.SystemSoundError";
constexpr char CLASS_NAME_TUPLE2[] = "std.core.Tuple2";
constexpr char CLASS_NAME_TUPLE3[] = "std.core.Tuple3";
}

static const std::map<OHOS::Media::SystemSoundError, int32_t> ANI_SYSTEMSOUNDERROR_INDEX_MAP = {
    {OHOS::Media::SystemSoundError::ERROR_IO, 0},
    {OHOS::Media::SystemSoundError::ERROR_OK, 1},
    {OHOS::Media::SystemSoundError::ERROR_TYPE_MISMATCH, 2},
    {OHOS::Media::SystemSoundError::ERROR_UNSUPPORTED_OPERATION, 3},
    {OHOS::Media::SystemSoundError::ERROR_DATA_TOO_LARGE, 4},
    {OHOS::Media::SystemSoundError::ERROR_TOO_MANY_FILES, 5},
    {OHOS::Media::SystemSoundError::ERROR_INSUFFICIENT_ROM, 6},
    {OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM, 7},
};

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

ToneAttrsTaihe SystemSoundManagerImpl::GetCurrentRingtoneAttributeSync(RingtoneTypeTaihe type)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    int32_t typeInner = type.get_value();
    if (!(typeInner == OHOS::Media::RingtoneType::RINGTONE_TYPE_SIM_CARD_0 ||
        typeInner == OHOS::Media::RingtoneType::RINGTONE_TYPE_SIM_CARD_1)) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    auto toneAttrs = std::make_shared<OHOS::Media::ToneAttrs>(sysSoundMgrClient_->GetCurrentRingtoneAttribute(
        static_cast<OHOS::Media::RingtoneType>(typeInner)));
    if (toneAttrs == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    return make_holder<ToneAttrsImpl, ToneAttrsTaihe>(toneAttrs);
}

static ani_object GetAniObjectTuple2(ani_env *env, const std::string &str, int systemSoundErrorIndex)
{
    ani_object aniObjectTuple2 {};
    ani_class cls {};
    const std::string className = CLASS_NAME_TUPLE2;
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindClass(className.c_str(), &cls), aniObjectTuple2,
        "Failed to find class std.core.Tuple2");

    ani_method ctor;
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor), aniObjectTuple2,
        "Failed to find method ctor");

    ani_string aniStringP0 {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->String_NewUTF8(str.c_str(), str.size(), &aniStringP0), aniObjectTuple2,
        "Failed to String_NewUTF8");

    ani_enum aniEnumP1 {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(ENUM_SYSTEM_SOUND_ERROR, &aniEnumP1), aniObjectTuple2,
        "Failed to find enum SystemSoundError");
    ani_enum_item aniEnumItemP1 {};
    ani_int enumIndex = static_cast<ani_int>(systemSoundErrorIndex);
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnumP1, enumIndex, &aniEnumItemP1),
        aniObjectTuple2, "Failed to get enum item by index");

    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_New(cls, ctor, &aniObjectTuple2, aniStringP0,
        aniEnumItemP1), aniObjectTuple2, "Failed to new Tuple3 object");

    return aniObjectTuple2;
}

static ani_object GetAniObjectTuple3(ani_env *env, const std::string &str, int64_t number, int systemSoundErrorIndex)
{
    ani_object aniObjectTuple3 {};
    ani_class cls {};
    const std::string className = CLASS_NAME_TUPLE3;
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindClass(className.c_str(), &cls), aniObjectTuple3,
        "Failed to find class std.core.Tuple3");

    ani_method ctor;
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor), aniObjectTuple3,
        "Failed to find method ctor");

    ani_string aniStringP0 {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->String_NewUTF8(str.c_str(), str.size(), &aniStringP0), aniObjectTuple3,
        "Failed to String_NewUTF8");

    ani_object aniLongP1 {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == CommonTaihe::ToAniLongObject(env, number, aniLongP1), aniObjectTuple3,
        "Failed to get ani long object");

    ani_enum aniEnumP2 {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(ENUM_SYSTEM_SOUND_ERROR, &aniEnumP2), aniObjectTuple3,
        "Failed to find enum SystemSoundError");
    ani_enum_item aniEnumItemP2 {};
    ani_int enumIndex = static_cast<ani_int>(systemSoundErrorIndex);
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnumP2, enumIndex, &aniEnumItemP2),
        aniObjectTuple3, "Failed to get enum item by index");

    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_New(cls, ctor, &aniObjectTuple3, aniStringP0, aniLongP1,
        aniEnumItemP2), aniObjectTuple3, "Failed to new Tuple3 object");

    return aniObjectTuple3;
}

static ani_status GetAniIndexByValue(ani_env *env, OHOS::Media::SystemSoundError value, int32_t &aniEnumIndex)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_SYSTEMSOUNDERROR_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_SYSTEMSOUNDERROR_INDEX_MAP.end(), ANI_INVALID_ARGS,
        "Unsupport SystemSoundError enum: %{public}d", value);
    aniEnumIndex = it->second;

    return ANI_OK;
}

::taihe::array<uintptr_t>  SystemSoundManagerImpl::RemoveCustomizedToneListSync(
    ::taihe::array_view<::taihe::string> uriList)
{
    std::vector<uintptr_t> results;
    MEDIA_LOGI("RemoveCustomizedToneList start");
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ::taihe::array<uintptr_t>(results);
    }
    if (!(CommonTaihe::VerifyRingtonePermission())) {
        MEDIA_LOGE("Permission denied");
        CommonTaihe::ThrowError(TAIHE_ERR_NO_PERMISSION, TAIHE_ERR_NO_PERMISSION_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    ani_env *env = get_env();
    if (env == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_SYSTEM, TAIHE_ERR_SYSTEM_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    std::vector<std::string> uriVec;
    for (const auto &uri : uriList) {
        uriVec.emplace_back(std::string(uri));
    }
    if (uriVec.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    OHOS::Media::SystemSoundError errCode = OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM;
    std::vector<std::pair<std::string, OHOS::Media::SystemSoundError>> removeResultArray;
    if (sysSoundMgrClient_ != nullptr) {
        removeResultArray = sysSoundMgrClient_->RemoveCustomizedToneList(uriVec, errCode);
    }
    MEDIA_LOGI("RemoveCustomizedToneList errCode = %{public}d", static_cast<int>(errCode));
    if (errCode == OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM) {
        CommonTaihe::ThrowError(OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM, TAIHE_ERR_URILIST_OVER_LIMIT_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    ani_object aniObjectTuple2 {};
    int32_t systemSoundErrorIndex = 0;
    for (const auto& removeResult : removeResultArray) {
        if (ANI_OK != GetAniIndexByValue(env, std::get<PARAM1>(removeResult), systemSoundErrorIndex)) {
            CommonTaihe::ThrowError(TAIHE_ERR_SYSTEM, TAIHE_ERR_SYSTEM_INFO);
            return ::taihe::array<uintptr_t>(results);
        }
        aniObjectTuple2 = GetAniObjectTuple2(env, std::get<PARAM0>(removeResult).c_str(), systemSoundErrorIndex);
        results.push_back(reinterpret_cast<uintptr_t>(aniObjectTuple2));
    }
    return ::taihe::array<uintptr_t>(results);
}

::taihe::array<uintptr_t> SystemSoundManagerImpl::OpenToneListSync(::taihe::array_view<::taihe::string> uriList)
{
    std::vector<uintptr_t> results;
    MEDIA_LOGI("OpenToneList start");
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    ani_env *env = get_env();
    if (env == nullptr) {
        MEDIA_LOGE("get_env is nullptr");
        CommonTaihe::ThrowError(TAIHE_ERR_SYSTEM, TAIHE_ERR_SYSTEM_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    std::vector<std::string> uriVec;
    for (const auto &uri : uriList) {
        uriVec.emplace_back(std::string(uri));
    }
    if (uriVec.empty()) {
        MEDIA_LOGE("uriList is empty");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    OHOS::Media::SystemSoundError errCode = OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM;
    std::vector<std::tuple<std::string, int64_t, OHOS::Media::SystemSoundError>> openToneResultArray;
    if (sysSoundMgrClient_ != nullptr) {
        openToneResultArray = sysSoundMgrClient_->OpenToneList(uriVec, errCode);
    }
    MEDIA_LOGI("OpenToneList errCode = %{public}d", static_cast<int>(errCode));
    if (errCode == OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM) {
        CommonTaihe::ThrowError(OHOS::Media::SystemSoundError::ERROR_INVALID_PARAM, TAIHE_ERR_URILIST_OVER_LIMIT_INFO);
        return ::taihe::array<uintptr_t>(results);
    }

    ani_object aniObjectTuple3 {};
    int32_t systemSoundErrorIndex = 0;
    for (const auto& openToneResult : openToneResultArray) {
        if (ANI_OK != GetAniIndexByValue(env, std::get<PARAM2>(openToneResult), systemSoundErrorIndex)) {
            MEDIA_LOGE("GetAniIndexByValue failed");
            CommonTaihe::ThrowError(TAIHE_ERR_SYSTEM, TAIHE_ERR_SYSTEM_INFO);
            return ::taihe::array<uintptr_t>(results);
        }
        aniObjectTuple3 = GetAniObjectTuple3(env, std::get<PARAM0>(openToneResult).c_str(),
            std::get<PARAM1>(openToneResult), systemSoundErrorIndex);
        results.push_back(reinterpret_cast<uintptr_t>(aniObjectTuple3));
    }
    return ::taihe::array<uintptr_t>(results);
}
} // namespace ANI::Media