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

#include <thread>
#include "common_taihe.h"
#include "ringtone_player_taihe.h"
#include "system_sound_log.h"
#include "tone_attrs_taihe.h"

namespace {
/* Constants for tone type */
const int32_t CARD_0 = 0;
const int32_t CARD_1 = 1;
const int32_t SYSTEM_NOTIFICATION = 32;

const int TYPEERROR = -2;
const int ERROR = -1;

const std::string ERR_URI = "";
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerTaihe"};
}

using namespace ANI::Media;

namespace ANI::Media {
std::shared_ptr<OHOS::AbilityRuntime::Context> SystemSoundManagerImpl::GetAbilityContext(
    ani_env* env, uintptr_t contextArg)
{
    MEDIA_LOGI("SystemSoundManagerTaihe::GetAbilityContext");

    MEDIA_LOGI("GetAbilityContext: Getting context with stage model");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, reinterpret_cast<ani_object>(contextArg));
    CHECK_AND_RETURN_RET_LOG(context != nullptr, nullptr, "Failed to obtain ability in STAGE mode");
    return context;
}

array<ToneAttrsTaihe> SystemSoundManagerImpl::ReturnErrToneAttrsTaiheArray()
{
    std::vector<ToneAttrsTaihe> emptyVec;
    return array<ToneAttrsTaihe>(emptyVec);
}

array<ToneAttrsTaihe> SystemSoundManagerImpl::ToToneAttrsTaiheArray(
    std::vector<std::shared_ptr<OHOS::Media::ToneAttrs>> &src)
{
    std::vector<ToneAttrsTaihe> vec;
    for (auto &item : src) {
        ToneAttrsTaihe toneAttrsTaihe = make_holder<ToneAttrsImpl, ToneAttrsTaihe>(ToneAttrsImpl(item));
        vec.emplace_back(toneAttrsTaihe);
    }
    return array<ToneAttrsTaihe>(vec);
}

bool SystemSoundManagerImpl::CheckResultUriAndThrowError(std::string uri)
{
    std::string result = "TYPEERROR";
    if (uri == result) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO);
        return false;
    } else if (uri.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    }
    return true;
}

SystemSoundManagerImpl::SystemSoundManagerImpl() : sysSoundMgrClient_(nullptr) {}

SystemSoundManagerImpl::SystemSoundManagerImpl(std::unique_ptr<SystemSoundManagerImpl> obj)
{
    if (obj != nullptr) {
        sysSoundMgrClient_ = obj->sysSoundMgrClient_;
    }
}

SystemSoundManagerImpl::~SystemSoundManagerImpl() = default;

string SystemSoundManagerImpl::GetSystemToneUriSync(uintptr_t context, SystemToneTypeTaihe type)
{
    auto abilityContext = GetAbilityContext(get_env(), context);
    int32_t systemToneType = type.get_value();
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }
    std::string uri = sysSoundMgrClient_->GetSystemToneUri(
        abilityContext, static_cast<OHOS::Media::SystemToneType>(systemToneType));
    return uri;
}

::systemTonePlayer::SystemTonePlayer SystemSoundManagerImpl::GetSystemTonePlayerSync(uintptr_t context,
    SystemToneTypeTaihe type)
{
    auto abilityContext = GetAbilityContext(get_env(), context);
    int32_t systemToneType = type.get_value();
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<SystemTonePlayerImpl, ::systemTonePlayer::SystemTonePlayer>();
    }
    std::shared_ptr<OHOS::Media::SystemTonePlayer> systemTonePlayer = sysSoundMgrClient_->GetSystemTonePlayer(
        abilityContext, static_cast<OHOS::Media::SystemToneType>(systemToneType));
    if (systemTonePlayer == nullptr) {
        MEDIA_LOGE("Failed to get system tone player!");
        CommonTaihe::ThrowError("GetSystemTonePlayer Error: Operation is not supported or failed");
        return make_holder<SystemTonePlayerImpl, ::systemTonePlayer::SystemTonePlayer>();
    }
    return SystemTonePlayerImpl::GetSystemTonePlayerInstance(systemTonePlayer);
}

void SystemSoundManagerImpl::CloseSync(int32_t fd)
{
    CHECK_AND_RETURN_RET_LOG(CommonTaihe::VerifySelfSystemPermission(),
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO), "No system permission");

    CHECK_AND_RETURN_RET_LOG(static_cast<int32_t>(fd) > 0,
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO), "invalid arguments");

    CHECK_AND_RETURN_RET(sysSoundMgrClient_ != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));

    if (sysSoundMgrClient_->Close(fd)) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    }
}

ToneAttrsTaihe SystemSoundManagerImpl::GetDefaultRingtoneAttrsSync(uintptr_t context, RingtoneTypeTaihe type)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t typeInner = type.get_value();
    if (abilityContext == nullptr && (typeInner != CARD_0 || typeInner != CARD_1)) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    auto toneAttrs = sysSoundMgrClient_->GetDefaultRingtoneAttrs(
        abilityContext, static_cast<OHOS::Media::RingtoneType>(typeInner));
    if (toneAttrs == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    return make_holder<ToneAttrsImpl, ToneAttrsTaihe>(toneAttrs);
}

::taihe::array<ToneAttrsTaihe> SystemSoundManagerImpl::GetAlarmToneAttrListSync(uintptr_t context)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    auto toneAttrsArray = sysSoundMgrClient_->GetAlarmToneAttrList(abilityContext);
    if (toneAttrsArray.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    return ToToneAttrsTaiheArray(toneAttrsArray);
}

void SystemSoundManagerImpl::RemoveCustomizedToneSync(uintptr_t context, ::taihe::string_view uri)
{
    CHECK_AND_RETURN_RET_LOG(CommonTaihe::VerifyRingtonePermission(),
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO),
        "Permission denied");

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    CHECK_AND_RETURN_RET_LOG(abilityContext != nullptr && !std::string(uri).empty(),
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO), "invalid arguments");

    CHECK_AND_RETURN_RET(sysSoundMgrClient_ != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));

    int32_t result = sysSoundMgrClient_->RemoveCustomizedTone(abilityContext, std::string(uri));
    if (result == TYPEERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_OPERATE_NOT_ALLOWED, TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO);
    } else if (result == ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    }
}

::taihe::array<ToneAttrsTaihe> SystemSoundManagerImpl::GetSystemToneAttrListSync(
    uintptr_t context, SystemToneTypeTaihe type)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t systemToneType = type.get_value();
    if (abilityContext == nullptr ||
        !(systemToneType == CARD_0 || systemToneType == CARD_1 || systemToneType == SYSTEM_NOTIFICATION)) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    auto toneAttrsArray = sysSoundMgrClient_->GetAlarmToneAttrList(abilityContext);
    if (toneAttrsArray.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    }
    return ToToneAttrsTaiheArray(toneAttrsArray);
}

::taihe::string SystemSoundManagerImpl::AddCustomizedToneByUriSync(
    uintptr_t context, WeakToneAttrsTaihe toneAttr, ::taihe::string_view externalUri)
{
    if (!(CommonTaihe::VerifyRingtonePermission())) {
        MEDIA_LOGE("Permission denied");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ERR_URI;
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr || toneAttr.is_error()) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ERR_URI;
    }

    std::string externalUriInner = std::string(externalUri);
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }

    if (!externalUriInner.empty()) {
        std::string uri;
        ToneAttrsImpl* toneAttrsImplPtr = reinterpret_cast<ToneAttrsImpl*>(toneAttr->GetImplPtr());
        if (toneAttrsImplPtr == nullptr) {
            CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
            return ERR_URI;
        }
        uri = sysSoundMgrClient_->AddCustomizedToneByExternalUri(
            abilityContext, toneAttrsImplPtr->GetToneAttrs(), externalUriInner);
        if (!CheckResultUriAndThrowError(uri)) {
            return ERR_URI;
        }
        return uri;
    }

    CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    return ERR_URI;
}

::taihe::string SystemSoundManagerImpl::AddCustomizedToneByFdSync(
    uintptr_t context, WeakToneAttrsTaihe toneAttr, int32_t fd, ::taihe::optional_view<int64_t> offset,
    ::taihe::optional_view<int64_t> length)
{
    if (!(CommonTaihe::VerifyRingtonePermission())) {
        MEDIA_LOGE("Permission denied");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ERR_URI;
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr || toneAttr.is_error()) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ERR_URI;
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }
    if (static_cast<int32_t>(fd) > 0) {
        std::string uri;
        int32_t offsetInput = offset.value_or(0);
        int32_t lengthInput = length.value_or(0);
        ToneAttrsImpl* toneAttrsImplPtr = reinterpret_cast<ToneAttrsImpl*>(toneAttr->GetImplPtr());
        if (toneAttrsImplPtr == nullptr) {
            CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
            return ERR_URI;
        }
        if (offsetInput >= 0 && lengthInput >= 0) {
            OHOS::Media::ParamsForAddCustomizedTone paramsForAddCustomizedTone = { "", static_cast<int32_t>(fd),
                lengthInput, offsetInput, false };
            uri = sysSoundMgrClient_->AddCustomizedToneByFdAndOffset(
                abilityContext, toneAttrsImplPtr->GetToneAttrs(), paramsForAddCustomizedTone);
        } else if (offsetInput == 0 && lengthInput == 0) {
            uri = sysSoundMgrClient_->AddCustomizedToneByFd(
                abilityContext, toneAttrsImplPtr->GetToneAttrs(), static_cast<int32_t>(fd));
        }
        if (!CheckResultUriAndThrowError(uri)) {
            return ERR_URI;
        }
        return uri;
    }

    CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    return ERR_URI;
}

int32_t SystemSoundManagerImpl::OpenAlarmToneSync(uintptr_t context, ::taihe::string_view uri)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ERROR;
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ERROR;
    }
    if (sysSoundMgrClient_ == nullptr || std::string(uri).empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERROR;
    }

    int32_t fd = sysSoundMgrClient_->OpenAlarmTone(abilityContext, std::string(uri));
    if (fd == TYPEERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_URI_ERROR, TAIHE_ERR_URI_ERROR_INFO);
        return ERROR;
    } else if (fd == ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERROR;
    }
    return fd;
}

ToneAttrsTaihe SystemSoundManagerImpl::GetDefaultSystemToneAttrsSync(uintptr_t context, SystemToneTypeTaihe type)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t systemToneType = type.get_value();
    if (abilityContext == nullptr ||
        !(systemToneType == CARD_0 || systemToneType == CARD_1 || systemToneType == SYSTEM_NOTIFICATION)) {
        MEDIA_LOGE("Parameter error");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    std::shared_ptr<OHOS::Media::ToneAttrs> toneAttrs = sysSoundMgrClient_->GetDefaultSystemToneAttrs(
        abilityContext, static_cast<OHOS::Media::SystemToneType>(systemToneType));
    if (toneAttrs == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    return make_holder<ToneAttrsImpl, ToneAttrsTaihe>(toneAttrs);
}

::taihe::array<ToneAttrsTaihe> SystemSoundManagerImpl::GetRingtoneAttrListSync(
    uintptr_t context, RingtoneTypeTaihe type)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t typeInner = type.get_value();
    if (abilityContext == nullptr && (typeInner !=  CARD_0 || typeInner !=  CARD_1)) {
        MEDIA_LOGE("invalid arguments");
        return ReturnErrToneAttrsTaiheArray();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    auto toneAttrsArray = sysSoundMgrClient_->GetRingtoneAttrList(
        abilityContext, static_cast<OHOS::Media::RingtoneType>(typeInner));
    if (toneAttrsArray.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ReturnErrToneAttrsTaiheArray();
    }
    return ToToneAttrsTaiheArray(toneAttrsArray);
}

void SystemSoundManagerImpl::SetAlarmToneUriSync(uintptr_t context, ::taihe::string_view uri)
{
    CHECK_AND_RETURN_RET_LOG(CommonTaihe::VerifySelfSystemPermission(),
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO),
        "No system permission");

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    CHECK_AND_RETURN_RET_LOG(abilityContext != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO),
        "invalid arguments");
    CHECK_AND_RETURN_RET_NOLOG(sysSoundMgrClient_ != nullptr && !std::string(uri).empty(),
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));

    int32_t result = sysSoundMgrClient_->SetAlarmToneUri(abilityContext, std::string(uri));
    if (result == TYPEERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_URI_ERROR, TAIHE_ERR_URI_ERROR_INFO);
    } else if (result == ERROR) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
    }
}

::taihe::string SystemSoundManagerImpl::GetAlarmToneUriSync(uintptr_t context)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return ERR_URI;
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ERR_URI;
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }

    std::string uri = sysSoundMgrClient_->GetAlarmToneUri(abilityContext);
    if (uri.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }
    return uri;
}

ToneAttrsTaihe SystemSoundManagerImpl::GetDefaultAlarmToneAttrsSync(uintptr_t context)
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }

    std::shared_ptr<OHOS::Media::ToneAttrs> toneAttrs = sysSoundMgrClient_->GetDefaultAlarmToneAttrs(abilityContext);
    if (toneAttrs == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    return make_holder<ToneAttrsImpl, ToneAttrsTaihe>(toneAttrs);
}

void SystemSoundManagerImpl::SetSystemToneUriSync(uintptr_t context, ::taihe::string_view uri, SystemToneTypeTaihe type)
{
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    CHECK_AND_RETURN_RET_NOLOG(sysSoundMgrClient_ != nullptr,
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));
    CHECK_AND_RETURN_RET_NOLOG(!std::string(uri).empty(),
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO));

    sysSoundMgrClient_->SetSystemToneUri(
        abilityContext, std::string(uri), static_cast<OHOS::Media::SystemToneType>(type.get_value()));
}

::ringtonePlayer::RingtonePlayer SystemSoundManagerImpl::GetRingtonePlayerSync(
    uintptr_t context, RingtoneTypeTaihe type)
{
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t typeInner = type.get_value();
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return make_holder<RingtonePlayerImpl, ::ringtonePlayer::RingtonePlayer>();
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return make_holder<RingtonePlayerImpl, ::ringtonePlayer::RingtonePlayer>();
    }

    std::shared_ptr<OHOS::Media::RingtonePlayer> ringtonePlayer = sysSoundMgrClient_->GetRingtonePlayer(
        abilityContext, static_cast<OHOS::Media::RingtoneType>(typeInner));
    if (ringtonePlayer == nullptr) {
        CommonTaihe::ThrowError("GetRingtonePlayer Error: Operation is not supported or failed");
        return make_holder<RingtonePlayerImpl, ::ringtonePlayer::RingtonePlayer>();
    }
    return make_holder<RingtonePlayerImpl, ::ringtonePlayer::RingtonePlayer>(ringtonePlayer);
}

::taihe::string SystemSoundManagerImpl::GetRingtoneUriSync(uintptr_t context, RingtoneTypeTaihe type)
{
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t typeInner = type.get_value();
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return ERR_URI;
    }
    if (sysSoundMgrClient_ == nullptr) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return ERR_URI;
    }
    return sysSoundMgrClient_->GetRingtoneUri(abilityContext, static_cast<OHOS::Media::RingtoneType>(typeInner));
}

void SystemSoundManagerImpl::SetRingtoneUriSync(uintptr_t context, ::taihe::string_view uri, RingtoneTypeTaihe type)
{
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env(), context);
    int32_t typeInner = type.get_value();
    if (abilityContext == nullptr) {
        MEDIA_LOGE("invalid arguments");
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return;
    }
    if (sysSoundMgrClient_ == nullptr || std::string(uri).empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_IO_ERROR, TAIHE_ERR_IO_ERROR_INFO);
        return;
    }
    sysSoundMgrClient_->SetRingtoneUri(
        abilityContext, std::string(uri), static_cast<OHOS::Media::RingtoneType>(typeInner));
}

ToneAttrsTaihe CreateCustomizedToneAttrs()
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<ToneAttrsImpl, ToneAttrsTaihe>();
    }
    std::shared_ptr<OHOS::Media::ToneAttrs> nativeToneAttrs = std::make_shared<OHOS::Media::ToneAttrs>("default",
        "default", "default", OHOS::Media::CUSTOMISED, OHOS::Media::TONE_CATEGORY_INVALID);
    return make_holder<ToneAttrsImpl, ToneAttrsTaihe>(nativeToneAttrs);
}

SystemSoundManagerTaihe GetSystemSoundManager()
{
    if (!(CommonTaihe::VerifySelfSystemPermission())) {
        MEDIA_LOGE("No system permission");
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return make_holder<SystemSoundManagerImpl, SystemSoundManagerTaihe>();
    }
    std::unique_ptr<SystemSoundManagerImpl> obj = std::make_unique<SystemSoundManagerImpl>();
    if (obj != nullptr) {
        obj->sysSoundMgrClient_ = OHOS::Media::SystemSoundManagerFactory::CreateSystemSoundManager();
        if (obj->sysSoundMgrClient_ == nullptr) {
            MEDIA_LOGE("Failed to create sysSoundMgrClient_ instance.");
            return make_holder<SystemSoundManagerImpl, SystemSoundManagerTaihe>();
        }
        return make_holder<SystemSoundManagerImpl, SystemSoundManagerTaihe>(std::move(obj));
    }
    return make_holder<SystemSoundManagerImpl, SystemSoundManagerTaihe>();
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateCustomizedToneAttrs(CreateCustomizedToneAttrs);
TH_EXPORT_CPP_API_GetSystemSoundManager(GetSystemSoundManager);