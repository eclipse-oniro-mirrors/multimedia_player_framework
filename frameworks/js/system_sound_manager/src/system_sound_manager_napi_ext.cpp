/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "system_sound_manager_napi.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "audio_renderer_info_napi.h"
#include "ipc_skeleton.h"
#include "system_sound_log.h"
#include "tokenid_kit.h"

using namespace std;
using OHOS::Security::AccessToken::AccessTokenKit;

namespace {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

/* Constants for array size */
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t SIZE = 1024;

const int UNSUPPORTED_ERROR = -5;
const int OPERATION_ERROR = -4;
const int IO_ERROR = -3;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundManagerNapi"};
}

namespace OHOS {
namespace Media {
napi_value SystemSoundManagerNapi::GetToneHapticsSettings(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO,
        NAPI_ERR_PERMISSION_DENIED), "No system permission");
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value thisVar = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {};

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok && thisVar != nullptr), result,
        "GetToneHapticsSettings: Failed to retrieve details about the callback");
    CHECK_AND_RETURN_RET_LOG(argc == ARGS_TWO, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO,
        NAPI_ERR_INPUT_INVALID), "invalid arguments");
    std::unique_ptr<SystemSoundManagerAsyncContext> asyncContext = std::make_unique<SystemSoundManagerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "GetToneHapticsSettings: Failed to unwrap object");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            asyncContext->abilityContext_ = GetAbilityContext(env, argv[i]);
        } else if (i == PARAM1 && valueType == napi_number) {
            napi_get_value_int32(env, argv[PARAM1], &asyncContext->toneHapticsType);
            asyncContext->toneHapticsType = asyncContext->toneHapticsType;
        }
    }
    MEDIA_LOGI("GetToneHapticsSettings toneHapticsType : %{public}d", asyncContext->toneHapticsType);
    CHECK_AND_RETURN_RET_LOG(asyncContext->abilityContext_ != nullptr,
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO, NAPI_ERR_INPUT_INVALID), "invalid arguments");
    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_create_string_utf8(env, "GetToneHapticsSettings", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncGetToneHapticsSettings,
        GetToneHapticsSettingsAsyncCallbackComp, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_LOGE("GetToneHapticsSettings: Failed to get create async work");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemSoundManagerNapi::AsyncGetToneHapticsSettings(napi_env env, void *data)
{
    SystemSoundManagerAsyncContext *context = static_cast<SystemSoundManagerAsyncContext *>(data);
    if (context->objectInfo->sysSoundMgrClient_ == nullptr) {
        return;
    }
    int32_t result = context->objectInfo->sysSoundMgrClient_->GetToneHapticsSettings(context->abilityContext_,
        static_cast<ToneHapticsType>(context->toneHapticsType), context->toneHapticsSettings);
    context->status = result;
    if (result == IO_ERROR) {
        context->errCode = NAPI_ERR_IO_ERROR;
        context->errMessage = NAPI_ERR_IO_ERROR_INFO;
    } else if (result == UNSUPPORTED_ERROR) {
        context->errCode = NAPI_ERR_UNSUPPORTED_OPERATION;
        context->errMessage = NAPI_ERR_UNSUPPORTED_OPERATION_INFO;
    }
}

void SystemSoundManagerNapi::GetToneHapticsSettingsAsyncCallbackComp(napi_env env, napi_status status,
    void *data)
{
    auto context = static_cast<SystemSoundManagerAsyncContext *>(data);
    napi_value result[2] = {};

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        context->status = ToneHapticsSettingsNapi::NewInstance(env, context->toneHapticsSettings, result[PARAM1]);
    } else {
        result[PARAM0] = AsyncThrowErrorAndReturn(env, context->errMessage, context->errCode);
        napi_get_undefined(env, &result[PARAM1]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

std::string SystemSoundManagerNapi::ExtractStringToEnv(const napi_env &env, const napi_value &argv)
{
    char buffer[SIZE] = {0};
    size_t res = 0;
    napi_get_value_string_utf8(env, argv, buffer, SIZE, &res);
    return std::string(buffer);
}

void SystemSoundManagerNapi::GetToneHapticsSettingsToEnv(const napi_env &env, const napi_value &argv,
    ToneHapticsSettings &toneHapticsSettings)
{
    napi_value property = nullptr;
    char buffer[SIZE] = {0};
    size_t res = 0;
    int32_t mode = 0;

    if (napi_get_named_property(env, argv, "mode", &property) == napi_ok) {
        napi_get_value_int32(env, property, &mode);
        toneHapticsSettings.mode = static_cast<ToneHapticsMode>(mode);
    }
    if (napi_get_named_property(env, argv, "hapticsUri", &property) == napi_ok) {
        napi_get_value_string_utf8(env, property, buffer, SIZE, &res);
        toneHapticsSettings.hapticsUri = std::string(buffer);
    }
}

napi_value SystemSoundManagerNapi::SetToneHapticsSettings(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO,
        NAPI_ERR_PERMISSION_DENIED), "No system permission");
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value thisVar = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result,
        "SetToneHapticsSettings: get_cb_info failed");
    CHECK_AND_RETURN_RET_LOG(argc == ARGS_THREE, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO,
        NAPI_ERR_INPUT_INVALID), "invalid arguments");
    std::unique_ptr<SystemSoundManagerAsyncContext> asyncContext = std::make_unique<SystemSoundManagerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "SetToneHapticsSettings: Failed to unwrap object");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            asyncContext->abilityContext_ = GetAbilityContext(env, argv[i]);
        } else if (i == PARAM1 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &asyncContext->toneHapticsType);
            asyncContext->toneHapticsType = asyncContext->toneHapticsType;
        } else if (i == PARAM2 && valueType == napi_object) {
            GetToneHapticsSettingsToEnv(env, argv[PARAM2], asyncContext->toneHapticsSettings);
        }
    }
    MEDIA_LOGI("SetToneHapticsSettings toneHapticsType : %{public}d mode : %{public}d", asyncContext->toneHapticsType,
        asyncContext->toneHapticsSettings.mode);
    CHECK_AND_RETURN_RET_LOG(asyncContext->abilityContext_ != nullptr,
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO, NAPI_ERR_INPUT_INVALID), "invalid arguments");
    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_create_string_utf8(env, "SetToneHapticsSettings", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncSetToneHapticsSettings,
        SetToneHapticsSettingsAsyncCallbackComp, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_LOGE("SetToneHapticsSettings: Failed to get create async work");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemSoundManagerNapi::AsyncSetToneHapticsSettings(napi_env env, void *data)
{
    SystemSoundManagerAsyncContext *context = static_cast<SystemSoundManagerAsyncContext *>(data);
    if (context->objectInfo->sysSoundMgrClient_ == nullptr) {
        return;
    }
    int32_t result = context->objectInfo->sysSoundMgrClient_->SetToneHapticsSettings(context->abilityContext_,
        static_cast<ToneHapticsType>(context->toneHapticsType), context->toneHapticsSettings);
    context->status = result;
    if (result == OPERATION_ERROR) {
        context->errCode = NAPI_ERR_OPERATE_NOT_ALLOWED;
        context->errMessage = NAPI_ERR_OPERATE_NOT_ALLOWED_INFO;
    } else if (result == IO_ERROR) {
        context->errCode = NAPI_ERR_IO_ERROR;
        context->errMessage = NAPI_ERR_IO_ERROR_INFO;
    } else if (result == UNSUPPORTED_ERROR) {
        context->errCode = NAPI_ERR_UNSUPPORTED_OPERATION;
        context->errMessage = NAPI_ERR_UNSUPPORTED_OPERATION_INFO;
    }
}

void SystemSoundManagerNapi::SetToneHapticsSettingsAsyncCallbackComp(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemSoundManagerAsyncContext *>(data);
    napi_value result[2] = {};

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
    } else {
        result[PARAM0] = AsyncThrowErrorAndReturn(env, context->errMessage, context->errCode);
        napi_get_undefined(env, &result[PARAM1]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

napi_value SystemSoundManagerNapi::GetToneHapticsList(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO,
        NAPI_ERR_PERMISSION_DENIED), "No system permission");
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value thisVar = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok && thisVar != nullptr), result,
        "GetToneHapticsList: Failed to retrieve details about the callback");
    CHECK_AND_RETURN_RET_LOG(argc == ARGS_TWO, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO,
        NAPI_ERR_INPUT_INVALID), "invalid arguments");
    std::unique_ptr<SystemSoundManagerAsyncContext> asyncContext = std::make_unique<SystemSoundManagerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "GetToneHapticsList: Failed to unwrap object");
    for (size_t i = PARAM0; i < argc; i ++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            asyncContext->abilityContext_ = GetAbilityContext(env, argv[i]);
        } else if (i == PARAM1 && valueType == napi_boolean) {
            napi_get_value_bool(env, argv[i], &asyncContext->isSynced);
        }
    }
    MEDIA_LOGI("GetToneHapticsList isSynced : %{public}s", asyncContext->isSynced ? "true" : "false");
    CHECK_AND_RETURN_RET_LOG(asyncContext->abilityContext_ != nullptr,
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO, NAPI_ERR_INPUT_INVALID), "Parameter error");
    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_create_string_utf8(env, "GetToneHapticsList", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncGetToneHapticsList,
        GetToneHapticsListAsyncCallbackComp, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to get create async work");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemSoundManagerNapi::AsyncGetToneHapticsList(napi_env env, void *data)
{
    SystemSoundManagerAsyncContext *context = static_cast<SystemSoundManagerAsyncContext *>(data);
    if (context->objectInfo->sysSoundMgrClient_ == nullptr) {
        return;
    }
    int32_t result = context->objectInfo->sysSoundMgrClient_->GetToneHapticsList(context->abilityContext_,
        context->isSynced, context->toneHapticsAttrsArray);
    context->status = result;
    if (result == IO_ERROR) {
        context->errCode = NAPI_ERR_IO_ERROR;
        context->errMessage = NAPI_ERR_IO_ERROR_INFO;
    } else if (result == UNSUPPORTED_ERROR) {
        context->errCode = NAPI_ERR_UNSUPPORTED_OPERATION;
        context->errMessage = NAPI_ERR_UNSUPPORTED_OPERATION_INFO;
    }
}

void SystemSoundManagerNapi::GetToneHapticsListAsyncCallbackComp(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemSoundManagerAsyncContext *>(data);
    napi_value result[2] = {};
    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        context->status = napi_create_array_with_length(env, context->toneHapticsAttrsArray.size(), &result[PARAM1]);
        size_t count = 0;
        for (auto &toneHapticsAttrs : context->toneHapticsAttrsArray) {
            napi_value jsToneHapticsAttrs = nullptr;
            ToneHapticsAttrsNapi::NewInstance(env, toneHapticsAttrs, jsToneHapticsAttrs);
            context->status = napi_set_element(env, result[PARAM1], count, jsToneHapticsAttrs);
            count++;
        }
    } else {
        result[PARAM0] = AsyncThrowErrorAndReturn(env, context->errMessage, context->errCode);
        napi_get_undefined(env, &result[PARAM1]);
    }
    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

napi_value SystemSoundManagerNapi::GetHapticsAttrsSyncedWithTone(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO,
        NAPI_ERR_PERMISSION_DENIED), "No system permission");
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value thisVar = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {};
    char buffer[SIZE];
    size_t res = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok && thisVar != nullptr), result,
        "GetHapticsAttrsSyncedWithTone: Failed to retrieve details about the callback");
    CHECK_AND_RETURN_RET_LOG(argc == ARGS_TWO, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO,
        NAPI_ERR_INPUT_INVALID), "invalid arguments");
    std::unique_ptr<SystemSoundManagerAsyncContext> asyncContext = std::make_unique<SystemSoundManagerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "GetHapticsAttrsSyncedWithTone: Failed to unwrap object");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            asyncContext->abilityContext_ = GetAbilityContext(env, argv[i]);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, SIZE, &res);
            asyncContext->toneUri = std::string(buffer);
        }
    }
    MEDIA_LOGI("GetHapticsAttrsSyncedWithTone toneUri : %{public}s", asyncContext->toneUri.c_str());
    CHECK_AND_RETURN_RET_LOG(asyncContext->abilityContext_ != nullptr,
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO, NAPI_ERR_INPUT_INVALID), "invalid arguments");
    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_create_string_utf8(env, "GetHapticsAttrsSyncedWithTone", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncGetHapticsAttrsSyncedWithTone,
        GetHapticsAttrsSyncedWithToneAsyncCallbackComp, static_cast<void*>(asyncContext.get()),
        &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone : Failed to get create async work");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemSoundManagerNapi::AsyncGetHapticsAttrsSyncedWithTone(napi_env env, void *data)
{
    SystemSoundManagerAsyncContext *context = static_cast<SystemSoundManagerAsyncContext *>(data);
    if (context->objectInfo->sysSoundMgrClient_ == nullptr) {
        return;
    }
    int32_t result = context->objectInfo->sysSoundMgrClient_->GetHapticsAttrsSyncedWithTone(context->abilityContext_,
        context->toneUri, context->toneHapticsAttrs);
    context->status = result;
    if (result == OPERATION_ERROR) {
        context->errCode = NAPI_ERR_OPERATE_NOT_ALLOWED;
        context->errMessage = NAPI_ERR_OPERATE_NOT_ALLOWED_INFO;
    } else if (result == IO_ERROR) {
        context->errCode = NAPI_ERR_IO_ERROR;
        context->errMessage = NAPI_ERR_IO_ERROR_INFO;
    } else if (result == UNSUPPORTED_ERROR) {
        context->errCode = NAPI_ERR_UNSUPPORTED_OPERATION;
        context->errMessage = NAPI_ERR_UNSUPPORTED_OPERATION_INFO;
    }
}

void SystemSoundManagerNapi::GetHapticsAttrsSyncedWithToneAsyncCallbackComp(napi_env env, napi_status status,
    void *data)
{
    auto context = static_cast<SystemSoundManagerAsyncContext *>(data);
    napi_value result[2] = {};

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        ToneHapticsAttrsNapi::NewInstance(env, context->toneHapticsAttrs, result[PARAM1]);
    } else {
        result[PARAM0] = AsyncThrowErrorAndReturn(env, context->errMessage, context->errCode);
        napi_get_undefined(env, &result[PARAM1]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}


napi_value SystemSoundManagerNapi::OpenToneHaptics(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value thisVar = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {};
    char buffer[SIZE];
    size_t res = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok && thisVar != nullptr), result,
        "OpenToneHaptics: Failed to retrieve details about the callback");
    CHECK_AND_RETURN_RET_LOG(argc == ARGS_TWO, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO,
        NAPI_ERR_INPUT_INVALID), "invalid arguments");
    std::unique_ptr<SystemSoundManagerAsyncContext> asyncContext = std::make_unique<SystemSoundManagerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "OpenToneHaptics: Failed to unwrap object");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            asyncContext->abilityContext_ = GetAbilityContext(env, argv[i]);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, SIZE, &res);
            asyncContext->hapticsUri = std::string(buffer);
        }
    }
    MEDIA_LOGI("OpenToneHaptics hapticsUri : %{public}s", asyncContext->hapticsUri.c_str());
    CHECK_AND_RETURN_RET_LOG(asyncContext->abilityContext_ != nullptr,
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID_INFO, NAPI_ERR_INPUT_INVALID), "invalid arguments");
    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_create_string_utf8(env, "OpenToneHaptics", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncOpenToneHaptics,
        OpenToneHapticsAsyncCallbackComp, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_LOGE("OpenToneHaptics : Failed to get create async work");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemSoundManagerNapi::AsyncOpenToneHaptics(napi_env env, void *data)
{
    SystemSoundManagerAsyncContext *context = static_cast<SystemSoundManagerAsyncContext *>(data);
    if (context->objectInfo->sysSoundMgrClient_ == nullptr) {
        return;
    }
    int32_t result = context->objectInfo->sysSoundMgrClient_->OpenToneHaptics(context->abilityContext_,
        context->hapticsUri);
    context->fd = result;
    context->status = context->fd <= 0;
    if (result == OPERATION_ERROR) {
        context->errCode = NAPI_ERR_OPERATE_NOT_ALLOWED;
        context->errMessage = NAPI_ERR_OPERATE_NOT_ALLOWED_INFO;
    } else if (result == IO_ERROR) {
        context->errCode = NAPI_ERR_IO_ERROR;
        context->errMessage = NAPI_ERR_IO_ERROR_INFO;
    } else if (result == UNSUPPORTED_ERROR) {
        context->errCode = NAPI_ERR_UNSUPPORTED_OPERATION;
        context->errMessage = NAPI_ERR_UNSUPPORTED_OPERATION_INFO;
    }
}

void SystemSoundManagerNapi::OpenToneHapticsAsyncCallbackComp(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemSoundManagerAsyncContext *>(data);
    napi_value result[2] = {};
    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_int32(env, context->fd, &result[PARAM1]);
    } else {
        result[PARAM0] = AsyncThrowErrorAndReturn(env, context->errMessage, context->errCode);
        napi_get_undefined(env, &result[PARAM1]);
    }
    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    }
    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}
} // namespace Media
} // namespace OHOS
