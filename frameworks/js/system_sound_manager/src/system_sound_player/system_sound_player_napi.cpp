/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "system_sound_player_napi.h"

#include "common_napi.h"
#include "system_sound_log.h"

namespace {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t ARGS_ONE = 1;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundPlayerNapi"};
}

namespace OHOS {
namespace Media {
thread_local napi_ref SystemSoundPlayerNapi::g_constructor = nullptr;
thread_local napi_ref SystemSoundPlayerNapi::g_systemSoundType = nullptr;
std::shared_ptr<SystemSoundPlayer> SystemSoundPlayerNapi::g_systemSoundPlayer = nullptr;

SystemSoundPlayerNapi::SystemSoundPlayerNapi() : env_(nullptr) {}

SystemSoundPlayerNapi::~SystemSoundPlayerNapi() = default;

napi_value SystemSoundPlayerNapi::CreateSystemSoundPlayerNapiInstance(napi_env env,
    std::shared_ptr<SystemSoundPlayer> systemSoundPlayer)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, g_constructor, &ctor);
    if (status == napi_ok) {
        g_systemSoundPlayer = systemSoundPlayer;
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            MEDIA_LOGE("CreateSystemSoundPlayerNapiInstance: New instance could not be obtained.");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

bool SystemSoundPlayerNapi::IsSystemSoundTypeValid(int32_t systemSoundType)
{
    return systemSoundType >= PHOTO_SHUTTER && systemSoundType <= VIDEO_RECORDING_END;
}

napi_status SystemSoundPlayerNapi::DefineClassProperties(napi_env env, napi_value &ctorObj)
{
    napi_property_descriptor system_sound_player_prop[] = {
        DECLARE_NAPI_FUNCTION("load", Load),
        DECLARE_NAPI_FUNCTION("play", Play),
        DECLARE_NAPI_FUNCTION("unload", Unload),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    return napi_define_class(env, g_SYSTEM_SOUND_PLAYER_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
        Construct, nullptr, sizeof(system_sound_player_prop) / sizeof(system_sound_player_prop[0]),
        system_sound_player_prop, &ctorObj);
}

napi_value SystemSoundPlayerNapi::Init(napi_env env, napi_value exports)
{
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_status status = DefineClassProperties(env, ctorObj);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_create_reference(env, ctorObj, refCount, &g_constructor);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env, exports, g_SYSTEM_SOUND_PLAYER_NAPI_CLASS_NAME.c_str(), ctorObj);
    if (status != napi_ok) {
        return nullptr;
    }

    return exports;
}

napi_value SystemSoundPlayerNapi::Construct(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SystemSoundPlayerNapi> obj = std::make_unique<SystemSoundPlayerNapi>();
        if (obj != nullptr) {
            ObjectRefMap<SystemSoundPlayerNapi>::Insert(obj.get());
            obj->env_ = env;
            if (obj->g_systemSoundPlayer != nullptr) {
                obj->systemSoundPlayer_ = std::move(obj->g_systemSoundPlayer);
            } else {
                MEDIA_LOGE("Failed to create g_systemSoundPlayer instance.");
                return result;
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                SystemSoundPlayerNapi::Destructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                ObjectRefMap<SystemSoundPlayerNapi>::Erase(obj.get());
                MEDIA_LOGE("Failed to wrap the native SystemSoundPlayer object with JS.");
            }
        }
    }

    return result;
}

void SystemSoundPlayerNapi::Destructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    SystemSoundPlayerNapi *systemSoundPlayer = reinterpret_cast<SystemSoundPlayerNapi*>(nativeObject);
    if (systemSoundPlayer != nullptr) {
        ObjectRefMap<SystemSoundPlayerNapi>::DecreaseRef(systemSoundPlayer);
    }
}

napi_value SystemSoundPlayerNapi::Load(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Load: napi_get_cb_info failed");

    std::unique_ptr<SystemSoundPlayerAsyncContext> asyncContext = std::make_unique<SystemSoundPlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Load: napi_unwrap failed or objectInfo is nullptr");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argc == ARGS_ONE,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Load: invalid number of arguments");

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && valueType == napi_number,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Load: type mismatch");
    napi_get_value_int32(env, argv[0], &asyncContext->systemSoundType);
    CHECK_AND_RETURN_RET_LOG(IsSystemSoundTypeValid(asyncContext->systemSoundType),
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Load: the SystemSoundType value is invalid!");

    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "Load", NAPI_AUTO_LENGTH, &resource);

    status = napi_create_async_work(env, nullptr, resource, AsyncLoad, CommonAsyncComplete,
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return result;
}

void SystemSoundPlayerNapi::AsyncLoad(napi_env env, void *data)
{
    SystemSoundPlayerAsyncContext *context = static_cast<SystemSoundPlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemSoundPlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemSoundPlayer = objectGuard.GetPtr();

    if (napiSystemSoundPlayer == nullptr || napiSystemSoundPlayer->systemSoundPlayer_ == nullptr) {
        MEDIA_LOGE("The system sound player is nullptr!");
        context->status = SSP_ERROR;
        context->errCode = ERRCODE_SYSTEM_ERROR;
        context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        return;
    }

    SystemSoundType systemSoundType = static_cast<SystemSoundType>(context->systemSoundType);
    int32_t result = napiSystemSoundPlayer->systemSoundPlayer_->Load(systemSoundType);
    if (result == SSP_SUCCESS) {
        context->status = SSP_SUCCESS;
    } else {
        context->status = SSP_ERROR;
        if (result == ERRCODE_IO_ERROR) {
            context->errCode = ERRCODE_IO_ERROR;
            context->errMessage = ERRCODE_IO_ERROR_INFO;
        } else if (result == ERRCODE_INVALID_PARAM) {
            context->errCode = ERRCODE_INVALID_PARAM;
            context->errMessage = ERRCODE_INVALID_PARAM_INFO;
        } else {
            context->errCode = ERRCODE_SYSTEM_ERROR;
            context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        }
    }
}

napi_value SystemSoundPlayerNapi::Play(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Play: napi_get_cb_info failed");

    std::unique_ptr<SystemSoundPlayerAsyncContext> asyncContext = std::make_unique<SystemSoundPlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Play: napi_unwrap failed or objectInfo is nullptr");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argc == ARGS_ONE,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Play: invalid number of arguments");

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && valueType == napi_number,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Play: type mismatch");
    napi_get_value_int32(env, argv[0], &asyncContext->systemSoundType);
    CHECK_AND_RETURN_RET_LOG(IsSystemSoundTypeValid(asyncContext->systemSoundType),
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Play: the SystemSoundType value is invalid!");

    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "Play", NAPI_AUTO_LENGTH, &resource);

    status = napi_create_async_work(env, nullptr, resource, AsyncPlay, CommonAsyncComplete,
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return result;
}

void SystemSoundPlayerNapi::AsyncPlay(napi_env env, void *data)
{
    SystemSoundPlayerAsyncContext *context = static_cast<SystemSoundPlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemSoundPlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemSoundPlayer = objectGuard.GetPtr();

    if (napiSystemSoundPlayer == nullptr || napiSystemSoundPlayer->systemSoundPlayer_ == nullptr) {
        MEDIA_LOGE("The system sound player is nullptr!");
        context->status = SSP_ERROR;
        context->errCode = ERRCODE_SYSTEM_ERROR;
        context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        return;
    }

    SystemSoundType systemSoundType = static_cast<SystemSoundType>(context->systemSoundType);
    int32_t result = napiSystemSoundPlayer->systemSoundPlayer_->Play(systemSoundType);
    if (result == SSP_SUCCESS) {
        context->status = SSP_SUCCESS;
    } else {
        context->status = SSP_ERROR;
        if (result == ERRCODE_IO_ERROR) {
            context->errCode = ERRCODE_IO_ERROR;
            context->errMessage = ERRCODE_IO_ERROR_INFO;
        } else if (result == ERRCODE_INVALID_PARAM) {
            context->errCode = ERRCODE_INVALID_PARAM;
            context->errMessage = ERRCODE_INVALID_PARAM_INFO;
        } else {
            context->errCode = ERRCODE_SYSTEM_ERROR;
            context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        }
    }
}

napi_value SystemSoundPlayerNapi::Unload(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Unload: napi_get_cb_info failed");

    std::unique_ptr<SystemSoundPlayerAsyncContext> asyncContext = std::make_unique<SystemSoundPlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Unload: napi_unwrap failed or objectInfo is nullptr");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && argc == ARGS_ONE,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Unload: invalid number of arguments");

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && valueType == napi_number,
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Unload: type mismatch");
    napi_get_value_int32(env, argv[0], &asyncContext->systemSoundType);
    CHECK_AND_RETURN_RET_LOG(IsSystemSoundTypeValid(asyncContext->systemSoundType),
        ThrowErrorAndReturn(env, ERRCODE_INVALID_PARAM_INFO, ERRCODE_INVALID_PARAM),
        "Unload: the SystemSoundType value is invalid!");

    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "Unload", NAPI_AUTO_LENGTH, &resource);

    status = napi_create_async_work(env, nullptr, resource, AsyncUnload, CommonAsyncComplete,
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return result;
}

void SystemSoundPlayerNapi::AsyncUnload(napi_env env, void *data)
{
    SystemSoundPlayerAsyncContext *context = static_cast<SystemSoundPlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemSoundPlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemSoundPlayer = objectGuard.GetPtr();

    if (napiSystemSoundPlayer == nullptr || napiSystemSoundPlayer->systemSoundPlayer_ == nullptr) {
        MEDIA_LOGE("The system sound player is nullptr!");
        context->status = SSP_ERROR;
        context->errCode = ERRCODE_SYSTEM_ERROR;
        context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        return;
    }

    SystemSoundType systemSoundType = static_cast<SystemSoundType>(context->systemSoundType);
    int32_t result = napiSystemSoundPlayer->systemSoundPlayer_->Unload(systemSoundType);
    if (result == SSP_SUCCESS) {
        context->status = SSP_SUCCESS;
    } else {
        context->status = SSP_ERROR;
        if (result == ERRCODE_INVALID_PARAM) {
            context->errCode = ERRCODE_INVALID_PARAM;
            context->errMessage = ERRCODE_INVALID_PARAM_INFO;
        } else {
            context->errCode = ERRCODE_SYSTEM_ERROR;
            context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        }
    }
}

napi_value SystemSoundPlayerNapi::Release(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Release: napi_get_cb_info failed");

    std::unique_ptr<SystemSoundPlayerAsyncContext> asyncContext = std::make_unique<SystemSoundPlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr,
        ThrowErrorAndReturn(env, ERRCODE_SYSTEM_ERROR_INFO, ERRCODE_SYSTEM_ERROR),
        "Release: napi_unwrap failed or objectInfo is nullptr");

    napi_create_promise(env, &asyncContext->deferred, &result);
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "Release", NAPI_AUTO_LENGTH, &resource);

    status = napi_create_async_work(env, nullptr, resource, AsyncRelease, CommonAsyncComplete,
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return result;
}

void SystemSoundPlayerNapi::AsyncRelease(napi_env env, void *data)
{
    SystemSoundPlayerAsyncContext *context = static_cast<SystemSoundPlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemSoundPlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemSoundPlayer = objectGuard.GetPtr();

    if (napiSystemSoundPlayer == nullptr || napiSystemSoundPlayer->systemSoundPlayer_ == nullptr) {
        MEDIA_LOGE("The system sound player is nullptr!");
        context->status = SSP_ERROR;
        context->errCode = ERRCODE_SYSTEM_ERROR;
        context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
        return;
    }

    int32_t result = napiSystemSoundPlayer->systemSoundPlayer_->Release();
    if (result == SSP_SUCCESS) {
        context->status = SSP_SUCCESS;
    } else {
        context->status = SSP_ERROR;
        context->errCode = ERRCODE_SYSTEM_ERROR;
        context->errMessage = ERRCODE_SYSTEM_ERROR_INFO;
    }
}

void SystemSoundPlayerNapi::CommonAsyncComplete(napi_env env, napi_status status, void* data)
{
    SystemSoundPlayerAsyncContext *context = static_cast<SystemSoundPlayerAsyncContext *>(data);
    napi_value result[2] = {};
    napi_get_undefined(env, &result[PARAM1]);
    if (context->status == SSP_SUCCESS) {
        napi_get_undefined(env, &result[PARAM0]);
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

napi_value SystemSoundPlayerNapi::ThrowErrorAndReturn(napi_env env, const std::string& errMsg, int32_t errCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value errVal = nullptr;
    napi_value errNameVal = nullptr;
    napi_value result{};
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &errVal);
    napi_create_int32(env, errCode, &code);
    napi_set_named_property(env, errVal, "code", code);
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &errNameVal);
    napi_set_named_property(env, errVal, "BusinessError", errNameVal);
    napi_throw(env, errVal);
    napi_get_undefined(env, &result);
    return result;
}

napi_value SystemSoundPlayerNapi::AsyncThrowErrorAndReturn(napi_env env, const std::string& errMsg, int32_t errCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value errVal = nullptr;
    napi_value errNameVal = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &errVal);
    napi_create_int32(env, errCode, &code);
    napi_set_named_property(env, errVal, "code", code);
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &errNameVal);
    napi_set_named_property(env, errVal, "BusinessError", errNameVal);
    return errVal;
}
} // namespace Media
} // namespace OHOS