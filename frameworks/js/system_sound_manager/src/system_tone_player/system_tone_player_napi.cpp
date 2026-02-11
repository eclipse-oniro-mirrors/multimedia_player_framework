/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "system_tone_player_napi.h"

#include "system_sound_log.h"
#include "common_napi.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "ringtone_common_napi.h"

namespace {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

/* Constants for array size */
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t ALL_STREAMID = 0;
const std::string PLAY_FINISHED_CALLBACK_NAME = "playFinished";
const std::string ERROR_CALLBACK_NAME = "error";

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerNapi"};
}

namespace OHOS {
namespace Media {
const std::string SYSTEM_TONE_PLAYER_NAPI_CLASS_NAME = "SystemTonePlayer";
thread_local napi_ref SystemTonePlayerNapi::sConstructor_ = nullptr;
std::shared_ptr<SystemTonePlayer> SystemTonePlayerNapi::sSystemTonePlayer_ = nullptr;

SystemTonePlayerNapi::SystemTonePlayerNapi() : env_(nullptr) {}

SystemTonePlayerNapi::~SystemTonePlayerNapi() = default;

napi_value SystemTonePlayerNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor system_tone_player_prop[] = {
        DECLARE_NAPI_FUNCTION("getTitle", GetTitle),
        DECLARE_NAPI_FUNCTION("prepare", Prepare),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("setAudioVolumeScale", SetAudioVolumeScale),
        DECLARE_NAPI_FUNCTION("getAudioVolumeScale", GetAudioVolumeScale),
        DECLARE_NAPI_FUNCTION("getSupportedHapticsFeatures", GetSupportedHapticsFeatures),
        DECLARE_NAPI_FUNCTION("setHapticsFeature", SetHapticsFeature),
        DECLARE_NAPI_FUNCTION("getHapticsFeature", GetHapticsFeature),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    status = napi_define_class(env, SYSTEM_TONE_PLAYER_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
        SystemTonePlayerNapiConstructor, nullptr, sizeof(system_tone_player_prop) / sizeof(system_tone_player_prop[0]),
        system_tone_player_prop, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, SYSTEM_TONE_PLAYER_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

napi_value SystemTonePlayerNapi::SystemTonePlayerNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SystemTonePlayerNapi> obj = std::make_unique<SystemTonePlayerNapi>();
        if (obj != nullptr) {
            ObjectRefMap<SystemTonePlayerNapi>::Insert(obj.get());
            obj->env_ = env;
            if (obj->sSystemTonePlayer_ != nullptr) {
                obj->systemTonePlayer_ = move(obj->sSystemTonePlayer_);
            } else {
                MEDIA_LOGE("Failed to create sSystemTonePlayer_ instance.");
                return result;
            }

            if (obj->systemTonePlayer_ != nullptr && obj->callbackNapi_ == nullptr) {
                obj->callbackNapi_ = std::make_shared<SystemTonePlayerCallbackNapi>(env);
                CHECK_AND_RETURN_RET_LOG(obj->callbackNapi_ != nullptr, result, "No memory");
                int32_t ret = obj->systemTonePlayer_->SetSystemTonePlayerFinishedAndErrorCallback(obj->callbackNapi_);
                MEDIA_LOGI("SetSystemTonePlayerFinishedAndErrorCallback %{public}s", ret == 0 ? "succeess" : "failed");
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                SystemTonePlayerNapi::SystemTonePlayerNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                ObjectRefMap<SystemTonePlayerNapi>::Erase(obj.get());
                MEDIA_LOGE("Failed to wrap the native system tone player object with JS.");
            }
        }
    }

    return result;
}

void SystemTonePlayerNapi::SystemTonePlayerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    SystemTonePlayerNapi *systemTonePlayerHelper = reinterpret_cast<SystemTonePlayerNapi*>(nativeObject);
    if (systemTonePlayerHelper != nullptr) {
        ObjectRefMap<SystemTonePlayerNapi>::DecreaseRef(systemTonePlayerHelper);
    }
}

napi_value SystemTonePlayerNapi::GetSystemTonePlayerInstance(napi_env env,
    std::shared_ptr<SystemTonePlayer> &systemTonePlayer)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        sSystemTonePlayer_ = systemTonePlayer;
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            MEDIA_LOGE("GetSystemTonePlayerInstance: New instance could not be obtained.");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

void SystemTonePlayerNapi::CommonAsyncCallbackComplete(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<SystemTonePlayerAsyncContext *>(data);
    napi_value callback = nullptr;
    napi_value retVal = nullptr;
    napi_value result[2] = {};

    napi_get_undefined(env, &result[PARAM1]);
    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "Error: Operation is not supported or failed", NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[PARAM0]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    } else {
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }
    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

void SystemTonePlayerNapi::GetTitleAsyncCallbackComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemTonePlayerAsyncContext *>(data);
    napi_value getTitleCallback = nullptr;
    napi_value retVal = nullptr;
    napi_value result[2] = {};

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_string_utf8(env, context->title.c_str(), NAPI_AUTO_LENGTH, &result[PARAM1]);
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "GetTitle Error: Operation is not supported or failed",
            NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    } else {
        napi_get_reference_value(env, context->callbackRef, &getTitleCallback);
        napi_call_function(env, nullptr, getTitleCallback, ARGS_TWO, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }
    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

napi_value SystemTonePlayerNapi::GetTitle(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    const int32_t refCount = 1;

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result, "GetTitle: napi_get_cb_info failed");

    NAPI_ASSERT(env, argc <= ARGS_ONE, "GetTitle: requires 1 parameter maximum");
    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            CHECK_AND_RETURN_RET_LOG(valueType == napi_function, result,
                "GetTitle: the param type is not napi_function");
            napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
        } else {
            napi_create_promise(env, &asyncContext->deferred, &result);
        }

        napi_create_string_utf8(env, "GetTitle", NAPI_AUTO_LENGTH, &resource);
        status = napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void *data) {
                SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
                auto obj = reinterpret_cast<SystemTonePlayerNapi*>(context->objectInfo);
                ObjectRefMap objectGuard(obj);
                auto *napiSystemTonePlayer = objectGuard.GetPtr();
                if (napiSystemTonePlayer == nullptr || napiSystemTonePlayer->systemTonePlayer_ == nullptr) {
                    MEDIA_LOGE("The system tone player is nullptr!");
                    context->status = MSERR_INVALID_STATE;
                    return;
                }
                context->title = napiSystemTonePlayer->systemTonePlayer_->GetTitle();
                context->status = MSERR_OK;
            },
            GetTitleAsyncCallbackComplete, static_cast<void *>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_LOGE("GetTitle: Failed to get create async work");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value SystemTonePlayerNapi::Prepare(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    const int32_t refCount = 1;

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result,
        "Prepare: Failed to retrieve details about the callback");

    NAPI_ASSERT(env, argc <= ARGS_ONE, "Prepare: requires 1 parameter maximum");
    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            CHECK_AND_RETURN_RET_LOG(valueType == napi_function, result,
                "Prepare: the param type is not napi_function");
            napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
        } else {
            napi_create_promise(env, &asyncContext->deferred, &result);
        }

        napi_create_string_utf8(env, "Prepare", NAPI_AUTO_LENGTH, &resource);
        status = napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void* data) {
                SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
                auto obj = reinterpret_cast<SystemTonePlayerNapi *>(context->objectInfo);
                ObjectRefMap objectGuard(obj);
                auto *napiSystemTonePlayer = objectGuard.GetPtr();
                if (napiSystemTonePlayer == nullptr || napiSystemTonePlayer->systemTonePlayer_ == nullptr) {
                    MEDIA_LOGE("The system tone player is nullptr!");
                    context->status = MSERR_INVALID_STATE;
                    return;
                }
                context->status = napiSystemTonePlayer->systemTonePlayer_->Prepare();
            },
            CommonAsyncCallbackComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_LOGE("Prepare: Failed to get create async work");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

void SystemTonePlayerNapi::StartAsyncCallbackComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemTonePlayerAsyncContext *>(data);
    napi_value getTitleCallback = nullptr;
    napi_value retVal = nullptr;
    napi_value result[2] = {};

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_int32(env, context->streamID, &result[PARAM1]);
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "GetTitle Error: Operation is not supported or failed",
            NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
    }

    if (context->deferred) {
        if (!context->status) {
            napi_resolve_deferred(env, context->deferred, result[PARAM1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[PARAM0]);
        }
    } else {
        napi_get_reference_value(env, context->callbackRef, &getTitleCallback);
        napi_call_function(env, nullptr, getTitleCallback, ARGS_TWO, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }
    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

napi_value SystemTonePlayerNapi::Start(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value resource = nullptr;
    napi_value property = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result, "Start: napi_get_cb_info failed");
    NAPI_ASSERT(env, argc <= ARGS_TWO, "Start: requires 2 parameter maximum");

    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && asyncContext->objectInfo != nullptr, result,
        "Start: napi_unwrap failed or objectInfo is nullptr.");

    if (argc == 0) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    }
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
            if (napi_get_named_property(env, argv[PARAM0], "muteAudio", &property) == napi_ok) {
                napi_get_value_bool(env, property, &(asyncContext->systemToneOptions.muteAudio));
            }
            if (napi_get_named_property(env, argv[PARAM0], "muteHaptics", &property) == napi_ok) {
                napi_get_value_bool(env, property, &(asyncContext->systemToneOptions.muteHaptics));
            }
            if (argc == ARGS_ONE) {
                napi_create_promise(env, &asyncContext->deferred, &result);
            }
        } else if ((i == PARAM0 || i == PARAM1) && valueType == napi_function) {
            napi_create_reference(env, argv[PARAM0], 1, &asyncContext->callbackRef);
        } else {
            NAPI_ASSERT(env, false, "Start: type mismatch");
        }
    }

    napi_create_string_utf8(env, "Start", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(env, nullptr, resource, AsyncStart,
        StartAsyncCallbackComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }
    return result;
}

void SystemTonePlayerNapi::AsyncStart(napi_env env, void *data)
{
    SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemTonePlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemTonePlayer = objectGuard.GetPtr();
    if (napiSystemTonePlayer == nullptr || napiSystemTonePlayer->systemTonePlayer_ == nullptr) {
        MEDIA_LOGE("The system tone player is nullptr!");
        context->status = MSERR_INVALID_STATE;
        return;
    }
    context->streamID = napiSystemTonePlayer->systemTonePlayer_->Start(context->systemToneOptions);
    std::shared_ptr<SystemTonePlayerCallbackNapi> cb =
        std::static_pointer_cast<SystemTonePlayerCallbackNapi>(napiSystemTonePlayer->callbackNapi_);
    if (cb) {
        cb->RemovePlayFinishedCallbackReference(context->streamID);
    }
    context->status = MSERR_OK;
}

napi_value SystemTonePlayerNapi::Stop(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    const int32_t refCount = 1;

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_LOGE("Stop: Failed to retrieve details about the callback");
        return result;
    }

    NAPI_ASSERT(env, argc == ARGS_ONE || argc == ARGS_TWO, "Stop: requires 1 or 2 parameter");
    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valueType);
        if (valueType == napi_number) {
            napi_get_value_int32(env, argv[PARAM0], &(asyncContext->streamID));
            napi_create_promise(env, &asyncContext->deferred, &result);
        } else {
            NAPI_ASSERT(env, false, "Stop: type mismatch");
        }
        if (argc == ARGS_TWO) {
            napi_typeof(env, argv[PARAM1], &valueType);
            CHECK_AND_RETURN_RET_LOG(valueType == napi_function, result, "Stop: the param type is not napi_function");
            napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
        } else {
            napi_create_promise(env, &asyncContext->deferred, &result);
        }

        napi_create_string_utf8(env, "Stop", NAPI_AUTO_LENGTH, &resource);
        status = napi_create_async_work(env, nullptr, resource, AsyncStop,
            CommonAsyncCallbackComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_LOGE("Stop: Failed to get create async work");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

void SystemTonePlayerNapi::AsyncStop(napi_env env, void *data)
{
    SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemTonePlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemTonePlayer = objectGuard.GetPtr();
    if (napiSystemTonePlayer == nullptr || napiSystemTonePlayer->systemTonePlayer_ == nullptr) {
        MEDIA_LOGE("The system tone player is nullptr!");
        context->status = MSERR_INVALID_STATE;
        return;
    }
    context->status = napiSystemTonePlayer->systemTonePlayer_->Stop(context->streamID);
}

napi_value SystemTonePlayerNapi::Release(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    const int32_t refCount = 1;

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_LOGE("Release: Failed to retrieve details about the callback");
        return result;
    }

    NAPI_ASSERT(env, argc <= ARGS_ONE, "Release: requires 1 parameter maximum");
    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            CHECK_AND_RETURN_RET_LOG(valueType == napi_function, result,
                "Release: the param type is not napi_function");
            napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
        } else {
            napi_create_promise(env, &asyncContext->deferred, &result);
        }

        napi_create_string_utf8(env, "Release", NAPI_AUTO_LENGTH, &resource);
        status = napi_create_async_work(env, nullptr, resource, AsyncRelease,
            CommonAsyncCallbackComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_LOGE("Release: Failed to get create async work");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

void SystemTonePlayerNapi::AsyncRelease(napi_env env, void *data)
{
    SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
    auto obj = reinterpret_cast<SystemTonePlayerNapi *>(context->objectInfo);
    ObjectRefMap objectGuard(obj);
    auto *napiSystemTonePlayer = objectGuard.GetPtr();
    if (napiSystemTonePlayer == nullptr || napiSystemTonePlayer->systemTonePlayer_ == nullptr) {
        MEDIA_LOGE("The system tone player is nullptr!");
        context->status = MSERR_INVALID_STATE;
        return;
    }
    context->status = napiSystemTonePlayer->systemTonePlayer_->Release();
}

napi_value SystemTonePlayerNapi::SetAudioVolumeScale(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_LOGE("SetAudioVolumeScale: Failed to retrieve details about the callback");
        return result;
    }

    NAPI_ASSERT(env, argc >= ARGS_ONE, "SetAudioVolumeScale: requires 1 parameter");
    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    SystemTonePlayerNapi *objectInfo = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&objectInfo));
    if (status == napi_ok && objectInfo != nullptr) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "SetAudioVolumeScale: type mismatch");
        double value;
        napi_get_value_double(env, argv[PARAM0], &value);
        float volume  = static_cast<float>(value);
        ObjectRefMap objectGuard(objectInfo);
        auto *napiSystemTonePlayer = objectGuard.GetPtr();
        int32_t ret = napiSystemTonePlayer->systemTonePlayer_->SetAudioVolume(volume);
        if (ret != MSERR_OK) {
            napi_throw_error(env, std::to_string(ret).c_str(),
                "SetAudioVolumeScale: Operation is not supported or failed");
        }
    }
    return result;
}

napi_value SystemTonePlayerNapi::GetAudioVolumeScale(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result,
        "GetAudioVolume: napi_get_cb_info failed");

    SystemTonePlayerNapi* objectInfo = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    if (status == napi_ok && objectInfo != nullptr) {
        ObjectRefMap objectGuard(objectInfo);
        auto *napiSystemTonePlayer = objectGuard.GetPtr();
        float volume;
        int32_t ret = napiSystemTonePlayer->systemTonePlayer_->GetAudioVolume(volume);
        if (ret != MSERR_OK) {
            napi_throw_error(env, std::to_string(ret).c_str(),
                "SetAudioVolumeScale: Operation is not supported or failed");
        } else {
            napi_create_double(env, static_cast<double>(volume), &result);
        }
    }
    return result;
}

static void GetSupportHapticsFeaturesComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SystemTonePlayerAsyncContext *>(data);
    napi_value result[2] = {};
    napi_status curStatus;

    if (!context->status) {
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_array_with_length(env, context->toneHapticsFeatures.size(), &result[PARAM1]);
        napi_value value;
        for (size_t i = 0; i < context->toneHapticsFeatures.size(); i++) {
            value = nullptr;
            curStatus = napi_create_int32(env, static_cast<int32_t>(context->toneHapticsFeatures[i]), &value);
            if (curStatus != napi_ok || value == nullptr||
                napi_set_element(env, result[PARAM1], i, value) != napi_ok) {
                MEDIA_LOGE("GetSupportHapticsFeatures error : Failed to create number or add number to array");
                napi_value message = nullptr;
                napi_create_string_utf8(env,
                    "GetSupportHapticsFeatures Error: Failed to create number or add number to array",
                    NAPI_AUTO_LENGTH, &message);
                napi_create_error(env, nullptr, message, &result[PARAM0]);
                napi_get_undefined(env, &result[PARAM1]);
                context->status = MSERR_NO_MEMORY;
                break;
            }
        }
    } else {
        napi_value message = nullptr;
        napi_create_string_utf8(env, "GetSupportHapticsFeatures Error: Operation is not supported or failed",
            NAPI_AUTO_LENGTH, &message);
        napi_create_error(env, nullptr, message, &result[PARAM0]);
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

napi_value SystemTonePlayerNapi::GetSupportedHapticsFeatures(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result,
        "GetSupportHapticsFeatures: napi_get_cb_info failed");

    std::unique_ptr<SystemTonePlayerAsyncContext> asyncContext = std::make_unique<SystemTonePlayerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
        napi_create_string_utf8(env, "GetSupportHapticsFeatures", NAPI_AUTO_LENGTH, &resource);
        status = napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void *data) {
                SystemTonePlayerAsyncContext *context = static_cast<SystemTonePlayerAsyncContext *>(data);
                auto obj = reinterpret_cast<SystemTonePlayerNapi*>(context->objectInfo);
                ObjectRefMap objectGuard(obj);
                auto *napiSystemTonePlayer = objectGuard.GetPtr();
                context->status = napiSystemTonePlayer->systemTonePlayer_->GetSupportHapticsFeatures(
                    context->toneHapticsFeatures);
            },
            GetSupportHapticsFeaturesComplete, static_cast<void *>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_LOGE("GetSupportHapticsFeatures: Failed to get create async work");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

napi_value SystemTonePlayerNapi::SetHapticsFeature(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_LOGE("SetHapticsFeature: Failed to retrieve details about the callback");
        return result;
    }

    NAPI_ASSERT(env, argc >= ARGS_ONE, "SetHapticsFeature: requires 1 parameter");
    SystemTonePlayerNapi* objectInfo = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&objectInfo));
    if (status == napi_ok && objectInfo != nullptr) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "SetHapticsFeature: type mismatch");
        ToneHapticsFeature toneHapticsFeature;
        napi_get_value_int32(env, argv[PARAM0], reinterpret_cast<int32_t*>(&toneHapticsFeature));
        ObjectRefMap objectGuard(objectInfo);
        auto *napiSystemTonePlayer = objectGuard.GetPtr();
        int32_t ret = napiSystemTonePlayer->systemTonePlayer_->SetHapticsFeature(
            toneHapticsFeature);
        if (ret != MSERR_OK) {
            napi_throw_error(env, std::to_string(ret).c_str(),
                "SetHapticsFeature: Operation is not supported or failed");
        }
    }
    return result;
}

napi_value SystemTonePlayerNapi::GetHapticsFeature(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_get_undefined(env, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && thisVar != nullptr, result,
        "GetHapticsFeature: napi_get_cb_info failed");

    SystemTonePlayerNapi* objectInfo = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    if (status == napi_ok && objectInfo != nullptr) {
        ObjectRefMap objectGuard(objectInfo);
        auto *napiSystemTonePlayer = objectGuard.GetPtr();
        ToneHapticsFeature toneHapticsFeature;
        int32_t ret = napiSystemTonePlayer->systemTonePlayer_->GetHapticsFeature(toneHapticsFeature);
        if (ret != MSERR_OK) {
            napi_throw_error(env, std::to_string(ret).c_str(),
                "GetHapticsFeature: Operation is not supported or failed");
        } else {
            napi_create_int32(env, static_cast<int32_t>(toneHapticsFeature), &result);
        }
    }
    return result;
}

bool SystemTonePlayerNapi::VerifySelfSystemPermission()
{
    Security::AccessToken::FullTokenID selfTokenID = IPCSkeleton::GetSelfTokenID();
    auto tokenTypeFlag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<uint32_t>(selfTokenID));
    if (tokenTypeFlag == Security::AccessToken::TOKEN_NATIVE ||
        tokenTypeFlag == Security::AccessToken::TOKEN_SHELL ||
        Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID)) {
        return true;
    }
    return false;
}

napi_value SystemTonePlayerNapi::ThrowErrorAndReturn(napi_env env, int32_t errCode, const std::string &errMsg)
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

napi_value SystemTonePlayerNapi::On(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED,
        NAPI_ERR_PERMISSION_DENIED_INFO), "No system permission");

    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "On: napi_get_cb_info fail");
    CHECK_AND_RETURN_RET_LOG(argc >= ARGS_TWO, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "invalid arguments");

    napi_valuetype argvType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &argvType);
    CHECK_AND_RETURN_RET_LOG(argvType == napi_string, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "The type of callbackName must be string");

    std::string callbackName = RingtoneCommonNapi::GetStringArgument(env, argv[0]);
    MEDIA_LOGI("On: callbackName: %{public}s", callbackName.c_str());

    if (argc == ARGS_TWO) {
        napi_valuetype callbackFunction = napi_undefined;
        napi_typeof(env, argv[PARAM1], &callbackFunction);
        CHECK_AND_RETURN_RET_LOG(callbackFunction == napi_function, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
            NAPI_ERR_INPUT_INVALID_INFO), "The type of callback must be function");
    } else {
        napi_valuetype paramArg1 = napi_undefined;
        napi_typeof(env, argv[PARAM1], &paramArg1);
        CHECK_AND_RETURN_RET_LOG(paramArg1 == napi_number, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
            NAPI_ERR_INPUT_INVALID_INFO), "The type of streamId must be number");

        napi_valuetype paramArg2 = napi_undefined;
        napi_typeof(env, argv[PARAM2], &paramArg2);
        CHECK_AND_RETURN_RET_LOG(paramArg2 == napi_function, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
            NAPI_ERR_INPUT_INVALID_INFO), "The type of callback must be function");
    }

    return RegisterCallback(env, jsThis, argv, callbackName);
}

napi_value SystemTonePlayerNapi::RegisterCallback(napi_env env, napi_value jsThis, napi_value *argv,
    const std::string &cbName)
{
    SystemTonePlayerNapi *systemTonePlayerNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&systemTonePlayerNapi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "system err");
    CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi != nullptr, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "systemTonePlayerNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi->systemTonePlayer_ != nullptr, ThrowErrorAndReturn(env,
        NAPI_ERR_INPUT_INVALID, NAPI_ERR_INPUT_INVALID_INFO), "systemTonePlayer_ is nullptr");

    if (!cbName.compare(PLAY_FINISHED_CALLBACK_NAME) ||
        !cbName.compare(ERROR_CALLBACK_NAME)) {
        return RegisterSystemTonePlayerCallback(env, argv, cbName, systemTonePlayerNapi);
    }

    return ThrowErrorAndReturn(env, NAPI_ERR_PARAM_CHECK_ERROR, NAPI_ERR_PARAM_CHECK_ERROR_INFO);
}

napi_value SystemTonePlayerNapi::RegisterSystemTonePlayerCallback(napi_env env, napi_value *argv,
    const std::string &cbName, SystemTonePlayerNapi *systemTonePlayerNapi)
{
    CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi->callbackNapi_ != nullptr, ThrowErrorAndReturn(env,
        NAPI_ERR_INPUT_INVALID, NAPI_ERR_INPUT_INVALID_INFO), "callbackNapi_ is nullptr");

    std::shared_ptr<SystemTonePlayerCallbackNapi> cb =
        std::static_pointer_cast<SystemTonePlayerCallbackNapi>(systemTonePlayerNapi->callbackNapi_);
    if (cbName == PLAY_FINISHED_CALLBACK_NAME) {
        int32_t streamId = -1;
        napi_get_value_int32(env, argv[PARAM1], &streamId);
        // streamId is 0 means all streamId
        CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi->systemTonePlayer_->IsStreamIdExist(streamId) ||
            streamId == ALL_STREAMID,
            ThrowErrorAndReturn(env, NAPI_ERR_PARAM_CHECK_ERROR, NAPI_ERR_PARAM_CHECK_ERROR_INFO),
            "streamId is not exists");
        cb->SavePlayFinishedCallbackReference(cbName, argv[PARAM2], streamId);
    } else if (cbName == ERROR_CALLBACK_NAME) {
        cb->SaveCallbackReference(cbName, argv[PARAM1]);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value SystemTonePlayerNapi::Off(napi_env env, napi_callback_info info)
{
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(), ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED,
        NAPI_ERR_PERMISSION_DENIED_INFO), "No system permission");

    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "Off: napi_get_cb_info fail");
    CHECK_AND_RETURN_RET_LOG(argc >= ARGS_ONE, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "invalid arguments");

    napi_valuetype argvType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &argvType);
    CHECK_AND_RETURN_RET_LOG(argvType == napi_string, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "The type of callbackName must be string");

    std::string callbackName = RingtoneCommonNapi::GetStringArgument(env, argv[0]);
    MEDIA_LOGI("Off: callbackName: %{public}s", callbackName.c_str());

    napi_value callback = nullptr;
    if (argc == ARGS_TWO) {
        napi_valuetype callbackFunction = napi_undefined;
        napi_typeof(env, argv[PARAM1], &callbackFunction);
        CHECK_AND_RETURN_RET_LOG(callbackFunction == napi_function, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
            NAPI_ERR_INPUT_INVALID_INFO), "The type of callback must be function");
        callback = argv[PARAM1];
    }

    return UnregisterCallback(env, jsThis, callbackName, callback);
}

napi_value SystemTonePlayerNapi::UnregisterCallback(napi_env env, napi_value jsThis, const std::string &cbName,
    const napi_value &callback)
{
    SystemTonePlayerNapi *systemTonePlayerNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&systemTonePlayerNapi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "system err");
    CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi != nullptr, ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID,
        NAPI_ERR_INPUT_INVALID_INFO), "systemTonePlayerNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(systemTonePlayerNapi->systemTonePlayer_  != nullptr, ThrowErrorAndReturn(env,
        NAPI_ERR_INPUT_INVALID, NAPI_ERR_INPUT_INVALID_INFO), "systemTonePlayer_ is nullptr");

    if (!cbName.compare(PLAY_FINISHED_CALLBACK_NAME) ||
        !cbName.compare(ERROR_CALLBACK_NAME)) {
        UnregisterSystemTonePlayerCallback(env, systemTonePlayerNapi, cbName, callback);
    } else {
        ThrowErrorAndReturn(env, NAPI_ERR_PARAM_CHECK_ERROR, NAPI_ERR_PARAM_CHECK_ERROR_INFO);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

void SystemTonePlayerNapi::UnregisterSystemTonePlayerCallback(napi_env env, SystemTonePlayerNapi *systemTonePlayerNapi,
    const std::string &cbName, const napi_value &callback)
{
    if (systemTonePlayerNapi->callbackNapi_ == nullptr) {
        ThrowErrorAndReturn(env, NAPI_ERR_INPUT_INVALID, NAPI_ERR_INPUT_INVALID_INFO);
        MEDIA_LOGE("callbackNapi_ is nullptr");
        return;
    }

    std::shared_ptr<SystemTonePlayerCallbackNapi> cb =
        std::static_pointer_cast<SystemTonePlayerCallbackNapi>(systemTonePlayerNapi->callbackNapi_);
    cb->RemoveCallbackReference(cbName, callback);
}
} // namespace Media
} // namespace OHOS