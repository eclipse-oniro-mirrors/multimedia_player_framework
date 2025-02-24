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

#include "screen_capture_monitor_napi.h"
#include "media_dfx.h"
#include "media_log.h"
#include <refbase.h>

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "ScreenCaptureMonitorNapi"};
}

namespace OHOS {
namespace Media {
thread_local napi_ref ScreenCaptureMonitorNapi::constructor_ = nullptr;
const std::string CLASS_NAME = "ScreenCaptureMonitor";

ScreenCaptureMonitorNapi::ScreenCaptureMonitorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

ScreenCaptureMonitorNapi::~ScreenCaptureMonitorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

napi_value ScreenCaptureMonitorNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_LOGI("JS Init Start");
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getScreenCaptureMonitor", JsGetScreenCaptureMonitor),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("on", JsSetEventCallback),
        DECLARE_NAPI_FUNCTION("off", JsCancelEventCallback),

        DECLARE_NAPI_GETTER("isSystemScreenRecorderWorking", JsIsSystemScreenRecorderWorking),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
                                           sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define ScreenCaptureMonitor class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function");

    MEDIA_LOGI("Js Init End");
    return exports;
}

napi_value ScreenCaptureMonitorNapi::Constructor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::Constructor");
    MEDIA_LOGI("Js Constructor Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    ScreenCaptureMonitorNapi *jsMonitor = new(std::nothrow) ScreenCaptureMonitorNapi();
    CHECK_AND_RETURN_RET_LOG(jsMonitor != nullptr, result, "failed to new ScreenCaptureMonitorNapi");

    jsMonitor->env_ = env;

    sptr<ScreenCaptureMonitorCallback> monitorCb(new ScreenCaptureMonitorCallback(env));
    jsMonitor->monitorCb_ = monitorCb;
    CHECK_AND_RETURN_RET_LOG(jsMonitor->monitorCb_ != nullptr, result, "failed to CreateRecorderCb");
    ScreenCaptureMonitor::GetInstance()->RegisterScreenCaptureMonitorListener(jsMonitor->monitorCb_);
    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(jsMonitor),
                       ScreenCaptureMonitorNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsMonitor;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("Js Constructor End");

    return jsThis;
}

void ScreenCaptureMonitorNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::Destructor");
    MEDIA_LOGI("Js Destructor Start");
    (void)finalize;
    if (nativeObject != nullptr) {
        ScreenCaptureMonitorNapi *napi = reinterpret_cast<ScreenCaptureMonitorNapi *>(nativeObject);

        napi->monitorCb_ = nullptr;

        delete napi;
    }
    MEDIA_LOGI("Js Destructor End");
}

napi_value ScreenCaptureMonitorNapi::JsGetScreenCaptureMonitor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::JsGetScreenCaptureMonitor");
    MEDIA_LOGI("Js GetScreenCaptureMonitor Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    // get args
    napi_value jsThis = nullptr;
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    std::unique_ptr<ScreenCaptureMonitorAsyncContext> asyncCtx =
        std::make_unique<ScreenCaptureMonitorAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    asyncCtx->JsResult = std::make_unique<MediaJsResultInstance>(constructor_);
    asyncCtx->ctorFlag = true;

    auto ret = MediaAsyncContext::SendCompleteEvent(env, asyncCtx.get(), napi_eprio_immediate);
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);
    }
    asyncCtx.release();

    MEDIA_LOGI("Js JsGetScreenCaptureMonitor End");
    
    return result;
}

napi_value ScreenCaptureMonitorNapi::JsSetEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::JsSetEventCallback");
    MEDIA_LOGI("JsSetEventCallback Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    
    size_t argCount = 2;
    constexpr size_t requireArgc = 1;
    napi_value args[2] = { nullptr, nullptr };
    ScreenCaptureMonitorNapi *monitorNapi = ScreenCaptureMonitorNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(monitorNapi != nullptr, result, "Failed to retrieve instance");

    napi_valuetype valueType0 = napi_undefined;
    napi_valuetype valueType1 = napi_undefined;

    if (argCount < requireArgc) {
        return result;
    }

    if (napi_typeof(env, args[0], &valueType0) != napi_ok || valueType0 != napi_string) {
        return result;
    }

    if (napi_typeof(env, args[1], &valueType1) != napi_ok || valueType1 != napi_function) {
        return result;
    }

    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    if (callbackName != EVENT_SYSTEM_SCREEN_RECORD) {
        return result;
    }

    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, args[1], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    monitorNapi->SetCallbackReference(callbackName, autoRef);

    MEDIA_LOGI("JsSetEventCallback End");
    return result;
}

napi_value ScreenCaptureMonitorNapi::JsCancelEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::JsCancelEventCallback");
    MEDIA_LOGI("JsCancelEventCallback Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    constexpr size_t requireArgc = 1;
    size_t argCount = 1;

    napi_value args[1] = { nullptr };
    ScreenCaptureMonitorNapi *monitorNapi = ScreenCaptureMonitorNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(monitorNapi != nullptr, result, "Failed to retrieve instance");

    napi_valuetype valueType0 = napi_undefined;

    if (argCount < requireArgc) {
        return result;
    }

    if (napi_typeof(env, args[0], &valueType0) != napi_ok || valueType0 != napi_string) {
        return result;
    }

    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    if (callbackName != EVENT_SYSTEM_SCREEN_RECORD) {
        return result;
    }

    monitorNapi->CancelCallbackReference(callbackName);

    MEDIA_LOGI("JsCancelEventCallback End");
    return result;
}

napi_value ScreenCaptureMonitorNapi::JsIsSystemScreenRecorderWorking(napi_env env, napi_callback_info info)
{
    MediaTrace trace("ScreenCaptureMonitorNapi::JsIsSystemScreenRecorderWorking");
    MEDIA_LOGI("Js IsSystemScreenRecorderWorking Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    bool isSystemScreenRecorderWorking = false;
    napi_status status = napi_get_boolean(env, isSystemScreenRecorderWorking, &result);

    ScreenCaptureMonitorNapi *monitorNapi = ScreenCaptureMonitorNapi::GetJsInstanceAndArgs(env, info, argCount, nullptr);
    CHECK_AND_RETURN_RET_LOG(monitorNapi != nullptr, result, "Failed to GetJsInstanceAndArgs");

    isSystemScreenRecorderWorking = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorderWorking();
    status = napi_get_boolean(env, isSystemScreenRecorderWorking, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "napi_get_boolean failed");

    return result;
}

ScreenCaptureMonitorNapi *ScreenCaptureMonitorNapi::GetJsInstanceAndArgs(
    napi_env env, napi_callback_info info, size_t &argCount, napi_value *args)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");
    MEDIA_LOGD("argCount:%{public}zu", argCount);

    ScreenCaptureMonitorNapi *monitorNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&monitorNapi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && monitorNapi != nullptr, nullptr, "failed to retrieve instance");

    return monitorNapi;
}

void ScreenCaptureMonitorNapi::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(monitorCb_ != nullptr, "monitorCb_ is nullptr!");
    auto napiCb = static_cast<ScreenCaptureMonitorCallback*>(monitorCb_.GetRefPtr());
    napiCb->SaveCallbackReference(callbackName, ref);
}

void ScreenCaptureMonitorNapi::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(monitorCb_ != nullptr, "monitorCb_ is nullptr!");
    auto napiCb = static_cast<ScreenCaptureMonitorCallback*>(monitorCb_.GetRefPtr());
    napiCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}
} // Media
} // OHOS