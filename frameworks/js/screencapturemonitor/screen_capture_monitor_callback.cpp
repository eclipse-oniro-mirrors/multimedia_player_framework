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
#include "screen_capture_monitor_callback.h"
#include "screen_capture_monitor_napi.h"
#include "media_log.h"
#include "scope_guard.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "ScreenCaptureMonitorCallback"};
}

namespace OHOS {
namespace Media {
ScreenCaptureMonitorCallback::ScreenCaptureMonitorCallback(napi_env env) : env_(env)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

ScreenCaptureMonitorCallback::~ScreenCaptureMonitorCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void ScreenCaptureMonitorCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
}

void ScreenCaptureMonitorCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void ScreenCaptureMonitorCallback::OnScreenCaptureStarted(int32_t pid)
{
    MEDIA_LOGI("OnScreenCaptureStarted S %{public}d", pid);
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    bool shouldSendCb = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(pid);
    if (!shouldSendCb) {
        MEDIA_LOGW("pid not match, do not send callback!");
        return;
    }

    ScreenCaptureMonitorJsCallback *cb = new(std::nothrow) ScreenCaptureMonitorJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_STARTED;
    MEDIA_LOGI("OnScreenCaptureStarted E");
    return OnJsCaptureCallBack(cb);
}

void ScreenCaptureMonitorCallback::OnScreenCaptureFinished(int32_t pid)
{
    MEDIA_LOGI("OnScreenCaptureFinished S %{public}d", pid);
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    bool shouldSendCb = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(pid);
    if (!shouldSendCb) {
        MEDIA_LOGW("pid not match, do not send callback!");
        return;
    }

    ScreenCaptureMonitorJsCallback *cb = new(std::nothrow) ScreenCaptureMonitorJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_STOPPED;
    MEDIA_LOGI("OnScreenCaptureFinished E");
    return OnJsCaptureCallBack(cb);
}

void ScreenCaptureMonitorCallback::OnScreenCaptureDied()
{
    MEDIA_LOGI("ScreenCaptureMonitorCallback::OnScreenCaptureDied S");
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    ScreenCaptureMonitorJsCallback *cb = new(std::nothrow) ScreenCaptureMonitorJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_DIED;
    MEDIA_LOGI("ScreenCaptureMonitorCallback::OnScreenCaptureDied E");
    return OnJsCaptureCallBack(cb);
}

void ScreenCaptureMonitorCallback::OnJsCaptureCallBack(ScreenCaptureMonitorJsCallback *jsCb) const
{
    ON_SCOPE_EXIT(0) {
        delete jsCb;
    };

    auto task = [jsCb]() {
        std::string request = jsCb->callbackName;
        if (jsCb->captureEvent == ScreenCaptureMonitorEvent::SCREENCAPTURE_DIED) {
            MEDIA_LOGI("ScreenCaptureMonitorCallback::ScreenCaptureMonitorServiceDied S");
            ScreenCaptureMonitor::GetInstance()->ScreenCaptureMonitorServiceDied();
        }
        do {
            std::shared_ptr<AutoRef> ref = jsCb->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
                request.c_str());

            napi_value args[1] = { nullptr };
            nstatus = napi_create_int32(ref->env_, jsCb->captureEvent, &args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr,
                "%{public}s fail to create callback", request.c_str());

            const size_t argCount = 1;
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        } while (0);
        delete jsCb;
    };
    CHECK_AND_RETURN_LOG(napi_send_event(env_, task, napi_eprio_immediate,
        ScreenCaptureMonitorCallbackNapiTask::ON_JS_CAPTURE_CALLBACK.c_str()) == napi_status::napi_ok,
        "OnJsCaptureCallBack napi_send_event failed");

    CANCEL_SCOPE_EXIT_GUARD(0);
}
} // namespace Media
} // namespace OHOS