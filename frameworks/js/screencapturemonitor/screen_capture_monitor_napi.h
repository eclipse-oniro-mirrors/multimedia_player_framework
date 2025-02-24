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

#ifndef SCREEN_CAPTURE_MONITOR_NAPI_H
#define SCREEN_CAPTURE_MONITOR_NAPI_H

#include "screen_capture_monitor.h"
#include "screen_capture_monitor_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "common_napi.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {

using RetInfo = std::pair<int32_t, std::string>;

const std::string EVENT_SYSTEM_SCREEN_RECORD = "systemScreenRecorder";

class ScreenCaptureMonitorNapi {
public:
    __attribute__((visibility("default"))) static napi_value Init(napi_env env, napi_value exports);

    using ScreenCaptureMonitorTaskqFunc = RetInfo (ScreenCaptureMonitorNapi::*)();
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    /**
     * getScreenCaptureMonitor(): Promise<ScreenCaptureMonitor>
     */
    static napi_value JsGetScreenCaptureMonitor(napi_env env, napi_callback_info info);
    /**
     * on(type: 'systemScreenRecorder', callback: (state: AVPlayerState, reason: StateChangeReason) => void): void
     */
    static napi_value JsSetEventCallback(napi_env env, napi_callback_info info);
    /**
     * off(type: 'systemScreenRecorder'): void;
     */
    static napi_value JsCancelEventCallback(napi_env env, napi_callback_info info);
    /**
     * readonly isSystemScreenRecorderWorking: boolean;
    */
    static napi_value JsIsSystemScreenRecorderWorking(napi_env env, napi_callback_info info);
    static ScreenCaptureMonitorNapi* GetJsInstanceAndArgs(napi_env env, napi_callback_info info,
        size_t &argCount, napi_value *args);

    ScreenCaptureMonitorNapi();
    ~ScreenCaptureMonitorNapi();

    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);

    static thread_local napi_ref constructor_;
    napi_env env_ = nullptr;

    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> monitorCb_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
};

struct ScreenCaptureMonitorAsyncContext : public MediaAsyncContext {
    explicit ScreenCaptureMonitorAsyncContext(napi_env env) : MediaAsyncContext(env) {}
    ~ScreenCaptureMonitorAsyncContext() = default;
};

} // Media
} // OHOS
#endif