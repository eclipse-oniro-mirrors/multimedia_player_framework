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

#ifndef SCREEN_CAPTURE_MONITOR_CALLBACK_H
#define SCREEN_CAPTURE_MONITOR_CALLBACK_H

#include "screen_capture_monitor.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "common_napi.h"

namespace OHOS {
namespace Media {
namespace ScreenCaptureMonitorCallbackNapiTask {
const std::string ON_JS_CAPTURE_CALLBACK = "ScreenCaptureMonitorCallback::OnJsCaptureCallBack";
}

class ScreenCaptureMonitorCallback : public ScreenCaptureMonitor::ScreenCaptureMonitorListener {
public:
    explicit ScreenCaptureMonitorCallback(napi_env env);
    virtual ~ScreenCaptureMonitorCallback();
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &name);
private:
    struct ScreenCaptureMonitorJsCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        ScreenCaptureMonitorEvent captureEvent;
    };
    void OnScreenCaptureStarted(int32_t pid) override;
    void OnScreenCaptureFinished(int32_t pid) override;
    void OnScreenCaptureDied() override;
    void OnJsCaptureCallBack(ScreenCaptureMonitorJsCallback *jsCb) const;

    napi_env env_ = nullptr;
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};
} // Media
} // OHOS
#endif