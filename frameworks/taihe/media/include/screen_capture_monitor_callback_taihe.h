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
#ifndef SCREEN_CAPTURE_MONITOR_CALLBACK_TAIHE_H
#define SCREEN_CAPTURE_MONITOR_CALLBACK_TAIHE_H

#include "screen_capture_monitor.h"
#include "media_ani_common.h"
#include "event_handler.h"
namespace ANI {
namespace Media {
using namespace OHOS::Media;

class ScreenCaptureMonitorCallback : public OHOS::Media::ScreenCaptureMonitor::ScreenCaptureMonitorListener {
public:
    explicit ScreenCaptureMonitorCallback();
    virtual ~ScreenCaptureMonitorCallback();
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &name);
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
private:
    struct ScreenCaptureMonitorAniCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        OHOS::Media::ScreenCaptureMonitorEvent captureEvent;
    };
    void OnScreenCaptureStarted(int32_t pid) override;
    void OnScreenCaptureFinished(int32_t pid) override;
    void OnScreenCaptureDied() override;
    void OnTaiheCaptureCallBack(ScreenCaptureMonitorAniCallback *taiheCb) const;

    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};
} // namespace Media
} // namespace ANI
#endif // SCREEN_CAPTURE_MONITOR_CALLBACK_TAIHE_H