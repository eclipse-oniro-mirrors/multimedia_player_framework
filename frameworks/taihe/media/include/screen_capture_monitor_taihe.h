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
#ifndef SCREEN_CAPTURE_MONITOR_TAIHE_H
#define SCREEN_CAPTURE_MONITOR_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "screen_capture_monitor.h"
#include "screen_capture_monitor_callback_taihe.h"
#include "media_ani_common.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;

class ScreenCaptureMonitorImpl {
public:
    ScreenCaptureMonitorImpl();
    bool GetisSystemScreenRecorderWorking();
    void OnSystemScreenRecorder(callback_view<void(ohos::multimedia::media::ScreenCaptureEvent)> callback);
    void OffSystemScreenRecorder(optional_view<callback<void(ohos::multimedia::media::ScreenCaptureEvent)>> callback);

    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);

private:
    std::mutex mutex_;
    OHOS::sptr<OHOS::Media::ScreenCaptureMonitor::ScreenCaptureMonitorListener> monitorCb_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
};
} // namespace ANI::Media
#endif // SCREEN_CAPTURE_MONITOR_TAIHE_H