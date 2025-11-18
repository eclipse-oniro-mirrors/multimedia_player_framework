/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_MONITOR_H
#define SCREEN_CAPTURE_MONITOR_H
#include <cstdint>
#include <refbase.h>
#include <list>

namespace OHOS {
namespace Media {

enum ScreenCaptureMonitorErrorType : int32_t {
    SCREEN_CAPTURE_MONITOR_ERROR_INTERNAL,
};

enum ScreenCaptureMonitorEvent : int32_t {
    SCREENCAPTURE_STARTED = 0,
    SCREENCAPTURE_STOPPED = 1,
    SCREENCAPTURE_DIED = 2,
};

class ScreenCaptureMonitor {
public:
#ifdef UNSUPPORT_SCREEN_CAPTURE
    static ScreenCaptureMonitor *GetInstance()
    {
        return nullptr;
    }
    class ScreenCaptureMonitorListener : public virtual RefBase {
    public:
        virtual void OnScreenCaptureStarted(int32_t pid) = 0;
        virtual void OnScreenCaptureFinished(int32_t pid) = 0;
        virtual void OnScreenCaptureDied() = 0;
    };

    std::list<int32_t> IsScreenCaptureWorking()
    {
        return {};
    }
    void RegisterScreenCaptureMonitorListener(sptr<ScreenCaptureMonitorListener> listener) {}
    void UnregisterScreenCaptureMonitorListener(sptr<ScreenCaptureMonitorListener> listener) {}
    bool IsSystemScreenRecorder(int32_t pid)
    {
        return false;
    }
    bool IsSystemScreenRecorderWorking()
    {
        return false;
    }
#else
    static ScreenCaptureMonitor *GetInstance();
    class ScreenCaptureMonitorListener : public virtual RefBase {
    public:
        /**
         * @brief Notify when screen capture started.
         * @param pid Indicates the screen capture instance pid.
         * @since 1.0
         * @version 1.0
         */
        virtual void OnScreenCaptureStarted(int32_t pid) = 0;
        /**
         * @brief Notify when screen capture finished.
         * @param pid Indicates the screen capture instance pid.
         * @since 1.0
         * @version 1.0
         */
        virtual void OnScreenCaptureFinished(int32_t pid) = 0;

        /**
         * @brief Notify when screen capture died.
         * @since 1.0
         * @version 1.0
         */
        virtual void OnScreenCaptureDied() = 0;
    };

    std::list<int32_t> IsScreenCaptureWorking();
    void RegisterScreenCaptureMonitorListener(sptr<ScreenCaptureMonitorListener> listener);
    void UnregisterScreenCaptureMonitorListener(sptr<ScreenCaptureMonitorListener> listener);
    bool IsSystemScreenRecorder(int32_t pid);
    bool IsSystemScreenRecorderWorking();
    virtual void ScreenCaptureMonitorServiceDied() {};
    virtual ~ScreenCaptureMonitor() = default;
#endif
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_MONITOR_H