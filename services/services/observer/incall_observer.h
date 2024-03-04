/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef IN_CALL_OBSERVER_H
#define IN_CALL_OBSERVER_H

#include <mutex>
#include <vector>
#include <unordered_map>
#include <chrono>
#include "task_queue.h"
#include "media_telephony_listener.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {

class ScreenCaptureObserverCallBack {
public:
    virtual ~ScreenCaptureObserverCallBack() = default;
    virtual void StopAndReleaseScreenCapture();
};

class InCallObserver {
public:
    virtual ~InCallObserver();

    static InCallObserver& GetInstance();
    void RegisterObserver();
    void UnRegisterObserver();
    void OnCallStateUpdated(bool inCall);
    bool IsInCall();
    std::vector<MediaTelephonyListener *> mediaTelephonyListeners_;
    void RegisterScreenCaptureCallBack(std::weak_ptr<ScreenCaptureObserverCallBack> screenCaptureObserverCallBack);
    void UnRegisterScreenCaptureCallBack(std::weak_ptr<ScreenCaptureObserverCallBack> screenCaptureObserverCallBack);

private:

    std::weak_ptr<ScreenCaptureObserverCallBack> screenCaptureObserverCallBack_;
    InCallObserver();
    bool inCall_;
    std::mutex mutex_;
    bool Init();
    bool isTelephonyStateListenerDied_ = true;
};
}
}
#endif // IN_CALL_OBSERVER_H