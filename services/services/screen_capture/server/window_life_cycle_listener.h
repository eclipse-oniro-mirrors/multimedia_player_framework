/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#ifndef WINDOW_LIFE_CYCLE_LISTENER_H
#define WINDOW_LIFE_CYCLE_LISTENER_H
 
#include "window_manager.h"
#include "session_manager_lite.h"
#include "window_manager_lite.h"
#include "session_lifecycle_listener_stub.h"
#include <memory>
#include "json/json.h"

namespace OHOS {
namespace Media {
class ScreenCaptureServer;
 
class SCWindowLifecycleListener : public Rosen::SessionLifecycleListenerStub {
public:
    explicit SCWindowLifecycleListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~SCWindowLifecycleListener() override = default;
    void OnLifecycleEvent(SessionLifecycleEvent event, const LifecycleEventPayload& payload) override;
    void OnBatchLifecycleEvent(const std::vector<LifecycleEventPayload>& payloads) override;
    void OnAppInstanceLifecycleEvent(const LifecycleEventPayload& payload) override;

private:
    nlohmann::json SetLogJson(const LifecycleEventPayload& payload);

    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};
}
}
#endif // WINDOW_LIFE_CYCLE_LISTENER_H