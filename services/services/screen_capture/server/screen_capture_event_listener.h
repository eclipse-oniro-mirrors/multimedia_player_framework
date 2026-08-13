/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_EVENT_LISTENER_H
#define SCREEN_CAPTURE_EVENT_LISTENER_H

#include "audio_stream_manager.h"
#include "display_manager.h"
#include "screen_manager.h"
#include "session_lifecycle_listener_stub.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace OHOS::Media {

class IScreenCaptureEventListener {
  public:
    virtual ~IScreenCaptureEventListener() = default;

    virtual void OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent event) = 0;
    virtual void OnWindowInfoChanged(Rosen::DisplayId displayId) = 0;
    virtual void OnPrivateWindowChange(bool hasPrivate) = 0;
    virtual void OnScreenConnect(Rosen::ScreenId screenId) = 0;
    virtual void OnScreenDisconnect(Rosen::ScreenId screenId) = 0;
    virtual void OnLanguageSwitch() = 0;
    virtual void OnRecordDisplayChange(const std::vector<Rosen::DisplayId> &displayIds) = 0;
#ifdef SUPPORT_CALL
    virtual void OnCallStateChanged(bool isInCall) = 0;
#endif
    virtual void OnAccountSwitched() = 0;
    virtual void OnAudioRendererStateChanged(
        const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos) = 0;
    virtual void
    OnBatchLifecycleEvent(const std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> &payloads) = 0;
    virtual void
    OnAppInstanceLifecycleEvent(const Rosen::ISessionLifecycleListener::LifecycleEventPayload &payload) = 0;
};

} // namespace OHOS::Media

#endif // SCREEN_CAPTURE_EVENT_LISTENER_H
