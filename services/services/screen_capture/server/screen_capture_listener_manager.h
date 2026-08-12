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

#ifndef SCREEN_CAPTURE_LISTENER_MANAGER_H
#define SCREEN_CAPTURE_LISTENER_MANAGER_H

#include "screen_capture.h"
#include "screen_capture_event_listener.h"
#include "screen_capture_service_providers.h"
#include <audio_stream_manager.h>
#include <common_event_manager.h>
#include <cstdint>
#include <display_manager.h>
#include <memory>
#include <mutex>
#include <screen_manager.h>
#include <vector>
#include <window_manager.h>
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif
#include "account_observer.h"

namespace OHOS::Media {

enum ListenerFlag : uint32_t {
    LF_NONE = 0,
    LF_WIN_LIFECYCLE = 1 << 0,
    LF_WIN_INFO = 1 << 1,
    LF_RECORD_DISP = 1 << 2,
    LF_PRIVATE_WIN = 1 << 3,
    LF_SCREEN_CONN = 1 << 4,
    LF_LANG_SWITCH = 1 << 5,
    LF_ACCOUNT = 1 << 6,
#ifdef SUPPORT_CALL
    LF_CALL = 1 << 7,
#endif
    LF_AUDIO_RENDERER = 1 << 8,
    LF_APP_LIFECYCLE = 1 << 9,
    LF_ALL = LF_WIN_LIFECYCLE | LF_WIN_INFO | LF_RECORD_DISP | LF_PRIVATE_WIN | LF_SCREEN_CONN | LF_LANG_SWITCH |
        LF_ACCOUNT | LF_AUDIO_RENDERER | LF_APP_LIFECYCLE,
};

class SessionLifecycleListenerWrapper : public Rosen::SessionLifecycleListenerStub {
public:
    explicit SessionLifecycleListenerWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
        : eventListener_(listener)
    {
    }
    ~SessionLifecycleListenerWrapper() override = default;

    void OnLifecycleEvent(SessionLifecycleEvent event, const LifecycleEventPayload &payload) override;
    void OnBatchLifecycleEvent(const std::vector<LifecycleEventPayload> &payloads) override;
    void OnAppInstanceLifecycleEvent(const LifecycleEventPayload &payload) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

class WindowInfoListenerWrapper : public Rosen::IWindowInfoChangedListener {
public:
    explicit WindowInfoListenerWrapper(std::weak_ptr<IScreenCaptureEventListener> listener) : eventListener_(listener)
    {
    }
    ~WindowInfoListenerWrapper() override = default;

    void OnWindowInfoChanged(
        const std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> &windowInfoList)
        override;

    void SetWindowId(int32_t windowId);

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
    int32_t interestWindowId_ = -1;
};

class RecordDisplayListenerWrapper : public Rosen::ScreenManager::IRecordDisplayListener {
public:
    explicit RecordDisplayListenerWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
        : eventListener_(listener)
    {
    }
    ~RecordDisplayListenerWrapper() override = default;

    void OnChange(const std::vector<Rosen::DisplayId> &displayIds) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

class PrivateWindowListenerWrapper : public Rosen::DisplayManager::IPrivateWindowListener {
public:
    explicit PrivateWindowListenerWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
        : eventListener_(listener)
    {
    }
    ~PrivateWindowListenerWrapper() override = default;

    void OnPrivateWindow(bool hasPrivate) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

class ScreenConnectListenerWrapper : public Rosen::ScreenManager::IScreenListener {
public:
    explicit ScreenConnectListenerWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
        : eventListener_(listener)
    {
    }
    ~ScreenConnectListenerWrapper() override = default;

    void OnConnect(Rosen::ScreenId screenId) override;
    void OnDisconnect(Rosen::ScreenId screenId) override;
    void OnChange(Rosen::ScreenId screenId) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

class LanguageSwitchSubscriberWrapper : public EventFwk::CommonEventSubscriber {
public:
    LanguageSwitchSubscriberWrapper(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        std::weak_ptr<IScreenCaptureEventListener> listener)
        : EventFwk::CommonEventSubscriber(subscribeInfo), eventListener_(listener)
    {
    }
    ~LanguageSwitchSubscriberWrapper() override = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

class AccountObserverCallbackWrapper : public AccountObserverCallBack {
public:
    explicit AccountObserverCallbackWrapper(std::weak_ptr<IScreenCaptureEventListener> listener);
    ~AccountObserverCallbackWrapper() override = default;

    bool OnAccountsSwitch() override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

#ifdef SUPPORT_CALL
class InCallObserverCallbackWrapper : public InCallObserverCallBack {
public:
    explicit InCallObserverCallbackWrapper(std::weak_ptr<IScreenCaptureEventListener> listener);
    ~InCallObserverCallbackWrapper() override = default;

    bool OnTelCallStateUpdated(bool isInCall) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};
#endif

class AudioRendererCallbackWrapper : public AudioStandard::AudioRendererStateChangeCallback {
public:
    explicit AudioRendererCallbackWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
        : eventListener_(listener)
    {
    }
    ~AudioRendererCallbackWrapper() override = default;

    void OnRendererStateChange(
        const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos) override;

private:
    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
};

struct ListenerRegisterParams {
    std::vector<int32_t> windowIdList;
    int32_t appPid = -1;
    std::string appBundleName;
    int32_t appIndex = 0;
};

class ScreenCaptureListenerManager : public std::enable_shared_from_this<ScreenCaptureListenerManager> {
public:
    ScreenCaptureListenerManager(std::shared_ptr<IScreenCaptureEventListener> listener,
        IScreenCaptureServiceProviders *providers);
    ~ScreenCaptureListenerManager();

    int32_t RegisterListeners(uint32_t listenerFlags, const ListenerRegisterParams &params);
    int32_t UnregisterListeners(uint32_t listenerFlags = LF_ALL);
    void OnSceneSessionManagerDied();

private:
    template <typename Func>
    int32_t ExecuteIf(uint32_t listenerFlags, uint32_t flag, Func func)
    {
        if (listenerFlags & flag) {
            return func();
        }
        return MSERR_OK;
    }

    void SetupSceneSessionManagerDeathRecipient();

    int32_t RegisterWindowLifecycleListener();
    int32_t UnregisterWindowLifecycleListener();

    int32_t RegisterWindowInfoChangedListener();
    int32_t UnregisterWindowInfoChangedListener();

    int32_t RegisterRecordDisplayListener();
    int32_t UnregisterRecordDisplayListener();

    int32_t RegisterPrivateWindowListener();
    int32_t UnregisterPrivateWindowListener();

    int32_t RegisterScreenConnectListener();
    int32_t UnregisterScreenConnectListener();

    int32_t RegisterLanguageSwitchListener();
    int32_t UnregisterLanguageSwitchListener();

    int32_t RegisterAccountObserver();
    int32_t UnregisterAccountObserver();

#ifdef SUPPORT_CALL
    int32_t RegisterInCallObserver();
    int32_t UnregisterInCallObserver();
#endif

    int32_t RegisterAudioRendererEventListener();
    int32_t UnregisterAudioRendererEventListener();
    int32_t RegisterAppLifecycleListener();
    int32_t UnregisterAppLifecycleListener();

    std::weak_ptr<IScreenCaptureEventListener> eventListener_;
    IScreenCaptureServiceProviders *providers_;

    sptr<SessionLifecycleListenerWrapper> windowLifecycleListener_;
    sptr<SessionLifecycleListenerWrapper> appLifecycleListener_;
    sptr<WindowInfoListenerWrapper> windowInfoChangedListener_;
    sptr<RecordDisplayListenerWrapper> recordDisplayListener_;
    sptr<PrivateWindowListenerWrapper> privateWindowListener_;
    sptr<ScreenConnectListenerWrapper> screenConnectListener_;
    sptr<IRemoteObject::DeathRecipient> lifecycleListenerDeathRecipient_;
    std::shared_ptr<LanguageSwitchSubscriberWrapper> languageSwitchSubscriber_;
    std::shared_ptr<AccountObserverCallbackWrapper> accountObserverCallback_;
#ifdef SUPPORT_CALL
    std::shared_ptr<InCallObserverCallbackWrapper> incallObserverCallback_;
#endif
    std::shared_ptr<AudioRendererCallbackWrapper> audioRendererCallback_;

    ListenerRegisterParams registerParams_;
    std::mutex mutex_;
};
} // namespace OHOS::Media

#endif // SCREEN_CAPTURE_LISTENER_MANAGER_H
