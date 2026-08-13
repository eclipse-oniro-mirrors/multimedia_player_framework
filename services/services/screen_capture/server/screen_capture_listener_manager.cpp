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

#include "screen_capture_listener_manager.h"
#include "media_errors.h"
#include "media_log.h"
#include <session_manager_lite.h>

namespace OHOS::Media {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureListenerManager"};

class SceneSessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SceneSessionDeathRecipient(std::weak_ptr<ScreenCaptureListenerManager> manager) : manager_(manager) {}
    ~SceneSessionDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) final
    {
        auto listenerManager = manager_.lock();
        if (listenerManager) {
            listenerManager->OnSceneSessionManagerDied();
        }
    }

private:
    std::weak_ptr<ScreenCaptureListenerManager> manager_;
};

ScreenCaptureListenerManager::ScreenCaptureListenerManager(std::shared_ptr<IScreenCaptureEventListener> listener,
    IScreenCaptureServiceProviders *providers)
    : eventListener_(listener), providers_(providers)
{
    MEDIA_LOGI("ScreenCaptureListenerManager created");
}

ScreenCaptureListenerManager::~ScreenCaptureListenerManager()
{
    MEDIA_LOGI("ScreenCaptureListenerManager destroyed");
    UnregisterListeners();
}

int32_t ScreenCaptureListenerManager::RegisterListeners(uint32_t listenerFlags, const ListenerRegisterParams &params)
{
    MEDIA_LOGI("RegisterListeners start, flags: %{public}u", listenerFlags);
    std::lock_guard<std::mutex> lock(mutex_);

    if (listenerFlags == LF_NONE) {
        MEDIA_LOGI("no listener need to register");
        return MSERR_OK;
    }

    auto listener = eventListener_.lock();
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_INVALID_OPERATION, "eventListener is nullptr or expired");

    if (listenerFlags & (LF_WIN_LIFECYCLE | LF_WIN_INFO)) {
        registerParams_.windowIdList = params.windowIdList;
    }

    if (listenerFlags & LF_AUDIO_RENDERER) {
        registerParams_.appPid = params.appPid;
    }

    if (listenerFlags & LF_APP_LIFECYCLE) {
        registerParams_.appBundleName = params.appBundleName;
        registerParams_.appIndex = params.appIndex;
    }

    SetupSceneSessionManagerDeathRecipient();

    ExecuteIf(listenerFlags, LF_WIN_LIFECYCLE, [this]() { return RegisterWindowLifecycleListener(); });
    ExecuteIf(listenerFlags, LF_WIN_INFO, [this]() { return RegisterWindowInfoChangedListener(); });
    ExecuteIf(listenerFlags, LF_RECORD_DISP, [this]() { return RegisterRecordDisplayListener(); });
    ExecuteIf(listenerFlags, LF_PRIVATE_WIN, [this]() { return RegisterPrivateWindowListener(); });
    ExecuteIf(listenerFlags, LF_SCREEN_CONN, [this]() { return RegisterScreenConnectListener(); });
    ExecuteIf(listenerFlags, LF_LANG_SWITCH, [this]() { return RegisterLanguageSwitchListener(); });
    ExecuteIf(listenerFlags, LF_ACCOUNT, [this]() { return RegisterAccountObserver(); });
#ifdef SUPPORT_CALL
    ExecuteIf(listenerFlags, LF_CALL, [this]() { return RegisterInCallObserver(); });
#endif
    ExecuteIf(listenerFlags, LF_AUDIO_RENDERER, [this]() { return RegisterAudioRendererEventListener(); });
    ExecuteIf(listenerFlags, LF_APP_LIFECYCLE, [this]() { return RegisterAppLifecycleListener(); });

    MEDIA_LOGI("RegisterListeners end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterListeners(uint32_t listenerFlags)
{
    MEDIA_LOGI("UnregisterListeners start, flags: %{public}u", listenerFlags);
    std::lock_guard<std::mutex> lock(mutex_);

    if (listenerFlags == LF_NONE) {
        MEDIA_LOGI("no listener need to unregister");
        return MSERR_OK;
    }

    ExecuteIf(listenerFlags, LF_WIN_LIFECYCLE, [this]() { return UnregisterWindowLifecycleListener(); });
    ExecuteIf(listenerFlags, LF_WIN_INFO, [this]() { return UnregisterWindowInfoChangedListener(); });
    ExecuteIf(listenerFlags, LF_RECORD_DISP, [this]() { return UnregisterRecordDisplayListener(); });
    ExecuteIf(listenerFlags, LF_PRIVATE_WIN, [this]() { return UnregisterPrivateWindowListener(); });
    ExecuteIf(listenerFlags, LF_SCREEN_CONN, [this]() { return UnregisterScreenConnectListener(); });
    ExecuteIf(listenerFlags, LF_LANG_SWITCH, [this]() { return UnregisterLanguageSwitchListener(); });
    ExecuteIf(listenerFlags, LF_ACCOUNT, [this]() { return UnregisterAccountObserver(); });
#ifdef SUPPORT_CALL
    ExecuteIf(listenerFlags, LF_CALL, [this]() { return UnregisterInCallObserver(); });
#endif
    ExecuteIf(listenerFlags, LF_AUDIO_RENDERER, [this]() { return UnregisterAudioRendererEventListener(); });
    ExecuteIf(listenerFlags, LF_APP_LIFECYCLE, [this]() { return UnregisterAppLifecycleListener(); });

    MEDIA_LOGI("UnregisterListeners end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterAudioRendererEventListener()
{
    CHECK_AND_RETURN_RET_LOG(registerParams_.appPid > 0, MSERR_INVALID_OPERATION, "appPid is invalid");

    if (audioRendererCallback_ != nullptr) {
        MEDIA_LOGI("audioRendererCallback already registered");
        return MSERR_OK;
    }

    audioRendererCallback_ = std::make_shared<AudioRendererCallbackWrapper>(eventListener_);

    int32_t ret = AudioStandard::AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(
        registerParams_.appPid, audioRendererCallback_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterAudioRendererEventListener failed");

    MEDIA_LOGI("RegisterAudioRendererEventListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterAudioRendererEventListener()
{
    if (audioRendererCallback_ == nullptr) {
        MEDIA_LOGI("audioRendererCallback already unregistered");
        return MSERR_OK;
    }

    AudioStandard::AudioStreamManager::GetInstance()->UnregisterAudioRendererEventListener(registerParams_.appPid);
    audioRendererCallback_ = nullptr;

    MEDIA_LOGI("UnregisterAudioRendererEventListener end");
    return MSERR_OK;
}

void ScreenCaptureListenerManager::SetupSceneSessionManagerDeathRecipient()
{
    MEDIA_LOGI("SetupSceneSessionManagerDeathRecipient start");

    if (lifecycleListenerDeathRecipient_) {
        MEDIA_LOGI("deathRecipient already setup");
        return;
    }

    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_LOG(sceneSessionManager != nullptr, "sceneSessionManager is nullptr");

    lifecycleListenerDeathRecipient_ = sptr<SceneSessionDeathRecipient>::MakeSptr(weak_from_this());

    auto listenerObject = sceneSessionManager->AsObject();
    if (listenerObject && lifecycleListenerDeathRecipient_) {
        listenerObject->AddDeathRecipient(lifecycleListenerDeathRecipient_);
        MEDIA_LOGI("SetupSceneSessionManagerDeathRecipient success");
    }
}

void ScreenCaptureListenerManager::OnSceneSessionManagerDied()
{
    MEDIA_LOGI("SCB Crash! Please Check!");
    std::lock_guard<std::mutex> lock(mutex_);

    bool hadWindowLifecycle = (windowLifecycleListener_ != nullptr);
    bool hadAppLifecycle = (appLifecycleListener_ != nullptr);

    windowLifecycleListener_ = nullptr;
    appLifecycleListener_ = nullptr;
    lifecycleListenerDeathRecipient_ = nullptr;

    SetupSceneSessionManagerDeathRecipient();

    if (hadWindowLifecycle) {
        int32_t ret = RegisterWindowLifecycleListener();
        CHECK_AND_RETURN_LOG(ret == MSERR_OK, "OnSceneSessionManagerDied: RegisterWindowLifecycleListener failed.");
    }

    if (hadAppLifecycle) {
        int32_t ret = RegisterAppLifecycleListener();
        CHECK_AND_RETURN_LOG(ret == MSERR_OK, "OnSceneSessionManagerDied: RegisterAppLifecycleListener failed.");
    }

    MEDIA_LOGI("OnSceneSessionManagerDied End");
}

int32_t ScreenCaptureListenerManager::RegisterWindowLifecycleListener()
{
    if (windowLifecycleListener_ != nullptr) {
        MEDIA_LOGI("windowLifecycleListener already registered");
        return MSERR_OK;
    }

    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION, "sceneSessionManager is nullptr");

    windowLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(eventListener_);
    CHECK_AND_RETURN_RET_LOG(windowLifecycleListener_ != nullptr, MSERR_INVALID_OPERATION,
        "create windowLifecycleListener failed");

    auto ret = sceneSessionManager->RegisterSessionLifecycleListenerByIds(windowLifecycleListener_,
        registerParams_.windowIdList);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "RegisterSessionLifecycleListenerByIds failed");

    MEDIA_LOGI("RegisterWindowLifecycleListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterWindowLifecycleListener()
{
    if (windowLifecycleListener_ == nullptr) {
        MEDIA_LOGI("windowLifecycleListener already unregistered");
        return MSERR_OK;
    }

    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION, "sceneSessionManager is nullptr");

    if (lifecycleListenerDeathRecipient_) {
        auto listenerObject = sceneSessionManager->AsObject();
        if (listenerObject) {
            listenerObject->RemoveDeathRecipient(lifecycleListenerDeathRecipient_);
        }
        lifecycleListenerDeathRecipient_ = nullptr;
    }

    Rosen::WMError ret = sceneSessionManager->UnregisterSessionLifecycleListener(windowLifecycleListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "UnregisterSessionLifecycleListener failed");

    windowLifecycleListener_ = nullptr;
    MEDIA_LOGI("UnregisterWindowLifecycleListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterWindowInfoChangedListener()
{
    if (windowInfoChangedListener_ != nullptr) {
        MEDIA_LOGI("windowInfoChangedListener already registered");
        return MSERR_OK;
    }

    windowInfoChangedListener_ = sptr<WindowInfoListenerWrapper>::MakeSptr(eventListener_);
    CHECK_AND_RETURN_RET_LOG(windowInfoChangedListener_ != nullptr, MSERR_INVALID_OPERATION,
        "create windowInfoChangedListener failed");

    windowInfoChangedListener_->AddInterestInfo(Rosen::WindowInfoKey::WINDOW_ID);
    CHECK_AND_RETURN_RET_LOG(!registerParams_.windowIdList.empty(), MSERR_INVALID_OPERATION, "windowIdList is empty");
    windowInfoChangedListener_->SetWindowId(registerParams_.windowIdList.front());

    std::unordered_set<Rosen::WindowInfoKey> observedInfo;
    observedInfo.insert(Rosen::WindowInfoKey::DISPLAY_ID);
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().RegisterWindowInfoChangeCallback(observedInfo,
        windowInfoChangedListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "RegisterWindowInfoChangeCallback failed");

    MEDIA_LOGI("RegisterWindowInfoChangedListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterWindowInfoChangedListener()
{
    if (windowInfoChangedListener_ == nullptr) {
        MEDIA_LOGI("windowInfoChangedListener already unregistered");
        return MSERR_OK;
    }

    std::unordered_set<Rosen::WindowInfoKey> observedInfo;
    observedInfo.insert(Rosen::WindowInfoKey::DISPLAY_ID);
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().UnregisterWindowInfoChangeCallback(observedInfo,
        windowInfoChangedListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "UnregisterWindowInfoChangeCallback failed");

    windowInfoChangedListener_ = nullptr;
    MEDIA_LOGI("UnregisterWindowInfoChangedListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterRecordDisplayListener()
{
#ifdef PC_STANDARD
    if (recordDisplayListener_ != nullptr) {
        MEDIA_LOGI("recordDisplayListener already registered");
        return MSERR_OK;
    }

    recordDisplayListener_ = sptr<RecordDisplayListenerWrapper>::MakeSptr(eventListener_);
    auto ret = Rosen::ScreenManager::GetInstance().RegisterRecordDisplayListener(recordDisplayListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_UNKNOWN,
        "register record display listener failed %{public}d", ret);

    MEDIA_LOGI("RegisterRecordDisplayListener success");
#endif
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterRecordDisplayListener()
{
#ifdef PC_STANDARD
    if (recordDisplayListener_ == nullptr) {
        MEDIA_LOGI("recordDisplayListener already unregistered");
        return MSERR_OK;
    }

    auto ret = Rosen::ScreenManager::GetInstance().UnRegisterRecordDisplayListener(recordDisplayListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_UNKNOWN,
        "unregister record display listener failed %{public}d", ret);

    recordDisplayListener_ = nullptr;
    MEDIA_LOGI("UnregisterRecordDisplayListener success");
#endif
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterPrivateWindowListener()
{
    if (privateWindowListener_ != nullptr) {
        MEDIA_LOGI("privateWindowListener already registered");
        return MSERR_OK;
    }

    privateWindowListener_ = sptr<PrivateWindowListenerWrapper>::MakeSptr(eventListener_);
    CHECK_AND_RETURN_RET_LOG(privateWindowListener_ != nullptr, MSERR_NO_MEMORY, "create privateWindowListener failed");

    Rosen::DMError ret = Rosen::DisplayManager::GetInstance().RegisterPrivateWindowListener(privateWindowListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_INVALID_OPERATION,
        "RegisterPrivateWindowListener failed, ret: %{public}d", ret);

    MEDIA_LOGI("RegisterPrivateWindowListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterPrivateWindowListener()
{
    if (privateWindowListener_ == nullptr) {
        MEDIA_LOGI("privateWindowListener already unregistered");
        return MSERR_OK;
    }

    Rosen::DMError ret = Rosen::DisplayManager::GetInstance().UnregisterPrivateWindowListener(privateWindowListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_INVALID_OPERATION,
        "UnregisterPrivateWindowListener failed, ret: %{public}d", ret);

    privateWindowListener_ = nullptr;
    MEDIA_LOGI("UnregisterPrivateWindowListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterScreenConnectListener()
{
    if (screenConnectListener_ != nullptr) {
        MEDIA_LOGI("screenConnectListener already registered");
        return MSERR_OK;
    }

    screenConnectListener_ = sptr<ScreenConnectListenerWrapper>::MakeSptr(eventListener_);
    CHECK_AND_RETURN_RET_LOG(screenConnectListener_ != nullptr, MSERR_NO_MEMORY, "create screenConnectListener failed");

    Rosen::DMError ret = Rosen::ScreenManager::GetInstance().RegisterScreenListener(screenConnectListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_INVALID_OPERATION,
        "RegisterScreenListener failed, ret: %{public}d", ret);

    MEDIA_LOGI("RegisterScreenConnectListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterScreenConnectListener()
{
    if (screenConnectListener_ == nullptr) {
        MEDIA_LOGI("screenConnectListener already unregistered");
        return MSERR_OK;
    }

    Rosen::DMError ret = Rosen::ScreenManager::GetInstance().UnregisterScreenListener(screenConnectListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::DMError::DM_OK, MSERR_INVALID_OPERATION,
        "UnregisterScreenListener failed, ret: %{public}d", ret);

    screenConnectListener_ = nullptr;
    MEDIA_LOGI("UnregisterScreenConnectListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterLanguageSwitchListener()
{
    if (languageSwitchSubscriber_ != nullptr) {
        MEDIA_LOGI("languageSwitchSubscriber already registered");
        return MSERR_OK;
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.LOCALE_CHANGED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    languageSwitchSubscriber_ = std::make_shared<LanguageSwitchSubscriberWrapper>(subscribeInfo, eventListener_);
    CHECK_AND_RETURN_RET_LOG(languageSwitchSubscriber_ != nullptr, MSERR_NO_MEMORY,
        "create languageSwitchSubscriber failed");

    bool ret = EventFwk::CommonEventManager::SubscribeCommonEvent(languageSwitchSubscriber_);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "SubscribeCommonEvent failed");

    MEDIA_LOGI("RegisterLanguageSwitchListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterLanguageSwitchListener()
{
    if (languageSwitchSubscriber_ == nullptr) {
        MEDIA_LOGI("languageSwitchSubscriber already unregistered");
        return MSERR_OK;
    }

    bool ret = EventFwk::CommonEventManager::UnSubscribeCommonEvent(languageSwitchSubscriber_);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "UnSubscribeCommonEvent failed");

    languageSwitchSubscriber_ = nullptr;
    MEDIA_LOGI("UnregisterLanguageSwitchListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::RegisterAccountObserver()
{
    if (accountObserverCallback_ != nullptr) {
        MEDIA_LOGI("accountObserverCallback already registered");
        return MSERR_OK;
    }

    accountObserverCallback_ = std::make_shared<AccountObserverCallbackWrapper>(eventListener_);
    CHECK_AND_RETURN_RET_LOG(accountObserverCallback_ != nullptr, MSERR_NO_MEMORY,
        "create accountObserverCallback failed");

    CHECK_AND_RETURN_RET_LOG(providers_->GetAccountObserver().RegisterAccountObserverCallBack(accountObserverCallback_),
        MSERR_INVALID_OPERATION, "RegisterAccountObserverCallBack failed");

    MEDIA_LOGI("RegisterAccountObserver end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterAccountObserver()
{
    if (accountObserverCallback_ != nullptr) {
        providers_->GetAccountObserver().UnregisterAccountObserverCallBack(accountObserverCallback_);
        accountObserverCallback_ = nullptr;
    }

    MEDIA_LOGI("UnregisterAccountObserver end");
    return MSERR_OK;
}

#ifdef SUPPORT_CALL
int32_t ScreenCaptureListenerManager::RegisterInCallObserver()
{
    if (incallObserverCallback_ != nullptr) {
        MEDIA_LOGI("incallObserverCallback already registered");
        return MSERR_OK;
    }

    incallObserverCallback_ = std::make_shared<InCallObserverCallbackWrapper>(eventListener_);
    CHECK_AND_RETURN_RET_LOG(incallObserverCallback_ != nullptr, MSERR_NO_MEMORY,
        "create incallObserverCallback failed");

    CHECK_AND_RETURN_RET_LOG(providers_->GetInCallObserver().RegisterInCallObserverCallBack(incallObserverCallback_),
        MSERR_INVALID_OPERATION, "RegisterInCallObserverCallBack failed");

    MEDIA_LOGI("RegisterInCallObserver end");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterInCallObserver()
{
    if (incallObserverCallback_ != nullptr) {
        providers_->GetInCallObserver().UnregisterInCallObserverCallBack(incallObserverCallback_);
        incallObserverCallback_ = nullptr;
    }

    MEDIA_LOGI("UnregisterInCallObserver end");
    return MSERR_OK;
}
#endif

void SessionLifecycleListenerWrapper::OnLifecycleEvent(SessionLifecycleEvent event,
    const LifecycleEventPayload &payload)
{
    MEDIA_LOGI("SessionLifecycleListenerWrapper::OnLifecycleEvent %{public}d", static_cast<int>(event));
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnWindowLifecycle(event);
    }
}

void SessionLifecycleListenerWrapper::OnBatchLifecycleEvent(const std::vector<LifecycleEventPayload> &payloads)
{
    MEDIA_LOGI("SessionLifecycleListenerWrapper::OnBatchLifecycleEvent Start.");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnBatchLifecycleEvent(payloads);
    }
    MEDIA_LOGI("SessionLifecycleListenerWrapper::OnBatchLifecycleEvent End.");
}

void SessionLifecycleListenerWrapper::OnAppInstanceLifecycleEvent(const LifecycleEventPayload &payload)
{
    MEDIA_LOGI("SessionLifecycleListenerWrapper::OnAppInstanceLifecycleEvent Start.");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnAppInstanceLifecycleEvent(payload);
    }
    MEDIA_LOGI("SessionLifecycleListenerWrapper::OnAppInstanceLifecycleEvent End.");
}

void WindowInfoListenerWrapper::OnWindowInfoChanged(
    const std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> &windowInfoList)
{
    MEDIA_LOGI("WindowInfoListenerWrapper::OnWindowInfoChanged");

    auto listener = eventListener_.lock();
    if (listener == nullptr || windowInfoList.empty()) {
        MEDIA_LOGE("eventListener is null or windowInfoList is empty");
        return;
    }

    auto iter = windowInfoList.front().find(Rosen::WindowInfoKey::DISPLAY_ID);
    if (iter != windowInfoList.front().end()) {
        uint64_t displayId = std::get<uint64_t>(iter->second);
        MEDIA_LOGI("OnWindowInfoChanged: displayId %{public}" PRIu64, displayId);
        listener->OnWindowInfoChanged(displayId);
    }
}

void WindowInfoListenerWrapper::SetWindowId(int32_t windowId)
{
    interestWindowId_ = windowId;
    AddInterestWindowId(windowId);
}

void RecordDisplayListenerWrapper::OnChange(const std::vector<Rosen::DisplayId> &displayIds)
{
    MEDIA_LOGI("RecordDisplayListenerWrapper::OnChange");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnRecordDisplayChange(displayIds);
    }
}

void PrivateWindowListenerWrapper::OnPrivateWindow(bool hasPrivate)
{
    MEDIA_LOGI("PrivateWindowListenerWrapper::OnPrivateWindow %{public}d", hasPrivate);
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnPrivateWindowChange(hasPrivate);
    }
}

void ScreenConnectListenerWrapper::OnConnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerWrapper::OnConnect %{public}" PRIu64, screenId);
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnScreenConnect(screenId);
    }
}

void ScreenConnectListenerWrapper::OnDisconnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerWrapper::OnDisconnect %{public}" PRIu64, screenId);
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnScreenDisconnect(screenId);
    }
}

void ScreenConnectListenerWrapper::OnChange(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerWrapper::OnChange %{public}" PRIu64, screenId);
}

void LanguageSwitchSubscriberWrapper::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    MEDIA_LOGI("LanguageSwitchSubscriberWrapper::OnReceiveEvent");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnLanguageSwitch();
    }
}

AccountObserverCallbackWrapper::AccountObserverCallbackWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
    : eventListener_(listener)
{
    MEDIA_LOGI("AccountObserverCallbackWrapper created");
}

bool AccountObserverCallbackWrapper::OnAccountsSwitch()
{
    MEDIA_LOGI("AccountObserverCallbackWrapper::OnAccountsSwitch");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnAccountSwitched();
    }
    return true;
}

#ifdef SUPPORT_CALL
InCallObserverCallbackWrapper::InCallObserverCallbackWrapper(std::weak_ptr<IScreenCaptureEventListener> listener)
    : eventListener_(listener)
{
    MEDIA_LOGI("InCallObserverCallbackWrapper created");
}

bool InCallObserverCallbackWrapper::OnTelCallStateUpdated(bool isInCall)
{
    MEDIA_LOGI("InCallObserverCallbackWrapper::OnTelCallStateUpdated %{public}d", isInCall);
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnCallStateChanged(isInCall);
    }
    return true;
}
#endif

void AudioRendererCallbackWrapper::OnRendererStateChange(
    const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    MEDIA_LOGD("AudioRendererCallbackWrapper::OnRendererStateChange");
    auto listener = eventListener_.lock();
    if (listener) {
        listener->OnAudioRendererStateChanged(audioRendererChangeInfos);
    }
}

int32_t ScreenCaptureListenerManager::RegisterAppLifecycleListener()
{
    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION,
        "sceneSessionManager is nullptr, RegisterAppLifecycleListener failed.");

    SetupSceneSessionManagerDeathRecipient();

    if (appLifecycleListener_ != nullptr) {
        MEDIA_LOGI("appLifecycleListener already registered");
        return MSERR_OK;
    }

    appLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(eventListener_);
    CHECK_AND_RETURN_RET_LOG(appLifecycleListener_ != nullptr, MSERR_INVALID_OPERATION,
        "create appLifecycleListener failed.");

    Rosen::WMError ret = sceneSessionManager->RegisterSessionLifecycleListenerByAppInstance(appLifecycleListener_,
        registerParams_.appBundleName, registerParams_.appIndex, "");
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "RegisterSessionLifecycleListenerByAppInstance failed.");

    MEDIA_LOGI("RegisterAppLifecycleListener end.");
    return MSERR_OK;
}

int32_t ScreenCaptureListenerManager::UnregisterAppLifecycleListener()
{
    if (appLifecycleListener_ == nullptr) {
        MEDIA_LOGI("appLifecycleListener already unregistered");
        return MSERR_OK;
    }

    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION,
        "sceneSessionManager is nullptr, UnregisterAppLifecycleListener failed.");

    if (lifecycleListenerDeathRecipient_) {
        auto listenerObject = sceneSessionManager->AsObject();
        if (listenerObject) {
            listenerObject->RemoveDeathRecipient(lifecycleListenerDeathRecipient_);
        }
        lifecycleListenerDeathRecipient_ = nullptr;
    }

    Rosen::WMError ret = sceneSessionManager->UnregisterSessionLifecycleListener(appLifecycleListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "UnregisterSessionLifecycleListener failed.");

    appLifecycleListener_ = nullptr;
    MEDIA_LOGI("UnregisterAppLifecycleListener end.");
    return MSERR_OK;
}
} // namespace OHOS::Media
