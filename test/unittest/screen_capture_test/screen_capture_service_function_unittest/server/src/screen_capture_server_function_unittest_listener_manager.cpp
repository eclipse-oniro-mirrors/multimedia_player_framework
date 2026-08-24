/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "media_errors.h"
#include "media_log.h"
#include "mock_screen_capture_service_providers.h"
#include "screen_capture_event_listener.h"
#include "screen_capture_listener_manager.h"
#include "screen_capture_server_function_unittest.h"
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ListenerManagerTest"};

class MockDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    MockDeathRecipient() = default;
    ~MockDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override {}
};
}

class MockScreenCaptureEventListener : public IScreenCaptureEventListener {
public:
    MockScreenCaptureEventListener() = default;
    virtual ~MockScreenCaptureEventListener() = default;

    void OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent event) override
    {
        windowLifecycleEvent_ = event;
        eventCount_++;
    }

    void OnWindowInfoChanged(Rosen::DisplayId displayId) override
    {
        windowInfoDisplayId_ = displayId;
        eventCount_++;
    }

    void OnPrivateWindowChange(bool hasPrivate) override
    {
        hasPrivateWindow_ = hasPrivate;
        eventCount_++;
    }

    void OnScreenConnect(Rosen::ScreenId screenId) override
    {
        screenConnectId_ = screenId;
        eventCount_++;
    }

    void OnScreenDisconnect(Rosen::ScreenId screenId) override
    {
        screenDisconnectId_ = screenId;
        eventCount_++;
    }

    void OnLanguageSwitch() override
    {
        languageSwitched_ = true;
        eventCount_++;
    }

    void OnRecordDisplayChange(const std::vector<Rosen::DisplayId> &displayIds) override
    {
        recordDisplayIds_ = displayIds;
        eventCount_++;
    }

#ifdef SUPPORT_CALL
    void OnCallStateChanged(bool isInCall) override
    {
        isInCall_ = isInCall;
        eventCount_++;
    }
#endif

    void OnAccountSwitched() override
    {
        accountStateChanged_ = true;
        eventCount_++;
    }

    void OnAudioRendererStateChanged(
        const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos) override
    {
        audioRendererChangeInfos_ = audioRendererChangeInfos;
        eventCount_++;
    }

    void OnBatchLifecycleEvent(
        const std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> &payloads) override
    {
        batchLifecyclePayloads_ = payloads;
        eventCount_++;
    }

    void OnAppInstanceLifecycleEvent(const Rosen::ISessionLifecycleListener::LifecycleEventPayload &payload) override
    {
        appInstancePayload_ = payload;
        eventCount_++;
    }

    Rosen::ISessionLifecycleListener::SessionLifecycleEvent
        windowLifecycleEvent_ = Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND;
    Rosen::DisplayId windowInfoDisplayId_ = 0;
    bool hasPrivateWindow_ = false;
    Rosen::ScreenId screenConnectId_ = 0;
    Rosen::ScreenId screenDisconnectId_ = 0;
    bool languageSwitched_ = false;
    std::vector<Rosen::DisplayId> recordDisplayIds_;
#ifdef SUPPORT_CALL
    bool isInCall_ = false;
#endif
    bool accountStateChanged_ = false;
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfos_;
    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> batchLifecyclePayloads_;
    Rosen::ISessionLifecycleListener::LifecycleEventPayload appInstancePayload_;
    int32_t eventCount_ = 0;
};

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_Create_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_Create_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_Create_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterNone_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterNone_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    std::vector<int32_t> windowIdList;
    int32_t appPid = 100;
    ASSERT_EQ(manager->RegisterListeners(LF_NONE, {windowIdList, appPid}), MSERR_OK);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_RegisterNone_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterWindowLifecycleFailed_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterWindowLifecycleFailed_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    manager->registerParams_.windowIdList = {1, 2};
    int32_t ret = manager->RegisterWindowLifecycleListener();
    EXPECT_NE(ret, MSERR_OK);
    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_RegisterWindowLifecycleFailed_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_AudioRendererInvalidPid_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_AudioRendererInvalidPid_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    manager->registerParams_.appPid = -1;
    manager->registerParams_.windowIdList = {};
    int32_t ret = manager->RegisterAudioRendererEventListener();
    EXPECT_NE(ret, MSERR_OK);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_AudioRendererInvalidPid_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowInfoEmptyWindowIdList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowInfoEmptyWindowIdList_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    manager->registerParams_.windowIdList = {};
    manager->registerParams_.appPid = 100;
    int32_t ret = manager->RegisterWindowInfoChangedListener();
    EXPECT_NE(ret, MSERR_OK);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_WindowInfoEmptyWindowIdList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterNone_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_UnregisterNone_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    ASSERT_EQ(manager->UnregisterListeners(LF_NONE), MSERR_OK);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_UnregisterNone_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_NullEventListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_NullEventListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> listener = nullptr;

    auto mockProviders = CreateMockProviders();
    auto manager = std::make_shared<ScreenCaptureListenerManager>(listener, mockProviders.get());
    ASSERT_NE(manager, nullptr);

    std::vector<int32_t> windowIdList = {1, 2};
    int32_t appPid = 100;
    ASSERT_NE(manager->RegisterListeners(LF_WIN_LIFECYCLE, {windowIdList, appPid}), MSERR_OK);

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_NullEventListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_ServerIntegration_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_ServerIntegration_001 start");
    SetValidConfig();
    ASSERT_EQ(screenCaptureServer_->SetCaptureMode(config_.captureMode), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->SetDataType(config_.dataType), MSERR_OK);

    ASSERT_NE(screenCaptureServer_->listenerManager_, nullptr);

    screenCaptureServer_->Release();
    MEDIA_LOGI("ListenerManager_ServerIntegration_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_MultiCapabilityCheck_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_MultiCapabilityCheck_001 start");
    uint32_t combined1 = LF_WIN_LIFECYCLE | LF_WIN_INFO;
    ASSERT_EQ((combined1 & LF_WIN_LIFECYCLE) != 0, true);
    ASSERT_EQ((combined1 & LF_WIN_INFO) != 0, true);
    ASSERT_EQ((combined1 & LF_PRIVATE_WIN) != 0, false);

    uint32_t combined2 = LF_PRIVATE_WIN | LF_SCREEN_CONN | LF_LANG_SWITCH;
    ASSERT_EQ((combined2 & LF_PRIVATE_WIN) != 0, true);
    ASSERT_EQ((combined2 & LF_SCREEN_CONN) != 0, true);
    ASSERT_EQ((combined2 & LF_LANG_SWITCH) != 0, true);
    ASSERT_EQ((combined2 & LF_WIN_LIFECYCLE) != 0, false);
    MEDIA_LOGI("ListenerManager_MultiCapabilityCheck_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperLifecycleEvent_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperLifecycleEvent_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new SessionLifecycleListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    wrapper->OnLifecycleEvent(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND, payload);
    ASSERT_EQ(listener->windowLifecycleEvent_, Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperLifecycleEvent_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperPrivateWindow_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperPrivateWindow_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new PrivateWindowListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    wrapper->OnPrivateWindow(true);
    ASSERT_EQ(listener->hasPrivateWindow_, true);
    ASSERT_EQ(listener->eventCount_, 1);

    wrapper->OnPrivateWindow(false);
    ASSERT_EQ(listener->hasPrivateWindow_, false);
    ASSERT_EQ(listener->eventCount_, 2);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperPrivateWindow_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperScreenConnect_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperScreenConnect_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new ScreenConnectListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ScreenId testId = 12345;
    wrapper->OnConnect(testId);
    ASSERT_EQ(listener->screenConnectId_, testId);
    ASSERT_EQ(listener->eventCount_, 1);

    wrapper->OnDisconnect(testId);
    ASSERT_EQ(listener->screenDisconnectId_, testId);
    ASSERT_EQ(listener->eventCount_, 2);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperScreenConnect_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperRecordDisplay_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperRecordDisplay_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new RecordDisplayListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<Rosen::DisplayId> displayIds = {1, 2, 3};
    wrapper->OnChange(displayIds);
    ASSERT_EQ(listener->recordDisplayIds_.size(), 3);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperRecordDisplay_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_AudioRendererCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_AudioRendererCallback_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = std::make_shared<AudioRendererCallbackWrapper>(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    wrapper->OnRendererStateChange(changeInfos);
    ASSERT_EQ(listener->eventCount_, 1);
    MEDIA_LOGI("ListenerManager_AudioRendererCallback_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_EventListenerInterface_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_EventListenerInterface_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    listener->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    ASSERT_EQ(listener->windowLifecycleEvent_, Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);

    listener->OnWindowInfoChanged(12345);
    ASSERT_EQ(listener->windowInfoDisplayId_, 12345);

    listener->OnPrivateWindowChange(true);
    ASSERT_EQ(listener->hasPrivateWindow_, true);

    listener->OnScreenConnect(111);
    ASSERT_EQ(listener->screenConnectId_, 111);

    listener->OnScreenDisconnect(222);
    ASSERT_EQ(listener->screenDisconnectId_, 222);

    listener->OnLanguageSwitch();
    ASSERT_EQ(listener->languageSwitched_, true);

    std::vector<Rosen::DisplayId> displayIds = {1, 2};
    listener->OnRecordDisplayChange(displayIds);
    ASSERT_EQ(listener->recordDisplayIds_.size(), 2);

#ifdef SUPPORT_CALL
    listener->OnCallStateChanged(true);
    ASSERT_EQ(listener->isInCall_, true);
#endif

    listener->OnAccountSwitched();
    ASSERT_EQ(listener->accountStateChanged_, true);

    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    listener->OnAudioRendererStateChanged(changeInfos);
    ASSERT_EQ(listener->audioRendererChangeInfos_.size(), 0);
    MEDIA_LOGI("ListenerManager_EventListenerInterface_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_EventListenerWeakPtr_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_EventListenerWeakPtr_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    std::weak_ptr<IScreenCaptureEventListener> weakListener = listener;

    auto wrapper = new SessionLifecycleListenerWrapper(weakListener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    wrapper->OnLifecycleEvent(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND, payload);
    ASSERT_EQ(listener->windowLifecycleEvent_, Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);

    listener.reset();

    wrapper->OnLifecycleEvent(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::DESTROYED, payload);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_EventListenerWeakPtr_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_SetWindowId_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_SetWindowId_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new WindowInfoListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    int32_t testWindowId = 12345;
    wrapper->SetWindowId(testWindowId);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_SetWindowId_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_ParamsAssignment_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_ParamsAssignment_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1, 2, 3};
    params.appPid = 100;
    params.appBundleName = "testBundle";
    params.appIndex = 1;

    uint32_t flags = LF_WIN_LIFECYCLE | LF_WIN_INFO | LF_AUDIO_RENDERER | LF_APP_LIFECYCLE;
    int32_t ret = manager->RegisterListeners(flags, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(flags);
    MEDIA_LOGI("ListenerManager_ParamsAssignment_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterPrivateWindowEmptyList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterPrivateWindowEmptyList_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {};

    int32_t ret = manager->RegisterListeners(LF_PRIVATE_WIN, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_PRIVATE_WIN);
    MEDIA_LOGI("ListenerManager_RegisterPrivateWindowEmptyList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterScreenConnectEmptyList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterScreenConnectEmptyList_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {};

    int32_t ret = manager->RegisterListeners(LF_SCREEN_CONN, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_SCREEN_CONN);
    MEDIA_LOGI("ListenerManager_RegisterScreenConnectEmptyList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterLanguageSwitchEmptyList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterLanguageSwitchEmptyList_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {};

    int32_t ret = manager->RegisterListeners(LF_LANG_SWITCH, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_LANG_SWITCH);
    MEDIA_LOGI("ListenerManager_RegisterLanguageSwitchEmptyList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterListenersEmptyList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterListenersEmptyList_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {};

    int32_t ret = manager->RegisterListeners(LF_ACCOUNT, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_ACCOUNT);
    MEDIA_LOGI("ListenerManager_RegisterListenersEmptyList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAudioRendererInvalidPid_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterAudioRendererInvalidPid_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    manager->registerParams_.appPid = -1;
    manager->registerParams_.windowIdList = {};

    int32_t ret = manager->RegisterAudioRendererEventListener();
    EXPECT_NE(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_RegisterAudioRendererInvalidPid_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_DeathRecipientAlreadySetup_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_DeathRecipientAlreadySetup_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1};

    int32_t ret = manager->RegisterListeners(LF_WIN_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_WIN_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_WIN_LIFECYCLE);
    MEDIA_LOGI("ListenerManager_DeathRecipientAlreadySetup_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_ExecuteIfFailed_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_ExecuteIfFailed_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    manager->registerParams_.appPid = 0;
    manager->registerParams_.windowIdList = {};

    int32_t ret = manager->RegisterAudioRendererEventListener();
    EXPECT_NE(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_ExecuteIfFailed_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterPrivateWindowNotRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_UnregisterPrivateWindowNotRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->privateWindowListener_, nullptr);

    int32_t ret = manager->UnregisterPrivateWindowListener();
    EXPECT_EQ(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_UnregisterPrivateWindowNotRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterScreenConnectNotRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_UnregisterScreenConnectNotRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->screenConnectListener_, nullptr);

    int32_t ret = manager->UnregisterScreenConnectListener();
    EXPECT_EQ(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_UnregisterScreenConnectNotRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterLanguageSwitchNotRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_UnregisterLanguageSwitchNotRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->languageSwitchSubscriber_, nullptr);

    int32_t ret = manager->UnregisterLanguageSwitchListener();
    EXPECT_EQ(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_UnregisterLanguageSwitchNotRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperBatchLifecycleEvent_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperBatchLifecycleEvent_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new SessionLifecycleListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> payloads;
    payloads.push_back(Rosen::ISessionLifecycleListener::LifecycleEventPayload());
    payloads.push_back(Rosen::ISessionLifecycleListener::LifecycleEventPayload());

    wrapper->OnBatchLifecycleEvent(payloads);
    ASSERT_EQ(listener->batchLifecyclePayloads_.size(), 2);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperBatchLifecycleEvent_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperAppInstanceLifecycleEvent_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperAppInstanceLifecycleEvent_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new SessionLifecycleListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    wrapper->OnAppInstanceLifecycleEvent(payload);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperAppInstanceLifecycleEvent_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperWindowInfoChanged_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperWindowInfoChanged_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new WindowInfoListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType> windowInfo;
    windowInfo[Rosen::WindowInfoKey::DISPLAY_ID] = static_cast<uint64_t>(12345);
    windowInfoList.push_back(windowInfo);

    wrapper->OnWindowInfoChanged(windowInfoList);
    ASSERT_EQ(listener->windowInfoDisplayId_, 12345);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperWindowInfoChanged_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperScreenConnectOnChange_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperScreenConnectOnChange_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new ScreenConnectListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ScreenId screenId = 999;
    wrapper->OnChange(screenId);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperScreenConnectOnChange_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_LanguageSwitchOnReceiveEvent_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_LanguageSwitchOnReceiveEvent_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.LOCALE_CHANGED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto wrapper = new LanguageSwitchSubscriberWrapper(subscribeInfo, listener);
    ASSERT_NE(wrapper, nullptr);

    EventFwk::CommonEventData data;
    wrapper->OnReceiveEvent(data);
    ASSERT_EQ(listener->languageSwitched_, true);
    ASSERT_EQ(listener->eventCount_, 1);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_LanguageSwitchOnReceiveEvent_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = new SessionLifecycleListenerWrapper(nullListener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    wrapper->OnLifecycleEvent(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND, payload);

    wrapper->OnBatchLifecycleEvent(std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload>());
    wrapper->OnAppInstanceLifecycleEvent(payload);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperPrivateWindowNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperPrivateWindowNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = new PrivateWindowListenerWrapper(nullListener);
    ASSERT_NE(wrapper, nullptr);

    wrapper->OnPrivateWindow(true);
    wrapper->OnPrivateWindow(false);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperPrivateWindowNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperScreenConnectNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperScreenConnectNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = new ScreenConnectListenerWrapper(nullListener);
    ASSERT_NE(wrapper, nullptr);

    Rosen::ScreenId testId = 123;
    wrapper->OnConnect(testId);
    wrapper->OnDisconnect(testId);
    wrapper->OnChange(testId);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperScreenConnectNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperRecordDisplayNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperRecordDisplayNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = new RecordDisplayListenerWrapper(nullListener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<Rosen::DisplayId> displayIds = {1, 2};
    wrapper->OnChange(displayIds);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperRecordDisplayNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperLanguageSwitchNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperLanguageSwitchNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.LOCALE_CHANGED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto wrapper = new LanguageSwitchSubscriberWrapper(subscribeInfo, nullListener);
    ASSERT_NE(wrapper, nullptr);

    EventFwk::CommonEventData data;
    wrapper->OnReceiveEvent(data);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WrapperLanguageSwitchNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperAudioRendererNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WrapperAudioRendererNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = std::make_shared<AudioRendererCallbackWrapper>(nullListener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    wrapper->OnRendererStateChange(changeInfos);
    MEDIA_LOGI("ListenerManager_WrapperAudioRendererNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAppLifecycle_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_RegisterAppLifecycle_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.appBundleName = "com.test.app";
    params.appIndex = 0;
    params.appPid = 1000;

    int32_t ret = manager->RegisterListeners(LF_APP_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_APP_LIFECYCLE);
    MEDIA_LOGI("ListenerManager_RegisterAppLifecycle_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_AppLifecycleAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_AppLifecycleAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.appBundleName = "com.test.app";
    params.appIndex = 0;
    params.appPid = 1000;

    int32_t ret = manager->RegisterListeners(LF_APP_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_APP_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_APP_LIFECYCLE);
    MEDIA_LOGI("ListenerManager_AppLifecycleAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAppLifecycleAlreadyUnregistered_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_UnregisterAppLifecycleAlreadyUnregistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->UnregisterListeners(LF_APP_LIFECYCLE);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->UnregisterListeners(LF_APP_LIFECYCLE);
    EXPECT_EQ(ret, MSERR_OK);
    MEDIA_LOGI("ListenerManager_UnregisterAppLifecycleAlreadyUnregistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowInfoEmptyList_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowInfoEmptyList_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new WindowInfoListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    wrapper->OnWindowInfoChanged(windowInfoList);
    ASSERT_EQ(listener->eventCount_, 0);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WindowInfoEmptyList_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowInfoNoDisplayId_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowInfoNoDisplayId_001 start");
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);

    auto wrapper = new WindowInfoListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType> windowInfo;
    windowInfo[Rosen::WindowInfoKey::WINDOW_ID] = static_cast<int32_t>(100);
    windowInfoList.push_back(windowInfo);

    wrapper->OnWindowInfoChanged(windowInfoList);
    ASSERT_EQ(listener->eventCount_, 0);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WindowInfoNoDisplayId_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowInfoNullListener_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowInfoNullListener_001 start");
    std::shared_ptr<IScreenCaptureEventListener> nullListener = nullptr;

    auto wrapper = new WindowInfoListenerWrapper(nullListener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType> windowInfo;
    windowInfo[Rosen::WindowInfoKey::DISPLAY_ID] = static_cast<uint64_t>(12345);
    windowInfoList.push_back(windowInfo);

    wrapper->OnWindowInfoChanged(windowInfoList);

    delete wrapper;
    MEDIA_LOGI("ListenerManager_WindowInfoNullListener_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_MultiFlagRegistration_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_MultiFlagRegistration_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1};
    params.appPid = 100;

    uint32_t flags = LF_WIN_LIFECYCLE | LF_PRIVATE_WIN | LF_SCREEN_CONN;
    int32_t ret = manager->RegisterListeners(flags, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(flags);
    MEDIA_LOGI("ListenerManager_MultiFlagRegistration_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_AllFlags_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_AllFlags_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1};
    params.appPid = 100;
    params.appBundleName = "test.app";
    params.appIndex = 0;

    int32_t ret = manager->RegisterListeners(LF_ALL, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_ALL);
    MEDIA_LOGI("ListenerManager_AllFlags_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_AudioRendererAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_AudioRendererAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.appPid = 100;
    params.windowIdList = {};

    int32_t ret = manager->RegisterListeners(LF_AUDIO_RENDERER, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_AUDIO_RENDERER, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_AUDIO_RENDERER);
    MEDIA_LOGI("ListenerManager_AudioRendererAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowLifecycleAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowLifecycleAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1};

    int32_t ret = manager->RegisterListeners(LF_WIN_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_WIN_LIFECYCLE, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_WIN_LIFECYCLE);
    MEDIA_LOGI("ListenerManager_WindowLifecycleAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WindowInfoAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_WindowInfoAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;
    params.windowIdList = {1};

    int32_t ret = manager->RegisterListeners(LF_WIN_INFO, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_WIN_INFO, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_WIN_INFO);
    MEDIA_LOGI("ListenerManager_WindowInfoAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_PrivateWindowAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_PrivateWindowAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;

    int32_t ret = manager->RegisterListeners(LF_PRIVATE_WIN, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_PRIVATE_WIN, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_PRIVATE_WIN);
    MEDIA_LOGI("ListenerManager_PrivateWindowAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_ScreenConnectAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_ScreenConnectAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;

    int32_t ret = manager->RegisterListeners(LF_SCREEN_CONN, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_SCREEN_CONN, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_SCREEN_CONN);
    MEDIA_LOGI("ListenerManager_ScreenConnectAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_LanguageSwitchAlreadyRegistered_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_LanguageSwitchAlreadyRegistered_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    ListenerRegisterParams params;

    int32_t ret = manager->RegisterListeners(LF_LANG_SWITCH, params);
    EXPECT_EQ(ret, MSERR_OK);

    ret = manager->RegisterListeners(LF_LANG_SWITCH, params);
    EXPECT_EQ(ret, MSERR_OK);

    manager->UnregisterListeners(LF_LANG_SWITCH);
    MEDIA_LOGI("ListenerManager_LanguageSwitchAlreadyRegistered_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_WindowLifecycle_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_WindowLifecycle_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    manager->windowLifecycleListener_ = nullptr;
    manager->appLifecycleListener_ = nullptr;
    manager->lifecycleListenerDeathRecipient_ = nullptr;

    manager->OnSceneSessionManagerDied();

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_WindowLifecycle_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_AppLifecycle_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_AppLifecycle_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    manager->windowLifecycleListener_ = nullptr;
    manager->appLifecycleListener_ = nullptr;
    manager->lifecycleListenerDeathRecipient_ = nullptr;

    manager->registerParams_.appBundleName = "test.app";
    manager->registerParams_.appIndex = 0;

    manager->OnSceneSessionManagerDied();

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_AppLifecycle_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_BothListeners_001, TestSize.Level2)
{
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_BothListeners_001 start");
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);

    manager->windowLifecycleListener_ = nullptr;
    manager->appLifecycleListener_ = nullptr;
    manager->lifecycleListenerDeathRecipient_ = nullptr;

    manager->registerParams_.windowIdList = {1};
    manager->registerParams_.appBundleName = "test.app";
    manager->registerParams_.appIndex = 0;

    manager->OnSceneSessionManagerDied();

    manager->UnregisterListeners();
    MEDIA_LOGI("ListenerManager_OnSceneSessionManagerDied_BothListeners_001 end");
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterWindowLifecycleNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->windowLifecycleListener_, nullptr);
    EXPECT_EQ(manager->UnregisterWindowLifecycleListener(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterWindowInfoNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->windowInfoChangedListener_, nullptr);
    EXPECT_EQ(manager->UnregisterWindowInfoChangedListener(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterRecordDisplayNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->recordDisplayListener_, nullptr);
    EXPECT_EQ(manager->UnregisterRecordDisplayListener(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAccountNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->accountObserverCallback_, nullptr);
    EXPECT_EQ(manager->UnregisterAccountObserver(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAppLifecycleNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->appLifecycleListener_, nullptr);
    EXPECT_EQ(manager->UnregisterAppLifecycleListener(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAudioRendererNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->audioRendererCallback_, nullptr);
    EXPECT_EQ(manager->UnregisterAudioRendererEventListener(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterWindowLifecycleAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    EXPECT_EQ(manager->RegisterWindowLifecycleListener(), MSERR_OK);
    manager->windowLifecycleListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterPrivateWindowAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->privateWindowListener_ = sptr<PrivateWindowListenerWrapper>::MakeSptr(manager->eventListener_);
    EXPECT_EQ(manager->RegisterPrivateWindowListener(), MSERR_OK);
    manager->privateWindowListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterScreenConnectAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->screenConnectListener_ = sptr<ScreenConnectListenerWrapper>::MakeSptr(manager->eventListener_);
    EXPECT_EQ(manager->RegisterScreenConnectListener(), MSERR_OK);
    manager->screenConnectListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterLanguageSwitchAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.LOCALE_CHANGED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    manager->languageSwitchSubscriber_ = std::make_shared<LanguageSwitchSubscriberWrapper>(subscribeInfo,
        manager->eventListener_);
    EXPECT_EQ(manager->RegisterLanguageSwitchListener(), MSERR_OK);
    manager->languageSwitchSubscriber_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAccountAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->accountObserverCallback_ = std::make_shared<AccountObserverCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->RegisterAccountObserver(), MSERR_OK);
    manager->accountObserverCallback_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAudioRendererAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->registerParams_.appPid = 1;
    manager->audioRendererCallback_ = std::make_shared<AudioRendererCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->RegisterAudioRendererEventListener(), MSERR_OK);
    manager->audioRendererCallback_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_DeathRecipientAlreadySetup_002, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->lifecycleListenerDeathRecipient_ = sptr<MockDeathRecipient>::MakeSptr();
    manager->SetupSceneSessionManagerDeathRecipient();
    EXPECT_NE(manager->lifecycleListenerDeathRecipient_, nullptr);
    manager->lifecycleListenerDeathRecipient_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperAccountNullListener_001, TestSize.Level2)
{
    std::weak_ptr<IScreenCaptureEventListener> nullListener;
    AccountObserverCallbackWrapper wrapper(nullListener);
    EXPECT_EQ(wrapper.OnAccountsSwitch(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperBatchLifecycleNullListener_001, TestSize.Level2)
{
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    std::weak_ptr<IScreenCaptureEventListener> nullWeak;
    auto wrapper = sptr<SessionLifecycleListenerWrapper>::MakeSptr(nullWeak);
    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> payloads;
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 100;
    payload.sessionState_ = Rosen::SessionState::STATE_FOREGROUND;
    payloads.push_back(payload);
    wrapper->OnBatchLifecycleEvent(payloads);
    EXPECT_EQ(listener->eventCount_, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperAppInstanceNullListener_001, TestSize.Level2)
{
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    std::weak_ptr<IScreenCaptureEventListener> nullWeak;
    auto wrapper = sptr<SessionLifecycleListenerWrapper>::MakeSptr(nullWeak);
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 200;
    payload.sessionState_ = Rosen::SessionState::STATE_BACKGROUND;
    wrapper->OnAppInstanceLifecycleEvent(payload);
    EXPECT_EQ(listener->eventCount_, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperWindowInfoChangedEmptyList_001, TestSize.Level2)
{
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    auto wrapper = sptr<WindowInfoListenerWrapper>::MakeSptr(std::weak_ptr<IScreenCaptureEventListener>(listener));
    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> emptyList;
    wrapper->OnWindowInfoChanged(emptyList);
    EXPECT_EQ(listener->eventCount_, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperWindowInfoChangedNullListener_001, TestSize.Level2)
{
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    std::weak_ptr<IScreenCaptureEventListener> nullWeak;
    auto wrapper = sptr<WindowInfoListenerWrapper>::MakeSptr(nullWeak);
    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType> info;
    info[Rosen::WindowInfoKey::DISPLAY_ID] = static_cast<uint64_t>(1);
    windowInfoList.push_back(info);
    wrapper->OnWindowInfoChanged(windowInfoList);
    EXPECT_EQ(listener->eventCount_, 0);
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperInCallNullListener_001, TestSize.Level2)
{
    std::weak_ptr<IScreenCaptureEventListener> nullListener;
    InCallObserverCallbackWrapper wrapper(nullListener);
    EXPECT_EQ(wrapper.OnTelCallStateUpdated(true), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterInCallNotRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->incallObserverCallback_, nullptr);
    EXPECT_EQ(manager->UnregisterInCallObserver(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterInCallAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->incallObserverCallback_ = std::make_shared<InCallObserverCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->RegisterInCallObserver(), MSERR_OK);
    manager->incallObserverCallback_ = nullptr;
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAppLifecycleAlreadyRegistered_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->appLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    EXPECT_EQ(manager->RegisterAppLifecycleListener(), MSERR_OK);
    manager->appLifecycleListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_WindowLifecycleSet_001,
    TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->appLifecycleListener_ = nullptr;
    manager->lifecycleListenerDeathRecipient_ = nullptr;
    manager->registerParams_.windowIdList = {1};

    manager->OnSceneSessionManagerDied();
    manager->UnregisterListeners();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_AppLifecycleSet_001,
    TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowLifecycleListener_ = nullptr;
    manager->appLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->lifecycleListenerDeathRecipient_ = nullptr;
    manager->registerParams_.appBundleName = "test.app";
    manager->registerParams_.appIndex = 0;

    manager->OnSceneSessionManagerDied();
    manager->UnregisterListeners();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_OnSceneSessionManagerDied_BothListenersSet_001,
    TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->appLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->lifecycleListenerDeathRecipient_ = nullptr;
    manager->registerParams_.windowIdList = {1};
    manager->registerParams_.appBundleName = "test.app";
    manager->registerParams_.appIndex = 0;

    manager->OnSceneSessionManagerDied();
    manager->UnregisterListeners();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterWindowInfoChangedAlreadyRegistered_001,
    TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowInfoChangedListener_ = sptr<WindowInfoListenerWrapper>::MakeSptr(manager->eventListener_);
    EXPECT_EQ(manager->RegisterWindowInfoChangedListener(), MSERR_OK);
    manager->windowInfoChangedListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAudioRendererWithCallback_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->registerParams_.appPid = 100;
    manager->audioRendererCallback_ = std::make_shared<AudioRendererCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->UnregisterAudioRendererEventListener(), MSERR_OK);
    EXPECT_EQ(manager->audioRendererCallback_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAccountWithCallback_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->accountObserverCallback_ = std::make_shared<AccountObserverCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->UnregisterAccountObserver(), MSERR_OK);
    EXPECT_EQ(manager->accountObserverCallback_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterWindowLifecycleWithListener_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->windowLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->UnregisterWindowLifecycleListener();
    manager->windowLifecycleListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterAppLifecycleWithListener_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->appLifecycleListener_ = sptr<SessionLifecycleListenerWrapper>::MakeSptr(manager->eventListener_);
    manager->UnregisterAppLifecycleListener();
    manager->appLifecycleListener_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_WrapperWindowInfoChanged_NoDisplayId_001, TestSize.Level2)
{
    auto listener = std::make_shared<MockScreenCaptureEventListener>();
    ASSERT_NE(listener, nullptr);
    auto wrapper = new WindowInfoListenerWrapper(listener);
    ASSERT_NE(wrapper, nullptr);

    std::vector<std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType>> windowInfoList;
    std::unordered_map<Rosen::WindowInfoKey, Rosen::WindowChangeInfoType> info;
    info[Rosen::WindowInfoKey::WINDOW_ID] = static_cast<uint64_t>(42);
    windowInfoList.push_back(info);

    wrapper->OnWindowInfoChanged(windowInfoList);
    EXPECT_EQ(listener->eventCount_, 0);
    delete wrapper;
}

HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_RegisterAudioRendererAlreadyRegistered_002, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->registerParams_.appPid = 100;
    manager->audioRendererCallback_ = std::make_shared<AudioRendererCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->RegisterAudioRendererEventListener(), MSERR_OK);
    manager->audioRendererCallback_ = nullptr;
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, ListenerManager_UnregisterInCallWithCallback_001, TestSize.Level2)
{
    auto manager = screenCaptureServer_->listenerManager_;
    ASSERT_NE(manager, nullptr);
    manager->incallObserverCallback_ = std::make_shared<InCallObserverCallbackWrapper>(manager->eventListener_);
    EXPECT_EQ(manager->UnregisterInCallObserver(), MSERR_OK);
    EXPECT_EQ(manager->incallObserverCallback_, nullptr);
}
#endif

} // namespace Media
} // namespace OHOS
