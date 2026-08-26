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

#include "audio_data_source.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "screen_capture_event_listener.h"
#include "screen_capture_listener_manager.h"
#include "screen_capture_server_function_unittest.h"
#include <algorithm>
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ServerCallbackTest"};
} // namespace

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Foreground_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Foreground_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.push_back(screenCaptureServer_->curWindowInDisplayId_.load());
    screenCaptureServer_->interestWindowId_ = 1;
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Foreground_NotCaptureScreen_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Foreground_NotCaptureScreen_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->interestWindowId_ = 1;
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Foreground_EmptyWindowIdList_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Foreground_EmptyWindowIdList_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.push_back(screenCaptureServer_->curWindowInDisplayId_.load());
    screenCaptureServer_->interestWindowId_ = -1;
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Background_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Background_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.push_back(screenCaptureServer_->curWindowInDisplayId_.load());
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Background_NotCaptureScreen_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Background_NotCaptureScreen_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Destroyed_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Destroyed_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::DESTROYED);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::DESTROYED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Default_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Default_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    auto beforeState = screenCaptureServer_->curWindowLifecycle_.load();
    screenCaptureServer_->OnWindowLifecycle(static_cast<Rosen::ISessionLifecycleListener::SessionLifecycleEvent>(999));
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(), beforeState);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowInfoChanged_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowInfoChanged_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.captureMode = CAPTURE_SPECIFIED_WINDOW;
    Rosen::DisplayId displayId = 12345;
    screenCaptureServer_->OnWindowInfoChanged(displayId);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowInDisplayId_.load(), displayId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnScreenDisconnect_InList_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnScreenDisconnect_InList_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    Rosen::ScreenId screenId = 111;
    screenCaptureServer_->sourceDisplayIds_.push_back(screenId);
    screenCaptureServer_->OnScreenDisconnect(screenId);
    WaitForTaskComplete();

    auto it = std::find(screenCaptureServer_->sourceDisplayIds_.begin(), screenCaptureServer_->sourceDisplayIds_.end(),
        screenId);
    ASSERT_TRUE(it != screenCaptureServer_->sourceDisplayIds_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnBatchLifecycleEvent_Foreground_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnBatchLifecycleEvent_Foreground_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_.clear();

    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> payloads;
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 100;
    payload.sessionState_ = Rosen::SessionState::STATE_FOREGROUND;
    payloads.push_back(payload);

    payload.persistentId_ = 200;
    payload.sessionState_ = Rosen::SessionState::STATE_ACTIVE;
    payloads.push_back(payload);

    screenCaptureServer_->OnBatchLifecycleEvent(payloads);
    WaitForTaskComplete();

    auto it100 = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 100; });
    ASSERT_TRUE(it100 != screenCaptureServer_->missionInfos_.end());

    auto itGround = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 100 && m.isForeground; });
    ASSERT_TRUE(itGround != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnBatchLifecycleEvent_Disconnect_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnBatchLifecycleEvent_Disconnect_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{300, true}, {400, true}};

    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> payloads;
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 300;
    payload.sessionState_ = Rosen::SessionState::STATE_DISCONNECT;
    payloads.push_back(payload);

    screenCaptureServer_->OnBatchLifecycleEvent(payloads);
    WaitForTaskComplete();

    auto it300 = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 300; });
    ASSERT_TRUE(it300 != screenCaptureServer_->missionInfos_.end());

    auto it400 = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 400; });
    ASSERT_TRUE(it400 != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_Foreground_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_Foreground_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_.clear();

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 500;
    payload.sessionState_ = Rosen::SessionState::STATE_FOREGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto itGround = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 500 && m.isForeground; });
    ASSERT_TRUE(itGround != screenCaptureServer_->missionInfos_.end());

    auto itIds = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 500; });
    ASSERT_TRUE(itIds != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_Background_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_Background_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{600, true}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 600;
    payload.sessionState_ = Rosen::SessionState::STATE_BACKGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 600 && m.isForeground; });
    ASSERT_TRUE(it == screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_Disconnect_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_Disconnect_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{700, true}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 700;
    payload.sessionState_ = Rosen::SessionState::STATE_DISCONNECT;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 700; });
    ASSERT_TRUE(it == screenCaptureServer_->missionInfos_.end());
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_True_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_True_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_StopByCall_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_StopByCall_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = false;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_CanActive_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_CanActive_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_False_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_False_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isInTelCall_.store(true);

    screenCaptureServer_->OnCallStateChanged(false);
    WaitForTaskComplete();

    ASSERT_FALSE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_SameState_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_SameState_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->isInTelCall_.store(true);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->isInTelCall_.load());
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnScreenConnect_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnScreenConnect_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    Rosen::ScreenId screenId = 111;
    screenCaptureServer_->OnScreenConnect(screenId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnScreenDisconnect_NotInList_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnScreenDisconnect_NotInList_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.clear();
    Rosen::ScreenId screenId = 999;

    screenCaptureServer_->OnScreenDisconnect(screenId);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->sourceDisplayIds_.empty());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnLanguageSwitch_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnLanguageSwitch_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->OnLanguageSwitch();
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnRecordDisplayChange_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnRecordDisplayChange_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    std::vector<Rosen::DisplayId> displayIds = {1, 2, 3};
    screenCaptureServer_->OnRecordDisplayChange(displayIds);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAccountSwitched_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAccountSwitched_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->OnAccountSwitched();
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAudioRendererStateChanged_NullSource_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAudioRendererStateChanged_NullSource_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->audioSource_ = nullptr;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    screenCaptureServer_->OnAudioRendererStateChanged(changeInfos);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->audioSource_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAudioRendererStateChanged_Stopped_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAudioRendererStateChanged_Stopped_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->audioSource_ = std::make_shared<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    screenCaptureServer_->OnAudioRendererStateChanged(changeInfos);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAudioRendererStateChanged_VoIPMatch_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAudioRendererStateChanged_VoIPMatch_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->audioSource_ = std::make_shared<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE,
        screenCaptureServer_.get());
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_
        ->appName_ = GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> changeInfos;
    screenCaptureServer_->OnAudioRendererStateChanged(changeInfos);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnPrivateWindowChange_True_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnPrivateWindowChange_True_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->OnPrivateWindowChange(true);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnPrivateWindowChange_False_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnPrivateWindowChange_False_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->OnPrivateWindowChange(false);
    WaitForTaskComplete();
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_Active_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_Active_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_.clear();

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 800;
    payload.sessionState_ = Rosen::SessionState::STATE_ACTIVE;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 800 && m.isForeground; });
    ASSERT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_Default_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_Default_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{900, true}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 900;
    payload.sessionState_ = static_cast<Rosen::SessionState>(999);
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto itIds = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 900; });
    ASSERT_TRUE(itIds != screenCaptureServer_->missionInfos_.end());

    auto itGround = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 900 && m.isForeground; });
    ASSERT_TRUE(itGround != screenCaptureServer_->missionInfos_.end());
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_PausedState_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_PausedState_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = false;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::PAUSED;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_NotInCall_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_NotInCall_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = false;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(false);
    WaitForTaskComplete();

    ASSERT_FALSE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_NotActive_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_NotActive_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->isInTelCall_.store(false);

    screenCaptureServer_->OnCallStateChanged(true);
    WaitForTaskComplete();

    ASSERT_FALSE(screenCaptureServer_->isInTelCall_.load());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnCallStateChanged_Resumed_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnCallStateChanged_Resumed_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.strategy.keepCaptureDuringCall = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::RESUMED;
    screenCaptureServer_->isInTelCall_.store(true);

    screenCaptureServer_->OnCallStateChanged(false);
    WaitForTaskComplete();

    ASSERT_FALSE(screenCaptureServer_->isInTelCall_.load());
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnBatchLifecycleEvent_EmptyPayloads_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnBatchLifecycleEvent_EmptyPayloads_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->isGetAppMissionId_ = false;

    std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> emptyPayloads;
    screenCaptureServer_->OnBatchLifecycleEvent(emptyPayloads);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->missionInfos_.empty());
    ASSERT_FALSE(screenCaptureServer_->isGetAppMissionId_);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_DisconnectEmptyList_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_DisconnectEmptyList_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{800, true}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 800;
    payload.sessionState_ = Rosen::SessionState::STATE_DISCONNECT;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    ASSERT_TRUE(screenCaptureServer_->missionInfos_.empty());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_ForegroundExisting_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_ForegroundExisting_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{700, false}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 700;
    payload.sessionState_ = Rosen::SessionState::STATE_FOREGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 700 && m.isForeground; });
    ASSERT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_BackgroundNotForeground_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_BackgroundNotForeground_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{600, false}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 600;
    payload.sessionState_ = Rosen::SessionState::STATE_BACKGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 600; });
    ASSERT_TRUE(it != screenCaptureServer_->missionInfos_.end());
    ASSERT_FALSE(it->isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnAppInstanceLifecycleEvent_DisconnectNotInList_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnAppInstanceLifecycleEvent_DisconnectNotInList_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->missionInfos_ = {{500, true}};

    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 999;
    payload.sessionState_ = Rosen::SessionState::STATE_DISCONNECT;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();

    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 500; });
    ASSERT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowInfoChanged_NotSpecifiedWindow_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowInfoChanged_NotSpecifiedWindow_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    auto before = screenCaptureServer_->curWindowInDisplayId_.load();
    Rosen::DisplayId displayId = 54321;
    screenCaptureServer_->OnWindowInfoChanged(displayId);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowInDisplayId_.load(), before);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Foreground_AllConditions_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Foreground_AllConditions_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.push_back(screenCaptureServer_->curWindowInDisplayId_.load());
    screenCaptureServer_->interestWindowId_ = 42;
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnWindowLifecycle_Background_AllConditions_001,
    TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnWindowLifecycle_Background_AllConditions_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    screenCaptureServer_->sourceDisplayIds_.push_back(screenCaptureServer_->curWindowInDisplayId_.load());
    screenCaptureServer_->OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
    WaitForTaskComplete();

    ASSERT_EQ(screenCaptureServer_->curWindowLifecycle_.load(),
        Rosen::ISessionLifecycleListener::SessionLifecycleEvent::BACKGROUND);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ServerCallback_OnScreenDisconnect_InList_AllConditions_001, TestSize.Level2)
{
    MEDIA_LOGI("ServerCallback_OnScreenDisconnect_InList_AllConditions_001 start");
    ASSERT_NE(screenCaptureServer_, nullptr);

    Rosen::ScreenId screenId = 555;
    screenCaptureServer_->sourceDisplayIds_.push_back(screenId);
    screenCaptureServer_->OnScreenDisconnect(screenId);
    WaitForTaskComplete();

    ASSERT_FALSE(screenCaptureServer_->sourceDisplayIds_.empty());
}

HWTEST_F(ScreenCaptureServerFunctionTest, Server_UpdateMissionData_ForegroundExisting_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_ = {{700, false}};
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 700;
    payload.sessionState_ = Rosen::SessionState::STATE_FOREGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();
    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 700 && m.isForeground; });
    EXPECT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, Server_UpdateMissionData_ActiveExisting_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_ = {{800, false}};
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 800;
    payload.sessionState_ = Rosen::SessionState::STATE_ACTIVE;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();
    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 800 && m.isForeground; });
    EXPECT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}

HWTEST_F(ScreenCaptureServerFunctionTest, Server_UpdateMissionData_BackgroundNotForeground_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_ = {{900, false}};
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 900;
    payload.sessionState_ = Rosen::SessionState::STATE_BACKGROUND;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();
    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 900; });
    EXPECT_TRUE(it != screenCaptureServer_->missionInfos_.end());
    EXPECT_FALSE(it->isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, Server_UpdateMissionData_DisconnectNotInList_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_ = {{500, true}};
    Rosen::ISessionLifecycleListener::LifecycleEventPayload payload;
    payload.persistentId_ = 999;
    payload.sessionState_ = Rosen::SessionState::STATE_DISCONNECT;
    screenCaptureServer_->OnAppInstanceLifecycleEvent(payload);
    WaitForTaskComplete();
    auto it = std::find_if(screenCaptureServer_->missionInfos_.begin(), screenCaptureServer_->missionInfos_.end(),
        [](const auto &m) { return m.missionId == 500; });
    EXPECT_TRUE(it != screenCaptureServer_->missionInfos_.end());
}
} // namespace Media
} // namespace OHOS
