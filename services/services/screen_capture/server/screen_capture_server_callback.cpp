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

#include "screen_capture_server.h"

#include <algorithm>
#include <sstream>
#include <vector>

#include "media_dfx.h"
#include "media_log.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "task_queue.h"

using SessionLifecycleEvent = OHOS::Rosen::ISessionLifecycleListener::SessionLifecycleEvent;
using namespace OHOS::Notification;

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServer"};
} // namespace

void ScreenCaptureServer::OnWindowLifecycle(SessionLifecycleEvent event)
{
    MEDIA_LOGI("OnWindowLifecycle event: %{public}d", static_cast<int>(event));
    auto task = std::make_shared<TaskHandler<void>>([this, event] {
        switch (event) {
            case SessionLifecycleEvent::FOREGROUND: {
                std::lock_guard<std::mutex> lock(captureIdsMutex_);
                curWindowLifecycle_ = event;
                CHECK_AND_RETURN(IsCaptureScreen(curWindowInDisplayId_.load()));
                CHECK_AND_RETURN(interestWindowId_ != -1);
                NotifyWindowVisible(static_cast<uint64_t>(interestWindowId_));
                break;
            }
            case SessionLifecycleEvent::BACKGROUND: {
                std::lock_guard<std::mutex> lock(captureIdsMutex_);
                curWindowLifecycle_ = event;
                CHECK_AND_RETURN(IsCaptureScreen(curWindowInDisplayId_.load()));
                NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE, nullptr);
                break;
            }
            case SessionLifecycleEvent::DESTROYED: {
                curWindowLifecycle_ = event;
                NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE,
                    nullptr);
                break;
            }
            default: {
                break;
            }
        }
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnWindowInfoChanged(Rosen::DisplayId displayId)
{
    MEDIA_LOGI("OnWindowInfoChanged displayId: %{public}" PRIu64, displayId);
    auto task = std::make_shared<TaskHandler<void>>([this, displayId] {
        if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
            curWindowInDisplayId_.store(displayId);
        }
        OnCaptureContentChanged();
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnPrivateWindowChange(bool hasPrivate)
{
    MEDIA_LOGI("OnPrivateWindowChange hasPrivate: %{public}u", hasPrivate);
    auto task = std::make_shared<TaskHandler<void>>([this, hasPrivate] {
        MEDIA_LOGI("OnPrivateWindowChange hasPrivateWindow: %{public}u", hasPrivate);
        cbProxy_->OnStateChange(hasPrivate ? AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_ENTER_PRIVATE_SCENE
                                           : AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_EXIT_PRIVATE_SCENE);
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnScreenConnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("OnScreenConnect screenId: %{public}" PRIu64, screenId);
}

void ScreenCaptureServer::OnScreenDisconnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("OnScreenDisconnect screenId: %{public}" PRIu64, screenId);
    auto task = std::make_shared<TaskHandler<void>>([this, screenId] {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        if (IsCaptureScreen(screenId)) {
            NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE,
                nullptr);
        }
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnLanguageSwitch()
{
    MEDIA_LOGI("OnLanguageSwitch");
    auto task = std::make_shared<TaskHandler<void>>([this] {
        NotificationRequest request;
        UpdateLiveViewContent();
        SetupPublishRequest(request);
        NotificationHelper::PublishNotification(request);
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnRecordDisplayChange(const std::vector<Rosen::DisplayId> &displayIds)
{
    auto task = std::make_shared<TaskHandler<void>>([this, displayIds] {
        std::vector<uint64_t> displayIdVec;
        for (auto id : displayIds) {
            MEDIA_LOGD("mirror displays %{public}" PRIu64, id);
            displayIdVec.push_back(static_cast<uint64_t>(id));
        }
        SetDisplayId(std::forward<std::vector<uint64_t> &&>(displayIdVec));
        OnCaptureContentChanged(true);
    });
    taskQue_.EnqueueTask(task);
}

#ifdef SUPPORT_CALL
void ScreenCaptureServer::OnCallStateChanged(bool isInCall)
{
    MEDIA_LOGI("OnCallStateChanged isInCall: %{public}d", isInCall);
    auto task = std::make_shared<TaskHandler<void>>([this, isInCall] {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!captureConfig_.strategy.keepCaptureDuringCall && isInCall && !IsState(CAP_PAUSED)) {
            lock.unlock();
            StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
            Release();
            return;
        }
        CHECK_AND_RETURN(IsState(CAP_ACTIVE));
        if (isInTelCall_.load() == isInCall) {
            return;
        }
        isInTelCall_.store(isInCall);
        SyncAudioCaptures();
    });
    taskQue_.EnqueueTask(task);
}
#endif

void ScreenCaptureServer::OnAccountSwitched()
{
    MEDIA_LOGI("OnAccountSwitched");
    auto task = std::make_shared<TaskHandler<void>>([this] {
        StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER_SWITCHES);
        Release();
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnAudioRendererStateChanged(
    const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    MEDIA_LOGD("OnAudioRendererStateChanged");
    auto task = std::make_shared<TaskHandler<void>>(
        [this, audioRendererChangeInfos] { AudioRendererStateUpdate(audioRendererChangeInfos); });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnBatchLifecycleEvent(
    const std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> &payloads)
{
    MEDIA_LOGI("ScreenCaptureServer::OnBatchLifecycleEvent Start.");
    auto task = std::make_shared<TaskHandler<void>>([this, payloads] {
        nlohmann::json payloadsJson = nlohmann::json::array();
        std::vector<MissionInfo> missionInfos;
        for (auto &payload : payloads) {
            nlohmann::json payloadJson;
            payloadJson["bundleName_"] = payload.bundleName_;
            payloadJson["moduleName_"] = payload.moduleName_;
            payloadJson["abilityName_"] = payload.abilityName_;
            payloadJson["appIndex_"] = payload.appIndex_;
            payloadJson["persistentId_"] = payload.persistentId_;
            payloadJson["appInstanceKey_"] = payload.appInstanceKey_;
            payloadJson["sessionState_"] = payload.sessionState_;
            payloadJson["resultCode_"] = payload.resultCode_;
            payloadJson["fromScreenId_"] = payload.fromScreenId_;
            payloadJson["toScreenId_"] = payload.toScreenId_;
            payloadJson["screenId_"] = payload.screenId_;
            payloadsJson.push_back(payloadJson);

            if (payload.sessionState_ != Rosen::SessionState::STATE_DISCONNECT) {
                bool isForeground = payload.sessionState_ == Rosen::SessionState::STATE_FOREGROUND ||
                    payload.sessionState_ == Rosen::SessionState::STATE_ACTIVE;
                missionInfos.push_back({static_cast<uint64_t>(payload.persistentId_), isForeground});
            }
        }
        if (!missionInfos.empty()) {
            {
                std::lock_guard<std::mutex> lock(captureIdsMutex_);
                missionInfos_ = std::move(missionInfos);
                isGetAppMissionId_ = true;
            }
            FinishPrepareSelectWindow();
        }
        std::string events = payloadsJson.dump(4);
        MEDIA_LOGD("OnBatchLifecycleEvent payloadJsons %{public}s", events.c_str());
    });
    taskQue_.EnqueueTask(task);
}

void ScreenCaptureServer::OnAppInstanceLifecycleEvent(
    const Rosen::ISessionLifecycleListener::LifecycleEventPayload &payload)
{
    MEDIA_LOGI("ScreenCaptureServer::OnAppInstanceLifecycleEvent Start. %{public}d", payload.sessionState_);
    auto task = std::make_shared<TaskHandler<void>>([this, payload] {
        uint64_t missionId = static_cast<uint64_t>(payload.persistentId_);
        std::vector<uint64_t> allIds;
        auto flags = UpdateMissionData(missionId, payload.sessionState_, allIds);
        if (flags & ADD_WHITE_LIST) {
            AddWhiteListWindows(allIds);
        }
        if (flags & REMOVE_WHITE_LIST) {
            RemoveWhiteListWindows({missionId});
        }
        if (flags & NOTIFY_VISIBLE) {
            NotifyWindowVisible(missionId);
        }
        if (flags & NOTIFY_UNAVAILABLE) {
            NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE,
                nullptr);
        }
        if (flags & UPDATE_MIRROR) {
            GetDisplayIdOfWindows();
            ChangeMirrorScreen();
        }
    });
    taskQue_.EnqueueTask(task);
}
} // namespace Media
} // namespace OHOS
