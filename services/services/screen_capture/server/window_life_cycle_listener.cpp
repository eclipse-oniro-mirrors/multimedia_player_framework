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
#include "window_life_cycle_listener.h"
#include "screen_capture_server.h"
#include "media_log.h"
#include "media_utils.h"
 
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "SCWindowLifecycleListener"};
}
 
namespace OHOS::Media {
SCWindowLifecycleListener::SCWindowLifecycleListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " SCWindowLifecycleListener Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}
 
void SCWindowLifecycleListener::OnLifecycleEvent(SessionLifecycleEvent event, const LifecycleEventPayload& payload)
{
    MEDIA_LOGI("SCWindowLifecycleListener::OnLifecycleEvent Start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");
    SCServer->OnWindowLifecycle(event);
    MEDIA_LOGI("SCWindowLifecycleListener::OnLifecycleEvent End.");
}
 
void SCWindowLifecycleListener::OnBatchLifecycleEvent(const std::vector<LifecycleEventPayload>& payloads)
{
    MEDIA_LOGI("SCWindowLifecycleListener::OnBatchLifecycleEvent Start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");
    nlohmann::json payloadsJson = nlohmann::json::array();
    std::vector<uint64_t> missionIds;
    for (auto& payload : payloads) {
        payloadsJson.push_back(SetLogJson(payload));
        if (payload.sessionState_ != SessionState::STATE_DISCONNECT) {
            missionIds.emplace_back(payload.persistentId_);
        }
        if (payload.sessionState_ == SessionState::STATE_CONNECT ||
            payload.sessionState_ == SessionState::STATE_FOREGROUND) {
            SCServer->SetAppMissionIdsGround(payload.persistentId_);
        }
    }
    if (!missionIds.empty()) {
        SCServer->SetAppMissionIds(missionIds);
    }
    std::string events = payloadsJson.dump(4);
    MEDIA_LOGD("OnBatchLifecycleEvent payloadJsons %{public}s", events.c_str());
    MEDIA_LOGI("OnBatchLifecycleEvent End.");
}

void SCWindowLifecycleListener::OnAppInstanceLifecycleEvent(const LifecycleEventPayload& payload)
{
    MEDIA_LOGI("SCWindowLifecycleListener::OnAppInstanceLifecycleEvent Start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");
    switch (payload.sessionState_) {
        case SessionState::STATE_CONNECT:
        case SessionState::STATE_FOREGROUND: {
            MEDIA_LOGI("OnAppInstanceLifecycleEvent: SessionState::STATE_FOREGROUND OR SessionState::STATE_CONNECT");
            SCServer->SetAppMissionIds(payload.persistentId_);
            SCServer->SetAppMissionIdsGround(payload.persistentId_);
            break;
        }
        case SessionState::STATE_BACKGROUND: {
            MEDIA_LOGI("OnAppInstanceLifecycleEvent: SessionState::STATE_BACKGROUND");
            SCServer->RemoveAppMissionIdsGround(payload.persistentId_);
            break;
        }
        case SessionState::STATE_DISCONNECT: {
            MEDIA_LOGI("OnAppInstanceLifecycleEvent: SessionState::STATE_DISCONNECT");
            SCServer->RemoveAppMissionIds(payload.persistentId_);
            break;
        }
        default: {
            MEDIA_LOGD("OnAppInstanceLifecycleEvent: other event");
            break;
        }
    }
    std::string events = SetLogJson(payload).dump(4);
    MEDIA_LOGD("OnAppInstanceLifecycleEvent payloadJson %{public}s", events.c_str());
    MEDIA_LOGI("OnAppInstanceLifecycleEvent End.");
}

nlohmann::json SCWindowLifecycleListener::SetLogJson(const LifecycleEventPayload& payload)
{
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
    return payloadJson;
}

}