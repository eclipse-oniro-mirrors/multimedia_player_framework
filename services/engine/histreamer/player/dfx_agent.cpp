/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#define HST_LOG_TAG "DfxAgent"

#include "dfx_agent.h"
#include "common/log.h"
#include "common/media_source.h"
#include "hisysevent.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "DfxAgent" };
    constexpr int64_t LAG_EVENT_THRESHOLD_MS = 500; // Lag threshold is 500 ms
    ConcurrentUidSet g_appUidSet{};
}

const std::map<DfxEventType, DfxEventHandleFunc> DfxAgent::DFX_EVENT_HANDLERS_ = {
    { DfxEventType::DFX_INFO_PLAYER_VIDEO_LAG, DfxAgent::ProcessVideoLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_AUDIO_LAG, DfxAgent::ProcessAudioLagEvent },
<<<<<<< HEAD
=======
    { DfxEventType::DFX_INFO_PLAYER_STREAM_LAG, DfxAgent::ProcessStreamLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_EOS_SEEK, DfxAgent::ProcessEosSeekEvent },
>>>>>>> master
};

 
DfxAgent::DfxAgent(const std::string& groupId, const std::string& appName) : groupId_(groupId), appName_(appName)
{
    dfxTask_ = std::make_unique<Task>("OS_Ply_Dfx", groupId_, TaskType::GLOBAL, TaskPriority::NORMAL, false);
    MEDIA_LOG_I("DfxAgent create for app " PUBLIC_LOG_S, appName_.c_str());
}
 
DfxAgent::~DfxAgent()
{
    dfxTask_.reset();
}
 
void DfxAgent::SetSourceType(PlayerDfxSourceType type)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent, type] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        ptr->sourceType_ = type;
    });
}
 
void DfxAgent::SetInstanceId(const std::string& instanceId)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent, instanceId] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        ptr->instanceId_ = instanceId;
    });
}
 
void DfxAgent::OnDfxEvent(const DfxEvent &event)
{
    auto ret = DfxAgent::DFX_EVENT_HANDLERS_.find(event.type);
    FALSE_RETURN(ret != DfxAgent::DFX_EVENT_HANDLERS_.end());
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent, event, handler = ret->second] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        handler(ptr, event);
    });
}
 
void DfxAgent::ReportLagEvent(int64_t lagDuration, const std::string& eventMsg)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent, lagDuration, eventMsg] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        FALSE_RETURN(!(ptr->hasReported_));
        std::string msg = eventMsg;
        MEDIA_LOG_W("PLAYER_LAG event reported, lagDuration=" PUBLIC_LOG_D64 ", msg=" PUBLIC_LOG_S,
            lagDuration, eventMsg.c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA,
            "PLAYER_LAG",
            OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
            "APP_NAME", ptr->appName_,
            "INSTANCE_ID", ptr->instanceId_,
            "SOURCE_TYPE", static_cast<uint8_t>(ptr->sourceType_),
            "LAG_DURATION", static_cast<int32_t>(lagDuration),
            "MSG", msg);
        ptr->hasReported_ = true;
    });
}

void DfxAgent::ReportEosSeek0Event(int32_t appUid)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    dfxTask_->SubmitJobOnce([appUid, appName = appName_] {
        FALSE_RETURN(g_appUidSet.IsAppFirstEvent(appUid));
        MEDIA_LOG_I("EOS_SEEK_0 event reported, appName = %{public}s appUid = %{public}d", appName.c_str(), appUid);
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA,
            "EOS_SEEK_0",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "APP_NAME", appName,
            "APP_UID", appUid);
    });
}

void DfxAgent::ResetAgent()
{
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        ptr->hasReported_ = false;
    });
}

void DfxAgent::ProcessVideoLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    int64_t lagDuration = AnyCast<int64_t>(event.param);
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Video";
    agent->ReportLagEvent(lagDuration, msg);
}
 
void DfxAgent::ProcessAudioLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    int64_t lagDuration = AnyCast<int64_t>(event.param);
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Audio";
    agent->ReportLagEvent(lagDuration, msg);
}
<<<<<<< HEAD
=======
 
void DfxAgent::ProcessStreamLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    int64_t lagDuration = AnyCast<int64_t>(event.param);
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Stream";
    agent->ReportLagEvent(lagDuration, msg);
}

void DfxAgent::ProcessEosSeekEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    int64_t appUid = AnyCast<int32_t>(event.param);
    agent->ReportEosSeek0Event(appUid);
}
>>>>>>> master
}  // namespace Media
}  // namespace OHOS