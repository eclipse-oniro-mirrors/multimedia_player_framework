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
 
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "DfxAgent" };
constexpr int64_t LAG_EVENT_THRESHOLD_MS = 500; // Lag threshold is 500 ms
}
 
namespace OHOS {
namespace Media {
 
DfxAgent::DfxAgent(const std::string& groupId, const std::string& appName) : groupId_(groupId), appName_(appName)
{
    dfxTask_ = std::make_unique<Task>("OS_Ply_Dfx", groupId_, TaskType::GLOBAL, TaskPriority::NORMAL, false);
    MEDIA_LOG_I("DfxAgent create for app " PUBLIC_LOG_S, appName_.c_str());
}
 
DfxAgent::~DfxAgent()
{
    dfxTask_.reset();
}
 
void DfxAgent::SetDemuxer(std::weak_ptr<Pipeline::DemuxerFilter> demuxer)
{
    demuxer_ = demuxer;
}
 
void DfxAgent::SetSourceType(PlayerDfxSourceType type)
{
    sourceType_ = type;
}
 
void DfxAgent::SetInstanceId(const std::string& instanceId)
{
    instanceId_ = instanceId;
}
 
void DfxAgent::OnAudioLagEvent(int64_t lagDuration)
{
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Audio";
    ReportLagEvent(lagDuration, msg);
}
 
void DfxAgent::OnVideoLagEvent(int64_t lagDuration)
{
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Video";
    ReportLagEvent(lagDuration, msg);
}
 
void DfxAgent::OnStreamLagEvent(int64_t lagDuration)
{
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS);
    std::string msg = "lagEvent=Stream";
    ReportLagEvent(lagDuration, msg);
}
 
bool DfxAgent::GetNetworkInfo(std::string& networkInfo)
{
    auto demuxer = demuxer_.lock();
    FALSE_RETURN_V(demuxer != nullptr, false);
    DownloadInfo downLoadInfo;
    auto ret = demuxer->GetDownloadInfo(downLoadInfo);
    if (ret != Status::OK) {
        networkInfo = "";
        return false;
    }
    networkInfo = (";timeout=" + std::to_string(downLoadInfo.isTimeOut));
    networkInfo += (";avgDownloadSpeed=" + std::to_string(downLoadInfo.avgDownloadSpeed));
    return true;
}
 
void DfxAgent::ReportLagEvent(int64_t lagDuration, const std::string& eventMsg)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    dfxTask_->SubmitJobOnce([this, lagDuration, eventMsg] {
        FALSE_RETURN(!hasReported_);
        std::string msg = eventMsg;
        std::string netInfo = "";
        if (GetNetworkInfo(netInfo)) {
            msg += netInfo;
        }
        MEDIA_LOG_W("PLAYER_LAG event reported, lagDuration=" PUBLIC_LOG_D64 ", msg=" PUBLIC_LOG_S,
            lagDuration, eventMsg.c_str());
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA,
            "PLAYER_LAG",
            OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
            "APP_NAME", appName_,
            "INSTANCE_ID", instanceId_,
            "SOURCE_TYPE", static_cast<uint8_t>(sourceType_),
            "LAG_DURATION", static_cast<int32_t>(lagDuration),
            "MSG", msg);
        hasReported_ = true;
    });
}
void DfxAgent::ResetAgent()
{
    FALSE_RETURN(dfxTask_ != nullptr);
    dfxTask_->SubmitJobOnce([this] {
        hasReported_ = false;
    });
}
}  // namespace Media
}  // namespace OHOS