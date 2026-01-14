/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <charconv>
#include "dfx_agent.h"
#include "common/log.h"
#include "common/media_source.h"
#include "hisysevent.h"
#include "media_dfx.h"
#include "format.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "DfxAgent" };
    constexpr int64_t LAG_EVENT_THRESHOLD_MS = 500; // Lag threshold is 500 ms
    constexpr int64_t LAG_EVENT_UPPER_MS = 5000; // Lag upper threshold is 5000 ms
    constexpr int64_t TIME_S1_MS = 2; // 2ms
    constexpr int64_t TIME_S2_MS = 10; // 10ms
    constexpr int64_t TIME_S3_MS = 3; // 3ms
    ConcurrentUidSet g_appUidSet{};
    const std::string SOURCE = "SRC";
    const std::string DEMUXER = "DEMUX";
    const std::string VIDEO_SINK = "VSINK";
    const std::string AUDIO_SINK = "ASINK";
    const std::string VIDEO_RENDERER = "VRNDR";

    struct StallingTimestamps {
        int64_t timeDemuxerStart = 0;
        int64_t timeDecoderStart = 0;
        int64_t timeAVSyncStart = 0;
        int64_t timeRenderStart = 0;
        int64_t timePreFrameRender = 0;
        int64_t timeFrameInterval = 0;
        int64_t timeCurFramePts = 0;
    };
}

const std::map<DfxEventType, DfxEventHandleFunc> DfxAgent::DFX_EVENT_HANDLERS_ = {
    { DfxEventType::DFX_INFO_PLAYER_VIDEO_LAG, DfxAgent::ProcessVideoLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_AUDIO_LAG, DfxAgent::ProcessAudioLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_STREAM_LAG, DfxAgent::ProcessStreamLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_EOS_SEEK, DfxAgent::ProcessEosSeekEvent },
    { DfxEventType::DFX_INFO_PERF_REPORT, DfxAgent::ProcessPerfInfoEvent },
    { DfxEventType::DFX_EVENT_STALLING, DfxAgent::ProcessMetricsEvent }
};

const std::unordered_map<std::string, bool> PERF_ITEM_NECESSITY = {
    { SOURCE, false },
    { DEMUXER, false },
    { VIDEO_SINK, true },
    { AUDIO_SINK, false },
    { VIDEO_RENDERER, true },
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

void DfxAgent::SetMetricsCallback(DfxEventHandleFunc cb)
{
    FALSE_RETURN(dfxTask_ != nullptr);
    std::weak_ptr<DfxAgent> agent = shared_from_this();
    dfxTask_->SubmitJobOnce([agent, cb] {
        auto ptr = agent.lock();
        FALSE_RETURN_MSG(ptr != nullptr, "DfxAgent is released");
        ptr->metricsCallback_ = cb;
    });
}

void DfxAgent::ProcessVideoLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto perfStr = agent->GetPerfStr(false);
    MEDIA_LOG_W("%{public}s", perfStr.c_str());
    agent->needPrintPerfLog_ = true;
    int64_t lagDuration = AnyCast<int64_t>(event.param);
    FALSE_RETURN(lagDuration >= LAG_EVENT_THRESHOLD_MS && lagDuration <= LAG_EVENT_UPPER_MS);
    std::string msg = "lagEvent=Video ";
    agent->ReportLagEvent(lagDuration, msg + perfStr);
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

void DfxAgent::ProcessPerfInfoEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    agent->UpdateDfxInfo(event);
}

void DfxAgent::ProcessMetricsEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    agent->ReportMetricsEvent(event);
}

void DfxAgent::UpdateDfxInfo(const DfxEvent &event)
{
    auto data = AnyCast<MainPerfData>(event.param);
    perfDataMap_.insert_or_assign(event.callerName, data);
    FALSE_RETURN_NOLOG(needPrintPerfLog_);
    MEDIA_LOG_D("%{public}s", GetPerfStr(true).c_str());
}

static bool ExtractStallingTimestamps(const std::vector<int64_t>& timeStampList, StallingTimestamps& ts)
{
    std::unordered_map<int64_t, int64_t*> stageMap = {
        {static_cast<int64_t>(StallingStage::DEMUXER_START), &ts.timeDemuxerStart},
        {static_cast<int64_t>(StallingStage::DECODER_START), &ts.timeDecoderStart},
        {static_cast<int64_t>(StallingStage::AVSYNC_START), &ts.timeAVSyncStart},
        {static_cast<int64_t>(StallingStage::RENDERER_START), &ts.timeRenderStart},
        {static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), &ts.timePreFrameRender},
        {static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), &ts.timeFrameInterval},
        {static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), &ts.timeCurFramePts},
    };

    size_t foundCount = 0;
    size_t step = 2;
    for (size_t i = 0; i + 1 < timeStampList.size(); i += step) {
        int64_t stage = timeStampList[i];
        auto it = stageMap.find(stage);
        if (it != stageMap.end()) {
            *(it->second) = timeStampList[i + 1];
            ++foundCount;
            MEDIA_LOG_D("ExtractStallingTimestamps: found stage=%" PRId64 ", value=%" PRId64,
                stage, timeStampList[i + 1]);
        } else {
            MEDIA_LOG_D("ExtractStallingTimestamps: not found stage=%" PRId64, stage);
        }
    }
    return foundCount == stageMap.size();
}

static std::string BuildStageStr(int64_t expected, const StallingTimestamps& ts)
{
    std::string str{};

    if (ts.timeDemuxerStart > (expected - TIME_S1_MS - TIME_S2_MS - TIME_S3_MS)) {
        MEDIA_LOG_I("PLAYER_LAG stalling lag at loader stage.");
        str = "Loader";
    }
    if (ts.timeDemuxerStart < (expected - TIME_S1_MS - TIME_S2_MS - TIME_S3_MS)) {
        MEDIA_LOG_I("PLAYER_LAG stalling lag at demuxer stage.");
        str = "Demuxer";
    }
    if (ts.timeDecoderStart < (expected - TIME_S2_MS - TIME_S3_MS)) {
        MEDIA_LOG_I("PLAYER_LAG stalling lag at decoder stage.");
        str = "Decoder";
    }
    if (ts.timeAVSyncStart < (expected - TIME_S3_MS)) {
        MEDIA_LOG_I("PLAYER_LAG stalling lag at AVSync stage.");
        str = "AVSync";
    }
    return str;
}

int64_t DfxAgent::CalculateEventTimestamp(int64_t steadyMs)
{
    int64_t systemStartTimeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count() -
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
    return systemStartTimeStamp + steadyMs;
}

void DfxAgent::ReportMetricsEvent(const DfxEvent &event)
{
    auto timeStampList = AnyCast<std::vector<int64_t>>(event.param);
    StallingTimestamps ts;
    FALSE_RETURN(ExtractStallingTimestamps(timeStampList, ts));
    auto expected = ts.timePreFrameRender + ts.timeFrameInterval;
    int64_t delayTimeMs = ts.timeRenderStart - expected;
    totalStallingDuration_.fetch_add(delayTimeMs);
    totalStallingTimes_.fetch_add(1);
    FALSE_RETURN(delayTimeMs >= 0);

    AVMetricsEvent info {
        .timeStamp = CalculateEventTimestamp(expected),
        .playbackPosition = ts.timeCurFramePts,
        .details = {{"MediaType", OHOS::Media::MediaType::MEDIA_TYPE_VID}, {"Duration", delayTimeMs}},
    };
    auto agent = shared_from_this();
    FALSE_RETURN_MSG(agent != nullptr, "DfxAgent is released");
    uint64_t instanceId = 0;
    const auto &instanceIdStr = agent->instanceId_;
    auto parseRes = std::from_chars(instanceIdStr.data(), instanceIdStr.data() + instanceIdStr.size(), instanceId);
    if (parseRes.ec != std::errc()) {
        MEDIA_LOG_E("ReportMetricsEvent invalid instanceId: %{public}s", instanceIdStr.c_str());
        return;
    }

    StallingInfo infoMeta;
    infoMeta.appName = agent->appName_;
    infoMeta.lagDuration = delayTimeMs;
    infoMeta.sourceType = static_cast<uint8_t>(agent->sourceType_);
    infoMeta.instanceId = instanceId;
    infoMeta.timeStamp = info.timeStamp;
    infoMeta.playbackPosition = info.playbackPosition;
    infoMeta.stage = BuildStageStr(expected, ts);
    infoMeta.stallingInfo = timeStampList;
    AppendStallingInfo(infoMeta, instanceId);

    DfxEvent eventCopy;
    eventCopy.param = info;
    if (metricsCallback_ != nullptr) {
        metricsCallback_(shared_from_this(), eventCopy);
    }
}

void DfxAgent::GetTotalStallingDuration(int64_t* duration)
{
    *duration = totalStallingDuration_.load();
}

void DfxAgent::GetTotalStallingTimes(int64_t* times)
{
    *times = totalStallingTimes_.load();
}

std::string DfxAgent::GetPerfStr(const bool needWaitAllData)
{
    bool isAllDataReady = true;
    std::string waitFor = "not all ready, wait for";
    std::string perfStr = needPrintPerfLog_ ? "AfterLag\n" : "Lag\n";
    for (auto it = PERF_ITEM_NECESSITY.begin(); it != PERF_ITEM_NECESSITY.end(); ++it) {
        auto dataMapIt = perfDataMap_.find(it->first);
        if (dataMapIt != perfDataMap_.end()) {
            perfStr += "[" + it->first + " speed] max " + std::to_string(dataMapIt->second.max) + " min " +
                std::to_string(dataMapIt->second.min) + " avg " + std::to_string(dataMapIt->second.avg) + "\n";
        } else if (!it->second) {
            perfStr += "not enough data, but " + it->first + " is not bottleneck\n";
        } else {
            waitFor += " " + it->first;
            isAllDataReady = false;
        }
    }
    if (isAllDataReady) {
        perfDataMap_.clear();
    }
    needPrintPerfLog_ = !isAllDataReady;
    return (!isAllDataReady && needWaitAllData) ? waitFor : perfStr;
}

}  // namespace Media
}  // namespace OHOS