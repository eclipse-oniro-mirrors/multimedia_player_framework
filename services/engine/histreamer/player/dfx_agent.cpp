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
#include "event.h"
#include "meta/any.h"
#include "media_demuxer.h"
#include "media_dfx.h"
#include "format.h"
#include "player.h"

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

    constexpr int32_t STREAM_TYPE_MIXED = 0;
    constexpr int32_t STREAM_TYPE_VIDEO = 1;
    constexpr int32_t STREAM_TYPE_AUDIO = 2;
    constexpr int32_t STREAM_TYPE_SUBTITLE = 3;
    constexpr int32_t CHANGE_REASON_NETWORK_QUALITY = 1;
    constexpr int32_t CHANGE_REASON_MANUAL = 2;
    constexpr int32_t LOADING_STAGE_CONNECTION = 0;
    constexpr int32_t LOADING_STAGE_PLAYLIST = 1;
    constexpr int32_t LOADING_STAGE_MEDIA_DATA = 2;
    constexpr int32_t VIDEO_TYPE_SDR = 0;
    constexpr int32_t VIDEO_TYPE_HDR_VIVID = 1;
    constexpr int32_t VIDEO_TYPE_HDR_10 = 2;
    constexpr int32_t DISCONTINUE_TYPE_AUDIO_PARAM = 1;
    constexpr int32_t DISCONTINUE_TYPE_PTS = 2;
    constexpr int32_t RENDERER_STATE_RUNNING = 2;
    constexpr int32_t RENDERER_STATE_STOPPED = 3;
    constexpr int32_t RENDERER_STATE_PAUSED = 5;
    constexpr int32_t DECODER_TYPE_VIDEO = 1;
    constexpr int32_t DECODER_TYPE_AUDIO = 2;
    constexpr int32_t ASYNC_TYPE_VIDEO_AHEAD = 1;
    constexpr int32_t ASYNC_TYPE_VIDEO_BEHIND = 2;
    constexpr int32_t DISCONTINUE_TYPE_AUDIO = 1;
    constexpr int32_t DISCONTINUE_TYPE_VIDEO = 2;

    static std::string GetStreamTypeStr(int32_t streamType)
    {
        switch (streamType) {
            case STREAM_TYPE_MIXED:
                return "MIXED";
            case STREAM_TYPE_VIDEO:
                return "VIDEO";
            case STREAM_TYPE_AUDIO:
                return "AUDIO";
            case STREAM_TYPE_SUBTITLE:
                return "SUBTITLE";
            default:
                return "UNKNOWN";
        }
    }

    static std::string GetChangeReasonStr(int32_t changeReason)
    {
        switch (changeReason) {
            case CHANGE_REASON_NETWORK_QUALITY:
                return "NETWORK_QUALITY";
            case CHANGE_REASON_MANUAL:
                return "MANUAL";
            default:
                return "UNKNOWN";
        }
    }

    static std::string GetRequestStageStr(int32_t requestStage)
    {
        switch (requestStage) {
            case LOADING_STAGE_CONNECTION:
                return "CONNECTION";
            case LOADING_STAGE_PLAYLIST:
                return "PLAYLIST";
            case LOADING_STAGE_MEDIA_DATA:
                return "MEDIA_DATA";
            default:
                return "UNKNOWN";
        }
    }

    static std::string GetVideoTypeStr(int32_t videoType)
    {
        switch (videoType) {
            case VIDEO_TYPE_SDR:
                return "SDR";
            case VIDEO_TYPE_HDR_VIVID:
                return "HDR_VIVID";
            case VIDEO_TYPE_HDR_10:
                return "HDR_10";
            default:
                return "UNKNOWN";
        }
    }

    static void FillStreamBitrateDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        details["stream_id_before"] = Any(static_cast<int64_t>(changeInfo.streamIdBefore));
        details["stream_id_after"] = Any(static_cast<int64_t>(changeInfo.streamIdAfter));
        
        if (isLocalFd) {
            return;
        }
        details["bitrate_before"] = Any(static_cast<int64_t>(changeInfo.bitrateBefore));
        details["bitrate_after"] = Any(static_cast<int64_t>(changeInfo.bitrateAfter));
    }

    static void FillVideoDimensionDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        details["video_width_before"] = Any(static_cast<int64_t>(changeInfo.videoWidthBefore));
        details["video_height_before"] = Any(static_cast<int64_t>(changeInfo.videoHeightBefore));
        details["video_width_after"] = Any(static_cast<int64_t>(changeInfo.videoWidthAfter));
        details["video_height_after"] = Any(static_cast<int64_t>(changeInfo.videoHeightAfter));
    }

    static void FillVideoFrameRateDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        details["video_framerate_before"] = Any(static_cast<int64_t>(changeInfo.videoFrameRateBefore));
        details["video_framerate_after"] = Any(static_cast<int64_t>(changeInfo.videoFrameRateAfter));
    }

    static void FillAudioDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        details["audio_channels_before"] = Any(static_cast<int64_t>(changeInfo.audioChannelsBefore));
        details["audio_channels_after"] = Any(static_cast<int64_t>(changeInfo.audioChannelsAfter));
        details["audio_sample_rate_before"] = Any(static_cast<int64_t>(changeInfo.audioSampleRateBefore));
        details["audio_sample_rate_after"] = Any(static_cast<int64_t>(changeInfo.audioSampleRateAfter));
    }

    static void FillOtherDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        std::string videoTypeBeforeStr = GetVideoTypeStr(changeInfo.videoTypeBefore);
        std::string videoTypeAfterStr = GetVideoTypeStr(changeInfo.videoTypeAfter);
        details["video_type_before"] = Any(videoTypeBeforeStr);
        details["video_type_after"] = Any(videoTypeAfterStr);
        details["audio_lang_before"] = Any(changeInfo.audioLangBefore);
        details["audio_lang_after"] = Any(changeInfo.audioLangAfter);
        details["subtitle_lang_before"] = Any(changeInfo.subtitleLangBefore);
        details["subtitle_lang_after"] = Any(changeInfo.subtitleLangAfter);
        details["audio_mime_type_before"] = Any(changeInfo.audioMimeTypeBefore);
        details["audio_mime_type_after"] = Any(changeInfo.audioMimeTypeAfter);
        details["video_mime_type_before"] = Any(changeInfo.videoMimeTypeBefore);
        details["video_mime_type_after"] = Any(changeInfo.videoMimeTypeAfter);
        
        if (isLocalFd) {
            return;
        }
        details["codecs_before"] = Any(changeInfo.codecsBefore);
        details["codecs_after"] = Any(changeInfo.codecsAfter);
        details["origin_codecs_before"] = Any(changeInfo.originCodecsBefore);
        details["origin_codecs_after"] = Any(changeInfo.originCodecsAfter);
    }

    static void FillMediaChangeDetails(std::map<std::string, Any>& details,
        const OHOS::Media::MediaChangeInfo& changeInfo, bool isLocalFd)
    {
        FillStreamBitrateDetails(details, changeInfo, isLocalFd);
        FillVideoDimensionDetails(details, changeInfo, isLocalFd);
        FillVideoFrameRateDetails(details, changeInfo, isLocalFd);
        FillAudioDetails(details, changeInfo, isLocalFd);
        FillOtherDetails(details, changeInfo, isLocalFd);
    }

    static std::string GetStreamTypeStrDiscontinue(int32_t streamType)
    {
        if (streamType == DISCONTINUE_TYPE_AUDIO) {
            return "AUDIO";
        }
        if (streamType == DISCONTINUE_TYPE_VIDEO) {
            return "VIDEO";
        }
        return "UNKNOWN";
    }

    static std::string GetDiscontinueTypeStr(int32_t discontinueType)
    {
        if (discontinueType == DISCONTINUE_TYPE_AUDIO_PARAM) {
            return "AUDIO_PARAM";
        }
        if (discontinueType == DISCONTINUE_TYPE_PTS) {
            return "PTS";
        }
        return "UNKNOWN";
    }

    static std::string GetAudioStateStr(int32_t state)
    {
        switch (state) {
            case RENDERER_STATE_RUNNING:
                return "RUNNING";
            case RENDERER_STATE_STOPPED:
                return "STOPPED";
            case RENDERER_STATE_PAUSED:
                return "PAUSED";
            default:
                return "UNKNOWN";
        }
    }

    static std::string GetDecoderTypeStr(int32_t decoderType)
    {
        switch (decoderType) {
            case DECODER_TYPE_VIDEO:
                return "VIDEO";
            case DECODER_TYPE_AUDIO:
                return "AUDIO";
            default:
                return "UNKNOWN";
        }
    }

    static std::string GetAsyncTypeStr(int32_t asyncType)
    {
        switch (asyncType) {
            case ASYNC_TYPE_VIDEO_AHEAD:
                return "VIDEO_AHEAD";
            case ASYNC_TYPE_VIDEO_BEHIND:
                return "VIDEO_BEHIND";
            default:
                return "UNKNOWN";
        }
    }
}

const std::map<DfxEventType, DfxEventHandleFunc> DfxAgent::DFX_EVENT_HANDLERS_ = {
    { DfxEventType::DFX_INFO_PLAYER_VIDEO_LAG, DfxAgent::ProcessVideoLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_AUDIO_LAG, DfxAgent::ProcessAudioLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_STREAM_LAG, DfxAgent::ProcessStreamLagEvent },
    { DfxEventType::DFX_INFO_PLAYER_EOS_SEEK, DfxAgent::ProcessEosSeekEvent },
    { DfxEventType::DFX_INFO_PERF_REPORT, DfxAgent::ProcessPerfInfoEvent },
    { DfxEventType::DFX_EVENT_STALLING, DfxAgent::ProcessMetricsEvent },
    { DfxEventType::DFX_EVENT_AVDESYNC, DfxAgent::ProcessLipAsyncEvent },
    { DfxEventType::DFX_EVENT_LOADING_BITRATE, DfxAgent::ProcessLoadingBitrateEvent },
    { DfxEventType::DFX_EVENT_LOADING_ERROR, DfxAgent::ProcessLoadingErrorEvent },
    { DfxEventType::DFX_EVENT_MEDIA_CHANGED, DfxAgent::ProcessMediaChangedEvent },
    { DfxEventType::DFX_EVENT_MEDIA_DISCONTINUE, DfxAgent::ProcessMediaDiscontinueEvent },
    { DfxEventType::DFX_EVENT_AUDIO_STATUS, DfxAgent::ProcessAudioStatusEvent },
    { DfxEventType::DFX_EVENT_CODEC_ABNORMAL, DfxAgent::ProcessCodecAbnormalEvent },
    { DfxEventType::DFX_EVENT_AUDIO_ERROR, DfxAgent::ProcessPlayErrEvent },
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
    std::lock_guard<std::mutex> lock(taskMutex_);
    dfxTask_.reset();
}
 
void DfxAgent::SetSourceType(PlayerDfxSourceType type)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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
    std::lock_guard<std::mutex> lock(taskMutex_);
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

void DfxAgent::ProcessPlayErrEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    agent->ReportPlayErrEvent(event);
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
        .details = {
            {"MediaType", Any(OHOS::Media::MediaType::MEDIA_TYPE_VID)},
            {"Duration", Any(delayTimeMs)}
        }
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

void DfxAgent::ReportPlayErrEvent(const DfxEvent &event)
{
    PlayErrEvent eventType;
    switch (event.type) {
        case DfxEventType::DFX_EVENT_MEDIA_CHANGED:
            eventType = OHOS::Media::PlayErrEvent::MEDIA_CHANGED;
            break;
        case DfxEventType::DFX_EVENT_LOADING_ERROR:
            eventType = OHOS::Media::PlayErrEvent::LOADING_ERROR;
            break;
        case DfxEventType::DFX_EVENT_MEDIA_DISCONTINUE:
            eventType = OHOS::Media::PlayErrEvent::MEDIA_DISCONTINUE;
            break;
        case DfxEventType::DFX_EVENT_AUDIO_ERROR:
            eventType = OHOS::Media::PlayErrEvent::AUDIO_ERROR;
            break;
        default:
            return;
    }
    uint64_t instanceId = 0;
    const auto &instanceIdStr = this->instanceId_;
    auto parseRes = std::from_chars(instanceIdStr.data(), instanceIdStr.data() + instanceIdStr.size(), instanceId);
    if (parseRes.ec != std::errc()) {
        MEDIA_LOG_E("ReportMetricsEvent invalid instanceId: %{public}s", instanceIdStr.c_str());
        return;
    }
    AppendPlayErrInfo(eventType, instanceId);
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
    perfDataMap_.clear();
    needPrintPerfLog_ = !isAllDataReady;
    return (!isAllDataReady && needWaitAllData) ? waitFor : perfStr;
}

void DfxAgent::ProcessLoadingBitrateEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto bitratePair = AnyCast<std::pair<uint32_t, uint32_t>>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_LOADINGRATE_CHANGE,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = 0,
        .details = {
            {"bitrate_before", Any(static_cast<int64_t>(bitratePair.first))},
            {"bitrate_after", Any(static_cast<int64_t>(bitratePair.second))}
        },
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessLoadingErrorEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto errorInfo = AnyCast<std::tuple<int32_t, int64_t, int32_t>>(event.param);
    int32_t requestStage = std::get<0>(errorInfo);
    int64_t requestTimestamp = std::get<1>(errorInfo);
    int32_t errorCode = std::get<2>(errorInfo);
    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_LOADING_ERROR,
        .timeStamp = agent->CalculateEventTimestamp(requestTimestamp),
        .playbackPosition = 0,
        .details = {
            {"request_stage", Any(GetRequestStageStr(requestStage))},
            {"request_timestamp", Any(agent->CalculateEventTimestamp(requestTimestamp))},
            {"error_code", Any(static_cast<int64_t>(errorCode))}
        },
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessMediaChangedEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto changeInfo = AnyCast<OHOS::Media::MediaChangeInfo>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    bool isLocalFd = changeInfo.isLocalFd;
    std::string streamTypeStr = GetStreamTypeStr(changeInfo.streamType);
    std::string changeReasonStr = GetChangeReasonStr(changeInfo.changeReason);
    std::string changeResultStr = (changeInfo.changeResult == 0) ? "SUCCESS" : "FAILED";
    std::map<std::string, Any> details;
    details["is_local_fd"] = Any(isLocalFd);
    if (!isLocalFd) {
        details["media_stream_type"] = Any(streamTypeStr);
    }
    details["change_reason"] = Any(changeReasonStr);
    details["change_result"] = Any(changeResultStr);
    FillMediaChangeDetails(details, changeInfo, isLocalFd);

    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_CHANGED,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = 0,
        .details = details,
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessMediaDiscontinueEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto discontinueInfo = AnyCast<OHOS::Media::MediaDiscontinueInfo>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    
    std::string streamTypeStr = GetStreamTypeStrDiscontinue(discontinueInfo.streamType);
    std::string discontinueTypeStr = GetDiscontinueTypeStr(discontinueInfo.discontinueType);

    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = 0,
        .details = {
            {"media_stream_type", Any(streamTypeStr)},
            {"discontinue_type", Any(discontinueTypeStr)}
        },
    };
    if (discontinueInfo.discontinueType == DISCONTINUE_TYPE_PTS) {
        info.details["pts_before"] = Any(discontinueInfo.ptsBefore);
        info.details["pts_after"] = Any(discontinueInfo.ptsAfter);
    } else if (discontinueInfo.discontinueType == DISCONTINUE_TYPE_AUDIO_PARAM) {
        info.details["sample_rate_before"] = Any(static_cast<int64_t>(discontinueInfo.sampleRateBefore));
        info.details["sample_rate_after"] = Any(static_cast<int64_t>(discontinueInfo.sampleRateAfter));
        info.details["channels_before"] = Any(static_cast<int64_t>(discontinueInfo.channelsBefore));
        info.details["channels_after"] = Any(static_cast<int64_t>(discontinueInfo.channelsAfter));
        info.details["sample_format_before"] = Any(static_cast<int64_t>(discontinueInfo.sampleFormatBefore));
        info.details["sample_format_after"] = Any(static_cast<int64_t>(discontinueInfo.sampleFormatAfter));
    }
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessAudioStatusEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto statusInfo = AnyCast<AudioStatusInfo>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    std::string stateBeforeStr = GetAudioStateStr(statusInfo.stateBefore);
    std::string stateAfterStr = GetAudioStateStr(statusInfo.stateAfter);

    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_AUDIO_ABNORMAL,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = 0,
        .details = {
            {"state_before", Any(stateBeforeStr)},
            {"state_after", Any(stateAfterStr)},
            {"interrupt_hint", Any(statusInfo.interruptHint)}
        },
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessCodecAbnormalEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto codecAbnormalInfo = AnyCast<OHOS::Media::CodecAbnormalInfo>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    std::string decoderTypeStr = GetDecoderTypeStr(codecAbnormalInfo.decoderType);

    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_CODEC_ABNORMAL,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = 0,
        .details = {
            {"decoder_type", Any(decoderTypeStr)},
            {"error_code", Any(static_cast<int64_t>(codecAbnormalInfo.errorCode))}
        },
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

void DfxAgent::ProcessLipAsyncEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event)
{
    auto agent = ptr.lock();
    FALSE_RETURN(agent != nullptr);
    auto lipAsyncInfo = AnyCast<OHOS::Media::LipAsyncInfo>(event.param);
    int64_t steadyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    std::string asyncTypeStr = GetAsyncTypeStr(lipAsyncInfo.asyncType);

    AVMetricsEvent info {
        .metricsEventType = AVMetricsEventType::AV_METRICS_EVENT_TYPE_LIP_ASYNC,
        .timeStamp = agent->CalculateEventTimestamp(steadyMs),
        .playbackPosition = lipAsyncInfo.endTimeMs,
        .details = {
            {"async_type", Any(asyncTypeStr)},
            {"start_time", Any(lipAsyncInfo.startTimeMs)},
            {"end_time", Any(lipAsyncInfo.endTimeMs)}
        },
    };
    DfxEvent eventCopy;
    eventCopy.param = info;
    if (agent->metricsCallback_ != nullptr) {
        agent->metricsCallback_(ptr, eventCopy);
    }
}

}  // namespace Media
} // namespace OHOS