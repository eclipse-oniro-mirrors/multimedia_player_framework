/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#define HST_LOG_TAG "HiPlayer"

#include "hiplayer_impl.h"

#include <chrono>
#include <shared_mutex>

#include "audio_device_descriptor.h"
#include "common/log.h"
#include "common/media_source.h"
#include "directory_ex.h"
#include "filter/filter_factory.h"
#include "media_errors.h"
#include "osal/task/jobutils.h"
#include "osal/task/pipeline_threadpool.h"
#include "osal/task/task.h"
#include "osal/utils/dump_buffer.h"
#include "plugin/plugin_time.h"
#include "media_dfx.h"
#include "media_utils.h"
#include "meta_utils.h"
#include "meta/media_types.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "HiPlayer" };
const float MAX_MEDIA_VOLUME = 1.0f; // standard interface volume is between 0 to 1.
const int32_t AUDIO_SINK_MAX_LATENCY = 400; // audio sink write latency ms
const int32_t FRAME_RATE_UNIT_MULTIPLE = 100; // the unit of frame rate is frames per 100s
const int32_t PLAYING_SEEK_WAIT_TIME = 200; // wait up to 200 ms for new frame after seek in playing.
const int64_t PLAY_RANGE_DEFAULT_VALUE = -1; // play range default value.
const int64_t SAMPLE_AMPLITUDE_INTERVAL = 100;
const int64_t REPORT_PROGRESS_INTERVAL = 100; // progress interval is 100ms
const double FRAME_RATE_DEFAULT = -1.0;
const double FRAME_RATE_FOR_SEEK_PERFORMANCE = 2000.0;
constexpr int32_t BUFFERING_LOG_FREQUENCY = 5;
constexpr int32_t NOTIFY_BUFFERING_END_PARAM = 0;
constexpr int64_t FIRST_FRAME_FRAME_REPORT_DELAY_MS = 50;
static const std::unordered_set<OHOS::AudioStandard::StreamUsage> FOCUS_EVENT_USAGE_SET = {
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN,
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA,
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MUSIC,
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MOVIE,
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_GAME,
    OHOS::AudioStandard::StreamUsage::STREAM_USAGE_AUDIOBOOK,
};
}

namespace OHOS {
namespace Media {
using namespace Pipeline;
using namespace OHOS::Media::Plugins;
class PlayerEventReceiver : public EventReceiver {
public:
    explicit PlayerEventReceiver(HiPlayerImpl* hiPlayerImpl, std::string playerId)
    {
        MEDIA_LOG_I("PlayerEventReceiver ctor called.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiPlayerImpl_ = hiPlayerImpl;
        task_ = std::make_unique<Task>("PlayerEventReceiver", playerId, TaskType::GLOBAL,
            OHOS::Media::TaskPriority::HIGH, false);
    }

    void OnEvent(const Event &event) override
    {
        MEDIA_LOG_D("PlayerEventReceiver OnEvent.");
        task_->SubmitJobOnce([this, event] {
            std::shared_lock<std::shared_mutex> lk(cbMutex_);
            FALSE_RETURN(hiPlayerImpl_ != nullptr);
            hiPlayerImpl_->OnEvent(event);
        });
    }

    void OnDfxEvent(const DfxEvent &event) override
    {
        MEDIA_LOG_D("PlayerEventReceiver OnDfxEvent.");
        std::shared_lock<std::shared_mutex> lk(cbMutex_);
        FALSE_RETURN(hiPlayerImpl_ != nullptr);
        hiPlayerImpl_->HandleDfxEvent(event);
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("PlayerEventReceiver NotifyRelease.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiPlayerImpl_ = nullptr;
    }

private:
    std::shared_mutex cbMutex_ {};
    HiPlayerImpl* hiPlayerImpl_;
    std::unique_ptr<Task> task_;
};

class PlayerFilterCallback : public FilterCallback {
public:
    explicit PlayerFilterCallback(HiPlayerImpl* hiPlayerImpl)
    {
        MEDIA_LOG_I("PlayerFilterCallback ctor called.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiPlayerImpl_ = hiPlayerImpl;
    }

    Status OnCallback(const std::shared_ptr<Filter>& filter, FilterCallBackCommand cmd, StreamType outType) override
    {
        MEDIA_LOG_D_SHORT("PlayerFilterCallback OnCallback.");
        std::shared_lock<std::shared_mutex> lk(cbMutex_);
        FALSE_RETURN_V(hiPlayerImpl_ != nullptr, Status::OK); // hiPlayerImpl_ is destructed
        return hiPlayerImpl_->OnCallback(filter, cmd, outType);
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("PlayerEventReceiver NotifyRelease.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiPlayerImpl_ = nullptr;
    }

private:
    std::shared_mutex cbMutex_ {};
    HiPlayerImpl* hiPlayerImpl_;
};

HiPlayerImpl::HiPlayerImpl(int32_t appUid, int32_t appPid, uint32_t appTokenId, uint64_t appFullTokenId)
    : appUid_(appUid), appPid_(appPid), appTokenId_(appTokenId), appFullTokenId_(appFullTokenId)
{
    MEDIA_LOG_D("hiPlayerImpl ctor appUid " PUBLIC_LOG_D32 " appPid " PUBLIC_LOG_D32
        " appTokenId %{private}" PRIu32 " appFullTokenId %{private}" PRIu64,
        appUid_, appPid_, appTokenId_, appFullTokenId_);
    playerId_ = std::string("HiPlayer_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
    pipeline_ = std::make_shared<OHOS::Media::Pipeline::Pipeline>();
    syncManager_ = std::make_shared<MediaSyncManager>();
    callbackLooper_.SetPlayEngine(this, playerId_);
    bundleName_ = GetClientBundleName(appUid);
    dfxAgent_ = std::make_shared<DfxAgent>(playerId_, bundleName_);
}

HiPlayerImpl::~HiPlayerImpl()
{
    MEDIA_LOG_D("~HiPlayerImpl dtor called");
    if (demuxer_) {
        pipeline_->RemoveHeadFilter(demuxer_);
    }
    if (dfxAgent_ != nullptr) {
        dfxAgent_.reset();
    }
    if (playerEventReceiver_ != nullptr) {
        playerEventReceiver_->NotifyRelease();
    }
    if (playerFilterCallback_ != nullptr) {
        playerFilterCallback_->NotifyRelease();
    }
    PipeLineThreadPool::GetInstance().DestroyThread(playerId_);
}

void HiPlayerImpl::ReleaseInner()
{
    pipeline_->Stop();
    audioSink_.reset();
#ifdef SUPPORT_VIDEO
    if (videoDecoder_) {
        interruptMonitor_->DeregisterListener(videoDecoder_);
        videoDecoder_.reset();
    }
#endif
    if (subtitleSink_) {
        subtitleSink_.reset();
    }
    syncManager_.reset();
    if (demuxer_) {
        pipeline_->RemoveHeadFilter(demuxer_);
    }
}

Status HiPlayerImpl::Init()
{
    MediaTrace trace("HiPlayerImpl::Init");
    MEDIA_LOG_I("Init start");
    auto playerEventReceiver = std::make_shared<PlayerEventReceiver>(this, playerId_);
    auto playerFilterCallback = std::make_shared<PlayerFilterCallback>(this);
    auto interruptMonitor = std::make_shared<InterruptMonitor>();
    FALSE_RETURN_V_MSG_E(playerEventReceiver != nullptr && playerFilterCallback != nullptr &&
        interruptMonitor != nullptr, Status::ERROR_NO_MEMORY, "fail to init hiplayImpl");
    playerEventReceiver_ = playerEventReceiver;
    playerFilterCallback_ = playerFilterCallback;
    interruptMonitor_ = interruptMonitor;
    MEDIA_LOG_D("pipeline init");
    pipeline_->Init(playerEventReceiver_, playerFilterCallback_, playerId_);
    MEDIA_LOG_D("pipeline Init out");
    for (std::pair<std::string, bool>& item: completeState_) {
        item.second = false;
    }
    GetDumpFlag();
    return Status::OK;
}

void HiPlayerImpl::GetDumpFlag()
{
    const std::string dumpTag = "sys.media.player.dump.enable";
    std::string dumpEnable;
    int32_t dumpRes = OHOS::system::GetStringParameter(dumpTag, dumpEnable, "false");
    isDump_ = (dumpEnable == "true");
    MEDIA_LOG_D_SHORT("get dump flag, dumpRes: %{public}d, isDump_: %{public}d", dumpRes, isDump_);
}

void HiPlayerImpl::SetDefaultAudioRenderInfo(const std::vector<std::shared_ptr<Meta>> &trackInfos)
{
    MEDIA_LOG_D_SHORT("SetDefaultAudioRenderInfo");
    bool hasVideoTrack = false;
    for (size_t index = 0; index < trackInfos.size(); index++) {
        std::shared_ptr<Meta> meta = trackInfos[index];
        if (meta == nullptr) {
            continue;
        }
        std::string trackMime;
        if (!meta->GetData(Tag::MIME_TYPE, trackMime)) {
            continue;
        }
        if (trackMime.find("video/") == 0) {
            hasVideoTrack = true;
        }
    }
    Plugins::AudioRenderInfo audioRenderInfo;
    if (hasVideoTrack) {
        audioRenderInfo = {AudioStandard::CONTENT_TYPE_MOVIE, AudioStandard::STREAM_USAGE_MOVIE, 0};
    } else {
        audioRenderInfo = {AudioStandard::CONTENT_TYPE_MUSIC, AudioStandard::STREAM_USAGE_MUSIC, 0};
    }
    if (audioRenderInfo_ == nullptr) {
        audioRenderInfo_ = std::make_shared<Meta>();
        audioRenderInfo_->SetData(Tag::AUDIO_RENDER_INFO, audioRenderInfo);
    }
}

int32_t HiPlayerImpl::GetRealPath(const std::string &url, std::string &realUrlPath) const
{
    std::string fileHead = "file://";
    std::string tempUrlPath;

    if (url.find(fileHead) == 0 && url.size() > fileHead.size()) {
        tempUrlPath = url.substr(fileHead.size());
    } else {
        tempUrlPath = url;
    }
    if (tempUrlPath.find("..") != std::string::npos) {
        MEDIA_LOG_E("invalid url. The Url (%{private}s) path may be invalid.", tempUrlPath.c_str());
        return MSERR_FILE_ACCESS_FAILED;
    }
    bool ret = PathToRealPath(tempUrlPath, realUrlPath);
    if (!ret) {
        MEDIA_LOG_E("invalid url. The Url (%{private}s) path may be invalid.", url.c_str());
        return MSERR_OPEN_FILE_FAILED;
    }
    if (access(realUrlPath.c_str(), R_OK) != 0) {
        return MSERR_FILE_ACCESS_FAILED;
    }
    return MSERR_OK;
}

bool HiPlayerImpl::IsFileUrl(const std::string &url) const
{
    return url.find("://") == std::string::npos || url.find("file://") == 0;
}

bool HiPlayerImpl::IsValidPlayRange(int64_t start, int64_t end) const
{
    if (start < PLAY_RANGE_DEFAULT_VALUE || end < PLAY_RANGE_DEFAULT_VALUE || end == 0) {
        return false;
    }
    if (pipelineStates_ == PlayerStates::PLAYER_INITIALIZED) {
        return true;
    }
    if ((end == PLAY_RANGE_DEFAULT_VALUE) && (start < durationMs_.load())) {
        return true;
    }
    if (start >= end || start >= durationMs_.load() || end > durationMs_.load()) {
        return false;
    }
    return true;
}

bool HiPlayerImpl::IsInValidSeekTime(int32_t seekPos)
{
    if (endTimeWithMode_ == PLAY_RANGE_DEFAULT_VALUE) {
        return false;
    }
    int64_t seekTime = static_cast<int64_t>(seekPos);
    if (startTimeWithMode_ == PLAY_RANGE_DEFAULT_VALUE) {
        if (seekTime > endTimeWithMode_) {
            endTimeWithMode_ = PLAY_RANGE_DEFAULT_VALUE;
            pipeline_->SetPlayRange(startTimeWithMode_, endTimeWithMode_);
        }
        return false;
    }
    return seekTime < startTimeWithMode_ || seekTime > endTimeWithMode_;
}

int64_t HiPlayerImpl::GetPlayStartTime()
{
    if (playRangeStartTime_ > PLAY_RANGE_DEFAULT_VALUE) {
        return playRangeStartTime_;
    }
    int64_t rePlayStartTime = 0;
    if (startTimeWithMode_ != PLAY_RANGE_DEFAULT_VALUE && endTimeWithMode_ != PLAY_RANGE_DEFAULT_VALUE) {
        rePlayStartTime = startTimeWithMode_;
    }
    return rePlayStartTime;
}

void HiPlayerImpl::SetInstancdId(uint64_t instanceId)
{
    instanceId_ = instanceId;
    if (dfxAgent_ != nullptr) {
        dfxAgent_->SetInstanceId(std::to_string(instanceId_));
    }
}

void HiPlayerImpl::SetApiVersion(int32_t apiVersion)
{
    apiVersion_ = apiVersion;
}

int32_t HiPlayerImpl::SetSource(const std::string& uri)
{
    MediaTrace trace("HiPlayerImpl::SetSource uri");
    MEDIA_LOG_D("HiPlayerImpl SetSource uri");
    CreateMediaInfo(CallType::AVPLAYER, appUid_, instanceId_);
    playStatisticalInfo_.sourceUrl = "private";
    playStatisticalInfo_.sourceType = static_cast<int32_t>(SourceType::SOURCE_TYPE_URI);
    url_ = uri;
    PlayerDfxSourceType sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_UNKNOWN;
    if (IsFileUrl(uri)) {
        std::string realUriPath;
        int32_t result = GetRealPath(uri, realUriPath);
        if (result != MSERR_OK) {
            CollectionErrorInfo(result, "SetSource error: GetRealPath error");
            return result;
        }
        url_ = "file://" + realUriPath;
        sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_URL_FILE;
        SetPerfRecEnabled(true);
    }
    if (url_.find("http") == 0 || url_.find("https") == 0) {
        isNetWorkPlay_ = true;
        sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_URL_NETWORK;
    }
    if (url_.find("fd://") == 0) {
        sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_URL_FD;
        SetPerfRecEnabled(true);
    }
    if (dfxAgent_ != nullptr) {
        dfxAgent_->SetSourceType(sourceType);
    }
    hasExtSub_ = false;
    pipelineStates_ = PlayerStates::PLAYER_INITIALIZED;
    int ret = TransStatus(Status::OK);
    playStatisticalInfo_.errCode = ret;
    return ret;
}

int32_t HiPlayerImpl::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    MediaTrace trace("HiPlayerImpl::SetMediaSource.");
    MEDIA_LOG_I("SetMediaSource entered media source stream");
    if (mediaSource == nullptr) {
        CollectionErrorInfo(MSERR_INVALID_VAL, "mediaSource is nullptr");
        return MSERR_INVALID_VAL;
    }
    header_ = mediaSource->header;
    url_ = mediaSource->url;
    preferedWidth_ = strategy.preferredWidth;
    preferedHeight_ = strategy.preferredHeight;
    bufferDuration_ = strategy.preferredBufferDuration;
    preferHDR_ = strategy.preferredHdr;
    renderFirstFrame_ = strategy.showFirstFrameOnPrepare;
    mutedMediaType_ = strategy.mutedMediaType;
    audioLanguage_ = strategy.preferredAudioLanguage;
    subtitleLanguage_ = strategy.preferredSubtitleLanguage;
    mimeType_ = mediaSource->GetMimeType();
    bufferDurationForPlaying_ = strategy.preferredBufferDurationForPlaying;
    PlayerDfxSourceType sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_MEDIASOURCE_LOCAL;
    if (mimeType_ != AVMimeTypes::APPLICATION_M3U8 && IsFileUrl(url_)) {
        std::string realUriPath;
        int32_t result = GetRealPath(url_, realUriPath);
        if (result != MSERR_OK) {
            CollectionErrorInfo(result, "SetSource error: GetRealPath error");
            return result;
        }
        url_ = "file://" + realUriPath;
    }
    if (url_.find("http") == 0 || url_.find("https") == 0) {
        isNetWorkPlay_ = true;
        sourceType = PlayerDfxSourceType::DFX_SOURCE_TYPE_MEDIASOURCE_NETWORK;
    }
    if (dfxAgent_ != nullptr) {
        dfxAgent_->SetSourceType(sourceType);
    }

    pipelineStates_ = PlayerStates::PLAYER_INITIALIZED;
    int ret = TransStatus(Status::OK);
    playStatisticalInfo_.errCode = ret;
    return ret;
}

int32_t HiPlayerImpl::SetSource(const std::shared_ptr<IMediaDataSource>& dataSrc)
{
    MediaTrace trace("HiPlayerImpl::SetSource dataSrc");
    MEDIA_LOG_I("SetSource in source stream");
    if (dataSrc == nullptr) {
        MEDIA_LOG_E("SetSource error: dataSrc is null");
    }
    if (dfxAgent_ != nullptr) {
        dfxAgent_->SetSourceType(PlayerDfxSourceType::DFX_SOURCE_TYPE_DATASRC);
    }
    playStatisticalInfo_.sourceType = static_cast<int32_t>(SourceType::SOURCE_TYPE_STREAM);
    dataSrc_ = dataSrc;
    hasExtSub_ = false;
    pipelineStates_ = PlayerStates::PLAYER_INITIALIZED;
    int ret = TransStatus(Status::OK);
    playStatisticalInfo_.errCode = ret;
    return ret;
}

int32_t HiPlayerImpl::AddSubSource(const std::string &url)
{
    MediaTrace trace("HiPlayerImpl::AddSubSource uri");
    MEDIA_LOG_I("AddSubSource entered source uri: %{private}s", url.c_str());
    subUrl_ = url;
    if (IsFileUrl(url)) {
        std::string realUriPath;
        int32_t result = GetRealPath(url, realUriPath);
        if (result != MSERR_OK) {
            MEDIA_LOG_E("AddSubSource error: GetRealPath error");
            return result;
        }
        subUrl_ = "file://" + realUriPath;
    }

    hasExtSub_ = true;
    return TransStatus(Status::OK);
}

void HiPlayerImpl::ResetIfSourceExisted()
{
    FALSE_RETURN(demuxer_ != nullptr);
    MEDIA_LOG_I("Source is existed, reset the relatived objects");
    ReleaseInner();
    if (pipeline_ != nullptr) {
        pipeline_.reset();
    }
    if (audioDecoder_ != nullptr) {
        audioDecoder_.reset();
    }

    pipeline_ = std::make_shared<OHOS::Media::Pipeline::Pipeline>();
    syncManager_ = std::make_shared<MediaSyncManager>();
    MEDIA_LOG_I("Reset the relatived objects end");
}

int32_t HiPlayerImpl::Prepare()
{
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetPlayRange(int64_t start, int64_t end)
{
    if (!IsValidPlayRange(start, end)) {
        MEDIA_LOG_E("SetPlayRange failed! start: " PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64,
                    start, end);
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
        return TransStatus(Status::ERROR_INVALID_OPERATION);
    }
    playRangeStartTime_ = start;
    playRangeEndTime_ = end;

    if (pipeline_ != nullptr) {
        pipeline_->SetPlayRange(playRangeStartTime_, playRangeEndTime_);
    }

    MEDIA_LOG_I("SetPlayRange success! start: " PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64,
                playRangeStartTime_, playRangeEndTime_);
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    Status rtv = Status::OK;
    if (!IsValidPlayRange(start, end)) {
        MEDIA_LOG_E("SetPlayRangeWithMode failed! start: " PUBLIC_LOG_D64 ", end: "
            PUBLIC_LOG_D64, start, end);
        rtv = Status::ERROR_INVALID_PARAMETER;
        OnEvent({"engine", EventType::EVENT_ERROR, TransStatus(rtv)});
        return TransStatus(rtv);
    }
    startTimeWithMode_ = start;
    endTimeWithMode_ = end;
    playRangeSeekMode_ = mode;
    isSetPlayRange_ = true;
    if (pipelineStates_ == PlayerStates::PLAYER_INITIALIZED ||
        pipelineStates_ == PlayerStates::PLAYER_STOPPED) {
        MEDIA_LOG_I("current state is initialized/stopped SetPlayRangeWithMode start: "
             PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64, startTimeWithMode_, endTimeWithMode_);
        return TransStatus(rtv);
    }
    if (pipeline_ != nullptr && demuxer_ != nullptr) {
        pipeline_->SetPlayRange(startTimeWithMode_, endTimeWithMode_);
        int64_t seekTimeMs = 0;
        if (startTimeWithMode_ > PLAY_RANGE_DEFAULT_VALUE) {
            seekTimeMs = startTimeWithMode_;
        }
        MEDIA_LOG_I("seek to start time: " PUBLIC_LOG_D64, seekTimeMs);
        pipeline_->Flush();
        rtv = doSeek(seekTimeMs, playRangeSeekMode_);
        if (rtv != Status::OK) {
            UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
            MEDIA_LOG_E("seek failed to start time: " PUBLIC_LOG_D64, seekTimeMs);
            return TransStatus(rtv);
        }
        if (demuxer_->IsRenderNextVideoFrameSupported() && !demuxer_->IsVideoEos()) {
            rtv = pipeline_->Preroll(true);
        }
        if (pipelineStates_ == PlayerStates::PLAYER_PLAYBACK_COMPLETE) {
            isDoCompletedSeek_ = true;
            OnStateChanged(PlayerStateId::PAUSE);
        }
        Format format;
        callbackLooper_.OnInfo(INFO_TYPE_POSITION_UPDATE, static_cast<int32_t>(seekTimeMs), format);
    }
    MEDIA_LOG_I("SetPlayRangeWithMode start: " PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64,
                startTimeWithMode_, endTimeWithMode_);
    return TransStatus(rtv);
}

int64_t HiPlayerImpl::GetPlayRangeStartTime()
{
    return startTimeWithMode_ != PLAY_RANGE_DEFAULT_VALUE ? startTimeWithMode_ : playRangeStartTime_;
}

int64_t HiPlayerImpl::GetPlayRangeEndTime()
{
    return endTimeWithMode_ != PLAY_RANGE_DEFAULT_VALUE ? endTimeWithMode_ : playRangeEndTime_;
}

int32_t HiPlayerImpl::GetPlayRangeSeekMode()
{
    return playRangeSeekMode_;
}

int32_t HiPlayerImpl::SetRenderFirstFrame(bool display)
{
    MEDIA_LOG_I("SetRenderFirstFrame in, display: " PUBLIC_LOG_D32, display);
    renderFirstFrame_ = display;
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetIsCalledBySystemApp(bool isCalledBySystemApp)
{
    MEDIA_LOG_I("SetIsCalledBySystemApp in, isCalledBySystemApp: " PUBLIC_LOG_D32, isCalledBySystemApp);
    isCalledBySystemApp_ = isCalledBySystemApp;
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::PrepareAsync()
{
    MediaTrace trace("HiPlayerImpl::PrepareAsync");
    MEDIA_LOG_D("HiPlayerImpl PrepareAsync");
    if (!(pipelineStates_ == PlayerStates::PLAYER_INITIALIZED || pipelineStates_ == PlayerStates::PLAYER_STOPPED)) {
        CollectionErrorInfo(MSERR_INVALID_OPERATION, "PrepareAsync pipelineStates not initialized or stopped");
        return MSERR_INVALID_OPERATION;
    }
    auto ret = Init();
    if (ret != Status::OK || isInterruptNeeded_.load()) {
        auto errCode = TransStatus(Status::ERROR_UNSUPPORTED_FORMAT);
        CollectionErrorInfo(errCode, "PrepareAsync error: init error");
        return errCode;
    }
    DoSetMediaSource(ret);
    if (ret != Status::OK && !isInterruptNeeded_.load()) {
        auto errCode = TransStatus(Status::ERROR_UNSUPPORTED_FORMAT);
        CollectionErrorInfo(errCode, "PrepareAsync error: DoSetSource error");
        OnEvent({"engine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_CONTAINER_TYPE});
        return errCode;
    }
    FALSE_RETURN_V(!BreakIfInterruptted(), TransStatus(Status::OK));
    NotifyBufferingUpdate(PlayerKeys::PLAYER_BUFFERING_START, 0);
    MEDIA_LOG_I("PrepareAsync in, current pipeline state: " PUBLIC_LOG_S,
        StringnessPlayerState(pipelineStates_).c_str());
    OnStateChanged(PlayerStateId::PREPARING);
    ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        MEDIA_LOG_E("PrepareAsync failed with error " PUBLIC_LOG_D32, ret);
        auto errCode = TransStatus(ret);
        CollectionErrorInfo(errCode, "pipeline PrepareAsync failed");
        return errCode;
    }
    InitDuration();
    SetSeiMessageListener();
    UpdateMediaFirstPts();
    ret = DoSetPlayRange();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, TransStatus(ret), "DoSetPlayRange failed");
    if (demuxer_ != nullptr && demuxer_->IsRenderNextVideoFrameSupported()
        && IsAppEnableRenderFirstFrame(appUid_)) {
        ret = pipeline_->Preroll(renderFirstFrame_);
        auto code = TransStatus(ret);
        if (ret != Status::OK) {
            CollectionErrorInfo(code, "PrepareFrame failed.");
            return code;
        }
    }
    UpdatePlayerStateAndNotify();
    MEDIA_LOG_D_SHORT("PrepareAsync End");
    return TransStatus(ret);
}

void HiPlayerImpl::CollectionErrorInfo(int32_t errCode, const std::string& errMsg)
{
    MEDIA_LOG_E("Error: " PUBLIC_LOG_S, errMsg.c_str());
    playStatisticalInfo_.errCode = errCode;
    playStatisticalInfo_.errMsg = errMsg;
}

void HiPlayerImpl::DoSetMediaSource(Status& ret)
{
    if (dataSrc_ != nullptr) {
        ret = DoSetSource(std::make_shared<MediaSource>(dataSrc_));
    } else {
        if (!header_.empty()) {
            MEDIA_LOG_I("DoSetSource header");
            ret = DoSetSource(std::make_shared<MediaSource>(url_, header_));
        } else {
            MEDIA_LOG_I("DoSetSource url");
            ret = DoSetSource(std::make_shared<MediaSource>(url_));
        }
    }
}

Status HiPlayerImpl::DoSetPlayRange()
{
    Status ret = Status::OK;
    int64_t rangeStartTime = GetPlayRangeStartTime();
    int64_t rangeEndTime = GetPlayRangeEndTime();
    if (!IsValidPlayRange(rangeStartTime, rangeEndTime)) {
        MEDIA_LOG_E("DoSetPlayRange failed! start: " PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64,
                    rangeStartTime, rangeEndTime);
        ret = Status::ERROR_INVALID_PARAMETER;
        OnEvent({"engine", EventType::EVENT_ERROR, TransStatus(ret)});
        return ret;
    }
    if ((pipeline_ != nullptr) && (rangeEndTime > PLAY_RANGE_DEFAULT_VALUE)) {
        pipeline_->SetPlayRange(rangeStartTime, rangeEndTime);
    }
    if ((pipeline_ != nullptr) && (rangeStartTime > PLAY_RANGE_DEFAULT_VALUE)) {
        MEDIA_LOG_I("seek to start time: " PUBLIC_LOG_D64, rangeStartTime);
        pipeline_ -> Flush();
        ret = doSeek(rangeStartTime, playRangeSeekMode_);
        if (ret != Status::OK) {
            UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
            MEDIA_LOG_E("seek failed to start time: " PUBLIC_LOG_D64, rangeStartTime);
            return ret;
        }
        Format format;
        callbackLooper_.OnInfo(INFO_TYPE_POSITION_UPDATE, static_cast<int32_t>(rangeStartTime), format);
    }
    return ret;
}

void HiPlayerImpl::UpdatePlayerStateAndNotify()
{
    NotifyBufferingUpdate(PlayerKeys::PLAYER_BUFFERING_END, 0);
    if (durationMs_ <= 0) {
        HandleIsLiveStreamEvent(true);
    }
    NotifyDurationUpdate(PlayerKeys::PLAYER_CACHED_DURATION, durationMs_.load());
    InitVideoWidthAndHeight();
    NotifyResolutionChange();
    NotifyPositionUpdate();
    DoInitializeForHttp();
    OnStateChanged(PlayerStateId::READY);
}

void HiPlayerImpl::UpdateMediaFirstPts()
{
    FALSE_RETURN(syncManager_ != nullptr);
    std::string mime;
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    int64_t startTime = 0;
    for (const auto& trackInfo : metaInfo) {
        if (trackInfo == nullptr || !(trackInfo->GetData(Tag::MIME_TYPE, mime))) {
            MEDIA_LOG_W("TrackInfo is null or get mime fail");
            continue;
        }
        if (!(mime.find("audio/") == 0 || mime.find("video/") == 0)) {
            MEDIA_LOG_W("Not audio or video track");
            continue;
        }
        if (trackInfo->GetData(Tag::MEDIA_START_TIME, startTime)) {
            syncManager_->SetMediaStartPts(startTime);
        }
    }
    startTime = syncManager_->GetMediaStartPts();
    if (startTime != HST_TIME_NONE) {
        mediaStartPts_ = startTime;
    }
}

bool HiPlayerImpl::BreakIfInterruptted()
{
    if (isInterruptNeeded_.load()) {
        OnStateChanged(PlayerStateId::READY);
        return true;
    }
    return false;
}

void HiPlayerImpl::SetInterruptState(bool isInterruptNeeded)
{
    MEDIA_LOG_I("Hiplayer SetInterrupt %{public}d", isInterruptNeeded);
    isInterruptNeeded_ = isInterruptNeeded;
    if (interruptMonitor_) {
        interruptMonitor_->SetInterruptState(isInterruptNeeded);
    }
}

int32_t HiPlayerImpl::SelectBitRate(uint32_t bitRate)
{
    MEDIA_LOG_D("HiPlayerImpl:: Select BitRate %{public}d", bitRate);
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr,
        MSERR_INVALID_OPERATION, "SelectBitRate failed, demuxer_ is null");
    Status ret = demuxer_->SelectBitRate(bitRate);
    if (ret == Status::OK) {
        Format bitRateFormat;
        callbackLooper_.OnInfo(INFO_TYPE_BITRATEDONE, bitRate, bitRateFormat);
        MEDIA_LOG_I("SelectBitRate success");
        return MSERR_OK;
    }
    MEDIA_LOG_I("SelectBitRate failed");
    return MSERR_INVALID_OPERATION;
}

void HiPlayerImpl::DoInitializeForHttp()
{
    if (!isNetWorkPlay_) {
        MEDIA_LOG_E("DoInitializeForHttp failed, not network play");
        return;
    }
    std::vector<uint32_t> vBitRates;
    MEDIA_LOG_D_SHORT("DoInitializeForHttp");
    auto ret = demuxer_->GetBitRates(vBitRates);
    if (ret == Status::OK && vBitRates.size() > 0) {
        int mSize = static_cast<int>(vBitRates.size());
        const int size = mSize;
        uint32_t* bitrates = vBitRates.data();
        Format bitRateFormat;
        (void)bitRateFormat.PutBuffer(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES),
            static_cast<uint8_t *>(static_cast<void *>(bitrates)), size * sizeof(uint32_t));
        callbackLooper_.OnInfo(INFO_TYPE_BITRATE_COLLECT, 0, bitRateFormat);
        MEDIA_LOG_I("OnInfo INFO_TYPE_BITRATE_COLLEC");
    } else {
        MEDIA_LOG_D("GetBitRates failed, ret %{public}d", ret);
    }
}

int32_t HiPlayerImpl::Play()
{
    MediaTrace trace("HiPlayerImpl::Play");
    MEDIA_LOG_I("Play entered.");
    startTime_ = GetCurrentMillisecond();
    playStartTime_ = GetCurrentMillisecond();
    int32_t ret = MSERR_INVALID_VAL;
    if (!IsValidPlayRange(playRangeStartTime_, playRangeEndTime_)) {
        MEDIA_LOG_E("SetPlayRange failed! start: " PUBLIC_LOG_D64 ", end: " PUBLIC_LOG_D64,
                    playRangeStartTime_, playRangeEndTime_);
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
        return TransStatus(Status::ERROR_INVALID_OPERATION);
    }
    if (pipelineStates_ == PlayerStates::PLAYER_PLAYBACK_COMPLETE || pipelineStates_ == PlayerStates::PLAYER_STOPPED) {
        isStreaming_ = true;
        ret = ((GetPlayRangeStartTime() > PLAY_RANGE_DEFAULT_VALUE) ?
            TransStatus(Seek(GetPlayStartTime(), playRangeSeekMode_, false)) :
            TransStatus(Seek(0, PlayerSeekMode::SEEK_PREVIOUS_SYNC, false)));
        callbackLooper_.StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
        callbackLooper_.StartCollectMaxAmplitude(SAMPLE_AMPLITUDE_INTERVAL);
    } else if (pipelineStates_ == PlayerStates::PLAYER_PAUSED) {
        if (playRangeStartTime_ > PLAY_RANGE_DEFAULT_VALUE) {
            ret = TransStatus(Seek(playRangeStartTime_, PlayerSeekMode::SEEK_PREVIOUS_SYNC, false));
        }
        callbackLooper_.StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
        callbackLooper_.StartCollectMaxAmplitude(SAMPLE_AMPLITUDE_INTERVAL);
        ret = TransStatus(Resume());
    } else {
        if (playRangeStartTime_ > PLAY_RANGE_DEFAULT_VALUE) {
            ret = TransStatus(Seek(playRangeStartTime_, PlayerSeekMode::SEEK_PREVIOUS_SYNC, false));
        }
        callbackLooper_.StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
        callbackLooper_.StartCollectMaxAmplitude(SAMPLE_AMPLITUDE_INTERVAL);
        syncManager_->Resume();
        ret = TransStatus(pipeline_->Start());
        if (ret != MSERR_OK) {
            UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
        }
    }
    if (ret == MSERR_OK) {
        if (!isInitialPlay_) {
            OnStateChanged(PlayerStateId::PLAYING);
        } else {
            MEDIA_LOG_D_SHORT("InitialPlay, pending to change state of playing");
        }
    } else {
        CollectionErrorInfo(ret, "Play failed");
    }
    return ret;
}

int32_t HiPlayerImpl::Pause(bool isSystemOperation)
{
    MediaTrace trace("HiPlayerImpl::Pause");
    MEDIA_LOG_I("Pause in");
    FALSE_RETURN_V_MSG_E(pipelineStates_ != PlayerStates::PLAYER_PLAYBACK_COMPLETE,
        TransStatus(Status::OK), "completed not allow pause");
    Status ret = Status::OK;
    ret = pipeline_->Pause();
    syncManager_->Pause();
    if (ret != Status::OK) {
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
    }
    callbackLooper_.StopReportMediaProgress();
    callbackLooper_.StopCollectMaxAmplitude();
    callbackLooper_.ManualReportMediaProgressOnce();
    {
        AutoLock lock(interruptMutex_);
        OnStateChanged(PlayerStateId::PAUSE, isSystemOperation);
        if (isSystemOperation) {
            ReportAudioInterruptEvent();
        }
    }
    UpdatePlayTotalDuration();
    return TransStatus(ret);
}

void HiPlayerImpl::ReportAudioInterruptEvent()
{
    isHintPauseReceived_ = false;
    if (!interruptNotifyPlay_.load()) {
        isSaveInterruptEventNeeded_.store(false);
        return;
    }
    MEDIA_LOG_I("alreay receive an interrupt end event");
    interruptNotifyPlay_.store(false);
    Format format;
    int32_t hintType = interruptEvent_.hintType;
    int32_t forceType = interruptEvent_.forceType;
    int32_t eventType = interruptEvent_.eventType;
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    callbackLooper_.OnInfo(INFO_TYPE_INTERRUPT_EVENT, hintType, format);
}

int32_t HiPlayerImpl::PauseDemuxer()
{
    MediaTrace trace("HiPlayerImpl::PauseDemuxer");
    MEDIA_LOG_I("PauseDemuxer in");
    callbackLooper_.StopReportMediaProgress();
    callbackLooper_.StopCollectMaxAmplitude();
    Status ret = demuxer_->PauseDemuxerReadLoop();
    return TransStatus(ret);
}

int32_t HiPlayerImpl::ResumeDemuxer()
{
    MediaTrace trace("HiPlayerImpl::ResumeDemuxer");
    MEDIA_LOG_I("ResumeDemuxer in");
    FALSE_RETURN_V_MSG_E(pipelineStates_ != PlayerStates::PLAYER_STATE_ERROR,
        TransStatus(Status::OK), "PLAYER_STATE_ERROR not allow ResumeDemuxer");
    callbackLooper_.StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    callbackLooper_.StartCollectMaxAmplitude(SAMPLE_AMPLITUDE_INTERVAL);
    Status ret = demuxer_->ResumeDemuxerReadLoop();
    return TransStatus(ret);
}

int64_t HiPlayerImpl::GetCurrentMillisecond()
{
    auto duration = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

int32_t HiPlayerImpl::Stop()
{
    MediaTrace trace("HiPlayerImpl::Stop");
    MEDIA_LOG_I("Stop entered.");

    // triger drm waiting condition
    if (isDrmProtected_) {
        std::unique_lock<std::mutex> drmLock(drmMutex_);
        stopWaitingDrmConfig_ = true;
        drmConfigCond_.notify_all();
    }
    AutoLock lock(handleCompleteMutex_);
    UpdatePlayStatistics();
    callbackLooper_.StopReportMediaProgress();
    callbackLooper_.StopCollectMaxAmplitude();
    // close demuxer first to avoid concurrent problem
    auto ret = Status::ERROR_UNKNOWN;
    if (pipeline_ != nullptr) {
        ret = pipeline_->Stop();
    }
    syncManager_->Stop();
    if (audioDecoder_ != nullptr) {
        audioDecoder_->Flush();
    }
    #ifdef SUPPORT_VIDEO
        if (videoDecoder_) {
            videoDecoder_->Stop();
            videoDecoder_->Flush();
        }
    #endif
    if (audioSink_ != nullptr) {
        audioSink_->Flush();
    }
    if (subtitleSink_ != nullptr) {
        subtitleSink_->Flush();
    }
    for (std::pair<std::string, bool>& item: completeState_) {
        item.second = false;
    }

    ResetPlayRangeParameter();
    if (pipelineStates_ != PlayerStates::PLAYER_PREPARED) {
        AppendPlayerMediaInfo();
    }
    OnStateChanged(PlayerStateId::STOPPED);
    ReportMediaInfo(instanceId_);
    GetMediaInfoContainInstanceNum();
    return TransStatus(ret);
}

void HiPlayerImpl::ResetPlayRangeParameter()
{
    playRangeStartTime_ = PLAY_RANGE_DEFAULT_VALUE;
    playRangeEndTime_ = PLAY_RANGE_DEFAULT_VALUE;
    startTimeWithMode_ = PLAY_RANGE_DEFAULT_VALUE;
    endTimeWithMode_ = PLAY_RANGE_DEFAULT_VALUE;
    isSetPlayRange_ = false;
    playRangeSeekMode_ = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
}

void HiPlayerImpl::UpdatePlayStatistics()
{
    MEDIA_LOG_D_SHORT("HiPlayerImpl UpdatePlayStatistics");
    playStatisticalInfo_.isDrmProtected = isDrmProtected_;
    if (demuxer_ != nullptr) {
        DownloadInfo downLoadInfo;
        auto ret = demuxer_->GetDownloadInfo(downLoadInfo);
        if (ret == Status::OK) {
            MEDIA_LOG_D_SHORT("GetDownloadInfo success");
            playStatisticalInfo_.avgDownloadRate = downLoadInfo.avgDownloadRate;
            playStatisticalInfo_.avgDownloadSpeed = downLoadInfo.avgDownloadSpeed;
            playStatisticalInfo_.totalDownLoadBits = downLoadInfo.totalDownLoadBits;
            playStatisticalInfo_.isTimeOut = downLoadInfo.isTimeOut;
        } else {
            MEDIA_LOG_E("GetDownloadInfo failed with error " PUBLIC_LOG_D32, ret);
        }
    } else {
        MEDIA_LOG_E("GetDownloadInfo failed demuxer is null");
    }
    if (videoDecoder_ != nullptr) {
        auto ret = videoDecoder_->GetLagInfo(playStatisticalInfo_.lagTimes, playStatisticalInfo_.maxLagDuration,
            playStatisticalInfo_.avgLagDuration);
        if (ret == Status::OK) {
            MEDIA_LOG_I("GetLagInfo success");
        } else {
            MEDIA_LOG_E("GetLagInfo failed with error " PUBLIC_LOG_D32, ret);
        }
    } else {
        MEDIA_LOG_E("GetLagInfo failed videoDecoder is null error");
    }
}

inline bool HiPlayerImpl::IsStatisticalInfoValid()
{
    return playStatisticalInfo_.playDuration >= 0 && playStatisticalInfo_.startLatency >= 0;
}

void HiPlayerImpl::UpdatePlayTotalDuration()
{
    int64_t startTime = startTime_.load();
    FALSE_RETURN_NOLOG(startTime != -1);
    startTime_ = -1;
    playTotalDuration_ += GetCurrentMillisecond() - startTime;
}

void HiPlayerImpl::AppendPlayerMediaInfo()
{
    MEDIA_LOG_D_SHORT("AppendPlayerMediaInfo entered.");
    UpdatePlayTotalDuration();
    playStatisticalInfo_.playDuration = static_cast<int32_t>(playTotalDuration_);
    playStatisticalInfo_.maxSeekLatency = static_cast<int32_t>(maxSeekLatency_);
    playStatisticalInfo_.maxAccurateSeekLatency = static_cast<int32_t>(maxAccurateSeekLatency_);
    playStatisticalInfo_.maxSurfaceSwapLatency = static_cast<int32_t>(maxSurfaceSwapLatency_);
    playStatisticalInfo_.containerMime = playStatisticalInfo_.videoMime + " : " + playStatisticalInfo_.audioMime;
    FALSE_RETURN_MSG(IsStatisticalInfoValid(), "statistical info is invalid, don't report to bigdata");

    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::AV_PLAYER_ERR_CODE, playStatisticalInfo_.errCode);
    meta->SetData(Tag::AV_PLAYER_ERR_MSG, playStatisticalInfo_.errMsg);
    meta->SetData(Tag::AV_PLAYER_PLAY_DURATION, playStatisticalInfo_.playDuration);
    meta->SetData(Tag::AV_PLAYER_SOURCE_TYPE, playStatisticalInfo_.sourceType);
    meta->SetData(Tag::MEDIA_FILE_URI, playStatisticalInfo_.sourceUrl);
    meta->SetData(Tag::AV_PLAYER_AVG_DOWNLOAD_RATE, playStatisticalInfo_.avgDownloadRate);
    meta->SetData(Tag::AV_PLAYER_AVG_DOWNLOAD_SPEED, playStatisticalInfo_.avgDownloadSpeed);
    meta->SetData(Tag::AV_PLAYER_DOWNLOAD_TOTAL_BITS, playStatisticalInfo_.totalDownLoadBits);
    meta->SetData(Tag::AV_PLAYER_DOWNLOAD_TIME_OUT, playStatisticalInfo_.isTimeOut);
    meta->SetData(Tag::AV_PLAYER_CONTAINER_MIME, playStatisticalInfo_.containerMime);
    meta->SetData(Tag::AV_PLAYER_VIDEO_MIME, playStatisticalInfo_.videoMime);
    meta->SetData(Tag::AV_PLAYER_VIDEO_RESOLUTION, playStatisticalInfo_.videoResolution);
    meta->SetData(Tag::AV_PLAYER_VIDEO_BITRATE, playStatisticalInfo_.videoBitrate);
    meta->SetData(Tag::AV_PLAYER_VIDEO_FRAMERATE, playStatisticalInfo_.videoFrameRate);
    meta->SetData(Tag::AV_PLAYER_HDR_TYPE, playStatisticalInfo_.hdrType);
    meta->SetData(Tag::AV_PLAYER_AUDIO_MIME, playStatisticalInfo_.audioMime);
    meta->SetData(Tag::AUDIO_SAMPLE_RATE, playStatisticalInfo_.audioSampleRate);
    meta->SetData(Tag::AUDIO_CHANNEL_COUNT, playStatisticalInfo_.audioChannelCount);
    meta->SetData(Tag::AV_PLAYER_AUDIO_BITRATE, playStatisticalInfo_.audioBitrate);
    meta->SetData(Tag::AV_PLAYER_IS_DRM_PROTECTED, playStatisticalInfo_.isDrmProtected);
    meta->SetData(Tag::AV_PLAYER_START_LATENCY, playStatisticalInfo_.startLatency);
    meta->SetData(Tag::AV_PLAYER_MAX_SEEK_LATENCY, playStatisticalInfo_.maxSeekLatency);
    meta->SetData(Tag::AV_PLAYER_MAX_ACCURATE_SEEK_LATENCY, playStatisticalInfo_.maxAccurateSeekLatency);
    meta->SetData(Tag::AV_PLAYER_LAG_TIMES, playStatisticalInfo_.lagTimes);
    meta->SetData(Tag::AV_PLAYER_MAX_LAG_DURATION, playStatisticalInfo_.maxLagDuration);
    meta->SetData(Tag::AV_PLAYER_AVG_LAG_DURATION, playStatisticalInfo_.avgLagDuration);
    meta->SetData(Tag::AV_PLAYER_MAX_SURFACESWAP_LATENCY, playStatisticalInfo_.maxSurfaceSwapLatency);
    AppendMediaInfo(meta, instanceId_);
}

int32_t HiPlayerImpl::Reset()
{
    MediaTrace trace("HiPlayerImpl::Reset");
    if (pipelineStates_ == PlayerStates::PLAYER_STOPPED) {
        return TransStatus(Status::OK);
    }
    singleLoop_ = false;
    auto ret = Stop();
    if (syncManager_ != nullptr) {
        syncManager_->ResetMediaStartPts();
        syncManager_->Reset();
    }
    if (dfxAgent_ != nullptr) {
        dfxAgent_->SetSourceType(PlayerDfxSourceType::DFX_SOURCE_TYPE_UNKNOWN);
        dfxAgent_->ResetAgent();
    }
    OnStateChanged(PlayerStateId::STOPPED);
    return ret;
}

int32_t HiPlayerImpl::SeekToCurrentTime(int32_t mSeconds, PlayerSeekMode mode)
{
    MEDIA_LOG_I("SeekToCurrentTime in. mSeconds : " PUBLIC_LOG_D32 ", seekMode : " PUBLIC_LOG_D32,
                mSeconds, static_cast<int32_t>(mode));
    return Seek(mSeconds, mode);
}

int32_t HiPlayerImpl::HandleEosPlay()
{
    Plugins::AudioRenderInfo audioRenderInfo;
    FALSE_RETURN_V(
        audioRenderInfo_ && audioRenderInfo_->GetData(Tag::AUDIO_RENDER_INFO, audioRenderInfo), MSERR_INVALID_VAL);
    FALSE_RETURN_V(audioRenderInfo.streamUsage > AudioStandard::StreamUsage::STREAM_USAGE_INVALID &&
        audioRenderInfo.streamUsage < AudioStandard::StreamUsage::STREAM_USAGE_MAX, MSERR_INVALID_VAL);
    auto it = FOCUS_EVENT_USAGE_SET.find(static_cast<AudioStandard::StreamUsage>(audioRenderInfo.streamUsage));
    FALSE_RETURN_V(it == FOCUS_EVENT_USAGE_SET.end(), MSERR_INVALID_VAL);
    FALSE_RETURN_V(dfxAgent_ != nullptr, MSERR_INVALID_STATE);
    DfxEvent event = { .type = DfxEventType::DFX_INFO_PLAYER_EOS_SEEK, .param = appUid_ };
    dfxAgent_->OnDfxEvent(event);
    return MSERR_OK;
}

Status HiPlayerImpl::Seek(int64_t mSeconds, PlayerSeekMode mode, bool notifySeekDone)
{
    MediaTrace trace("HiPlayerImpl::Seek");
    MEDIA_LOG_I("Seek entered. mSeconds : " PUBLIC_LOG_D64 ", seekMode : " PUBLIC_LOG_D32,
                mSeconds, static_cast<int32_t>(mode));
    int64_t seekStartTime = GetCurrentMillisecond();
    if (audioSink_ != nullptr) {
        audioSink_->SetIsTransitent(true);
    }
    FALSE_RETURN_V_MSG_E(durationMs_.load() > 0, Status::ERROR_INVALID_PARAMETER,
        "Seek, invalid operation, source is unseekable or invalid");
    isSeek_ = true;
    int64_t seekPos = std::max(static_cast<int64_t>(0), std::min(mSeconds, static_cast<int64_t>(durationMs_.load())));
    auto rtv = seekPos >= 0 ? Status::OK : Status::ERROR_INVALID_PARAMETER;
    if (rtv == Status::OK) {
        rtv = HandleSeek(seekPos, mode);
    }
    NotifySeek(rtv, notifySeekDone, seekPos);
    if (audioSink_ != nullptr) {
        audioSink_->SetIsTransitent(false);
    }
    isSeek_ = false;
    UpdateMaxSeekLatency(mode, seekStartTime);
    return rtv;
}

Status HiPlayerImpl::HandleSeek(int64_t seekPos, PlayerSeekMode mode)
{
    switch (pipelineStates_) {
        case PlayerStates::PLAYER_STARTED: {
            return doStartedSeek(seekPos, mode);
        }
        case PlayerStates::PLAYER_PAUSED: {
            return doPausedSeek(seekPos, mode);
        }
        case PlayerStates::PLAYER_PLAYBACK_COMPLETE: {
            return doCompletedSeek(seekPos, mode);
        }
        case PlayerStates::PLAYER_PREPARED: {
            return doPreparedSeek(seekPos, mode);
        }
        default:
            MEDIA_LOG_I_SHORT("Seek in error pipelineStates: " PUBLIC_LOG_D32,
                static_cast<int32_t>(pipelineStates_));
            return Status::ERROR_WRONG_STATE;
    }
}

void HiPlayerImpl::UpdateMaxSeekLatency(PlayerSeekMode mode, int64_t seekStartTime)
{
    int64_t seekDiffTime = GetCurrentMillisecond() - seekStartTime;
    if (mode == PlayerSeekMode::SEEK_CLOSEST) {
        maxAccurateSeekLatency_ = (maxAccurateSeekLatency_ > seekDiffTime) ? maxAccurateSeekLatency_ : seekDiffTime;
    } else {
        maxSeekLatency_ = (maxSeekLatency_ > seekDiffTime) ? maxSeekLatency_ : seekDiffTime;
    }
}

void HiPlayerImpl::NotifySeek(Status rtv, bool flag, int64_t seekPos)
{
    if (rtv != Status::OK) {
        MEDIA_LOG_E("Seek done, seek error");
        FALSE_RETURN_MSG(!isInterruptNeeded_.load(), " Seek is Interrupted");
        // change player state to PLAYER_STATE_ERROR when seek error.
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
        Format format;
        callbackLooper_.OnError(PLAYER_ERROR, MSERR_DATA_SOURCE_IO_ERROR);
        callbackLooper_.OnInfo(INFO_TYPE_SEEKDONE, -1, format);
    }  else if (flag) {
        // only notify seekDone for external call.
        NotifySeekDone(seekPos);
    }
}

int32_t HiPlayerImpl::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    MediaTrace trace("HiPlayerImpl::Seek.");
    if (IsInValidSeekTime(mSeconds)) {
        MEDIA_LOG_E("Current seek time is not at playRange");
        auto errCode = TransStatus(Status::ERROR_INVALID_PARAMETER);
        OnEvent({"engine", EventType::EVENT_ERROR, errCode});
        return errCode;
    }
    MEDIA_LOG_I("Seek.");
    return TransStatus(Seek(mSeconds, mode, true));
}

Status HiPlayerImpl::doPreparedSeek(int64_t seekPos, PlayerSeekMode mode)
{
    MEDIA_LOG_I("doPreparedSeek.");
    pipeline_ -> Flush();
    auto rtv = doSeek(seekPos, mode);
    if ((rtv == Status::OK) && demuxer_->IsRenderNextVideoFrameSupported() && !demuxer_->IsVideoEos()) {
        rtv = pipeline_->Preroll(true);
    }
    return rtv;
}

Status HiPlayerImpl::doStartedSeek(int64_t seekPos, PlayerSeekMode mode)
{
    MEDIA_LOG_I("doStartedSeek");
    pipeline_ -> Pause();
    pipeline_ -> Flush();
    auto rtv = doSeek(seekPos, mode);
    pipeline_ -> Resume();
    inEosSeek_ = false;
    return rtv;
}

Status HiPlayerImpl::doPausedSeek(int64_t seekPos, PlayerSeekMode mode)
{
    MEDIA_LOG_I("doPausedSeek.");
    pipeline_ -> Pause();
    pipeline_ -> Flush();
    auto rtv = doSeek(seekPos, mode);
    inEosSeek_ = false;
    if ((rtv == Status::OK) && demuxer_->IsRenderNextVideoFrameSupported() && !demuxer_->IsVideoEos()) {
        rtv = pipeline_->Preroll(true);
    }
    return rtv;
}

Status HiPlayerImpl::doCompletedSeek(int64_t seekPos, PlayerSeekMode mode)
{
    MEDIA_LOG_D("doCompletedSeek");
    pipeline_ -> Flush();
    auto rtv = doSeek(seekPos, mode);
    if (mode != SEEK_CLOSEST && audioSink_ != nullptr) {
        audioSink_->SetSeekTime(0);
    }
    if (isStreaming_) {
        MEDIA_LOG_D("doCompletedSeek isStreaming_ is true");
        pipeline_->Resume();
        syncManager_->Resume();
    } else {
        if ((rtv == Status::OK) && demuxer_->IsRenderNextVideoFrameSupported() && !demuxer_->IsVideoEos()) {
            rtv = pipeline_->Preroll(true);
        }
        isDoCompletedSeek_ = true;
        callbackLooper_.StopReportMediaProgress();
        callbackLooper_.StopCollectMaxAmplitude();
        callbackLooper_.ManualReportMediaProgressOnce();
        OnStateChanged(PlayerStateId::PAUSE);
    }
    return rtv;
}

bool HiPlayerImpl::NeedSeekClosest()
{
    MEDIA_LOG_D("NeedSeekClosest begin");
    std::vector<Format> trackInfo;
    GetAudioTrackInfo(trackInfo);
    if (trackInfo.size() == 0) {
        MEDIA_LOG_D("NeedSeekClosest end true");
        return true;
    }
    for (size_t i = 0; i < trackInfo.size(); i++) {
        int32_t trackIndex = -1;
        trackInfo[i].GetIntValue("track_index", trackIndex);
        if (trackIndex != currentAudioTrackId_) {
            continue;
        }
        std::string mime = "";
        trackInfo[i].GetStringValue("codec_mime", mime);
        if (mime == "audio/x-ape") {
            MEDIA_LOG_D("NeedSeekClosest end false");
            return false;
        }
    }
    MEDIA_LOG_D("NeedSeekClosest end true");
    return true;
}

Status HiPlayerImpl::doSeek(int64_t seekPos, PlayerSeekMode mode)
{
    MEDIA_LOG_D("doSeek");
    int64_t seekTimeUs = 0;
    FALSE_RETURN_V_MSG_E(Plugins::Us2HstTime(seekPos, seekTimeUs),
        Status::ERROR_INVALID_PARAMETER, "Invalid seekPos: %{public}" PRId64, seekPos);
    if (mode == PlayerSeekMode::SEEK_CLOSEST && NeedSeekClosest()) {
        return HandleSeekClosest(seekPos, seekTimeUs);
    }
    if (mode == PlayerSeekMode::SEEK_CLOSEST) {   // reset mode
        mode = PlayerSeekMode::SEEK_NEXT_SYNC;
        if (audioSink_) {
            audioSink_->SetSeekTime(seekTimeUs);
        }
    }
    if (videoDecoder_ != nullptr) {
        videoDecoder_->ResetSeekInfo();
    }
    int64_t realSeekTime = seekPos;
    auto seekMode = Transform2SeekMode(mode);
    auto rtv = demuxer_->SeekTo(seekPos, seekMode, realSeekTime);
    // if it has no next key frames, seek previous.
    if (rtv != Status::OK && mode == PlayerSeekMode::SEEK_NEXT_SYNC) {
        seekMode = Transform2SeekMode(PlayerSeekMode::SEEK_PREVIOUS_SYNC);
        rtv = demuxer_->SeekTo(seekPos, seekMode, realSeekTime);
    }
    if (rtv == Status::OK) {
        syncManager_->Seek(seekTimeUs);
        if (subtitleSink_ != nullptr) {
            subtitleSink_->NotifySeek();
        }
    }
    return rtv;
}

Status HiPlayerImpl::HandleSeekClosest(int64_t seekPos, int64_t seekTimeUs)
{
    MEDIA_LOG_I_SHORT("doSeek SEEK_CLOSEST");
    isSeekClosest_.store(true);
    if (videoDecoder_ != nullptr) {
        videoDecoder_->SetSeekTime(seekTimeUs + mediaStartPts_);
    }
    if (audioSink_ != nullptr) {
        audioSink_->SetIsCancelStart(true);
    }
    seekAgent_ = std::make_shared<SeekAgent>(demuxer_, mediaStartPts_);
    interruptMonitor_->RegisterListener(seekAgent_);
    SetFrameRateForSeekPerformance(FRAME_RATE_FOR_SEEK_PERFORMANCE);
    bool timeout = false;
    auto res = seekAgent_->Seek(seekPos, timeout);
    SetFrameRateForSeekPerformance(FRAME_RATE_DEFAULT);
    MEDIA_LOG_I_SHORT("seekAgent_ Seek end");
    if (res != Status::OK) {
        MEDIA_LOG_E_SHORT("Seek closest failed");
    } else {
        syncManager_->Seek(seekTimeUs, true);
        if (timeout && videoDecoder_ != nullptr) {
            videoDecoder_->ResetSeekInfo();
        }
    }
    if (audioSink_ != nullptr) {
        audioSink_->SetIsCancelStart(false);
    }
    if (subtitleSink_ != nullptr) {
        subtitleSink_->NotifySeek();
    }
    interruptMonitor_->DeregisterListener(seekAgent_);
    seekAgent_.reset();
    return res;
}

int32_t HiPlayerImpl::SetVolume(float leftVolume, float rightVolume)
{
    MEDIA_LOG_D("SetVolume in");
    FALSE_RETURN_V_MSG_E(!(leftVolume < 0 || leftVolume > MAX_MEDIA_VOLUME
        || rightVolume < 0 || rightVolume > MAX_MEDIA_VOLUME),
        (int32_t)Status::ERROR_INVALID_PARAMETER, "volume not valid, should be in range [0,100]");
    float volume = 0.0f;
    if (leftVolume < 1e-6 && rightVolume >= 1e-6) {  // 1e-6
        volume = rightVolume;
    } else if (rightVolume < 1e-6 && leftVolume >= 1e-6) {  // 1e-6
        volume = leftVolume;
    } else {
        volume = (leftVolume + rightVolume) / 2;  // 2
    }
    volume /= MAX_MEDIA_VOLUME;  // normalize to 0~1
    FALSE_RETURN_V_MSG_E(audioSink_ != nullptr, (int32_t)TransStatus(Status::ERROR_INVALID_OPERATION),
        "Set volume failed, audio sink is nullptr");
    MEDIA_LOG_D("Sink SetVolume");
    Status ret = audioSink_->SetVolume(volume);
    if (ret != Status::OK) {
        MEDIA_LOG_E("SetVolume failed with error " PUBLIC_LOG_D32, static_cast<int>(ret));
    }
    return TransStatus(ret);
}

int32_t HiPlayerImpl::SetVideoSurface(sptr<Surface> surface)
{
    MEDIA_LOG_D("SetVideoSurface in");
#ifdef SUPPORT_VIDEO
    int64_t startSetSurfaceTime = GetCurrentMillisecond();
    FALSE_RETURN_V_MSG_E(surface != nullptr, (int32_t)(Status::ERROR_INVALID_PARAMETER),
                         "Set video surface failed, surface == nullptr");
    surface_ = surface;
    if (videoDecoder_ != nullptr &&
        pipelineStates_ != PlayerStates::PLAYER_STOPPED &&
        pipelineStates_ != PlayerStates::PLAYER_STATE_ERROR) {
        return TransStatus(videoDecoder_->SetVideoSurface(surface));
    }
    int64_t endSetSurfaceTime = GetCurrentMillisecond();
    int64_t diffTime = endSetSurfaceTime - startSetSurfaceTime;
    maxSurfaceSwapLatency_ = maxSurfaceSwapLatency_ > diffTime ? maxSurfaceSwapLatency_ : diffTime;
#endif
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetDecryptConfig(const sptr<OHOS::DrmStandard::IMediaKeySessionService> &keySessionProxy,
    bool svp)
{
    MEDIA_LOG_I("SetDecryptConfig in");
#ifdef SUPPORT_AVPLAYER_DRM
    FALSE_RETURN_V_MSG_E(keySessionProxy != nullptr, (int32_t)(Status::ERROR_INVALID_PARAMETER),
        "SetDecryptConfig failed, keySessionProxy == nullptr");
    keySessionServiceProxy_ = keySessionProxy;
    if (svp) {
        svpMode_ = HiplayerSvpMode::SVP_TRUE;
    } else {
        svpMode_ = HiplayerSvpMode::SVP_FALSE;
    }

    std::unique_lock<std::mutex> drmLock(drmMutex_);
    MEDIA_LOG_I("For Drmcond SetDecryptConfig will trig drmPreparedCond");
    isDrmPrepared_ = true;
    drmConfigCond_.notify_all();
#endif
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetLooping(bool loop)
{
    MEDIA_LOG_I("SetLooping in, loop: " PUBLIC_LOG_D32, loop);
    singleLoop_ = loop;
    if (audioSink_ != nullptr) {
        audioSink_->SetLooping(loop);
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetParameter(const Format& params)
{
    MediaTrace trace("HiPlayerImpl::SetParameter");
#ifdef SUPPORT_VIDEO
    if (params.ContainKey(PlayerKeys::VIDEO_SCALE_TYPE)) {
        int32_t videoScaleType = 0;
        params.GetIntValue(PlayerKeys::VIDEO_SCALE_TYPE, videoScaleType);
        return SetVideoScaleType(VideoScaleType(videoScaleType));
    }
#endif
    if (params.ContainKey(PlayerKeys::CONTENT_TYPE) && params.ContainKey(PlayerKeys::STREAM_USAGE)) {
        int32_t contentType;
        int32_t streamUsage;
        int32_t rendererFlag;
        params.GetIntValue(PlayerKeys::CONTENT_TYPE, contentType);
        params.GetIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
        params.GetIntValue(PlayerKeys::RENDERER_FLAG, rendererFlag);
        return SetAudioRendererInfo(contentType, streamUsage, rendererFlag);
    }
    if (params.ContainKey(PlayerKeys::AUDIO_INTERRUPT_MODE)) {
        int32_t interruptMode = 0;
        params.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, interruptMode);
        return SetAudioInterruptMode(interruptMode);
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetObs(const std::weak_ptr<IPlayerEngineObs>& obs)
{
    MEDIA_LOG_D_SHORT("SetObs");
    callbackLooper_.StartWithPlayerEngineObs(obs);
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetCurrentTime(int32_t& currentPositionMs)
{
    if (!isSetPlayRange_ && (curState_ == PlayerStateId::EOS || inEosSeek_)) {
        currentPositionMs = durationMs_.load();
        return TransStatus(Status::OK);
    }
    if (isSeek_.load()) {
        return TransStatus(Status::ERROR_UNKNOWN);
    }
    FALSE_RETURN_V(syncManager_ != nullptr, TransStatus(Status::ERROR_NULL_POINTER));
    currentPositionMs = Plugins::HstTime2Us32(syncManager_->GetMediaTimeNow());
    MEDIA_LOG_D("GetCurrentTime currentPositionMs: " PUBLIC_LOG_D32, currentPositionMs);
    if (currentPositionMs < 0) {
        currentPositionMs = 0;
    }
    if (durationMs_.load() > 0 && currentPositionMs > durationMs_.load()) {
        currentPositionMs = durationMs_.load();
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetPlaybackPosition(int32_t& playbackPositionMs)
{
    FALSE_RETURN_V(syncManager_ != nullptr, TransStatus(Status::ERROR_NULL_POINTER));
    playbackPositionMs = Plugins::HstTime2Us32(syncManager_->GetMediaTimeNow());
    MEDIA_LOG_D("GetPlaybackPosition playbackPositionMs: " PUBLIC_LOG_D32, playbackPositionMs);
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetDuration(int32_t& durationMs)
{
    durationMs = durationMs_.load();
    MEDIA_LOG_D_SHORT("GetDuration " PUBLIC_LOG_D32, durationMs);
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::InitDuration()
{
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr,
        TransStatus(Status::ERROR_WRONG_STATE), "Get media duration failed, demuxer is not ready");
    int64_t duration = 0;
    bool found = false;
    if (demuxer_->GetDuration(duration)) {
        found = true;
    } else {
        MEDIA_LOG_W("Get media duration failed");
    }
    if (found && duration > 0 && duration != durationMs_.load()) {
        durationMs_ = Plugins::HstTime2Us(duration);
    }
    durationMs_ = std::max(durationMs_.load(), 0);
    MEDIA_LOG_D("duration: " PUBLIC_LOG_D32, durationMs_.load());
    return TransStatus(Status::OK);
}

void HiPlayerImpl::SetBundleName(std::string bundleName)
{
    if (!bundleName.empty()) {
        MEDIA_LOG_I("SetBundleName bundleName: " PUBLIC_LOG_S, bundleName.c_str());
        demuxer_->SetBundleName(bundleName);
    } else {
        MEDIA_LOG_I("SetBundleName failed");
    }
}

int32_t HiPlayerImpl::InitVideoWidthAndHeight()
{
#ifdef SUPPORT_VIDEO
    std::vector<Format> videoTrackInfo;
    GetVideoTrackInfo(videoTrackInfo);
    if (videoTrackInfo.size() == 0) {
        MEDIA_LOG_E("InitVideoWidthAndHeight failed, as videoTrackInfo is empty!");
        return TransStatus(Status::ERROR_INVALID_OPERATION);
    }
    int32_t currentVideoTrackId = demuxer_->GetCurrentVideoTrackId();
    FALSE_RETURN_V_MSG_E(currentVideoTrackId != -1, TransStatus(Status::ERROR_INVALID_OPERATION),
        "InitVideoWidthAndHeight failed, as currentVideoTrackId is invalid!");
    for (auto& videoTrack : videoTrackInfo) {
        int32_t videoTrackId = -1;
        videoTrack.GetIntValue("track_index", videoTrackId);
        if (videoTrackId != currentVideoTrackId) {
            continue;
        }
        int32_t height;
        videoTrack.GetIntValue("height", height);
        int32_t width;
        videoTrack.GetIntValue("width", width);
        if (height <= 0 && width <= 0) {
            continue;
        }
        int32_t rotation = 0;
        needSwapWH_ = videoTrack.GetIntValue(Tag::VIDEO_ROTATION, rotation)
            && (rotation == rotation90 || rotation == rotation270);
        MEDIA_LOG_D("rotation %{public}d", rotation);
        videoWidth_ = !needSwapWH_.load() ? width : height;
        videoHeight_ = !needSwapWH_.load() ? height : width;
        MEDIA_LOG_D("InitVideo width %{public}d, height %{public}d",
            videoWidth_.load(), videoHeight_.load());
        break;
    }
#endif
    return TransStatus(Status::OK);
}

Status HiPlayerImpl::InitAudioDefaultTrackIndex()
{
    if (!demuxer_) {
        return Status::ERROR_UNKNOWN;
    }
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime))) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsAudioMime(mime)) {
            defaultAudioTrackId_ = static_cast<int32_t>(trackIndex);
            break;
        }
    }
    currentAudioTrackId_ = defaultAudioTrackId_;
    return Status::OK;
}

Status HiPlayerImpl::InitVideoDefaultTrackIndex()
{
    if (!demuxer_) {
        return Status::ERROR_UNKNOWN;
    }
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime))) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsVideoMime(mime)) {
            defaultVideoTrackId_ = static_cast<int32_t>(trackIndex);
            break;
        }
    }
    currentVideoTrackId_ = defaultVideoTrackId_;
    return Status::OK;
}

Status HiPlayerImpl::InitSubtitleDefaultTrackIndex()
{
    if (!demuxer_) {
        return Status::ERROR_UNKNOWN;
    }
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime))) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsSubtitleMime(mime)) {
            defaultSubtitleTrackId_ = static_cast<int32_t>(trackIndex);
            break;
        }
    }
    currentSubtitleTrackId_ = defaultSubtitleTrackId_;
    return Status::OK;
}

int32_t HiPlayerImpl::SetAudioEffectMode(int32_t effectMode)
{
    MEDIA_LOG_I("SetAudioEffectMode in");
    Status res = Status::OK;
    if (audioSink_ != nullptr) {
        res = audioSink_->SetAudioEffectMode(effectMode);
    }
    if (res != Status::OK) {
        MEDIA_LOG_E("audioSink set AudioEffectMode error");
        return MSERR_UNKNOWN;
    }
    return MSERR_OK;
}

int32_t HiPlayerImpl::GetAudioEffectMode(int32_t &effectMode)
{
    MEDIA_LOG_I("GetAudioEffectMode in");
    Status res = Status::OK;
    if (audioSink_ != nullptr) {
        res = audioSink_->GetAudioEffectMode(effectMode);
    }
    FALSE_RETURN_V_MSG_E(res == Status::OK,
        MSERR_UNKNOWN, "audioSink get AudioEffectMode error");
    return MSERR_OK;
}

float HiPlayerImpl::GetMaxAmplitude()
{
    float maxAmplitude = 0.0f;
    if (audioSink_ != nullptr) {
        maxAmplitude = audioSink_->GetMaxAmplitude();
    }
    return maxAmplitude;
}

int32_t HiPlayerImpl::SetPlaybackSpeed(PlaybackRateMode mode)
{
    MEDIA_LOG_I("SetPlaybackSpeed %{public}d", mode);
    Status res = Status::OK;
    float speed = TransformPlayRate2Float(mode);
    if (audioSink_ != nullptr) {
        res = audioSink_->SetSpeed(speed);
    }
    if (subtitleSink_ != nullptr) {
        res = subtitleSink_->SetSpeed(speed);
    }
    if (res != Status::OK) {
        MEDIA_LOG_E("SetPlaybackSpeed audioSink set speed  error");
        return MSERR_UNKNOWN;
    }
    if (syncManager_ != nullptr) {
        res = syncManager_->SetPlaybackRate(speed);
    }
    if (res != Status::OK) {
        MEDIA_LOG_E("SetPlaybackSpeed syncManager set audio speed error");
        return MSERR_UNKNOWN;
    }
    if (demuxer_ != nullptr) {
        demuxer_->SetSpeed(speed);
    }
    playbackRateMode_ = mode;
    Format format;
    callbackLooper_.OnInfo(INFO_TYPE_SPEEDDONE, mode, format);
    MEDIA_LOG_I("SetPlaybackSpeed end");
    return MSERR_OK;
}

int32_t HiPlayerImpl::GetPlaybackSpeed(PlaybackRateMode& mode)
{
    MEDIA_LOG_I("GetPlaybackSpeed in");
    mode = playbackRateMode_.load();
    MEDIA_LOG_I("GetPlaybackSpeed end, mode is " PUBLIC_LOG_D32, mode);
    return MSERR_OK;
}

bool HiPlayerImpl::IsVideoMime(const std::string& mime)
{
    return mime.find("video/") == 0;
}

bool HiPlayerImpl::IsAudioMime(const std::string& mime)
{
    return mime.find("audio/") == 0;
}

bool HiPlayerImpl::IsSubtitleMime(const std::string& mime)
{
    if (mime == "application/x-subrip" || mime == "text/vtt") {
        return true;
    }
    return false;
}

bool HiPlayerImpl::IsNeedAudioSinkChangeTrack(std::vector<std::shared_ptr<Meta>>& metaInfo, int32_t trackId)
{
    if (trackId == currentAudioTrackId_) {
        return false;
    }
    MEDIA_LOG_I("CurTrackId " PUBLIC_LOG_D32 " trackId " PUBLIC_LOG_D32, currentAudioTrackId_, trackId);

    int32_t sampleRate = -1;
    int32_t channels = -1;
    Plugins::AudioSampleFormat sampleFormat;

    int32_t currentSampleRate = -1;
    int32_t currentChannels = -1;
    Plugins::AudioSampleFormat currentSampleFormat;

    FALSE_RETURN_V(metaInfo[trackId]->GetData(Tag::AUDIO_SAMPLE_RATE, sampleRate), true);
    FALSE_RETURN_V(metaInfo[currentAudioTrackId_]->GetData(Tag::AUDIO_SAMPLE_RATE, currentSampleRate), true);
    FALSE_RETURN_V(sampleRate == currentSampleRate, true);

    FALSE_RETURN_V(metaInfo[trackId]->GetData(Tag::AUDIO_CHANNEL_COUNT, channels), true);
    FALSE_RETURN_V(metaInfo[currentAudioTrackId_]->GetData(Tag::AUDIO_CHANNEL_COUNT, currentChannels), true);
    FALSE_RETURN_V(channels == currentChannels, true);

    FALSE_RETURN_V(metaInfo[trackId]->GetData(Tag::AUDIO_SAMPLE_FORMAT, sampleFormat), true);
    FALSE_RETURN_V(metaInfo[currentAudioTrackId_]->GetData(Tag::AUDIO_SAMPLE_FORMAT, currentSampleFormat), true);
    FALSE_RETURN_V(sampleFormat == currentSampleFormat, true);

    std::string mimeType;
    AudioStandard::AudioEncodingType encodingType;
    std::string currentMimeType;
    AudioStandard::AudioEncodingType currentEncodingType;
    FALSE_RETURN_V(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mimeType), true);
    FALSE_RETURN_V(metaInfo[currentAudioTrackId_]->GetData(Tag::MIME_TYPE, currentMimeType), true);
    encodingType = (mimeType == MimeType::AUDIO_AVS3DA)
                ? AudioStandard::ENCODING_AUDIOVIVID : AudioStandard::ENCODING_PCM;
    currentEncodingType = (currentMimeType == MimeType::AUDIO_AVS3DA)
                ? AudioStandard::ENCODING_AUDIOVIVID : AudioStandard::ENCODING_PCM;
    FALSE_RETURN_V(mimeType == currentMimeType, true);

    return false;
}

int32_t HiPlayerImpl::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    FALSE_RETURN_V_MSG_W(trackType >= OHOS::Media::MediaType::MEDIA_TYPE_AUD &&
        trackType <= OHOS::Media::MediaType::MEDIA_TYPE_SUBTITLE,
        MSERR_INVALID_VAL, "Invalid trackType %{public}d", trackType);
    if (trackType == OHOS::Media::MediaType::MEDIA_TYPE_AUD) {
        if (currentAudioTrackId_ < 0) {
            if (Status::OK != InitAudioDefaultTrackIndex()) {
                return MSERR_UNKNOWN;
            }
        }
        index = currentAudioTrackId_;
    } else if (trackType == OHOS::Media::MediaType::MEDIA_TYPE_VID) {
        if (currentVideoTrackId_ < 0) {
            if (Status::OK != InitVideoDefaultTrackIndex()) {
                return MSERR_UNKNOWN;
            }
        }
        index = currentVideoTrackId_;
    } else if (trackType == OHOS::Media::MediaType::MEDIA_TYPE_SUBTITLE) {
        if (currentSubtitleTrackId_ < 0) {
            if (Status::OK != InitSubtitleDefaultTrackIndex()) {
                return MSERR_UNKNOWN;
            }
        }
        index = currentSubtitleTrackId_;
    } else {
        (void)index;
    }

    return MSERR_OK;
}

int32_t HiPlayerImpl::InnerSelectTrack(std::string mime, int32_t trackId, PlayerSwitchMode mode)
{
    if (Status::OK != demuxer_->SelectTrack(trackId)) {
        MEDIA_LOG_E_SHORT("SelectTrack error. trackId is " PUBLIC_LOG_D32, trackId);
        return MSERR_UNKNOWN;
    }
    if (IsAudioMime(mime)) {
        currentAudioTrackId_ = trackId;
    } else if (IsSubtitleMime(mime)) {
        currentSubtitleTrackId_ = trackId;
    } else if (IsVideoMime(mime)) {
        currentVideoTrackId_ = trackId;
        int32_t curPosMs = 0;
        GetCurrentTime(curPosMs);
        if (mode == PlayerSwitchMode::SWITCH_SEGMENT) {
            MEDIA_LOG_I("SelectTrack seek begin SWITCH_SEGMENT " PUBLIC_LOG_D32, trackId);
            return TransStatus(Seek(curPosMs, PlayerSeekMode::SEEK_PREVIOUS_SYNC, false));
        } else if (mode == PlayerSwitchMode::SWITCH_CLOSEST) {
            MEDIA_LOG_I("SelectTrack seek begin SWITCH_CLOSEST " PUBLIC_LOG_D32, trackId);
            return TransStatus(Seek(curPosMs, PlayerSeekMode::SEEK_CLOSEST, false));
        }
    }
    return MSERR_OK;
}

int32_t HiPlayerImpl::SelectTrack(int32_t trackId, PlayerSwitchMode mode)
{
    MEDIA_LOG_I("SelectTrack begin trackId is " PUBLIC_LOG_D32, trackId);
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    FALSE_RETURN_V_MSG_W(trackId >= 0 && trackId < static_cast<int32_t>(metaInfo.size()),
        MSERR_INVALID_VAL, "SelectTrack trackId invalid");
    if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime))) {
        MEDIA_LOG_E("SelectTrack trackId " PUBLIC_LOG_D32 "get mime error", trackId);
        return MSERR_INVALID_VAL;
    }
    if (IsAudioMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId != currentAudioTrackId_, MSERR_INVALID_VAL, "SelectTrack trackId invalid");
        if (currentAudioTrackId_ < 0) {
            if (Status::OK != InitAudioDefaultTrackIndex()) {
                MEDIA_LOG_W("Init audio default track index fail");
            }
        }
    } else if (IsVideoMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId != currentVideoTrackId_, MSERR_INVALID_VAL, "SelectTrack trackId invalid");
        if (currentVideoTrackId_ < 0) {
            if (Status::OK != InitVideoDefaultTrackIndex()) {
                MEDIA_LOG_W("Init video default track index fail");
            }
        }
    } else if (IsSubtitleMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId != currentSubtitleTrackId_, MSERR_INVALID_VAL, "SelectTrack trackId invalid");
        if (currentSubtitleTrackId_ < 0) {
            if (Status::OK != InitSubtitleDefaultTrackIndex()) {
                MEDIA_LOG_W("Init subtitle default track index fail");
            }
        }
    } else {
        MEDIA_LOG_E("SelectTrack invalid mimeType. trackId is " PUBLIC_LOG_D32, trackId);
        return MSERR_UNKNOWN;
    }
    return InnerSelectTrack(mime, trackId, mode);
}

int32_t HiPlayerImpl::DeselectTrack(int32_t trackId)
{
    MEDIA_LOG_I("DeselectTrack trackId is " PUBLIC_LOG_D32, trackId);
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    FALSE_RETURN_V_MSG_W(trackId >= 0 && trackId < static_cast<int32_t>(metaInfo.size()),
        MSERR_INVALID_VAL, "DeselectTrack trackId invalid");
    std::string mime;
    if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime))) {
        MEDIA_LOG_E("DeselectTrack trackId " PUBLIC_LOG_D32 "get mime error", trackId);
        return MSERR_INVALID_VAL;
    }
    if (IsAudioMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId == currentAudioTrackId_ && currentAudioTrackId_ >= 0,
            MSERR_INVALID_VAL, "DeselectTrack trackId invalid");
        return SelectTrack(defaultAudioTrackId_, PlayerSwitchMode::SWITCH_SMOOTH);
    } else if (IsVideoMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId == currentVideoTrackId_ && currentVideoTrackId_ >= 0,
            MSERR_INVALID_VAL, "DeselectTrack trackId invalid");
        return SelectTrack(defaultVideoTrackId_, PlayerSwitchMode::SWITCH_SMOOTH);
    } else if (IsSubtitleMime(mime)) {
        FALSE_RETURN_V_MSG_W(trackId == currentSubtitleTrackId_ && currentSubtitleTrackId_ >= 0,
            MSERR_INVALID_VAL, "DeselectTrack trackId invalid");
        if (needUpdateSubtitle_.load()) {
            needUpdateSubtitle_.store(false);
        } else {
            needUpdateSubtitle_.store(true);
        }
    } else {}
    return MSERR_OK;
}

int32_t HiPlayerImpl::GetVideoTrackInfo(std::vector<Format>& videoTrack)
{
    MEDIA_LOG_D("GetVideoTrackInfo in");
    FALSE_RETURN_V(demuxer_ != nullptr, MSERR_INVALID_STATE);
    std::string mime;
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime)) || mime.find("invalid") == 0) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsVideoMime(mime)) {
            Format videoTrackInfo {};
            playStatisticalInfo_.videoMime = mime;
            videoTrackInfo.PutStringValue("codec_mime", mime);
            videoTrackInfo.PutIntValue("track_type", static_cast<int32_t>(OHOS::Media::Plugins::MediaType::VIDEO));
            videoTrackInfo.PutIntValue("track_index", trackIndex);
            int64_t bitRate;
            trackInfo->GetData(Tag::MEDIA_BITRATE, bitRate);
            playStatisticalInfo_.videoBitrate = static_cast<int32_t>(bitRate);
            videoTrackInfo.PutLongValue("bitrate", bitRate);
            double frameRate;
            trackInfo->GetData(Tag::VIDEO_FRAME_RATE, frameRate);
            playStatisticalInfo_.videoFrameRate = static_cast<float>(frameRate);
            videoTrackInfo.PutDoubleValue("frame_rate", frameRate * FRAME_RATE_UNIT_MULTIPLE);
            int32_t height = GetSarVideoHeight(trackInfo);
            videoTrackInfo.PutIntValue("height", height);
            int32_t width = GetSarVideoWidth(trackInfo);
            playStatisticalInfo_.videoResolution = std::to_string(width) + "x" + std::to_string(height);
            videoTrackInfo.PutIntValue("width", width);
            Plugins::VideoRotation rotation;
            trackInfo->Get<Tag::VIDEO_ROTATION>(rotation);
            videoTrackInfo.PutIntValue(Tag::VIDEO_ROTATION, rotation);
            videoTrackInfo.PutStringValue("track_name", "video");
            bool isHdr = false;
            trackInfo->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdr);
            if (isHdr) {
                playStatisticalInfo_.hdrType = static_cast<int8_t>(VideoHdrType::VIDEO_HDR_TYPE_VIVID);
                videoTrackInfo.PutIntValue("hdr_type", 1);
            } else {
                playStatisticalInfo_.hdrType = static_cast<int8_t>(VideoHdrType::VIDEO_HDR_TYPE_NONE);
                videoTrackInfo.PutIntValue("hdr_type", 0);
            }
            videoTrack.emplace_back(std::move(videoTrackInfo));
        }
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetSarVideoWidth(std::shared_ptr<Meta> trackInfo)
{
    int32_t width;
    trackInfo->GetData(Tag::VIDEO_WIDTH, width);
    double videoSar;
    bool ret = trackInfo->GetData(Tag::VIDEO_SAR, videoSar);
    if (ret && videoSar < 1) {
        width = static_cast<int32_t>(width * videoSar);
    }
    return width;
}

int32_t HiPlayerImpl::GetSarVideoHeight(std::shared_ptr<Meta> trackInfo)
{
    int32_t height;
    trackInfo->GetData(Tag::VIDEO_HEIGHT, height);
    double videoSar;
    bool ret = trackInfo->GetData(Tag::VIDEO_SAR, videoSar);
    if (ret && videoSar > 1) {
        height = static_cast<int32_t>(height / videoSar);
    }
    return height;
}

int32_t HiPlayerImpl::GetPlaybackInfo(Format& playbackInfo)
{
    MEDIA_LOG_D("GetPlaybackInfo in");

    PlaybackInfo playbackInfoTmp;
    auto ret = demuxer_->GetPlaybackInfo(playbackInfoTmp);
    if (ret == Status::OK) {
        playbackInfo.PutStringValue("server_ip_address", playbackInfoTmp.serverIpAddress);
        playbackInfo.PutLongValue("average_download_rate", playbackInfoTmp.averageDownloadRate);
        playbackInfo.PutLongValue("download_rate", playbackInfoTmp.downloadRate);
        playbackInfo.PutIntValue("is_downloading", playbackInfoTmp.isDownloading);
        playbackInfo.PutLongValue("buffer_duration", playbackInfoTmp.bufferDuration);
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetAudioTrackInfo(std::vector<Format>& audioTrack)
{
    MEDIA_LOG_I("GetAudioTrackInfo in");
    std::string mime;
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime)) || mime.find("invalid") == 0) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsAudioMime(mime)) {
            playStatisticalInfo_.audioMime = mime;
            Format audioTrackInfo {};
            audioTrackInfo.PutStringValue("codec_mime", mime);
            audioTrackInfo.PutIntValue("track_type", static_cast<int32_t>(OHOS::Media::Plugins::MediaType::AUDIO));
            audioTrackInfo.PutIntValue("track_index", static_cast<int32_t>(trackIndex));
            int64_t bitRate = 0;
            trackInfo->GetData(Tag::MEDIA_BITRATE, bitRate);
            playStatisticalInfo_.audioBitrate = static_cast<int32_t>(bitRate);
            audioTrackInfo.PutLongValue("bitrate", bitRate);
            int32_t audioChannels = 0;
            trackInfo->GetData(Tag::AUDIO_CHANNEL_COUNT, audioChannels);
            playStatisticalInfo_.audioChannelCount = audioChannels;
            audioTrackInfo.PutIntValue("channel_count", audioChannels);
            int32_t audioSampleRate = 0;
            trackInfo->GetData(Tag::AUDIO_SAMPLE_RATE, audioSampleRate);
            playStatisticalInfo_.audioSampleRate = audioSampleRate;
            audioTrackInfo.PutIntValue("sample_rate", audioSampleRate);
            int32_t sampleDepth = 0;
            bool isHasData = trackInfo->GetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, sampleDepth);
            if (!isHasData || sampleDepth <= 0) {
                trackInfo->GetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, sampleDepth);
            }
            audioTrackInfo.PutIntValue("sample_depth", sampleDepth);
            std::string lang;
            trackInfo->GetData(Tag::MEDIA_LANGUAGE, lang);
            audioTrackInfo.PutStringValue("language", lang);
            audioTrackInfo.PutStringValue("track_name", "audio");
            audioTrack.emplace_back(std::move(audioTrackInfo));
        }
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetSubtitleTrackInfo(std::vector<Format>& subtitleTrack)
{
    MEDIA_LOG_I("GetSubtitleTrackInfo in");
    std::string mime;
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    for (size_t trackIndex = 0; trackIndex < metaInfo.size(); trackIndex++) {
        auto trackInfo = metaInfo[trackIndex];
        if (!(trackInfo->GetData(Tag::MIME_TYPE, mime)) || mime.find("invalid") == 0) {
            MEDIA_LOG_W("Get MIME fail");
            continue;
        }
        if (IsSubtitleMime(mime)) {
            playStatisticalInfo_.subtitleMime = mime;
            Format subtitleTrackInfo {};
            subtitleTrackInfo.PutStringValue("codec_mime", mime);
            subtitleTrackInfo.PutIntValue("track_type",
                static_cast<int32_t>(OHOS::Media::Plugins::MediaType::SUBTITLE));
            subtitleTrackInfo.PutIntValue("track_index", static_cast<int32_t>(trackIndex));

            std::string lang;
            trackInfo->GetData(Tag::MEDIA_LANGUAGE, lang);
            subtitleTrackInfo.PutStringValue("language", lang);
            subtitleTrackInfo.PutStringValue("track_name", "subtitle");

            subtitleTrack.emplace_back(std::move(subtitleTrackInfo));
        }
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::GetVideoWidth()
{
#ifdef SUPPORT_VIDEO
    MEDIA_LOG_D_SHORT("GetVideoWidth in. video width: " PUBLIC_LOG_D32, videoWidth_.load());
#endif
    return videoWidth_.load();
}

int32_t HiPlayerImpl::GetVideoHeight()
{
#ifdef SUPPORT_VIDEO
    MEDIA_LOG_D_SHORT("GetVideoHeight in. video height: " PUBLIC_LOG_D32, videoHeight_.load());
#endif
    return videoHeight_.load();
}

int32_t HiPlayerImpl::SetVideoScaleType(OHOS::Media::VideoScaleType videoScaleType)
{
    MEDIA_LOG_D_SHORT("SetVideoScaleType " PUBLIC_LOG_D32, videoScaleType);
#ifdef SUPPORT_VIDEO
    auto meta = std::make_shared<Meta>();
    meta->Set<Tag::VIDEO_SCALE_TYPE>(static_cast<int32_t>(videoScaleType));
    if (videoDecoder_) {
        videoDecoder_->SetParameter(meta);
    }
    return TransStatus(Status::OK);
#else
    return TransStatus(Status::OK);
#endif
}

int32_t HiPlayerImpl::SetFrameRateForSeekPerformance(double frameRate)
{
    MEDIA_LOG_I("SetFrameRateForSeekPerformance, frameRate: %{public}f", frameRate);
#ifdef SUPPORT_VIDEO
    auto meta = std::make_shared<Meta>();
    meta->Set<Tag::VIDEO_FRAME_RATE>(frameRate);
    if (videoDecoder_) {
        videoDecoder_->SetParameter(meta);
    }
    return TransStatus(Status::OK);
#else
    return TransStatus(Status::OK);
#endif
}

int32_t HiPlayerImpl::SetAudioRendererInfo(const int32_t contentType, const int32_t streamUsage,
                                           const int32_t rendererFlag)
{
    MEDIA_LOG_I("SetAudioRendererInfo in, coutentType: " PUBLIC_LOG_D32 ", streamUsage: " PUBLIC_LOG_D32
        ", rendererFlag: " PUBLIC_LOG_D32, contentType, streamUsage, rendererFlag);
    Plugins::AudioRenderInfo audioRenderInfo {contentType, streamUsage, rendererFlag};
    if (audioRenderInfo_ == nullptr) {
        audioRenderInfo_ = std::make_shared<Meta>();
    }
    audioRenderInfo_->SetData(Tag::AUDIO_RENDER_SET_FLAG, true);
    audioRenderInfo_->SetData(Tag::AUDIO_RENDER_INFO, audioRenderInfo);
    if (audioSink_ != nullptr) {
        audioSink_->SetParameter(audioRenderInfo_);
    }
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetAudioInterruptMode(const int32_t interruptMode)
{
    MEDIA_LOG_I("SetAudioInterruptMode in");
    audioInterruptMode_ = std::make_shared<Meta>();
    audioInterruptMode_->SetData(Tag::AUDIO_INTERRUPT_MODE, interruptMode);
    if (audioSink_ != nullptr) {
        audioSink_->SetParameter(audioInterruptMode_);
    }
    return TransStatus(Status::OK);
}

void HiPlayerImpl::OnEvent(const Event &event)
{
    MEDIA_LOG_D("OnEvent entered, event type is: %{public}d", event.type);
    switch (event.type) {
        case EventType::EVENT_IS_LIVE_STREAM: {
            HandleIsLiveStreamEvent(AnyCast<bool>(event.param));
            break;
        }
        case EventType::EVENT_ERROR: {
            OnStateChanged(PlayerStateId::ERROR);
            HandleErrorEvent(AnyCast<int32_t>(event.param));
            break;
        }
        case EventType::EVENT_READY: {
            OnStateChanged(PlayerStateId::READY);
            break;
        }
        case EventType::EVENT_COMPLETE: {
            HandleCompleteEvent(event);
            break;
        }
        case EventType::EVENT_AUDIO_INTERRUPT: {
            NotifyAudioInterrupt(event);
            break;
        }
        case EventType::EVENT_AUDIO_FIRST_FRAME: {
            NotifyAudioFirstFrame(event);
            HandleInitialPlayingStateChange(event.type);
            break;
        }
        case EventType::EVENT_DRM_INFO_UPDATED: {
            HandleDrmInfoUpdatedEvent(event);
            break;
        }
        case EventType::EVENT_VIDEO_RENDERING_START: {
            MEDIA_LOG_D_SHORT("video first frame reneder received");
            if (IsAppEnableRenderFirstFrame(appUid_)) {
                // if app enable render first frame, notify first frame render event at once
                Format format;
                callbackLooper_.OnInfo(INFO_TYPE_MESSAGE, PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START, format);
            }
            HandleInitialPlayingStateChange(event.type);
            break;
        }
        default:
            OnEventContinue(event);
    }
    OnEventSub(event);
}

void HiPlayerImpl::OnEventContinue(const Event &event)
{
    MEDIA_LOG_D("OnEvent entered, event type is: %{public}d", event.type);
    switch (event.type) {
        case EventType::EVENT_RESOLUTION_CHANGE: {
            MEDIA_LOG_D_SHORT("resolution change event received");
            HandleResolutionChangeEvent(event);
            break;
        }
        case EventType::EVENT_SEI_INFO: {
            HandleSeiInfoEvent(event);
            break;
        }
        default:
            break;
    }
}

void HiPlayerImpl::HandleSeiInfoEvent(const Event &event)
{
    Format format = AnyCast<Format>(event.param);

    int32_t playbackPos = 0;
    format.GetIntValue(Tag::AV_PLAYER_SEI_PLAYBACK_POSITION, playbackPos);
    format.PutIntValue(Tag::AV_PLAYER_SEI_PLAYBACK_POSITION, playbackPos - Plugins::Us2Ms(mediaStartPts_));

    callbackLooper_.OnInfo(INFO_TYPE_SEI_UPDATE_INFO, 0, format);
}

void HiPlayerImpl::OnEventSub(const Event &event)
{
    switch (event.type) {
        case EventType::EVENT_AUDIO_DEVICE_CHANGE : {
            NotifyAudioDeviceChange(event);
            break;
        }
        case EventType::EVENT_AUDIO_SERVICE_DIED : {
            NotifyAudioServiceDied();
            break;
        }
        case EventType::BUFFERING_END : {
            if (!isBufferingStartNotified_.load() || isSeekClosest_.load()) {
                MEDIA_LOGI_LIMIT(BUFFERING_LOG_FREQUENCY, "BUFFERING_END BLOCKED");
                break;
            }
            MEDIA_LOG_I_SHORT("BUFFERING_END PLAYING");
            NotifyBufferingEnd(AnyCast<int32_t>(event.param));
            break;
        }
        case EventType::BUFFERING_START : {
            if (isBufferingStartNotified_.load()) {
                MEDIA_LOGI_LIMIT(BUFFERING_LOG_FREQUENCY, "BUFFERING_START BLOCKED");
                break;
            }
            MEDIA_LOG_I_SHORT("BUFFERING_START PAUSE");
            NotifyBufferingStart(AnyCast<int32_t>(event.param));
            break;
        }
        case EventType::EVENT_SOURCE_BITRATE_START: {
            HandleBitrateStartEvent(event);
            break;
        }
        case EventType::EVENT_SUBTITLE_TEXT_UPDATE: {
            NotifySubtitleUpdate(event);
            break;
        }
        case EventType::EVENT_CACHED_DURATION: {
            NotifyCachedDuration(AnyCast<int32_t>(event.param));
            break;
        }
        case EventType::EVENT_BUFFER_PROGRESS: {
            NotifyBufferingUpdate(PlayerKeys::PLAYER_BUFFERING_PERCENT, AnyCast<int32_t>(event.param));
            break;
        }
        default:
            break;
    }
    OnEventSubTrackChange(event);
}

void HiPlayerImpl::OnEventSubTrackChange(const Event &event)
{
    switch (event.type) {
        case EventType::EVENT_AUDIO_TRACK_CHANGE: {
            HandleAudioTrackChangeEvent(event);
            break;
        }
        case EventType::EVENT_VIDEO_TRACK_CHANGE: {
            HandleVideoTrackChangeEvent(event);
            break;
        }
        case EventType::EVENT_SUBTITLE_TRACK_CHANGE: {
            HandleSubtitleTrackChangeEvent(event);
            break;
        }
        default:
            break;
    }
}

void HiPlayerImpl::HandleInitialPlayingStateChange(const EventType& eventType)
{
    AutoLock lock(initialPlayingEventMutex_);
    MEDIA_LOG_I("HandleInitialPlayingStateChange");
    if (!isInitialPlay_) {
        return;
    }
    for (std::pair<EventType, bool>& item : initialAVStates_) {
        if (item.first == eventType) {
            MEDIA_LOG_I("HandleInitialPlayingStateChange event type received = " PUBLIC_LOG_D32,
                static_cast<int32_t>(eventType));
            item.second = true;
        }
    }

    for (auto item : initialAVStates_) {
        if (item.second == false) {
            MEDIA_LOG_I("HandleInitialPlayingStateChange another event type not received " PUBLIC_LOG_D32,
                static_cast<int32_t>(item.first));
            return;
        }
    }

    MEDIA_LOG_D("av first frame reneder all received");

    isInitialPlay_ = false;
    if (!IsAppEnableRenderFirstFrame(appUid_)) {
        // if app not enable render first frame, notify first frame render event when notify playing state
        Format format;
        callbackLooper_.OnInfoDelay(INFO_TYPE_MESSAGE, PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START, format,
            FIRST_FRAME_FRAME_REPORT_DELAY_MS);
    }
    OnStateChanged(PlayerStateId::PLAYING);

    int64_t nowTimeMs = GetCurrentMillisecond();
    playStatisticalInfo_.startLatency = static_cast<int32_t>(nowTimeMs - playStartTime_);
}

void HiPlayerImpl::DoSetPlayStrategy(const std::shared_ptr<MediaSource> source)
{
    std::shared_ptr<PlayStrategy> playStrategy = std::make_shared<PlayStrategy>();
    playStrategy->width = preferedWidth_;
    playStrategy->height = preferedHeight_;
    playStrategy->duration = bufferDuration_;
    playStrategy->preferHDR = preferHDR_;
    playStrategy->audioLanguage = audioLanguage_;
    playStrategy->subtitleLanguage = subtitleLanguage_;
    playStrategy->bufferDurationForPlaying = bufferDurationForPlaying_;
    if (source) {
        source->SetPlayStrategy(playStrategy);
        source->SetAppUid(appUid_);
    }
}

Status HiPlayerImpl::DoSetSource(const std::shared_ptr<MediaSource> source)
{
    MediaTrace trace("HiPlayerImpl::DoSetSource");
    ResetIfSourceExisted();
    completeState_.clear();
    demuxer_ = FilterFactory::Instance().CreateFilter<DemuxerFilter>("builtin.player.demuxer",
        FilterType::FILTERTYPE_DEMUXER);
    FALSE_RETURN_V(demuxer_ != nullptr, Status::ERROR_NULL_POINTER);
    demuxer_->SetPerfRecEnabled(isPerfRecEnabled_);
    demuxer_->SetApiVersion(apiVersion_);
    pipeline_->AddHeadFilters({demuxer_});
    demuxer_->Init(playerEventReceiver_, playerFilterCallback_, interruptMonitor_);
    DoSetPlayStrategy(source);
    if (!mimeType_.empty()) {
        source->SetMimeType(mimeType_);
    }
    if (!seiMessageCbStatus_ && surface_ == nullptr) {
        MEDIA_LOG_D("HiPlayerImpl::DisableMediaTrack");
        demuxer_->DisableMediaTrack(OHOS::Media::Plugins::MediaType::VIDEO);
    }
    FALSE_RETURN_V(!isInterruptNeeded_, Status::OK);
    demuxer_->SetIsEnableReselectVideoTrack(true);
    Status ret = Status::OK;
    MEDIA_LOG_I("SetDataSource cost ms %{public}" PRId64, CALC_EXPR_TIME_MS(ret = demuxer_->SetDataSource(source)));
    demuxer_->SetCallerInfo(instanceId_, bundleName_);
    demuxer_->SetDumpFlag(isDump_);
    if (ret == Status::OK && !MetaUtils::CheckFileType(demuxer_->GetGlobalMetaInfo())) {
        MEDIA_LOG_W("0x%{public}06" PRIXPTR " SetSource unsupport", FAKE_POINTER(this));
        ret = Status::ERROR_INVALID_DATA;
    }
    FALSE_RETURN_V_NOLOG(ret == Status::OK, ret);
    std::unique_lock<std::mutex> lock(drmMutex_);
    isDrmProtected_ = demuxer_->IsDrmProtected();
    MEDIA_LOG_I("Is the source drm-protected : %{public}d", isDrmProtected_);
    lock.unlock();
    if (hasExtSub_) {
        demuxer_->SetSubtitleSource(std::make_shared<MediaSource>(subUrl_));
    }
    SetBundleName(bundleName_);
    demuxer_->OptimizeDecodeSlow(IsEnableOptimizeDecode());
    return ret;
}

Status HiPlayerImpl::Resume()
{
    MediaTrace trace("HiPlayerImpl::Resume");
    MEDIA_LOG_I("Resume entered.");
    Status ret = Status::OK;
    syncManager_->Resume();
    ret = pipeline_->Resume();
    if (ret != Status::OK) {
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
    }
    startTime_ = GetCurrentMillisecond();
    return ret;
}

void HiPlayerImpl::HandleIsLiveStreamEvent(bool isLiveStream)
{
    Format format;
    callbackLooper_.OnInfo(INFO_TYPE_IS_LIVE_STREAM, isLiveStream, format);
}

void HiPlayerImpl::HandleErrorEvent(int32_t errorCode)
{
    callbackLooper_.OnError(PLAYER_ERROR, errorCode);
}

void HiPlayerImpl::NotifyBufferingStart(int32_t param)
{
    Format format;
    isBufferingStartNotified_.store(true);
    callbackLooper_.StopReportMediaProgress();
    callbackLooper_.ManualReportMediaProgressOnce();
    (void)format.PutIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_START), 1);
    callbackLooper_.OnInfo(INFO_TYPE_BUFFERING_UPDATE, param, format);
}

void HiPlayerImpl::NotifyBufferingEnd(int32_t param)
{
    MEDIA_LOG_I("NotifyBufferingEnd");
    Format format;
    isBufferingStartNotified_.store(false);
    (void)format.PutIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_END), 1);
    callbackLooper_.OnInfo(INFO_TYPE_BUFFERING_UPDATE, param, format);
}

void HiPlayerImpl::NotifyCachedDuration(int32_t param)
{
    MEDIA_LOG_D("NotifyCachedDuration");
    Format format;
    (void)format.PutIntValue(std::string(PlayerKeys::PLAYER_CACHED_DURATION), param);
    callbackLooper_.OnInfo(INFO_TYPE_BUFFERING_UPDATE, param, format);
}

void HiPlayerImpl::HandleEosFlagState(const Event& event)
{
    for (std::pair<std::string, bool>& item: completeState_) {
        if (item.first == event.srcFilter) {
            MEDIA_LOG_I("one eos event received " PUBLIC_LOG_S, item.first.c_str());
            item.second = true;
        }
    }
}

void HiPlayerImpl::HandleCompleteEvent(const Event& event)
{
    MEDIA_LOG_D_SHORT("HandleCompleteEvent");
    AutoLock lock(handleCompleteMutex_);
    if (curState_ == PlayerStateId::STOPPED) {
        MEDIA_LOG_I("The Complete Task don't run, current status is Stopped.");
        return;
    }
    HandleEosFlagState(event);
    for (auto item : completeState_) {
        if (item.second == false) {
            MEDIA_LOG_I("expect receive eos event " PUBLIC_LOG_S, item.first.c_str());
            return;
        }
    }
    MEDIA_LOG_I("OnComplete looping: " PUBLIC_LOG_D32 ".", singleLoop_.load());
    isStreaming_ = false;
    Format format;
    int32_t curPosMs = 0;
    GetCurrentTime(curPosMs);
    if ((GetPlayRangeEndTime() == PLAY_RANGE_DEFAULT_VALUE) &&
        (durationMs_.load() > curPosMs && abs(durationMs_.load() - curPosMs) < AUDIO_SINK_MAX_LATENCY)) {
        MEDIA_LOG_I("OnComplete durationMs - curPosMs: " PUBLIC_LOG_D32, durationMs_.load() - curPosMs);
    }
    if (!singleLoop_.load()) {
        callbackLooper_.StopReportMediaProgress();
        callbackLooper_.StopCollectMaxAmplitude();
    } else {
        inEosSeek_ = true;
    }
    pipeline_->Pause();
    callbackLooper_.DoReportCompletedTime();
    if (isSetPlayRange_ && (startTimeWithMode_ == PLAY_RANGE_DEFAULT_VALUE ||
        endTimeWithMode_ == PLAY_RANGE_DEFAULT_VALUE)) {
        startTimeWithMode_ = PLAY_RANGE_DEFAULT_VALUE;
        endTimeWithMode_ = PLAY_RANGE_DEFAULT_VALUE;
        pipeline_->SetPlayRange(startTimeWithMode_, endTimeWithMode_);
    }
    callbackLooper_.ReportRemainedMaxAmplitude();
    if (!singleLoop_.load()) {
        OnStateChanged(PlayerStateId::EOS);
    }
    UpdatePlayTotalDuration();
    callbackLooper_.OnInfo(INFO_TYPE_EOS, static_cast<int32_t>(singleLoop_.load()), format);
    for (std::pair<std::string, bool>& item: completeState_) {
        item.second = false;
    }
}

void HiPlayerImpl::HandleDrmInfoUpdatedEvent(const Event& event)
{
    MEDIA_LOG_I("HandleDrmInfoUpdatedEvent");

    std::multimap<std::string, std::vector<uint8_t>> drmInfo =
        AnyCast<std::multimap<std::string, std::vector<uint8_t>>>(event.param);
    uint32_t infoCount = drmInfo.size();
    if (infoCount > DrmConstant::DRM_MAX_DRM_INFO_COUNT || infoCount == 0) {
        MEDIA_LOG_E("HandleDrmInfoUpdatedEvent info count is invalid");
        return;
    }
    DrmInfoItem *drmInfoArray = new DrmInfoItem[infoCount];
    if (drmInfoArray == nullptr) {
        MEDIA_LOG_E("HandleDrmInfoUpdatedEvent new drm info failed");
        return;
    }
    int32_t i = 0;
    for (auto item : drmInfo) {
        uint32_t step = 2;
        for (uint32_t j = 0; j < item.first.size(); j += step) {
            std::string byteString = item.first.substr(j, step);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
            drmInfoArray[i].uuid[j / step] = byte;
        }

        errno_t ret = memcpy_s(drmInfoArray[i].pssh, sizeof(drmInfoArray[i].pssh),
            item.second.data(), item.second.size());
        if (ret != EOK) {
            MEDIA_LOG_E("HandleDrmInfoUpdatedEvent memcpy drm info pssh failed");
            delete []drmInfoArray;
            return;
        }
        drmInfoArray[i].psshLen = item.second.size();
        i++;
    }

    // report event
    Format format;
    size_t drmInfoSize = static_cast<size_t>(infoCount) * sizeof(DrmInfoItem);
    (void) format.PutBuffer(PlayerKeys::PLAYER_DRM_INFO_ADDR,
        reinterpret_cast<const uint8_t *>(drmInfoArray), drmInfoSize);
    (void) format.PutIntValue(PlayerKeys::PLAYER_DRM_INFO_COUNT, static_cast<int32_t>(infoCount));
    callbackLooper_.OnInfo(INFO_TYPE_DRM_INFO_UPDATED, static_cast<int32_t>(singleLoop_.load()), format);

    delete []drmInfoArray;
}

void HiPlayerImpl::HandleResolutionChangeEvent(const Event& event)
{
#ifdef SUPPORT_VIDEO
    // update new video size
    std::pair<int32_t, int32_t> videoSize = AnyCast<std::pair<int32_t, int32_t>>(event.param);
    int32_t width = videoSize.first;
    int32_t height = videoSize.second;

    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    if (currentVideoTrackId_ >= 0 && currentVideoTrackId_ < static_cast<int32_t>(metaInfo.size())) {
        double videoSar;
        bool ret = metaInfo[currentVideoTrackId_]->GetData(Tag::VIDEO_SAR, videoSar);
        if (ret) {
            height = (videoSar > 1) ? static_cast<int32_t>(height / videoSar) : height;
            width = (videoSar < 1) ? static_cast<int32_t>(width * videoSar) : width;
        }
    }

    videoWidth_ = !needSwapWH_.load() ? width : height;
    videoHeight_ = !needSwapWH_.load() ? height : width;
    MEDIA_LOG_I("HandleResolutionChangeEvent, width = %{public}d, height = %{public}d",
        videoWidth_.load(), videoHeight_.load());
    // notify size change
    NotifyResolutionChange();
#endif
}

void HiPlayerImpl::HandleBitrateStartEvent(const Event& event)
{
#ifdef SUPPORT_VIDEO
    uint32_t bitrate = AnyCast<uint32_t>(event.param);
    MEDIA_LOG_I("HandleBitrateStartEvent in, bitrate is " PUBLIC_LOG_U32, bitrate);
    FALSE_RETURN(videoDecoder_ != nullptr);
    videoDecoder_->SetBitrateStart();
#endif
}

void HiPlayerImpl::NotifySubtitleUpdate(const Event& event)
{
    Format format = AnyCast<Format>(event.param);
    if (needUpdateSubtitle_.load()) {
        callbackLooper_.OnInfo(INFO_TYPE_SUBTITLE_UPDATE_INFO, 0, format);
    }
}

void HiPlayerImpl::UpdateStateNoLock(PlayerStates newState, bool notifyUpward, bool isSystemOperation)
{
    if (pipelineStates_ == newState) {
        return;
    }
    pipelineStates_ = newState;
    if (pipelineStates_ == PlayerStates::PLAYER_IDLE || pipelineStates_ == PlayerStates::PLAYER_PREPARING) {
        MEDIA_LOG_D_SHORT("do not report idle and preparing since av player doesn't need report idle and preparing");
        return;
    }
    if (notifyUpward) {
        if (callbackLooper_.IsStarted()) {
            Format format;
            if (isSystemOperation) {
                format.PutIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, StateChangeReason::BACKGROUND);
            }
            while (!pendingStates_.empty()) {
                auto pendingState = pendingStates_.front();
                pendingStates_.pop();
                MEDIA_LOG_I("sending pending state change: " PUBLIC_LOG_S, StringnessPlayerState(pendingState).c_str());
                callbackLooper_.OnInfo(INFO_TYPE_STATE_CHANGE, pendingState, format);
            }
            MEDIA_LOG_I("sending newest state change: " PUBLIC_LOG_S,
                    StringnessPlayerState(pipelineStates_.load()).c_str());
            callbackLooper_.OnInfo(INFO_TYPE_STATE_CHANGE, pipelineStates_, format);
        } else {
            pendingStates_.push(newState);
        }
    }
}

void HiPlayerImpl::NotifyBufferingUpdate(const std::string_view& type, int32_t param)
{
    Format format;
    format.PutIntValue(std::string(type), param);
    MEDIA_LOG_D("NotifyBufferingUpdate param " PUBLIC_LOG_D32, param);
    callbackLooper_.OnInfo(INFO_TYPE_BUFFERING_UPDATE, durationMs_.load(), format);
}

void HiPlayerImpl::NotifyDurationUpdate(const std::string_view& type, int32_t param)
{
    Format format;
    format.PutIntValue(std::string(type), param);
    MEDIA_LOG_I("NotifyDurationUpdate " PUBLIC_LOG_D64, durationMs_.load());
    callbackLooper_.OnInfo(INFO_TYPE_DURATION_UPDATE, durationMs_.load(), format);
}

void HiPlayerImpl::NotifySeekDone(int32_t seekPos)
{
    MediaTrace trace(std::string("HiPlayerImpl::NotifySeekDone, seekPos: ") + to_string(seekPos));
    Format format;
    // Report position firstly to make sure that client can get real position when seek done in playing state.
    if (curState_ == PlayerStateId::PLAYING) {
        std::unique_lock<std::mutex> lock(seekMutex_);
        syncManager_->seekCond_.wait_for(
            lock,
            std::chrono::milliseconds(PLAYING_SEEK_WAIT_TIME),
            [this]() {
                return !syncManager_->InSeeking();
            });
    }
    auto startTime = std::chrono::steady_clock::now();
    demuxer_->WaitForBufferingEnd();
    auto endTime = std::chrono::steady_clock::now();
    auto waitTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    MEDIA_LOG_D_SHORT("NotifySeekDone WaitForBufferingEnd: %{public}d ms", int(waitTime));
    if (isSeekClosest_.load()) {
        isSeekClosest_.store(false);
        if (isBufferingStartNotified_.load()) {
            MEDIA_LOG_I_SHORT("SEEK_CLOSEST BUFFERING_END PLAYING");
            NotifyBufferingEnd(NOTIFY_BUFFERING_END_PARAM);
        }
    }
    
    MEDIA_LOG_D_SHORT("NotifySeekDone seekPos: %{public}d", seekPos);
    callbackLooper_.OnInfo(INFO_TYPE_POSITION_UPDATE, seekPos, format);
    callbackLooper_.OnInfo(INFO_TYPE_SEEKDONE, seekPos, format);
}

void HiPlayerImpl::NotifyAudioInterrupt(const Event& event)
{
    Format format;
    auto interruptEvent = AnyCast<AudioStandard::InterruptEvent>(event.param);
    int32_t hintType = interruptEvent.hintType;
    int32_t forceType = interruptEvent.forceType;
    int32_t eventType = interruptEvent.eventType;
    MEDIA_LOG_I("NotifyAudioInterrupt eventType: %{public}d, hintType: %{public}d, forceType: %{public}d",
        eventType, hintType, forceType);
    if (forceType == OHOS::AudioStandard::INTERRUPT_FORCE) {
        if (hintType == OHOS::AudioStandard::INTERRUPT_HINT_PAUSE
            || hintType == OHOS::AudioStandard::INTERRUPT_HINT_STOP) {
            isHintPauseReceived_ = true;
            Status ret = Status::OK;
            ret = pipeline_->Pause();
            syncManager_->Pause();
            if (ret != Status::OK) {
                UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
            }
            callbackLooper_.StopReportMediaProgress();
            callbackLooper_.StopCollectMaxAmplitude();
        }
    }
    {
        AutoLock lock(interruptMutex_);
        if (isSaveInterruptEventNeeded_.load() && isHintPauseReceived_
            && eventType == OHOS::AudioStandard::INTERRUPT_TYPE_END
            && forceType == OHOS::AudioStandard::INTERRUPT_SHARE
            && hintType == OHOS::AudioStandard::INTERRUPT_HINT_RESUME) {
            interruptNotifyPlay_.store(true);
            interruptEvent_ = interruptEvent;
            return;
        }
        isSaveInterruptEventNeeded_.store(true);
    }
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    callbackLooper_.OnInfo(INFO_TYPE_INTERRUPT_EVENT, hintType, format);
    if (forceType == OHOS::AudioStandard::INTERRUPT_FORCE) {
        if (hintType == OHOS::AudioStandard::INTERRUPT_HINT_PAUSE
            || hintType == OHOS::AudioStandard::INTERRUPT_HINT_STOP) {
            callbackLooper_.OnSystemOperation(OPERATION_TYPE_PAUSE, OPERATION_REASON_AUDIO_INTERRUPT);
        }
    }
}

void HiPlayerImpl::NotifyAudioDeviceChange(const Event& event)
{
    MEDIA_LOG_I("NotifyAudioDeviceChange");
    auto [deviceInfo, reason] = AnyCast<std::pair<AudioStandard::AudioDeviceDescriptor,
        AudioStandard::AudioStreamDeviceChangeReason>>(event.param);
    Format format;
    Parcel parcel;
    deviceInfo.Marshalling(parcel);
    auto parcelSize = parcel.GetReadableBytes();
    (void)format.PutBuffer(PlayerKeys::AUDIO_DEVICE_CHANGE,
        parcel.ReadBuffer(parcelSize), parcelSize);
    format.PutIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, static_cast<int32_t>(reason));
    callbackLooper_.OnInfo(INFO_TYPE_AUDIO_DEVICE_CHANGE, static_cast<int32_t>(reason), format);
}

void HiPlayerImpl::NotifyAudioServiceDied()
{
    Format format;
    callbackLooper_.OnInfo(INFO_TYPE_ERROR_MSG, MSERR_EXT_API9_IO, format);
}

void HiPlayerImpl::NotifyAudioFirstFrame(const Event& event)
{
    uint64_t latency = AnyCast<uint64_t>(event.param);
    MEDIA_LOG_I("Audio first frame event in latency " PUBLIC_LOG_U64, latency);
    Format format;
    (void)format.PutLongValue(PlayerKeys::AUDIO_FIRST_FRAME, latency);
    callbackLooper_.OnInfo(INFO_TYPE_AUDIO_FIRST_FRAME, 0, format);
}

void HiPlayerImpl::NotifyResolutionChange()
{
#ifdef SUPPORT_VIDEO
    Format format;
    int32_t width = videoWidth_.load();
    int32_t height = videoHeight_.load();
    (void)format.PutIntValue(std::string(PlayerKeys::PLAYER_WIDTH), width);
    (void)format.PutIntValue(std::string(PlayerKeys::PLAYER_HEIGHT), height);
    MEDIA_LOG_I("video size change, width %{public}d, height %{public}d", width, height);
    callbackLooper_.OnInfo(INFO_TYPE_RESOLUTION_CHANGE, 0, format);
#endif
}

void HiPlayerImpl::NotifyPositionUpdate()
{
    int32_t currentPosMs = 0;
    GetCurrentTime(currentPosMs);
    MEDIA_LOG_D("NotifyPositionUpdate currentPosMs: %{public}d", currentPosMs);
    Format format;
    callbackLooper_.OnInfo(INFO_TYPE_POSITION_UPDATE, currentPosMs, format);
}

void HiPlayerImpl::NotifyUpdateTrackInfo()
{
    std::vector<Format> trackInfo;
    GetVideoTrackInfo(trackInfo);
    GetAudioTrackInfo(trackInfo);
    GetSubtitleTrackInfo(trackInfo);

    Format body;
    body.PutFormatVector(std::string(PlayerKeys::PLAYER_TRACK_INFO), trackInfo);
    MEDIA_LOG_I("NotifyUpdateTrackInfo");

    callbackLooper_.OnInfo(INFO_TYPE_TRACK_INFO_UPDATE, 0, body);
}

void HiPlayerImpl::HandleAudioTrackChangeEvent(const Event& event)
{
    int32_t trackId = AnyCast<int32_t>(event.param);
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    FALSE_RETURN_MSG(trackId >= 0 && trackId < static_cast<int32_t>(metaInfo.size()),
        "HandleAudioTrackChangeEvent trackId invalid");
    if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime))) {
        MEDIA_LOG_E("HandleAudioTrackChangeEvent trackId " PUBLIC_LOG_D32 "get mime error", trackId);
        return;
    }
    if (IsAudioMime(mime)) {
        if (Status::OK != audioDecoder_->ChangePlugin(metaInfo[trackId])) {
            MEDIA_LOG_E("HandleAudioTrackChangeEvent audioDecoder change plugin error");
            return;
        }
        if (IsNeedAudioSinkChangeTrack(metaInfo, trackId)) {
            MEDIA_LOG_I("AudioSink changeTrack in");
            if (Status::OK != audioSink_->ChangeTrack(metaInfo[trackId])) {
                MEDIA_LOG_E("HandleAudioTrackChangeEvent audioSink change track error");
                return;
            }
        }
        if (Status::OK != demuxer_->StartTask(trackId)) {
            MEDIA_LOG_E("HandleAudioTrackChangeEvent StartTask error. trackId is " PUBLIC_LOG_D32, trackId);
            return;
        }
        Format audioTrackInfo {};
        audioTrackInfo.PutIntValue("track_index", static_cast<int32_t>(trackId));
        audioTrackInfo.PutIntValue("track_is_select", 1);
        callbackLooper_.OnInfo(INFO_TYPE_TRACKCHANGE, 0, audioTrackInfo);
        currentAudioTrackId_ = trackId;

        NotifyUpdateTrackInfo();
    }
    return;
}

void HiPlayerImpl::HandleVideoTrackChangeEvent(const Event& event)
{
#ifdef SUPPORT_VIDEO
    int32_t trackId = AnyCast<int32_t>(event.param);
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    FALSE_RETURN_MSG(trackId >= 0 && trackId < static_cast<int32_t>(metaInfo.size()),
        "HandleVideoTrackChangeEvent trackId invalid");
    if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime))) {
        MEDIA_LOG_E("HandleVideoTrackChangeEvent trackId " PUBLIC_LOG_D32 "get mime error", trackId);
        return;
    }
    if (IsVideoMime(mime)) {
        if (Status::OK != demuxer_->StartTask(trackId)) {
            MEDIA_LOG_E("HandleVideoTrackChangeEvent StartTask error. trackId is " PUBLIC_LOG_D32, trackId);
            return;
        }
        Format videoTrackInfo {};
        videoTrackInfo.PutIntValue("track_index", static_cast<int32_t>(trackId));
        videoTrackInfo.PutIntValue("track_is_select", 1);
        callbackLooper_.OnInfo(INFO_TYPE_TRACKCHANGE, 0, videoTrackInfo);
        currentVideoTrackId_ = trackId;
    }
#endif
    return;
}

void HiPlayerImpl::HandleSubtitleTrackChangeEvent(const Event& event)
{
    int32_t trackId = AnyCast<int32_t>(event.param);
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    std::string mime;
    FALSE_RETURN_MSG(trackId >= 0 && trackId < static_cast<int32_t>(metaInfo.size()),
        "HandleSubtitleTrackChangeEvent trackId invalid");
    if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime))) {
        MEDIA_LOG_E("HandleSubtitleTrackChangeEvent trackId " PUBLIC_LOG_D32 "get mime error", trackId);
        return;
    }
    if (IsSubtitleMime(mime)) {
        if (Status::OK != subtitleSink_->DoFlush()) {
            MEDIA_LOG_E("HandleSubtitleTrackChangeEvent DoFlush error");
            return;
        }
        if (Status::OK != demuxer_->StartTask(trackId)) {
            MEDIA_LOG_E("HandleSubtitleTrackChangeEvent StartTask error. trackId is " PUBLIC_LOG_D32, trackId);
            return;
        }
        Format subtitleTrackInfo {};
        subtitleTrackInfo.PutIntValue("track_index", static_cast<int32_t>(trackId));
        subtitleTrackInfo.PutIntValue("track_is_select", 1);
        callbackLooper_.OnInfo(INFO_TYPE_TRACKCHANGE, 0, subtitleTrackInfo);
        currentSubtitleTrackId_ = trackId;
        needUpdateSubtitle_.store(true);
    }
    return;
}

void __attribute__((no_sanitize("cfi"))) HiPlayerImpl::OnStateChanged(PlayerStateId state, bool isSystemOperation)
{
    {
        AutoLock lockEos(stateChangeMutex_);
        if (isDoCompletedSeek_.load()) {
            isDoCompletedSeek_ = false;
        } else if ((curState_ == PlayerStateId::EOS) && (state == PlayerStateId::PAUSE)) {
            MEDIA_LOG_E("already at completed and not allow pause");
            return;
        } else if ((curState_ == PlayerStateId::ERROR) && (state == PlayerStateId::READY)) {
            MEDIA_LOG_E("already at error and not allow ready");
            return;
        }
        curState_ = state;
    }
    MEDIA_LOG_D_SHORT("OnStateChanged " PUBLIC_LOG_D32 " > " PUBLIC_LOG_D32, pipelineStates_.load(),
            TransStateId2PlayerState(state));
    UpdateStateNoLock(TransStateId2PlayerState(state), true, isSystemOperation);
    {
        AutoLock lock(stateMutex_);
        cond_.NotifyOne();
    }
}

Status HiPlayerImpl::OnCallback(std::shared_ptr<Filter> filter, const FilterCallBackCommand cmd, StreamType outType)
{
    MEDIA_LOG_D_SHORT("HiPlayerImpl::OnCallback filter, outType: %{public}d", outType);
    if (cmd == FilterCallBackCommand::NEXT_FILTER_NEEDED) {
        switch (outType) {
            case StreamType::STREAMTYPE_SUBTITLE:
                return LinkSubtitleSinkFilter(filter, outType);
            case StreamType::STREAMTYPE_RAW_AUDIO:
                return LinkAudioSinkFilter(filter, outType);
            case StreamType::STREAMTYPE_ENCODED_AUDIO:
                return LinkAudioDecoderFilter(filter, outType);
#ifdef SUPPORT_VIDEO
            case StreamType::STREAMTYPE_RAW_VIDEO:
                break;
            case StreamType::STREAMTYPE_ENCODED_VIDEO:
                return LinkVideoDecoderFilter(filter, outType);
#endif
            default:
                break;
        }
    }
    return Status::OK;
}

void HiPlayerImpl::OnDumpInfo(int32_t fd)
{
    MEDIA_LOG_D("HiPlayerImpl::OnDumpInfo called.");
    if (audioDecoder_ != nullptr) {
        audioDecoder_->OnDumpInfo(fd);
    }
    if (demuxer_ != nullptr) {
        demuxer_->OnDumpInfo(fd);
    }
#ifdef SUPPORT_VIDEO
    if (videoDecoder_ != nullptr) {
        videoDecoder_->OnDumpInfo(fd);
    }
#endif
}

Status HiPlayerImpl::LinkAudioDecoderFilter(const std::shared_ptr<Filter>& preFilter, StreamType type)
{
    MediaTrace trace("HiPlayerImpl::LinkAudioDecoderFilter");
    MEDIA_LOG_I_SHORT("HiPlayerImpl::LinkAudioDecoderFilter");
    FALSE_RETURN_V(audioDecoder_ == nullptr, Status::OK);

    audioDecoder_ = FilterFactory::Instance().CreateFilter<AudioDecoderFilter>("player.audiodecoder",
        FilterType::FILTERTYPE_ADEC);
    FALSE_RETURN_V(audioDecoder_ != nullptr, Status::ERROR_NULL_POINTER);
    interruptMonitor_->RegisterListener(audioDecoder_);
    audioDecoder_->Init(playerEventReceiver_, playerFilterCallback_);

    audioDecoder_->SetCallerInfo(instanceId_, bundleName_);
    audioDecoder_->SetDumpFlag(isDump_);
    // set decrypt config for drm audios
    if (isDrmProtected_) {
        MEDIA_LOG_D("HiPlayerImpl::LinkAudioDecoderFilter will SetDecryptConfig");
        std::unique_lock<std::mutex> lock(drmMutex_);
        static constexpr int32_t timeout = 5;
        bool notTimeout = drmConfigCond_.wait_for(lock, std::chrono::seconds(timeout), [this]() {
            return this->isDrmPrepared_ || this->stopWaitingDrmConfig_;
        });
        if (notTimeout && isDrmPrepared_) {
            MEDIA_LOG_I("LinkAudioDecoderFilter will SetDecryptConfig");
#ifdef SUPPORT_AVPLAYER_DRM
            bool svpFlag = svpMode_ == HiplayerSvpMode::SVP_TRUE ? true : false;
            audioDecoder_->SetDecryptionConfig(keySessionServiceProxy_, svpFlag);
#endif
        } else {
            MEDIA_LOG_E("HiPlayerImpl Drmcond wait timeout or has been stopped! Play drm protected audio failed!");
            return Status::ERROR_INVALID_OPERATION;
        }
    } else {
        MEDIA_LOG_D("HiPlayerImpl::LinkAudioDecoderFilter, and it's not drm-protected.");
    }
    return pipeline_->LinkFilters(preFilter, {audioDecoder_}, type);
}

Status HiPlayerImpl::LinkAudioSinkFilter(const std::shared_ptr<Filter>& preFilter, StreamType type)
{
    MediaTrace trace("HiPlayerImpl::LinkAudioSinkFilter");
    MEDIA_LOG_I("HiPlayerImpl::LinkAudioSinkFilter");
    FALSE_RETURN_V(audioSink_ == nullptr, Status::OK);

    audioSink_ = FilterFactory::Instance().CreateFilter<AudioSinkFilter>("player.audiosink",
        FilterType::FILTERTYPE_ASINK);
    FALSE_RETURN_V(audioSink_ != nullptr, Status::ERROR_NULL_POINTER);
    audioSink_->Init(playerEventReceiver_, playerFilterCallback_);
    audioSink_->SetMaxAmplitudeCbStatus(maxAmplitudeCbStatus_);
    audioSink_->SetPerfRecEnabled(isPerfRecEnabled_);
    audioSink_->SetIsCalledBySystemApp(isCalledBySystemApp_);
    if (demuxer_ != nullptr && audioRenderInfo_ == nullptr) {
        std::vector<std::shared_ptr<Meta>> trackInfos = demuxer_->GetStreamMetaInfo();
        SetDefaultAudioRenderInfo(trackInfos);
    }
    if (audioRenderInfo_ != nullptr) {
        audioSink_->SetParameter(audioRenderInfo_);
    }
    if (audioInterruptMode_ != nullptr) {
        audioSink_->SetParameter(audioInterruptMode_);
    }
    std::shared_ptr<Meta> globalMeta = std::make_shared<Meta>();
    if (demuxer_ != nullptr) {
        globalMeta = demuxer_->GetGlobalMetaInfo();
    }
    if (globalMeta != nullptr) {
        globalMeta->SetData(Tag::APP_PID, appPid_);
        globalMeta->SetData(Tag::APP_UID, appUid_);
        if (audioRenderInfo_ != nullptr) {
            for (MapIt iter = audioRenderInfo_->begin(); iter != audioRenderInfo_->end(); iter++) {
                globalMeta->SetData(iter->first, iter->second);
            }
        }
        if (audioInterruptMode_ != nullptr) {
            for (MapIt iter = audioInterruptMode_->begin(); iter != audioInterruptMode_->end(); iter++) {
                globalMeta->SetData(iter->first, iter->second);
            }
        }
        audioSink_->SetParameter(globalMeta);
    }
    audioSink_->SetSyncCenter(syncManager_);

    completeState_.emplace_back(std::make_pair("AudioSink", false));
    initialAVStates_.emplace_back(std::make_pair(EventType::EVENT_AUDIO_FIRST_FRAME, false));
    auto res = pipeline_->LinkFilters(preFilter, {audioSink_}, type);
    if (mutedMediaType_ == OHOS::Media::MediaType::MEDIA_TYPE_AUD) {
        audioSink_->SetMuted(true);
    }
    return res;
}

bool HiPlayerImpl::IsLiveStream()
{
    FALSE_RETURN_V_NOLOG(demuxer_ != nullptr, false);
    auto globalMeta = demuxer_->GetGlobalMetaInfo();
    FALSE_RETURN_V_NOLOG(globalMeta != nullptr, false);
    return globalMeta->Find(Tag::MEDIA_DURATION) == globalMeta->end();
}

#ifdef SUPPORT_VIDEO
Status HiPlayerImpl::LinkSeiDecoder(const std::shared_ptr<Filter>& preFilter, StreamType type)
{
    MEDIA_LOG_I("Link SeiParserFilterFilter Enter.");
    if (seiDecoder_ == nullptr) {
        seiDecoder_ = FilterFactory::Instance().CreateFilter<SeiParserFilter>("player.sei", FilterType::FILTERTYPE_SEI);
        FALSE_RETURN_V(seiDecoder_ != nullptr, Status::ERROR_NULL_POINTER);
        seiDecoder_->Init(playerEventReceiver_, playerFilterCallback_);
        seiDecoder_->SetSeiMessageCbStatus(seiMessageCbStatus_, payloadTypes_);
        seiDecoder_->SetSyncCenter(syncManager_);
        interruptMonitor_->RegisterListener(seiDecoder_);
    }
    return pipeline_->LinkFilters(preFilter, {seiDecoder_}, type);
}

Status HiPlayerImpl::LinkVideoDecoderFilter(const std::shared_ptr<Filter>& preFilter, StreamType type)
{
    MediaTrace trace("HiPlayerImpl::LinkVideoDecoderFilter");
    MEDIA_LOG_I("LinkVideoDecoderFilter");
    if (surface_ == nullptr && seiMessageCbStatus_ && IsLiveStream()) {
        return LinkSeiDecoder(preFilter, type);
    }
    if (videoDecoder_ == nullptr) {
        videoDecoder_ = FilterFactory::Instance().CreateFilter<DecoderSurfaceFilter>("player.videodecoder",
            FilterType::FILTERTYPE_VDEC);
        FALSE_RETURN_V(videoDecoder_ != nullptr, Status::ERROR_NULL_POINTER);
        videoDecoder_->Init(playerEventReceiver_, playerFilterCallback_);
        interruptMonitor_->RegisterListener(videoDecoder_);
        videoDecoder_->SetSyncCenter(syncManager_);
        videoDecoder_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
        if (surface_ != nullptr) {
            videoDecoder_->SetVideoSurface(surface_);
            videoDecoder_->SetSeiMessageCbStatus(seiMessageCbStatus_  && IsLiveStream(), payloadTypes_);
        }
        videoDecoder_->SetPerfRecEnabled(isPerfRecEnabled_);
        // set decrypt config for drm videos
        if (isDrmProtected_) {
            std::unique_lock<std::mutex> lock(drmMutex_);
            static constexpr int32_t timeout = 5;
            bool notTimeout = drmConfigCond_.wait_for(lock, std::chrono::seconds(timeout), [this]() {
                return this->isDrmPrepared_ || this->stopWaitingDrmConfig_;
            });
            if (notTimeout && isDrmPrepared_) {
                MEDIA_LOG_I("LinkVideoDecoderFilter will SetDecryptConfig");
#ifdef SUPPORT_AVPLAYER_DRM
                bool svpFlag = svpMode_ == HiplayerSvpMode::SVP_TRUE ? true : false;
                videoDecoder_->SetDecryptConfig(keySessionServiceProxy_, svpFlag);
#endif
            } else {
                MEDIA_LOG_E("HiPlayerImpl Drmcond wait timeout or has been stopped! Play drm protected video failed!");
                return Status::ERROR_INVALID_OPERATION;
            }
        } else {
            MEDIA_LOG_D("HiPlayerImpl::LinkVideoDecoderFilter, and it's not drm-protected.");
        }
    }
    completeState_.emplace_back(std::make_pair("VideoSink", false));
    initialAVStates_.emplace_back(std::make_pair(EventType::EVENT_VIDEO_RENDERING_START, false));
#ifdef SUPPORT_START_STOP_ON_DEMAND
    return pipeline_->LinkFilters(preFilter, {videoDecoder_}, type, true);
#else
    return pipeline_->LinkFilters(preFilter, {videoDecoder_}, type);
#endif
}
#endif

Status HiPlayerImpl::LinkSubtitleSinkFilter(const std::shared_ptr<Filter>& preFilter, StreamType type)
{
    MediaTrace trace("HiPlayerImpl::LinkSubtitleSinkFilter");
    FALSE_RETURN_V(subtitleSink_ == nullptr, Status::OK);
    subtitleSink_ = FilterFactory::Instance().CreateFilter<SubtitleSinkFilter>("player.subtitlesink",
        FilterType::FILTERTYPE_SSINK);
    FALSE_RETURN_V(subtitleSink_ != nullptr, Status::ERROR_NULL_POINTER);
    subtitleSink_->Init(playerEventReceiver_, playerFilterCallback_);
    std::shared_ptr<Meta> globalMeta = std::make_shared<Meta>();
    if (demuxer_ != nullptr) {
        globalMeta = demuxer_->GetGlobalMetaInfo();
    }
    if (globalMeta != nullptr) {
        subtitleSink_->SetParameter(globalMeta);
    }
    subtitleSink_->SetSyncCenter(syncManager_);
    return pipeline_->LinkFilters(preFilter, {subtitleSink_}, type);
}

int32_t HiPlayerImpl::SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
{
    MEDIA_LOG_D("SetMediaMuted %{public}d", static_cast<int32_t>(mediaType));
    FALSE_RETURN_V(mediaType == OHOS::Media::MediaType::MEDIA_TYPE_AUD, MSERR_INVALID_VAL);
    FALSE_RETURN_V(audioSink_ != nullptr, MSERR_NO_MEMORY);
    auto res = audioSink_->SetMuted(isMuted);
    return res == Status::OK ? MSERR_OK : MSERR_INVALID_OPERATION;
}

int32_t HiPlayerImpl::SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
{
    mutedMediaType_ = playbackStrategy.mutedMediaType;
    preferedWidth_ = playbackStrategy.preferredWidth;
    preferedHeight_ = playbackStrategy.preferredHeight;
    bufferDuration_ = playbackStrategy.preferredBufferDuration;
    preferHDR_ = playbackStrategy.preferredHdr;
    renderFirstFrame_ = playbackStrategy.showFirstFrameOnPrepare;
    audioLanguage_ = playbackStrategy.preferredAudioLanguage;
    subtitleLanguage_ = playbackStrategy.preferredSubtitleLanguage;
    bufferDurationForPlaying_ = playbackStrategy.preferredBufferDurationForPlaying;
    return MSERR_OK;
}

int32_t HiPlayerImpl::SeekContinous(int32_t mSeconds, int64_t seekContinousBatchNo)
{
    std::lock_guard<std::mutex> lock(seekContinousMutex_);
    FALSE_RETURN_V(demuxer_ && videoDecoder_, TransStatus(Status::OK));
    FALSE_RETURN_V(!isNetWorkPlay_, TransStatus(Status::OK));
    FALSE_RETURN_V(seekContinousBatchNo_.load() <= seekContinousBatchNo, TransStatus(Status::OK));
    lastSeekContinousPos_ = mSeconds;
    if (seekContinousBatchNo_.load() == seekContinousBatchNo) {
        FALSE_RETURN_V(draggingPlayerAgent_ != nullptr, TransStatus(Status::OK));
        draggingPlayerAgent_->UpdateSeekPos(mSeconds);
        MEDIA_LOG_I("HiPlayerImpl::SeekContinous in " PUBLIC_LOG_D32, mSeconds);
        return TransStatus(Status::OK);
    }
    seekContinousBatchNo_.store(seekContinousBatchNo);
    auto res = StartSeekContinous();
    FALSE_RETURN_V_MSG_E(res == Status::OK && draggingPlayerAgent_ != nullptr, TransStatus(res),
        "StartSeekContinous failed");
    draggingPlayerAgent_->UpdateSeekPos(mSeconds);
    MEDIA_LOG_I("HiPlayerImpl::SeekContinous start " PUBLIC_LOG_D32, mSeconds);
    return TransStatus(Status::OK);
}

Status HiPlayerImpl::StartSeekContinous()
{
    FALSE_RETURN_V(!draggingPlayerAgent_, Status::OK);
    FALSE_RETURN_V(demuxer_ && videoDecoder_, Status::OK);
    draggingPlayerAgent_ = DraggingPlayerAgent::Create(pipeline_, demuxer_, videoDecoder_, playerId_);
    FALSE_RETURN_V_MSG_E(draggingPlayerAgent_ != nullptr, Status::ERROR_INVALID_OPERATION, "failed to create agent");
    Status res = draggingPlayerAgent_->Init();
    if (res != Status::OK) {
        draggingPlayerAgent_ = nullptr;
        return res;
    }
    if (draggingPlayerAgent_->GetDraggingMode() == DraggingMode::DRAGGING_CONTINUOUS) {
        FlushVideoEOS();
        // Drive the head node to start the video channel.
        res = demuxer_->ResumeDragging();
        FALSE_LOG_MSG(res == Status::OK, "ResumeDragging failed");
    }
    SetFrameRateForSeekPerformance(FRAME_RATE_FOR_SEEK_PERFORMANCE);
    return res;
}

void HiPlayerImpl::FlushVideoEOS()
{
    bool demuxerEOS = demuxer_->HasEosTrack();
    bool decoderEOS = false;
    for (std::pair<std::string, bool>& item: completeState_) {
        if (item.second) {
            decoderEOS = true;
            break;
        }
    }
    bool playerEOS = pipelineStates_ == PlayerStates::PLAYER_PLAYBACK_COMPLETE;
    if (demuxerEOS || decoderEOS || playerEOS) {
        MEDIA_LOG_I("flush first when eos");
        pipeline_->Flush();
        curState_ = PlayerStateId::PAUSE;
        pipelineStates_ = TransStateId2PlayerState(PlayerStateId::PAUSE);
        for (std::pair<std::string, bool>& item: completeState_) {
            item.second = false;
        }
    }
}

int32_t HiPlayerImpl::ExitSeekContinous(bool align, int64_t seekContinousBatchNo)
{
    std::lock_guard<std::mutex> lock(seekContinousMutex_);
    FALSE_RETURN_V(demuxer_ && videoDecoder_, TransStatus(Status::OK));
    FALSE_RETURN_V(!isNetWorkPlay_, TransStatus(Status::OK));
    seekContinousBatchNo_.store(seekContinousBatchNo);
    FALSE_RETURN_V(draggingPlayerAgent_ != nullptr, TransStatus(Status::OK));
    draggingPlayerAgent_->Release();
    draggingPlayerAgent_ = nullptr;
    SetFrameRateForSeekPerformance(FRAME_RATE_DEFAULT);
    int64_t seekTimeUs = 0;
    FALSE_RETURN_V_MSG_E(Plugins::Us2HstTime(lastSeekContinousPos_, seekTimeUs),
        TransStatus(Status::OK), "Invalid lastSeekContinousPos_: %{public}" PRId64, lastSeekContinousPos_);
    syncManager_->Seek(seekTimeUs, true);
    if (align) {
        seekAgent_ = std::make_shared<SeekAgent>(demuxer_);
        interruptMonitor_->RegisterListener(seekAgent_);
        audioSink_->Flush();
        auto res = seekAgent_->AlignAudioPosition(lastSeekContinousPos_);
        FALSE_LOG_MSG(res == Status::OK, "AlignAudioPosition failed");
        MEDIA_LOG_I_SHORT("seekAgent_ AlignAudioPosition end");
        interruptMonitor_->DeregisterListener(seekAgent_);
        seekAgent_.reset();
    }
    return TransStatus(Status::OK);
}

void HiPlayerImpl::HandleDfxEvent(const DfxEvent &event)
{
    FALSE_RETURN(dfxAgent_ != nullptr);
    dfxAgent_->OnDfxEvent(event);
}

int32_t HiPlayerImpl::SetMaxAmplitudeCbStatus(bool status)
{
    maxAmplitudeCbStatus_ = status;
    if (audioSink_ != nullptr) {
        return audioSink_->SetMaxAmplitudeCbStatus(maxAmplitudeCbStatus_);
    }
    return MSERR_OK;
}

int32_t HiPlayerImpl::IsSeekContinuousSupported(bool &isSeekContinuousSupported)
{
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr && videoDecoder_ != nullptr, TransStatus(Status::ERROR_WRONG_STATE),
        "demuxer or decoder is null");
    FALSE_RETURN_V_MSG_E(pipelineStates_ != PlayerStates::PLAYER_STOPPED, TransStatus(Status::ERROR_WRONG_STATE),
        "call IsSeekContinuousSupported in stopped state");
    isSeekContinuousSupported = DraggingPlayerAgent::IsDraggingSupported(demuxer_, videoDecoder_);
    return TransStatus(Status::OK);
}

int32_t HiPlayerImpl::SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
{
    seiMessageCbStatus_ = status;
    payloadTypes_ = payloadTypes;
    MEDIA_LOG_I("SetSeiMessageCbStatus seiMessageCbStatus_  = " PUBLIC_LOG_D32, seiMessageCbStatus_);
    Status ret = SetSeiMessageListener();
    return TransStatus(ret);
}

Status HiPlayerImpl::SetSeiMessageListener()
{
    if (videoDecoder_ != nullptr && surface_ != nullptr) {
        return videoDecoder_->SetSeiMessageCbStatus(seiMessageCbStatus_, payloadTypes_);
    }
    if (seiDecoder_ != nullptr && surface_ == nullptr) {
        return seiDecoder_->SetSeiMessageCbStatus(seiMessageCbStatus_, payloadTypes_);
    }
    return Status::OK;
}

void HiPlayerImpl::SetPerfRecEnabled(bool isPerfRecEnabled)
{
    MEDIA_LOG_I("SetPerfRecEnabled %{public}d", isPerfRecEnabled);
    isPerfRecEnabled_ = isPerfRecEnabled;
}
}  // namespace Media
}  // namespace OHOS
