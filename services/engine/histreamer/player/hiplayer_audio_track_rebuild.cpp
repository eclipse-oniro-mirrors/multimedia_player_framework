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

#include "player.h"
#define HST_LOG_TAG "HiPlayer"

#include "hiplayer_impl.h"

#include <algorithm>

#include "common/log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "meta/media_types.h"
#include "meta/any.h"
#include "plugin/plugin_event.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "HiPlayer" };
} // namespace

namespace OHOS {
namespace Media {
using StreamType = OHOS::Media::Pipeline::StreamType;
void HiPlayerImpl::CheckAudioSupportOnDevice()
{
    MEDIA_LOG_I("CheckAudioSupportOnDevice");
    auto meta = GetCurrentAudioMeta();
    FALSE_RETURN(meta != nullptr);

    std::string mime;
    FALSE_RETURN_MSG_W(meta->GetData(Tag::MIME_TYPE, mime), "get mime failed");
    FALSE_RETURN_NOLOG(IsAudioMime(mime));

    if (!demuxer_->IsAudioSupportedOnDevice(mime)) {
        HandleAudioUnsupportedOnDevice(mime);
        return;
    }
    if (audioDecoder_ == nullptr && audioSink_ == nullptr &&
        currentAudioStreamType_ == StreamType::STREAMTYPE_PACKED &&
        currentAudioTrackId_ != defaultAudioTrackId_) {
        HandleAudioUnsupportedOnDevice(mime);
        return;
    }
    CheckAudioTopologyRebuild(meta, mime);
}

std::shared_ptr<Meta> HiPlayerImpl::GetCurrentAudioMeta()
{
    FALSE_RETURN_V_MSG(demuxer_ != nullptr, nullptr, "demuxer_ is nullptr");
    FALSE_RETURN_V_MSG_I(currentAudioTrackId_ >= 0, nullptr, "no current audio track");
    std::vector<std::shared_ptr<Meta>> metaInfo = demuxer_->GetStreamMetaInfo();
    FALSE_RETURN_V_MSG_W(currentAudioTrackId_ < static_cast<int32_t>(metaInfo.size()),
        nullptr, "currentAudioTrackId_ out of range");
    return metaInfo[currentAudioTrackId_];
}

void HiPlayerImpl::HandleAudioUnsupportedOnDevice(const std::string& mime)
{
    // Dedup within the same play cycle (a single unplug can trigger multiple callbacks).
    if (audioMutedReportedInPlayCycle_.load()) {
        MEDIA_LOG_I("Audio not supported and already reported this play cycle, skip. mime: %{public}s",
            mime.c_str());
        return;
    }
    bool alreadyTornDown = (audioDecoder_ == nullptr && audioSink_ == nullptr &&
        currentAudioStreamType_ == StreamType::STREAMTYPE_PACKED);
    if (alreadyTornDown) {
        // Pipeline already torn down by prior track change or Prepare; just re-notify.
        MEDIA_LOG_I("Audio already muted but not yet reported, re-notify. mime: %{public}s", mime.c_str());
        ReportAudioUnsupportedWarning();
        return;
    }
    // Filters still non-null: teardown to video-only.
    // Acquires audioRebuildMutex_ locally; must NOT call RebuildAudioPipeline here (deadlock).
    MEDIA_LOG_E("Audio not supported on current device, muting. mime: %{public}s", mime.c_str());
    {
        std::lock_guard<std::mutex> lock(audioRebuildMutex_);
        HandleAudioUnsupported();
    }
}

bool HiPlayerImpl::CheckAudioTopologyRebuild(std::shared_ptr<Meta>& meta, const std::string& mime)
{
    StreamType newStreamType;
    FALSE_RETURN_V_MSG_W(demuxer_->GetAudioStreamType(newStreamType, mime,
        static_cast<size_t>(currentAudioTrackId_), meta), false, "GetAudioStreamType failed");
    if (newStreamType == currentAudioStreamType_) {
        return false;
    }
    MEDIA_LOG_I("Audio pipeline rebuild needed, oldStreamType: %{public}d, newStreamType: %{public}d",
        static_cast<int32_t>(currentAudioStreamType_), static_cast<int32_t>(newStreamType));
    int32_t innerTrackId = -1;
    meta->GetData(Tag::REGULAR_TRACK_ID, innerTrackId);
    // Filters already null: pipeline torn down during initial Prepare. Skip rebuild.
    if (audioDecoder_ == nullptr && audioSink_ == nullptr) {
        MEDIA_LOG_I("Audio pipeline already torn down, skip rebuild for same unsupported track");
        return false;
    }
    Status ret = RebuildAudioPipeline(meta, newStreamType, innerTrackId, currentAudioTrackId_);
    if (ret != Status::OK) {
        HandleRebuildFailure("CheckAudioTopologyRebuild");
        return false;
    }
    currentAudioStreamType_ = newStreamType;
    return true;
}

bool HiPlayerImpl::ChangeAudioTrackSameTopology(std::shared_ptr<Meta>& meta,
    int32_t innerTrackId, int32_t index, std::vector<std::shared_ptr<Meta>>& metaInfo)
{
    MEDIA_LOG_I("ChangeAudioTrackSameTopology, same topology track switch");
    std::string mime;
    meta->GetData(Tag::MIME_TYPE, mime);
    if (audioDecoder_ != nullptr && Status::OK != audioDecoder_->ChangePlugin(meta)) {
        MEDIA_LOG_E("ChangeAudioTrackSameTopology audioDecoder change plugin error");
        // ChangePlugin failure leaves decoder's internal plugin broken; DoStop/DoRelease
        // would dereference NULL, so MuteAudioToVideoOnly handles cleanup safely.
        // Caller handles currentAudioStreamType_/currentAudioTrackId_/NotifyUpdateTrackInfo().
        MuteAudioToVideoOnly();
        return false;
    }
    FALSE_GOON_NOEXEC(audioDecoder_ != nullptr, audioDecoder_->DoFlush());
    FALSE_GOON_NOEXEC(audioSink_ != nullptr, audioSink_->DoFlush());
    FALSE_GOON_NOEXEC(audioDecoder_ != nullptr, audioDecoder_->Start());

    if (IsNeedAudioSinkChangeTrack(metaInfo, index)) {
        MEDIA_LOG_I("AudioSink changeTrack in same topology");
        if (audioSink_ != nullptr && audioSink_->ChangeTrack(meta) != Status::OK) {
            MEDIA_LOG_E("ChangeAudioTrackSameTopology audioSink change track error");
            // Half-broken pipeline (new decoder, failed sink). Tear down to video-only.
            // Caller handles currentAudioTrackId_/currentAudioStreamType_.
            MuteAudioToVideoOnly();
            return false;
        }
    }
    FALSE_RETURN_V_MSG(demuxer_->StartTask(innerTrackId) == Status::OK, false,
        "ChangeAudioTrackSameTopology StartTask error. trackId is " PUBLIC_LOG_D32, innerTrackId);
    return true;
}

bool HiPlayerImpl::ChangeAudioDecoderSameTopology(std::shared_ptr<Meta> meta, const std::string& mime,
    bool isStreamSwitch)
{
    // Same-topology audio decoder change (e.g. aac->mp3 within ENCODED_AUDIO).
    // Caller (HandleAudioDecoderChangeEvent) handles currentAudioStreamType_/currentAudioTrackId_.
    std::shared_ptr<Meta> preMeta = std::make_shared<Meta>();
    FALSE_RETURN_V(audioSink_ != nullptr, false);
    audioSink_->GetParameter(preMeta);
    FALSE_GOON_NOEXEC(audioDecoder_ != nullptr, audioDecoder_->UpdateTrackInfoSampleFormat(mime, meta));

    bool needSinkChange = IsNeedAudioSinkChangeTrack(preMeta, meta);
    if (!isStreamSwitch && !needSinkChange) {
        FALSE_GOON_NOEXEC(demuxer_ != nullptr, demuxer_->StartTask(OHOS::Media::Plugins::MediaType::AUDIO));
        return false;
    }
    if (audioDecoder_ != nullptr && Status::OK != audioDecoder_->ChangePlugin(meta)) {
        MEDIA_LOG_E("audioDecoder change plugin error");
        // ChangePlugin failure leaves decoder's internal plugin broken; teardown to video-only.
        // Caller handles currentAudioStreamType_/currentAudioTrackId_/NotifyUpdateTrackInfo().
        MuteAudioToVideoOnly();
        return false;
    }
    FALSE_GOON_NOEXEC(audioDecoder_ != nullptr, audioDecoder_->DoFlush());
    audioSink_->DoFlush();
    FALSE_GOON_NOEXEC(audioDecoder_ != nullptr, audioDecoder_->Start());
    if (needSinkChange && Status::OK != audioSink_->ChangeTrack(meta)) {
        MEDIA_LOG_E("audioSink change track error");
        // Half-broken pipeline (new decoder, failed sink). Tear down to video-only.
        // Caller handles currentAudioStreamType_/currentAudioTrackId_/NotifyUpdateTrackInfo().
        MuteAudioToVideoOnly();
        return false;
    }
    FALSE_GOON_NOEXEC(demuxer_ != nullptr, demuxer_->StartTask(OHOS::Media::Plugins::MediaType::AUDIO));
    return true;
}

void HiPlayerImpl::StopAudioDataFlow()
{
    MEDIA_LOG_I("StopAudioDataFlow");
    if (audioDecoder_ != nullptr) {
        audioDecoder_->DoFlush();
    }
    if (audioSink_ != nullptr) {
        audioSink_->DoFlush();
    }
}

void HiPlayerImpl::UnlinkOldAudioTopology()
{
    MEDIA_LOG_I("UnlinkOldAudioTopology");
    // Skip if filters already released (prior teardown removed the topology).
    if (audioDecoder_ == nullptr && audioSink_ == nullptr) {
        MEDIA_LOG_I("UnlinkOldAudioTopology: audio filters already released, skip");
        return;
    }
    if (currentAudioStreamType_ == StreamType::STREAMTYPE_ENCODED_AUDIO) {
        pipeline_->UnLinkFilters(audioDecoder_, {audioSink_},
            StreamType::STREAMTYPE_RAW_AUDIO);
        pipeline_->UnLinkFilters(demuxer_, {audioDecoder_},
            StreamType::STREAMTYPE_ENCODED_AUDIO);
    } else {
        pipeline_->UnLinkFilters(demuxer_, {audioSink_}, currentAudioStreamType_);
    }
}

void HiPlayerImpl::ReleaseOldAudioFilters()
{
    MEDIA_LOG_I("ReleaseOldAudioFilters");
    if (audioDecoder_ != nullptr) {
        audioDecoder_->DoStop();
        audioDecoder_->DoRelease();
        if (interruptMonitor_ != nullptr) {
            interruptMonitor_->DeregisterListener(audioDecoder_);
        }
        audioDecoder_.reset();
    }
    if (audioSink_ != nullptr) {
        audioSink_->DoStop();
        audioSink_->DoRelease();
        audioSink_.reset();
    }
    completeState_.erase(std::remove_if(completeState_.begin(), completeState_.end(),
        [](const std::pair<std::string, bool>& item) { return item.first == "AudioSink"; }),
        completeState_.end());
    initialAVStates_.erase(std::remove_if(initialAVStates_.begin(), initialAVStates_.end(),
        [](const std::pair<EventType, bool>& item) {
            return item.first == EventType::EVENT_AUDIO_FIRST_FRAME;
        }), initialAVStates_.end());
}

Status HiPlayerImpl::BuildNewAudioTopology(StreamType newStreamType, int32_t trackIndex)
{
    MEDIA_LOG_I("BuildNewAudioTopology, newStreamType: %{public}d, trackIndex: %{public}d",
        static_cast<int32_t>(newStreamType), trackIndex);

    // Clear stale track_id_map_ entries: muted tracks leave stale entries that
    // FindTrackId would consume first, causing LinkNext to use wrong track metadata.
    demuxer_->ClearTrackIdMap(newStreamType);
    demuxer_->UpdateTrackIdMap(newStreamType, trackIndex);
    if (newStreamType == StreamType::STREAMTYPE_ENCODED_AUDIO) {
        Status ret = LinkAudioDecoderFilter(demuxer_, newStreamType);
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "BuildNewAudioTopology: LinkAudioDecoderFilter failed");
    } else {
        Status ret = LinkAudioSinkFilter(demuxer_, newStreamType);
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "BuildNewAudioTopology: LinkAudioSinkFilter failed");
    }
    return Status::OK;
}

Status HiPlayerImpl::PrepareNewAudioFilters()
{
    MEDIA_LOG_I("PrepareNewAudioFilters");
    // Issue both async Prepares before waiting, allowing them to run in parallel.
    if (audioDecoder_ != nullptr) {
        Status ret = audioDecoder_->Prepare();
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "PrepareNewAudioFilters: audioDecoder Prepare failed");
    }
    if (audioSink_ != nullptr) {
        Status ret = audioSink_->Prepare();
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "PrepareNewAudioFilters: audioSink Prepare failed");
    }

    // Wait for async Prepare to complete before starting data flow.
    if (audioDecoder_ != nullptr) {
        Status ret = audioDecoder_->WaitAllState(FilterState::READY);
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "PrepareNewAudioFilters: audioDecoder WaitAllState READY failed");
    }
    if (audioSink_ != nullptr) {
        Status ret = audioSink_->WaitAllState(FilterState::READY);
        FALSE_RETURN_V_MSG(ret == Status::OK, ret, "PrepareNewAudioFilters: audioSink WaitAllState READY failed");
    }
    return Status::OK;
}

Status HiPlayerImpl::StartThenPauseFilter(const std::shared_ptr<OHOS::Media::Pipeline::Filter>& filter,
    bool wasRunning)
{
    FALSE_RETURN_V_MSG(filter != nullptr, Status::OK, "filter is nullptr, skip");
    filter->Start();
    // Always wait for RUNNING before deciding to pause. Skipping WaitAllState when
    // wasRunning=true left Start() async, causing spurious BUFFERING_START and freezing.
    Status ret = filter->WaitAllState(FilterState::RUNNING);
    FALSE_RETURN_V_MSG(ret == Status::OK, ret, "StartThenPauseFilter: WaitAllState RUNNING failed");
    if (!wasRunning) {
        filter->Pause();
    }
    return Status::OK;
}

Status HiPlayerImpl::StartAudioDataFlow(bool wasRunning, int32_t innerTrackId)
{
    MEDIA_LOG_I("StartAudioDataFlow, wasRunning: %{public}d", wasRunning);
    std::vector<std::shared_ptr<OHOS::Media::Pipeline::Filter>> filters = {audioDecoder_, audioSink_};
    for (auto& filter : filters) {
        if (filter == nullptr) {
            continue;
        }
        Status ret = StartThenPauseFilter(filter, wasRunning);
        FALSE_RETURN_V(ret == Status::OK, ret);
    }
    FALSE_RETURN_V_MSG(demuxer_->StartTask(innerTrackId) == Status::OK, Status::ERROR_UNKNOWN,
        "StartAudioDataFlow: StartTask error. trackId is " PUBLIC_LOG_D32, innerTrackId);
    return Status::OK;
}

Status HiPlayerImpl::RebuildAudioPipeline(std::shared_ptr<Meta>& meta,
    StreamType newStreamType, int32_t innerTrackId, int32_t trackIndex)
{
    // Acquires audioRebuildMutex_ internally. Callers must NOT hold it (would deadlock).
    std::lock_guard<std::mutex> lock(audioRebuildMutex_);
    MEDIA_LOG_I("RebuildAudioPipeline begin, newStreamType: %{public}d, innerTrackId: %{public}d, "
        "trackIndex: %{public}d", static_cast<int32_t>(newStreamType), innerTrackId, trackIndex);

    StopAudioDataFlow();
    UnlinkOldAudioTopology();
    ReleaseOldAudioFilters();

    Status ret = BuildNewAudioTopology(newStreamType, trackIndex);
    FALSE_RETURN_V(ret == Status::OK, ret);

    ret = PrepareNewAudioFilters();
    FALSE_RETURN_V(ret == Status::OK, ret);

    bool wasRunning = (pipelineStates_ == PlayerStates::PLAYER_STARTED);
    ret = StartAudioDataFlow(wasRunning, innerTrackId);
    FALSE_RETURN_V(ret == Status::OK, ret);

    MEDIA_LOG_I("RebuildAudioPipeline end");
    return Status::OK;
}

void HiPlayerImpl::HandleRebuildFailure(const char* scenario)
{
    // Centralized rebuild failure handling: reset state to PACKED (force next switch to
    // rebuild from scratch), report warning via WARN_MSG (app gets onError, player stays
    // PLAYING), and set dedup guard for this play cycle.
    // RebuildAudioPipeline already tore down old filters, so we only reset state + report.
    MEDIA_LOG_E("HandleRebuildFailure: %{public}s", scenario);
    currentAudioStreamType_ = StreamType::STREAMTYPE_PACKED;
    ReportAudioUnsupportedWarning();
}

void HiPlayerImpl::ReportAudioUnsupportedWarning()
{
    // Report MSERR_UNSUPPORT_AUD_DEC_TYPE via WARN_MSG (bypasses errorCbOnce_ and fatal-code
    // check; app gets onError, player stays PLAYING) and set per-play-cycle dedup guard.
    Format format;
    callbackLooper_.OnInfo(INFO_TYPE_WARN_MSG, MSERR_UNSUPPORT_AUD_DEC_TYPE, format);
    audioMutedReportedInPlayCycle_.store(true);
}

void HiPlayerImpl::HandleAudioUnsupported()
{
    // Unified entry for audio-not-supported-on-device. Pure-audio resources have
    // no video to fall back to, so report a fatal error and stop playback instead
    // of muting to video-only (which would leave the player in a dead PLAYING state).
    if (isOnlyAudio_.load()) {
        MEDIA_LOG_E("Audio not supported in pure-audio playback, reporting error and stopping");
        ReportAudioUnsupportedWarning();
        callbackLooper_.OnError(PlayerErrorType::AUD_DEC_ERR,
            MSERR_UNSUPPORT_AUD_DEC_TYPE, "Audio track not supported in pure-audio playback");
        UpdateStateNoLock(PlayerStates::PLAYER_STATE_ERROR);
        pipeline_->Stop();
    } else {
        MuteAudioToVideoOnly();
    }
}

void HiPlayerImpl::MuteAudioToVideoOnly()
{
    // Report + teardown audio pipeline to make the player video-only.
    // Caller is responsible for setting currentAudioTrackId_ and NotifyUpdateTrackInfo().
    ReportAudioUnsupportedWarning();
    if (audioSink_ != nullptr) {
        audioSink_->ReportEosToSyncCenter();
    }
    UnlinkOldAudioTopology();
    ReleaseOldAudioFilters();
    currentAudioStreamType_ = StreamType::STREAMTYPE_PACKED;
}

} // namespace Media
} // namespace OHOS