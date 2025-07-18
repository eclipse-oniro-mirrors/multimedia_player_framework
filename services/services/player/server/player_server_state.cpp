/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "player_server_state.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_dfx.h"
#include "account_subscriber.h"
#include "os_account_manager.h"
#include "plugin/plugin_time.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerServerState"};
constexpr int32_t COMPLETED_PLAY_REPORT_MS = 3000;
}

namespace OHOS {
namespace Media {
void PlayerServer::BaseState::ReportInvalidOperation() const
{
    MEDIA_LOGE("invalid operation for %{public}s", GetStateName().c_str());
    (void)server_.taskMgr_.MarkTaskDone("ReportInvalidOperation");
}

int32_t PlayerServer::BaseState::Prepare()
{
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::Play()
{
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::Pause(bool isSystemOperation)
{
    (void)isSystemOperation;
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::Freeze()
{
    return server_.HandleLiteFreeze();
}

int32_t PlayerServer::BaseState::UnFreeze()
{
    return server_.HandleLiteUnFreeze();
}

int32_t PlayerServer::BaseState::PauseDemuxer()
{
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::ResumeDemuxer()
{
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    (void)mSeconds;
    (void)mode;

    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::Stop()
{
    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::SetPlaybackSpeed(PlaybackRateMode mode)
{
    (void)mode;

    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::SetPlaybackRate(float rate)
{
    (void)rate;

    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::SeekContinous(int32_t mSeconds, int64_t batchNo)
{
    (void)mSeconds;
    (void)batchNo;

    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    (void)start;
    (void)end;
    (void)mode;

    ReportInvalidOperation();
    return MSERR_INVALID_STATE;
}

int32_t PlayerServer::BaseState::MessageSeekDone(int32_t extra)
{
    int32_t ret = MSERR_OK;
    (void)server_.taskMgr_.MarkTaskDone("seek done");
    MediaTrace::TraceEnd("PlayerServer::Seek", FAKE_POINTER(&server_));
    MediaTrace::TraceEnd("PlayerServer::track", FAKE_POINTER(&server_));
    if (server_.disableNextSeekDone_ && extra == 0) {
        ret = MSERR_UNSUPPORT;
    }
    server_.disableNextSeekDone_ = false;
    return ret;
}

int32_t PlayerServer::BaseState::MessageTrackDone(int32_t extra)
{
    (void)extra;
    (void)server_.taskMgr_.MarkTaskDone("track done");
    MediaTrace::TraceEnd("PlayerServer::track", FAKE_POINTER(&server_));
    return MSERR_OK;
}

int32_t PlayerServer::BaseState::MessageTrackInfoUpdate()
{
    (void)server_.taskMgr_.MarkTaskDone("addsubtitle done");
    MediaTrace::TraceEnd("PlayerServer::AddSubSource", FAKE_POINTER(&server_));
    return MSERR_OK;
}

int32_t PlayerServer::BaseState::MessageSpeedDone()
{
    (void)server_.taskMgr_.MarkTaskDone("speed done");
    MediaTrace::TraceEnd("PlayerServer::SetPlaybackSpeed", FAKE_POINTER(&server_));
    return MSERR_OK;
}

int32_t PlayerServer::BaseState::MessageRateDone()
{
    (void)server_.taskMgr_.MarkTaskDone("rate done");
    MediaTrace::TraceEnd("PlayerServer::SetPlaybackRate", FAKE_POINTER(&server_));
    return MSERR_OK;
}

int32_t PlayerServer::BaseState::MessageStateChange(int32_t extra)
{
    if (extra == PLAYER_PLAYBACK_COMPLETE) {
        HandlePlaybackComplete(extra);
    } else {
        HandleStateChange(extra);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Callback State change, currentState is %{public}s",
            FAKE_POINTER(this), server_.GetStatusDescription(extra).c_str());
    }

    if (extra == PLAYER_STOPPED && server_.disableStoppedCb_) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Callback State change disable StoppedCb", FAKE_POINTER(this));
        server_.disableStoppedCb_ = false;
        return MSERR_UNSUPPORT;
    }
    return MSERR_OK;
}

int32_t PlayerServer::BaseState::OnMessageReceived(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    MEDIA_LOGD("message received, type = %{public}d, extra = %{public}d", type, extra);
    (void)infoBody;

    int32_t ret = MSERR_OK;
    switch (type) {
        case INFO_TYPE_SEEKDONE:
            ret = MessageSeekDone(extra);
            break;

        case INFO_TYPE_SPEEDDONE:
            ret = MessageSpeedDone();
            break;

        case INFO_TYPE_RATEDONE:
            ret = MessageRateDone();
            break;

        case INFO_TYPE_EOS:
            HandleEos();
            break;

        case INFO_TYPE_STATE_CHANGE:
            ret = MessageStateChange(extra);
            break;

        case INFO_TYPE_TRACK_DONE:
            ret = MessageTrackDone(extra);
            break;

        case INFO_TYPE_ADD_SUBTITLE_DONE:
            ret = MessageTrackInfoUpdate();
            break;

        case INFO_TYPE_TRACK_INFO_UPDATE:
            ret = MessageTrackInfoUpdate();
            break;
        case INFO_TYPE_INTERRUPT_EVENT:
            HandleInterruptEvent(infoBody);
            break;

        case INFO_TYPE_AUDIO_DEVICE_CHANGE:
            HandleAudioDeviceChangeEvent(infoBody);
            break;
            
        default:
            break;
    }

    return ret;
}

void PlayerServer::IdleState::StateEnter()
{
    (void)server_.HandleReset();
}

int32_t PlayerServer::InitializedState::Prepare()
{
    server_.ChangeState(server_.preparingState_);
    return MSERR_OK;
}

int32_t PlayerServer::InitializedState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    return server_.HandleSetPlayRange(start, end, mode);
}

void PlayerServer::PreparingState::StateEnter()
{
    (void)server_.HandlePrepare();
    MEDIA_LOGD("PlayerServer::PreparingState::StateEnter finished");
}

int32_t PlayerServer::PreparingState::Stop()
{
    (void)server_.HandleStop();
    server_.ChangeState(server_.stoppedState_);
    return MSERR_OK;
}

void PlayerServer::PreparingState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_PREPARED || newState == PLAYER_STATE_ERROR) {
        MediaTrace::TraceEnd("PlayerServer::PrepareAsync", FAKE_POINTER(&server_));
        if (newState == PLAYER_STATE_ERROR) {
            server_.lastOpStatus_ = PLAYER_STATE_ERROR;
            server_.ChangeState(server_.initializedState_);
        } else {
            server_.ChangeState(server_.preparedState_);
        }
        (void)server_.taskMgr_.MarkTaskDone("preparing->prepared done");
    }
}

int32_t PlayerServer::PreparedState::Prepare()
{
    (void)server_.taskMgr_.MarkTaskDone("double prepare");
    return MSERR_OK;
}

int32_t PlayerServer::PreparedState::Play()
{
    return server_.HandlePlay();
}

int32_t PlayerServer::PreparedState::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    return server_.HandleSeek(mSeconds, mode);
}

int32_t PlayerServer::PreparedState::Stop()
{
    return server_.HandleStop();
}

int32_t PlayerServer::PreparedState::SetPlaybackSpeed(PlaybackRateMode mode)
{
    return server_.HandleSetPlaybackSpeed(mode);
}

int32_t PlayerServer::PreparedState::SetPlaybackRate(float rate)
{
    return server_.HandleSetPlaybackRate(rate);
}

int32_t PlayerServer::PreparedState::SeekContinous(int32_t mSeconds, int64_t batchNo)
{
    return server_.HandleSeekContinous(mSeconds, batchNo);
}

int32_t PlayerServer::PreparedState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    return server_.HandleSetPlayRange(start, end, mode);
}

void PlayerServer::PreparedState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_STARTED) {
        MediaTrace::TraceEnd("PlayerServer::Play", FAKE_POINTER(&server_));
        server_.ChangeState(server_.playingState_);
        (void)server_.taskMgr_.MarkTaskDone("prepared->started done");
    } else if (newState == PLAYER_STOPPED) {
        MediaTrace::TraceEnd("PlayerServer::Stop", FAKE_POINTER(&server_));
        server_.ChangeState(server_.stoppedState_);
        (void)server_.taskMgr_.MarkTaskDone("prepared->stopped done");
    } else if (newState == PLAYER_STATE_ERROR) {
        server_.lastOpStatus_ = PLAYER_STATE_ERROR;
        server_.ChangeState(server_.initializedState_);
        (void)server_.taskMgr_.MarkTaskDone("prepared->error done");
    }
}

void PlayerServer::PreparedState::HandleEos()
{
    server_.PreparedHandleEos();
}

int32_t PlayerServer::PlayingState::Play()
{
    (void)server_.taskMgr_.MarkTaskDone("double play");
    return MSERR_OK;
}

int32_t PlayerServer::PlayingState::Pause(bool isSystemOperation)
{
    return server_.HandlePause(isSystemOperation);
}

int32_t PlayerServer::PlayingState::Freeze()
{
    return server_.HandleFreeze();
}

int32_t PlayerServer::PlayingState::UnFreeze()
{
    return server_.HandleUnFreeze();
}

int32_t PlayerServer::PlayingState::PauseDemuxer()
{
    return server_.HandlePauseDemuxer();
}

int32_t PlayerServer::PlayingState::ResumeDemuxer()
{
    return server_.HandleResumeDemuxer();
}

int32_t PlayerServer::PlayingState::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    return server_.HandleSeek(mSeconds, mode);
}

int32_t PlayerServer::PlayingState::Stop()
{
    return server_.HandleStop();
}

int32_t PlayerServer::PlayingState::SetPlaybackSpeed(PlaybackRateMode mode)
{
    return server_.HandleSetPlaybackSpeed(mode);
}

int32_t PlayerServer::PlayingState::SetPlaybackRate(float rate)
{
    return server_.HandleSetPlaybackRate(rate);
}

int32_t PlayerServer::PlayingState::SeekContinous(int32_t mSeconds, int64_t batchNo)
{
    return server_.HandleSeekContinous(mSeconds, batchNo);
}

void PlayerServer::PlayingState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_PAUSED) {
        MediaTrace::TraceEnd("PlayerServer::Pause", FAKE_POINTER(&server_));
        server_.ChangeState(server_.pausedState_);
        (void)server_.taskMgr_.MarkTaskDone("started->paused done");
    } else if (newState == PLAYER_STOPPED) {
        MediaTrace::TraceEnd("PlayerServer::Stop", FAKE_POINTER(&server_));
        server_.ChangeState(server_.stoppedState_);
        (void)server_.taskMgr_.MarkTaskDone("started->stopped done");
    }
}

void PlayerServer::PlayingState::HandlePlaybackComplete(int32_t extra)
{
    (void)extra;
    server_.lastOpStatus_ = PLAYER_PLAYBACK_COMPLETE;
    server_.ChangeState(server_.playbackCompletedState_);
    (void)server_.taskMgr_.MarkTaskDone("playing->completed done");
}

void PlayerServer::PlayingState::HandleEos()
{
    server_.HandleEos();
}

void PlayerServer::PlayingState::HandleInterruptEvent(const Format &infoBody)
{
    server_.HandleInterruptEvent(infoBody);
}

void PlayerServer::PlayingState::HandleAudioDeviceChangeEvent(const Format &infoBody)
{
    (void)infoBody;
}

void PlayerServer::PlayingState::StateEnter()
{
    int32_t userId = server_.GetUserId();
    bool isBootCompleted = server_.IsBootCompleted();
    if (userId <= 0 || !isBootCompleted) {
        MEDIA_LOGI("PlayingState::StateEnter userId = %{public}d, isBootCompleted = %{public}d, return",
            userId, isBootCompleted);
        return;
    }

    bool isForeground = true;
    AccountSA::OsAccountManager::IsOsAccountForeground(userId, isForeground);
    MEDIA_LOGI("PlayingState::StateEnter userId = %{public}d isForeground = %{public}d isBootCompleted = %{public}d",
        userId, isForeground, isBootCompleted);
    if (!isForeground && !server_.GetInterruptState()) {
        server_.OnSystemOperation(
            PlayerOnSystemOperationType::OPERATION_TYPE_PAUSE, PlayerOperationReason::OPERATION_REASON_USER_BACKGROUND);
        return;
    }
    std::shared_ptr<CommonEventReceiver> receiver = server_.GetCommonEventReceiver();
    AccountSubscriber::GetInstance()->RegisterCommonEventReceiver(userId, receiver);
}

void PlayerServer::PlayingState::StateExit()
{
    std::shared_ptr<CommonEventReceiver> receiver = server_.GetCommonEventReceiver();
    AccountSubscriber::GetInstance()->UnregisterCommonEventReceiver(server_.GetUserId(), receiver);
}

int32_t PlayerServer::PausedState::Play()
{
    return server_.HandlePlay();
}

int32_t PlayerServer::PausedState::Pause(bool isSystemOperation)
{
    (void)server_.taskMgr_.MarkTaskDone("double pause");
    return MSERR_OK;
}

int32_t PlayerServer::PausedState::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    return server_.HandleSeek(mSeconds, mode);
}

int32_t PlayerServer::PausedState::Stop()
{
    return server_.HandleStop();
}

int32_t PlayerServer::PausedState::UnFreeze()
{
    return server_.HandleUnFreeze();
}

int32_t PlayerServer::PausedState::SetPlaybackSpeed(PlaybackRateMode mode)
{
    return server_.HandleSetPlaybackSpeed(mode);
}

int32_t PlayerServer::PausedState::SetPlaybackRate(float rate)
{
    return server_.HandleSetPlaybackRate(rate);
}

int32_t PlayerServer::PausedState::SeekContinous(int32_t mSeconds, int64_t batchNo)
{
    return server_.HandleSeekContinous(mSeconds, batchNo);
}

int32_t PlayerServer::PausedState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    return server_.HandleSetPlayRange(start, end, mode);
}

void PlayerServer::PausedState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_STARTED) {
        MediaTrace::TraceEnd("PlayerServer::Play", FAKE_POINTER(&server_));
        server_.ChangeState(server_.playingState_);
        (void)server_.taskMgr_.MarkTaskDone("paused->started done");
    } else if (newState == PLAYER_STOPPED) {
        MediaTrace::TraceEnd("PlayerServer::Stop", FAKE_POINTER(&server_));
        server_.ChangeState(server_.stoppedState_);
        (void)server_.taskMgr_.MarkTaskDone("paused->stopped done");
    }
}

void PlayerServer::PausedState::HandleEos()
{
    server_.HandleEos();
}

int32_t PlayerServer::StoppedState::Prepare()
{
    server_.ChangeState(server_.preparingState_);
    return MSERR_OK;
}

int32_t PlayerServer::StoppedState::Stop()
{
    (void)server_.taskMgr_.MarkTaskDone("double stop");
    return MSERR_OK;
}

void PlayerServer::StoppedState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_STATE_ERROR) {
        (void)server_.taskMgr_.MarkTaskDone("stopped->error done");
    } else if (newState == PLAYER_STOPPED) {
        (void)server_.taskMgr_.MarkTaskDone("double stop");
    }
}

int32_t PlayerServer::StoppedState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    return server_.HandleSetPlayRange(start, end, mode);
}

void PlayerServer::PlaybackCompletedState::StateEnter()
{
    MEDIA_LOGD("state enter completed");
    stateEnterTimeMs_ = Plugins::GetCurrentMillisecond();
}

int32_t PlayerServer::PlaybackCompletedState::Play()
{
    auto res = server_.HandlePlay();
    auto timeNow = Plugins::GetCurrentMillisecond();
    auto timeDiff = timeNow - stateEnterTimeMs_;
    MEDIA_LOGD("timeNow %{public}" PRId64 " timeStart %{public}" PRId64 " timeDiff %{public}" PRId64,
        timeNow, stateEnterTimeMs_, timeDiff);
    CHECK_AND_RETURN_RET(timeDiff < COMPLETED_PLAY_REPORT_MS, res);
    return res;
}

int32_t PlayerServer::PlaybackCompletedState::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    return server_.HandleSeek(mSeconds, mode);
}

int32_t PlayerServer::PlaybackCompletedState::SeekContinous(int32_t mSeconds, int64_t batchNo)
{
    return server_.HandleSeekContinous(mSeconds, batchNo);
}

int32_t PlayerServer::PlaybackCompletedState::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    return server_.HandleSetPlayRange(start, end, mode);
}

int32_t PlayerServer::PlaybackCompletedState::Stop()
{
    return server_.HandleStop();
}

int32_t PlayerServer::PlaybackCompletedState::UnFreeze()
{
    return server_.HandleUnFreeze();
}

void PlayerServer::PlaybackCompletedState::HandleStateChange(int32_t newState)
{
    if (newState == PLAYER_STARTED) {
        MediaTrace::TraceEnd("PlayerServer::Play", FAKE_POINTER(&server_));
        server_.ChangeState(server_.playingState_);
        (void)server_.taskMgr_.MarkTaskDone("completed->started done");
    } else if (newState == PLAYER_STOPPED) {
        MediaTrace::TraceEnd("PlayerServer::Stop", FAKE_POINTER(&server_));
        server_.ChangeState(server_.stoppedState_);
        server_.lastOpStatus_ = PLAYER_STOPPED;
        (void)server_.taskMgr_.MarkTaskDone("completed->stopped done");
    }
}

int32_t PlayerServer::PlaybackCompletedState::SetPlaybackSpeed(PlaybackRateMode mode)
{
    return server_.HandleSetPlaybackSpeed(mode);
}

int32_t PlayerServer::PlaybackCompletedState::SetPlaybackRate(float rate)
{
    return server_.HandleSetPlaybackRate(rate);
}
}
}
