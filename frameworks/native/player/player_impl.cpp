/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "player_impl.h"
#include <string>
#include <random>
#include <sstream>
#include <algorithm>
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"
#include "scope_guard.h"
#include "scoped_timer.h"
#include "player_xcollie.h"
#ifdef SUPPORT_AVPLAYER_DRM
#include "imedia_key_session_service.h"
#endif
#include "fd_utils.h"
#include "osal/utils/steady_clock.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerImpl"};
constexpr int32_t API_VERSION_14 = 14;
static int32_t apiVersion_ = -1;
constexpr int64_t OVERTIME_WARNING_MS = 10;
constexpr int64_t CREATE_AVPLAYER_WARNING_MS = 30;
constexpr int64_t RESET_WARNING_MS = 30;
constexpr int64_t RELEASE_WARNING_MS = 200;
const int32_t TIME_OUT_SECOND = 15;
}

namespace OHOS {
namespace Media {

namespace {
thread_local std::mt19937_64 g_shuffleRng = []() {
    std::random_device rd;
    std::mt19937_64::result_type seed = static_cast<std::mt19937_64::result_type>(rd()) ^
               (static_cast<std::mt19937_64::result_type>(rd()) << 32);
    return std::mt19937_64(seed);
}();
}

std::shared_ptr<Player> PlayerFactory::CreatePlayer()
{
    return CreatePlayer(PlayerProducer::INNER);
}

std::shared_ptr<Player> PlayerFactory::CreatePlayer(const PlayerProducer producer)
{
    ScopedTimer timer("CreatePlayer", CREATE_AVPLAYER_WARNING_MS);
    MEDIA_LOGD("PlayerImpl: CreatePlayer in");
    std::shared_ptr<PlayerImpl> impl = std::make_shared<PlayerImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new PlayerImpl");

    int32_t ret = MSERR_OK;
    LISTENER(ret = impl->Init(producer), "CreatePlayer", false, TIME_OUT_SECOND);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init PlayerImpl");

    return impl;
}

std::vector<pid_t> PlayerFactory::GetPlayerPids()
{
    std::vector<pid_t> pids = MediaServiceFactory::GetInstance().GetPlayerPids();
    std::string pidLog = "GetPlayerPids size=" + std::to_string(pids.size());
    if (pids.size() > 0) {
        pidLog += ", contents:";
        for (auto pid : pids) {
            pidLog += std::to_string(pid) + ", ";
        }
    }
    MEDIA_LOGI("%{public}s", pidLog.c_str());
    return pids;
}

int32_t PlayerImpl::Init(const PlayerProducer producer)
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Init in", FAKE_POINTER(this));
    HiviewDFX::HiTraceChain::SetId(traceId_);
    playerService_ = MediaServiceFactory::GetInstance().CreatePlayerService();
    auto ret = playerService_ == nullptr ? MSERR_UNKNOWN : MSERR_OK;
    if (ret == MSERR_OK) {
        playerService_->SetPlayerProducer(producer);
    }
    return ret;
}

HiviewDFX::HiTraceId PlayerImpl::GetTraceId()
{
    return traceId_;
}

PlayerImpl::PlayerImpl()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    ResetSeekVariables();
    traceId_ = HiTraceChainGetId();
    if (!traceId_.IsValid()) {
        MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " traceId not valid", FAKE_POINTER(this));
        traceId_ = HiviewDFX::HiTraceChain::Begin("PlayerImpl", HITRACE_FLAG_DEFAULT);
    }
}

PlayerImpl::~PlayerImpl()
{
    if (playerService_ != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyPlayerService(playerService_);
        playerService_ = nullptr;
    }
    ResetSeekVariables();
    if (traceId_.IsValid()) {
        MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " traceId valid", FAKE_POINTER(this));
        HiviewDFX::HiTraceChain::End(traceId_);
    }
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void PlayerImpl::ResetSeekVariables()
{
    mCurrentPosition = INT32_MIN;
    mCurrentSeekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    mSeekPosition = INT32_MIN;
    mSeekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    isSeeking_ = false;
}

int32_t PlayerImpl::SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
{
    ScopedTimer timer("SetMediaMuted", OVERTIME_WARNING_MS);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_INVALID_VAL, "playerService_ not exist");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetMediaMuted(mediaType, isMuted), "SetMediaMuted", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    ScopedTimer timer("SetSource dataSrc", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSource in(dataSrc)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(dataSrc != nullptr, MSERR_INVALID_VAL, "failed to create data source");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetSource(dataSrc), "SetSource dataSrc", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetSource(const std::string &url)
{
    ScopedTimer timer("SetSource url", OVERTIME_WARNING_MS);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!url.empty(), MSERR_INVALID_VAL, "url is empty..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetSource(url), "SetSource url", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetSource(int32_t fd, int64_t offset, int64_t size)
{
    ScopedTimer timer("SetSource fd", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSource in(fd)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = SetSourceTask(fd, offset, size), "SetSource fd", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetSourceTask(int32_t fd, int64_t offset, int64_t size)
{
    int32_t ret = MSERR_OK;
    FdsanFd reopenFd = FdUtils::ReOpenFd(fd);
    if (reopenFd.Get() >= 0) {
        MEDIA_LOGI("SetSourceTask: reopen success");
        ret = playerService_->SetSource(reopenFd.Get(), offset, size);
    } else {
        ret = playerService_->SetSource(fd, offset, size);
    }
    CHECK_AND_RETURN_RET_NOLOG(ret == MSERR_OK, ret);
    int32_t dupFd = dup(fd);
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " SetSourceTask dupFd", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(dupFd >= 0, ret, "Dup failed with err.");
    if (!fdsanFd_) {
        fdsanFd_ = std::make_unique<FdsanFd>(dupFd);
    } else {
        fdsanFd_->Reset(dupFd);
    }
    return ret;
}

int32_t PlayerImpl::AddSubSource(const std::string &url)
{
    ScopedTimer timer("AddSubSource url", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{private}06" PRIXPTR " AddSubSource in(url): %{private}s",
        FAKE_POINTER(this), url.c_str());
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!url.empty(), MSERR_INVALID_VAL, "url is empty..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->AddSubSource(url), "AddSubSource url", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::AddSubSource(int32_t fd, int64_t offset, int64_t size)
{
    ScopedTimer timer("AddSubSource fd", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " AddSubSource in(fd)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->AddSubSource(fd, offset, size), "AddSubSource fd", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Play()
{
    ScopedTimer timer("Play", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Play in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->Play(), "Play", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetPlayRange(int64_t start, int64_t end)
{
    ScopedTimer timer("SetPlayRange", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlayRange in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetPlayRange(start, end), "SetPlayRange", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    ScopedTimer timer("SetPlayRangeWithMode", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlayRangeWithMode in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(
        ret = playerService_->SetPlayRangeWithMode(start, end, mode), "SetPlayRangeWithMode", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetPlayRangeUsWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    const int64_t msToUs = 1000;
    const int64_t complementNum = 999;
    return SetPlayRangeWithMode(start / msToUs, (end + complementNum) / msToUs, mode);
}

int32_t PlayerImpl::Prepare()
{
    ScopedTimer timer("Prepare", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Prepare in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->Prepare(), "Prepare", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetRenderFirstFrame(bool display)
{
    ScopedTimer timer("SetRenderFirstFrame", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetRenderFirstFrame in, display %{public}d",
         FAKE_POINTER(this), display);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetRenderFirstFrame(display), "SetRenderFirstFrame", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::PrepareAsync()
{
    ScopedTimer timer("PrepareAsync", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " PrepareAsync in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->PrepareAsync(), "PrepareAsync", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Pause()
{
    ScopedTimer timer("Pause", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Pause in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->Pause(), "Pause", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Stop()
{
    ScopedTimer timer("Stop", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Stop in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    ResetSeekVariables();
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->Stop(), "Stop", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Reset()
{
    ScopedTimer timer("Reset", RESET_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Reset in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    ResetSeekVariables();
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->Reset(), "Reset", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Release()
{
    ScopedTimer timer("Release", RELEASE_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Release in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER((void)playerService_->Release(), "Release", false, TIME_OUT_SECOND);
    (void)MediaServiceFactory::GetInstance().DestroyPlayerService(playerService_);
    playerService_ = nullptr;
    return MSERR_OK;
}

int32_t PlayerImpl::ReleaseSync()
{
    ScopedTimer timer("ReleaseSync", RELEASE_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " ReleaseSync in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER((void)playerService_->ReleaseSync(), "ReleaseSync", false, TIME_OUT_SECOND);
    (void)MediaServiceFactory::GetInstance().DestroyPlayerService(playerService_);
    playerService_ = nullptr;
    return MSERR_OK;
}

int32_t PlayerImpl::SetVolumeMode(int32_t mode)
{
    ScopedTimer timer("SetVolumeMode", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl::SetVolumeMode mode = %{public}d", mode);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetVolumeMode(mode), "SetVolumeMode", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetVolume(float leftVolume, float rightVolume)
{
    ScopedTimer timer("SetVolume", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetVolume(%{public}f, %{public}f) in",
        FAKE_POINTER(this), leftVolume, rightVolume);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetVolume(leftVolume, rightVolume), "SetVolume", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    ScopedTimer timer("Seek", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Seek in, seek to %{public}d ms, mode is %{public}d",
        FAKE_POINTER(this), mSeconds, mode);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");

    std::unique_lock<std::recursive_mutex> lock(recMutex_);
    // SEEK_CONTINOUS is usually called in batches, and will not report seek done event.
    if (mode == PlayerSeekMode::SEEK_CONTINOUS) {
        int32_t ret = MSERR_OK;
        ret = playerService_->Seek(mSeconds, mode);
        return ret;
    }
    mCurrentPosition = mSeconds;
    mCurrentSeekMode = mode;
    if ((mSeekPosition != mCurrentPosition || mSeekMode != mCurrentSeekMode) && !isSeeking_) {
        MEDIA_LOGI("Start seek once.");
        isSeeking_ = true;
        mSeekPosition = mSeconds;
        mSeekMode = mode;
        int32_t retCode = MSERR_OK;
        LISTENER(retCode = playerService_->Seek(mSeconds, mode), "SetVolume", false, TIME_OUT_SECOND);
        if (retCode != MSERR_OK) {
            ResetSeekVariables();
        }
        MEDIA_LOGI("Start seek once end");
        return retCode;
    } else {
        MEDIA_LOGE("Seeking not completed, need wait the lastest seek end, then seek again.");
    }
    MEDIA_LOGI("Seeking task end. %{public}d ms, mode is %{public}d", mSeconds, mode);
    return MSERR_OK;
}

int32_t PlayerImpl::SeekToDefaultPosition()
{
    ScopedTimer timer("SeekToDefaultPosition", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SeekToDefaultPosition in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SeekToDefaultPosition(), "SeekToDefaultPosition", false, TIME_OUT_SECOND);
}

void PlayerImpl::HandleSeekDoneInfo(PlayerOnInfoType type, int32_t extra)
{
    if (type == INFO_TYPE_SEEKDONE) {
        MEDIA_LOGI("HandleSeekDoneInfo entered");
        CHECK_AND_RETURN_LOG(playerService_ != nullptr, "player service does not exist..");
        if (extra == -1) {
            MEDIA_LOGI("seek error, need reset seek variables");
            ResetSeekVariables();
            return;
        }
        std::unique_lock<std::recursive_mutex> lock(recMutex_);
        if (mSeekPosition != mCurrentPosition || mSeekMode != mCurrentSeekMode) {
            MEDIA_LOGI("Start seek again (%{public}d, %{public}d)", mCurrentPosition, mCurrentSeekMode);
            mSeekPosition = mCurrentPosition;
            mSeekMode = mCurrentSeekMode;
            playerService_->Seek(mCurrentPosition, mCurrentSeekMode);
        } else {
            MEDIA_LOGI("All seeks complete - return to regularly scheduled program");
            ResetSeekVariables();
        }
        MEDIA_LOGI("HandleSeekDoneInfo end seekTo(%{public}d, %{public}d)", mCurrentPosition, mCurrentSeekMode);
    }
}

void PlayerImpl::CheckPlaybackContentChange()
{
    if (!curSrcId_.empty()) {
        std::string changeId = curSrcId_;
        NotifyPlaybackContentChange(changeId);
    }
}

PlayerImpl::MediaSourceIterator PlayerImpl::FindMediaSource(const std::string &id) {
    return std::find_if(itemList_.begin(), itemList_.end(),
        [&id](const auto &item) {
            return item.first == id;
        });
}

void PlayerImpl::HandleListStateInfo(PlayerStates state, bool &updateState, int32_t &extra)
{
    if (state == PLAYER_PLAYBACK_COMPLETE) {
        bool shouldSwitch = false;
        int32_t count = static_cast<int32_t>(itemList_.size());
        auto currentIt = FindMediaSource(curSrcId_);
        bool isLast = (count > 0 && currentIt == std::prev(itemList_.end()));
        if (listLoopMode_ != PLAYLIST_LOOP_MODE_NONE || !isLast) {
            shouldSwitch = ShouldLoopCurrent() ? false : true;
            updateState = false;
        } else {
            listState_ = PLAYER_PLAYBACK_COMPLETE;
            curSrcId_ = itemList_[0].first;
        }
        if (shouldSwitch) {
            MediaSourceIterator nextIdx;
            (void)SelectNextIndex(true, nextIdx);
            if (nextIdx != itemList_.end()) {
                auto ret = SwitchToIndex(nextIdx);
                CHECK_AND_RETURN_LOG(ret == MSERR_OK, "switch mediaSource failed when handle list state info");
            }
        }
    } else if (isSwitchingItem_) {
        if (state == PLAYER_IDLE || state == PLAYER_INITIALIZED || state == PLAYER_PREPARED) {
            MEDIA_LOGD("Switching item, current state is %{public}d, wait for PLAYER_STARTED", state);
            updateState = false;
        } else if (state == PLAYER_STARTED) {
            CheckPlaybackContentChange();
            listState_ = PLAYER_STARTED;
            isSwitchingItem_ = false;
            updateState = isFirstSelect_ ? true : false;
            isFirstSelect_ = isFirstSelect_ ? false : isFirstSelect_;
        }
    } else {
        listState_ = state;
        extra = static_cast<int32_t>(listState_);
    }
}

void PlayerImpl::HandleListEOSInfo(bool &notifyEOS)
{
    if (listState_ == PLAYER_PLAYBACK_COMPLETE && listLoopMode_ == PLAYLIST_LOOP_MODE_NONE) {
        MEDIA_LOGD("EOS of last item, wait for state change to switch item");
    } else {
        CheckPlaybackContentChange();
        notifyEOS = false;
    }
}

void PlayerImpl::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    HandleSeekDoneInfo(type, extra);
    std::shared_ptr<PlayerCallback> callback;
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        callback = callback_;
    }

    CHECK_AND_RETURN_LOG(callback != nullptr, "callback is nullptr.");

    {
        std::lock_guard<std::mutex> lock(listMutex_);
        if (type == INFO_TYPE_STATE_CHANGE && IsInListMode()) {
            PlayerStates state = static_cast<PlayerStates>(extra);
            bool updateState = true;
            HandleListStateInfo(state, updateState, extra);
            if (!updateState) {
                MEDIA_LOGD("State change to %{public}d, but not update to upper layer", state);
                return;
            }
        }
        if (type == INFO_TYPE_EOS && IsInListMode()) {
            bool notifyEOS = true;
            HandleListEOSInfo(notifyEOS);
            if (!notifyEOS) {
                MEDIA_LOGD("Receive EOS, but not notify upper layer");
                return;
            }
        }
    }

    if (type == INFO_TYPE_SEEKDONE) {
        if (extra == -1) {
            MEDIA_LOGI("seek done error callback, no need report");
            return;
        }
        if (!isSeeking_) {
            callback->OnInfo(type, extra, infoBody);
        } else {
            MEDIA_LOGD("Is seeking to (%{public}d, %{public}d), not update now", mCurrentPosition, mCurrentSeekMode);
        }
    } else {
        callback->OnInfo(type, extra, infoBody);
    }
}

bool PlayerImpl::IsInListMode() const
{
    return !itemList_.empty();
}

bool PlayerImpl::ShouldLoopCurrent() const
{
    return listLoopMode_ == PLAYLIST_LOOP_MODE_ONE;
}

bool PlayerImpl::ShouldShuffle() const
{
    return listLoopMode_ == PLAYLIST_LOOP_MODE_SHUFFLE;
}

void PlayerImpl::RestoreLoopIfNeeded(bool wasInListMode, bool loop)
{
    if (wasInListMode) {
        (void)SetLooping(loop);
    }
}

static std::string GenerateUniqueId() {
    thread_local std::mt19937 gen(std::random_device{}());
    thread_local std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 8; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; ++i) ss << dis(gen);
    return ss.str();
}

int32_t PlayerImpl::AddPlaybackMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, const std::string &srcId,
    std::string &generateSrcId)
{
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist");

    generateSrcId = GenerateUniqueId();

    std::lock_guard<std::mutex> lock(listMutex_);
    bool isFirstAdd = !IsInListMode();
    if (isFirstAdd) {
        MEDIA_LOGD("PlayerImpl::AddPlaybackMediaSource first add, set mediaSource to service");
        int32_t ret = playerService_->SetMediaSource(mediaSource, AVPlayStrategy());
        if (ret != MSERR_OK) {
            MEDIA_LOGE("PlayerImpl::AddPlaybackMediaSource first add failed, ret=%{public}d", ret);
            return ret;
        }
        itemList_.push_back(std::make_pair(generateSrcId, mediaSource));
        curSrcId_ = generateSrcId;
        listState_ = PLAYER_INITIALIZED;
        return MSERR_OK;
    }

    auto it = FindMediaSource(srcId);
    CHECK_AND_RETURN_RET_LOG(!srcId.empty() && (it != itemList_.end()), MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE,
        "invalid srcId");
    itemList_.insert(it, std::make_pair(generateSrcId, mediaSource));
    return MSERR_OK;
}

void PlayerImpl::HandleRemovePlaybackMediaSource(bool isLast, MediaSourceIterator nextIt)
{
    auto nextIdx = isLast ? itemList_.begin() : nextIt;
    if (listState_ == PLAYER_STARTED) {
        if (!ShouldShuffle()) {
            (void)SwitchToIndex(nextIdx);
        } else {
            (void)SelectNextIndex(true, nextIdx);
            if (nextIdx != itemList_.end()) {
                (void)SwitchToIndex(nextIdx);
            }
        }
    } else {
        if (!ShouldShuffle()) {
            (void)SwitchSetMediaSource(nextIdx);
        } else {
            (void)SelectNextIndex(true, nextIdx);
            if (nextIdx != itemList_.end()) {
                (void)SwitchSetMediaSource(nextIdx);
            }
        }
    }
}

int32_t PlayerImpl::RemovePlaybackMediaSource(std::string srcId)
{
    std::lock_guard<std::mutex> lock(listMutex_);

    auto it = FindMediaSource(srcId);
    if (it == itemList_.end()) {
        return MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE;
    }

    bool isLast = (it == std::prev(itemList_.end()));
    bool isCurrent = (srcId == curSrcId_);

    auto nextIt = itemList_.erase(it);
    if (itemList_.empty()) {
        curSrcId_.clear();
        listState_ = PLAYER_IDLE;
        isFirstSelect_ = false;
        isSwitchingItem_ = false;
        listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
        Reset();
        return MSERR_OK;
    }

    if (isCurrent) {
        HandleRemovePlaybackMediaSource(isLast, nextIt);
    }
    return MSERR_OK;
}

int32_t PlayerImpl::ClearPlaybackList()
{
    {
        std::lock_guard<std::mutex> lock(listMutex_);
        itemList_.clear();
        curSrcId_ = "";
        listState_ = PLAYER_IDLE;
        isFirstSelect_ = false;
        isSwitchingItem_ = false;
        listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
        int32_t ret = Reset();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] Reset failed", __func__);
    }
    return MSERR_OK;
}

int32_t PlayerImpl::GetCurrentMediaSource(std::string &srcId) const
{
    std::lock_guard<std::mutex> lock(listMutex_);
    srcId = curSrcId_;
    return MSERR_OK;
}

int32_t PlayerImpl::GetMediaSourceCount(int32_t &count) const
{
    std::lock_guard<std::mutex> lock(listMutex_);
    count = static_cast<int32_t>(itemList_.size());
    return MSERR_OK;
}

int32_t PlayerImpl::GetMediaSources(std::vector<std::shared_ptr<AVMediaSource>> &mediaSources) const
{
    std::lock_guard<std::mutex> lock(listMutex_);
    for (const auto &item : itemList_) {
        mediaSources.push_back(item.second);
    }
    return MSERR_OK;
}

void PlayerImpl::SetPlaylistLoopMode(PlaylistLoopMode mode)
{
    CHECK_AND_RETURN_LOG(mode >= PLAYLIST_LOOP_MODE_ALL && mode <= PLAYLIST_LOOP_MODE_NONE,
        "invalid list loop mode: %{public}d", static_cast<int32_t>(mode));
    bool loop = false;
    {
        std::lock_guard<std::mutex> lock(listMutex_);
        listLoopMode_ = mode;
        loop = userLoop_;
    }

    (void)SetLooping(loop);
}

PlaylistLoopMode PlayerImpl::GetPlaylistLoopMode() const
{
    std::lock_guard<std::mutex> lock(listMutex_);
    return listLoopMode_;
}

int32_t PlayerImpl::AdvanceToNextMediaSource()
{
    std::lock_guard<std::mutex> lock(listMutex_);
    MediaSourceIterator nextIdx;
    CHECK_AND_RETURN_RET_LOG(IsInListMode(), MSERR_INVALID_STATE, "not in list mode");
    if (ShouldLoopCurrent()) {
        nextIdx = FindMediaSource(curSrcId_);
    } else if (FindMediaSource(curSrcId_) == std::prev(itemList_.end()) && listLoopMode_ == PLAYLIST_LOOP_MODE_NONE) {
        MEDIA_LOGD("already the last item and not in loop mode, not advance to next");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        (void)SelectNextIndex(true, nextIdx);
    }
    auto ret = SwitchToIndex(nextIdx);
    return ret;
}

int32_t PlayerImpl::AdvanceToPrevMediaSource()
{
    std::lock_guard<std::mutex> lock(listMutex_);
    MediaSourceIterator nextIdx;
    CHECK_AND_RETURN_RET_LOG(IsInListMode(), MSERR_INVALID_STATE, "not in list mode");
    if (ShouldLoopCurrent()) {
        nextIdx = FindMediaSource(curSrcId_);
    } else if (FindMediaSource(curSrcId_) == itemList_.begin()) {
        MEDIA_LOGD("already the first item, not advance to prev");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        (void)SelectNextIndex(false, nextIdx);
    }
    auto ret = SwitchToIndex(nextIdx);
    return ret;
}

int32_t PlayerImpl::AdvanceToMediaSource(const std::string &srcId)
{
    std::lock_guard<std::mutex> lock(listMutex_);
    CHECK_AND_RETURN_RET_LOG(IsInListMode(), MSERR_INVALID_STATE, "not in list mode");
    auto it = FindMediaSource(srcId);
    CHECK_AND_RETURN_RET_LOG(it != itemList_.end(), MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE, "invalid srcId");
    auto ret = SwitchToIndex(FindMediaSource(srcId));
    return ret;
}

int32_t PlayerImpl::SelectNextIndex(bool isNext, MediaSourceIterator &nextIndex)
{
    if (!IsInListMode()) {
        return MSERR_INVALID_STATE;
    }
    int32_t count = static_cast<int32_t>(itemList_.size());
    if (count <= 0) {
        return MSERR_INVALID_STATE;
    }
    MediaSourceIterator currentIt = FindMediaSource(curSrcId_);
    if (currentIt == itemList_.end()) {
        nextIndex = itemList_.begin();
        return MSERR_OK;
    }
    if (ShouldLoopCurrent()) {
        nextIndex = currentIt;
        return MSERR_OK;
    }
    if (ShouldShuffle()) {
        std::uniform_int_distribution<int32_t> dist(0, count - 1);
        int32_t idx = dist(g_shuffleRng);
        if (count > 1) {
            int32_t currentIdx = std::distance(itemList_.begin(), currentIt);
            while (idx == currentIdx) {
                idx = dist(g_shuffleRng);
            }
        }
        nextIndex = itemList_.begin() + idx;
        return MSERR_OK;
    }
    nextIndex = currentIt;
    if (isNext) {
        std::advance(nextIndex, 1);
        if (nextIndex == itemList_.end()) {
            nextIndex = itemList_.begin();
        }
    } else {
        std::advance(nextIndex, -1);
    }
    return MSERR_OK;
}

int32_t PlayerImpl::SwitchSetMediaSource(MediaSourceIterator nextIndex)
{
    if (nextIndex == itemList_.end() || itemList_.empty()) {
        return MSERR_INVALID_VAL;
    }

    std::shared_ptr<AVMediaSource> nextSource = nextIndex->second;
    std::string prevSrcId = curSrcId_;
    curSrcId_ = nextIndex->first;

    CHECK_AND_RETURN_RET_LOG(nextSource != nullptr, MSERR_INVALID_VAL, "nextSource is nullptr");

    AVPlayStrategy strategy;
    ON_SCOPE_EXIT(0) {
        curSrcId_ = prevSrcId;
    };

    int32_t ret = Reset();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] Reset failed", __func__);

    ret = SetMediaSource(nextSource, strategy);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] SetMediaSource failed", __func__);

    CANCEL_SCOPE_EXIT_GUARD(0);
    return MSERR_OK;
}

int32_t PlayerImpl::SwitchToIndex(MediaSourceIterator nextIndex)
{
    if (nextIndex == itemList_.end() || itemList_.empty()) {
        return MSERR_INVALID_VAL;
    }

    std::shared_ptr<AVMediaSource> nextSource = nextIndex->second;
    CHECK_AND_RETURN_RET_LOG(nextSource != nullptr, MSERR_INVALID_VAL, "nextSource is nullptr");

    MediaSourceIterator prevIndex = FindMediaSource(curSrcId_);
    bool prevIsFirstSelect = isFirstSelect_;

    curSrcId_ = nextIndex->first;
    isSwitchingItem_ = true;
    isFirstSelect_ = (listState_ == PLAYER_INITIALIZED) ? true : false;

    AVPlayStrategy strategy;
    ON_SCOPE_EXIT(0) {
        if (prevIndex != itemList_.end()) {
            curSrcId_ = prevIndex->first;
        } else {
            curSrcId_.clear();
        }
        isSwitchingItem_ = false;
        isFirstSelect_ = prevIsFirstSelect;
    };

    int32_t ret = Reset();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] Reset failed", __func__);

    ret = SetMediaSource(nextSource, strategy);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] SetMediaSource failed", __func__);

    ret = PrepareAsync();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] PrepareAsync failed", __func__);

    ret = Play();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "[%{public}s] Play failed", __func__);

    CANCEL_SCOPE_EXIT_GUARD(0);
    return MSERR_OK;
}

void PlayerImpl::NotifyPlaybackContentChange(const std::string &changeId)
{
    std::shared_ptr<PlayerCallback> callback;
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        callback = callback_;
    }
    CHECK_AND_RETURN_LOG(callback != nullptr, "callback is nullptr.");

    Format format;
    (void)format.PutStringValue(PlayerKeys::PLAYER_LIST_MEDIA_SOURCE_CHANGE_ID, changeId);
    callback->OnInfo(INFO_TYPE_PLAYBACK_CONTENT_CHANGE, 0, format);
}

void PlayerImpl::ResetListParameters()
{
    std::lock_guard<std::mutex> lock(listMutex_);
    itemList_.clear();
    curSrcId_ = "";
    listState_ = PLAYER_IDLE;
    isFirstSelect_ = false;
    isSwitchingItem_ = false;
    listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
}

int32_t PlayerImpl::GetCurrentTime(int32_t &currentTime)
{
    ScopedTimer timer("GetCurrentTime", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetCurrentTime in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetCurrentTime(currentTime), "GetCurrentTime", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetPlaybackPosition(int32_t &playbackPosition)
{
    ScopedTimer timer("GetPlaybackPosition", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackPosition in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(
        ret = playerService_->GetPlaybackPosition(playbackPosition), "GetPlaybackPosition", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetCurrentPresentationTimestamp(int64_t &currentPresentation)
{
    ScopedTimer timer("GetCurrentPresentationTimestamp", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetCurrentPresentationTimestamp in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetCurrentPresentationTimestamp(currentPresentation),
        "GetCurrentPresentationTimestamp", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    ScopedTimer timer("GetVideoTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetVideoTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetVideoTrackInfo(videoTrack), "GetVideoTrackInfo", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetPlaybackInfo(Format &playbackInfo)
{
    ScopedTimer timer("GetPlaybackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetPlaybackInfo(playbackInfo), "GetPlaybackInfo", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics)
{
    ScopedTimer timer("GetPlaybackStatisticMetrics", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackStatisticMetrics in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetPlaybackStatisticMetrics(playbackStatisticMetrics),
        "GetPlaybackStatisticMetrics", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    ScopedTimer timer("GetAudioTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetAudioTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetAudioTrackInfo(audioTrack), "GetAudioTrackInfo", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
{
    ScopedTimer timer("GetSubtitleTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetSubtitleTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(
        ret = playerService_->GetSubtitleTrackInfo(subtitleTrack), "GetSubtitleTrackInfo", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetVideoWidth()
{
    ScopedTimer timer("GetVideoWidth", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetVideoWidth in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetVideoWidth(), "GetVideoWidth", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetVideoHeight()
{
    ScopedTimer timer("GetVideoHeight", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetVideoHeight in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetVideoHeight(), "GetVideoHeight", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetPlaybackSpeed(PlaybackRateMode mode)
{
    ScopedTimer timer("SetPlaybackSpeed", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlaybackSpeed in, mode is %{public}d", FAKE_POINTER(this), mode);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetPlaybackSpeed(mode), "SetPlaybackSpeed", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetPlaybackRate(float rate)
{
    ScopedTimer timer("SetPlaybackRate", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlaybackRate in, mode is %{public}f", FAKE_POINTER(this), rate);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    const double minRate = 0.125f;
    const double maxRate = 4.0f;
    const double eps = 1e-15;
    if ((rate < minRate - eps) || (rate > maxRate + eps)) {
        return MSERR_INVALID_VAL;
    }
    LISTENER(return playerService_->SetPlaybackRate(rate), "SetPlaybackRate", false, TIME_OUT_SECOND);
}


int32_t PlayerImpl::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    ScopedTimer timer("SetMediaSource", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetMediaSource in(dataSrc)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr!");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetMediaSource(mediaSource, strategy), "SetMediaSource", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    ScopedTimer timer("GetPlaybackSpeed", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackSpeed in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetPlaybackSpeed(mode), "GetPlaybackSpeed", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetPlaybackRate(float &rate)
{
    ScopedTimer timer("GetPlaybackRate", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackRate in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetPlaybackRate(rate), "GetPlaybackRate", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SelectBitRate(uint32_t bitRate)
{
    ScopedTimer timer("SelectBitRate", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SelectBitRate(%{public}d) in", FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SelectBitRate(bitRate), "SelectBitRate", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetDuration(int32_t &duration)
{
    ScopedTimer timer("GetDuration", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetDuration in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetDuration(duration), "GetDuration", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetSeekableRanges(std::vector<Plugins::SeekRange> &seekableRanges)
{
    ScopedTimer timer("GetSeekableRanges", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetSeekableRanges in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetSeekableRanges(seekableRanges), "GetSeekableRanges", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetLoadedRanges(std::vector<Plugins::SeekRange> &loadedRanges)
{
    ScopedTimer timer("GetLoadedRanges", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetLoadedRanges in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetLoadedRanges(loadedRanges), "GetLoadedRanges", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetApiVersion(int32_t &apiVersion)
{
    ScopedTimer timer("GetApiVersion", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetApiVersion in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetApiVersion(apiVersion), "GetApiVersion", false, TIME_OUT_SECOND);
    return ret;
}

#ifdef SUPPORT_VIDEO
int32_t PlayerImpl::SetVideoSurface(sptr<Surface> surface)
{
    ScopedTimer timer("SetVideoSurface", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetVideoSurface in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_VAL, "surface is nullptr");
    surface_ = surface;
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetVideoSurface(surface), "SetVideoSurface", false, TIME_OUT_SECOND);
    return ret;
}
#endif

bool PlayerImpl::IsPlaying()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " IsPlaying in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, false, "player service does not exist..");

    return playerService_->IsPlaying();
}

bool PlayerImpl::IsLooping()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " IsLooping in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, false, "player service does not exist..");
    {
        std::lock_guard<std::mutex> lock(listMutex_);
        if (IsInListMode()) {
            // In list loop mode, whether to loop is determined by the user settings; in non-list loop mode, whether to
            // loop is determined by the server settings
            return userLoop_;
        }
    }
    return playerService_->IsLooping();
}

int32_t PlayerImpl::SetLooping(bool loop)
{
    ScopedTimer timer("SetLooping", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetLooping in, loop %{public}d", FAKE_POINTER(this), loop);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    bool serverLoop = loop;
    {
        std::lock_guard<std::mutex> lock(listMutex_);
        userLoop_ = loop;
        if (IsInListMode() && listLoopMode_ != PLAYLIST_LOOP_MODE_ONE) {
            serverLoop = false;
        }
    }

    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetLooping(serverLoop), "SetLooping", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback)
{
    ScopedTimer timer("SetPlayerCallback", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlayerCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        callback_ = callback;
    }

    std::shared_ptr<PlayerCallback> playerCb = std::make_shared<PlayerImplCallback>(callback, shared_from_this());
    LISTENER(return playerService_->SetPlayerCallback(playerCb), "SetPlayerCallback", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetParameter(const Format &param)
{
    ScopedTimer timer("SetParameter", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetParameter in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetParameter(param), "SetParameter", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SelectTrack(int32_t index, PlayerSwitchMode mode)
{
    ScopedTimer timer("SelectTrack", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SelectTrack in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    if (index == prevTrackIndex_) {
        MEDIA_LOGI("Select the same track, index: %{public}d", index);
        return 0;
    }
    prevTrackIndex_ = index;
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SelectTrack(index, mode), "SelectTrack", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::DeselectTrack(int32_t index)
{
    ScopedTimer timer("DeselectTrack", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " DeselectTrack in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->DeselectTrack(index), "DeselectTrack", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    ScopedTimer timer("GetCurrentTrack", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetCurrentTrack in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetCurrentTrack(trackType, index), "GetCurrentTrack", false, TIME_OUT_SECOND);
    return ret;
}


int32_t PlayerImpl::SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp)
{
    MEDIA_LOGI("PlayerImpl DRM SetDecryptConfig");
#ifdef SUPPORT_AVPLAYER_DRM
    ScopedTimer timer("SetDecryptConfig", OVERTIME_WARNING_MS);
    CHECK_AND_RETURN_RET_LOG(keySessionProxy != nullptr, MSERR_INVALID_VAL, "keysessionproxy is nullptr");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    MEDIA_LOGD("And it's count is: %{public}d in PlayerImpl", keySessionProxy->GetSptrRefCount());
    LISTENER(return playerService_->SetDecryptConfig(keySessionProxy, svp), "SetDecryptConfig", false, TIME_OUT_SECOND);
#else
    (void)keySessionProxy;
    (void)svp;
    return 0;
#endif
}

int32_t PlayerImpl::SetDeviceChangeCbStatus(bool status)
{
    ScopedTimer timer("SetDeviceChangeCbStatus", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetDeviceChangeCbStatus in, status is %{public}d",
        FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetDeviceChangeCbStatus(status), "SetDeviceChangeCbStatus", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
{
    ScopedTimer timer("SetPlaybackStrategy", OVERTIME_WARNING_MS);
    MEDIA_LOGD("Set playback strategy");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(
        ret = playerService_->SetPlaybackStrategy(playbackStrategy), "SetPlaybackStrategy", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetTrackSelectionFilter(AVPlayTrackSelectionFilter trackFilter)
{
    ScopedTimer timer("SetTrackSelectionFilter", OVERTIME_WARNING_MS);
    MEDIA_LOGD("SetTrackSelectionFilter");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(
        ret = playerService_->SetTrackSelectionFilter(trackFilter), "SetTrackSelectionFilter", false, TIME_OUT_SECOND);
    CHECK_AND_RETURN_RET_NOLOG(ret != MSERR_OK, ret);
    return ret;
}

int32_t PlayerImpl::GetTrackSelectionFilter(AVPlayTrackSelectionFilter &trackFilter)
{
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " GetTrackSelectionFilter", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerService_->GetTrackSelectionFilter(trackFilter);
}

int32_t PlayerImpl::SetSuperResolution(bool enabled)
{
    ScopedTimer timer("SetSuperResolution", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSuperResolution in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetSuperResolution(enabled), "SetSuperResolution", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetVideoWindowSize(int32_t width, int32_t height)
{
    ScopedTimer timer("SetVideoWindowSize", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR "SetVideoWindowSize  in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetVideoWindowSize(width, height), "SetVideoWindowSize", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::SetMaxAmplitudeCbStatus(bool status)
{
    ScopedTimer timer("SetMaxAmplitudeCbStatus", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetMaxAmplitudeCbStatus in, status is %{public}d",
        FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetMaxAmplitudeCbStatus(status), "SetMaxAmplitudeCbStatus", false, TIME_OUT_SECOND);
    return ret;
}

bool PlayerImpl::IsSeekContinuousSupported()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " IsSeekContinuousSupported in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, false, "player service does not exist.");
    return playerService_->IsSeekContinuousSupported();
}

int32_t PlayerImpl::SetReopenFd(int32_t fd)
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR "SetReopenFd  in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    MEDIA_LOGD("set reopen fd: %{public}d", fd);
    LISTENER(return playerService_->SetReopenFd(fd), "SetReopenFd", false, TIME_OUT_SECOND);
}
 
int32_t PlayerImpl::EnableCameraPostprocessing()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " EnableCameraPostprocessing  in", FAKE_POINTER(this));
    ScopedTimer timer("EnableCameraPostprocessing", OVERTIME_WARNING_MS);
    CHECK_AND_RETURN_RET_LOG(fdsanFd_ != nullptr, MSERR_OK, "source fd does not exist.");
    int fd = fdsanFd_->Get();
    MEDIA_LOGD("PlayerImpl EnableCameraPostprocessing reopen fd: %{public}d ", fd);
    FdsanFd reopenFd = FdUtils::ReOpenFd(fd);
    CHECK_AND_RETURN_RET_LOG(reopenFd.Get() >= 0, MSERR_UNKNOWN, "EnableCameraPostprocessing: reopen failed");
    auto ret = SetReopenFd(reopenFd.Get());
    reopenFd.Reset();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_OK, "SetReopenFd failed.");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->EnableCameraPostprocessing(), "EnableCameraPostprocessing", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetCameraPostprocessing(bool isOpen)
{
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR "SetCameraPostprocessing  in", FAKE_POINTER(this));
    ScopedTimer timer("SetCameraPostprocessing", OVERTIME_WARNING_MS);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetCameraPostprocessing(isOpen), "SetCameraPostprocessing", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
{
    ScopedTimer timer("SetSeiMessageCbStatus", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSeiMessageCbStatus in, status is %{public}d",
        FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->SetSeiMessageCbStatus(status, payloadTypes),
        "SetSeiMessageCbStatus", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::EnableReportMediaProgress(bool enable)
{
    ScopedTimer timer("EnableReportMediaProgress", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " EnableReportMediaProgress in, enable is %{public}d",
        FAKE_POINTER(this), enable);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->EnableReportMediaProgress(enable),
        "EnableReportMediaProgress", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::EnableReportAudioInterrupt(bool enable)
{
    ScopedTimer timer("EnableReportAudioInterrupt", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " EnableReportAudioInterrupt in, enable is %{public}d",
        FAKE_POINTER(this), enable);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->EnableReportAudioInterrupt(enable),
        "EnableReportAudioInterrupt", false, TIME_OUT_SECOND);
    return ret;
}

bool PlayerImpl::ReleaseClientListener()
{
    ScopedTimer timer("ReleaseClientListener", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " ReleaseClientListener in", FAKE_POINTER(this));
    return MediaServiceFactory::GetInstance().ReleaseClientListener(); // not related to playerService_ thus no XCollie
}

int32_t PlayerImpl::SetStartFrameRateOptEnabled(bool enabled)
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetStartFrameRateOptEnabled in, enabled is %{public}d",
        FAKE_POINTER(this), enabled);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerService_->SetStartFrameRateOptEnabled(enabled);
}

int32_t PlayerImpl::ForceLoadVideo(bool status)
{
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " ForceLoadVideo %{public}d", FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerService_->ForceLoadVideo(status);
}

int32_t PlayerImpl::SetLoudnessGain(float loudnessGain)
{
    ScopedTimer timer("SetLoudnessGain", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetLoudnessGain(%{public}f) in", FAKE_POINTER(this), loudnessGain);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetLoudnessGain(loudnessGain), "SetLoudnessGain", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetMediaDescription(Format &format)
{
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " GetMediaDescription", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerService_->GetMediaDescription(format);
}

int32_t PlayerImpl::GetTrackDescription(Format &format, uint32_t trackIndex)
{
    MEDIA_LOGI("PlayerImpl:0x%{public}06" PRIXPTR " GetTrackDescription", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerService_->GetTrackDescription(format, trackIndex);
}

PlayerImplCallback::PlayerImplCallback(const std::shared_ptr<PlayerCallback> playerCb,
    std::shared_ptr<PlayerImpl> player)
{
    playerCb_ = playerCb;
    player_ = player;
}

void PlayerImplCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    auto player = player_.lock();
    CHECK_AND_RETURN_LOG(player != nullptr, "player does not exist..");
    player->OnInfo(type, extra, infoBody);
}

void PlayerImplCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    std::shared_ptr<PlayerCallback> playerCb;
    {
        std::unique_lock<std::mutex> lock(playerImplCbMutex_);
        playerCb = playerCb_;
    }

    auto player = player_.lock();
    if (player != nullptr && getApiVersionFlag_) {
        player->GetApiVersion(apiVersion_);
        getApiVersionFlag_ = false;
    }
    MEDIA_LOGI("PlayerImplCallback apiVersion %{public}d", apiVersion_);
    if (apiVersion_ < API_VERSION_14) {
        if (IsAPI14IOError(static_cast<MediaServiceErrCode>(errorCode))) {
            errorCode = MSERR_DATA_SOURCE_IO_ERROR;
        }
    }
    CHECK_AND_RETURN_LOG(playerCb != nullptr, "playerCb does not exist..");
    playerCb->OnError(errorCode, errorMsg);
}

int32_t PlayerImpl::GetGlobalInfo(std::shared_ptr<Meta> &globalInfo)
{
    ScopedTimer timer("GetGlobalInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetGlobalInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->GetGlobalInfo(globalInfo), "GetGlobalInfo", false, TIME_OUT_SECOND);
    return ret;
}

int32_t PlayerImpl::RegisterDeviceCapability(IsAudioPassthrough callback, GetDolbyList getDolbyList)
{
    ScopedTimer timer("RegisterDeviceCapability", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " RegisterPeripheralSupportedTypeCallback", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    int32_t ret = MSERR_OK;
    LISTENER(ret = playerService_->RegisterDeviceCapability(callback, getDolbyList),
        "RegisterDeviceCapability", false, TIME_OUT_SECOND);
    return ret;
}

bool PlayerImpl::IsLiveSeek()
{
    ScopedTimer timer("IsLiveSeek", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " IsLiveSeek in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, false, "player service does not exist..");
    LISTENER(return playerService_->IsLiveSeek(), "IsLiveSeek", false, TIME_OUT_SECOND);
}
} // namespace Media
} // namespace OHOS
