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
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"
#include "scoped_timer.h"
#include "player_xcollie.h"
#ifdef SUPPORT_AVPLAYER_DRM
#include "imedia_key_session_service.h"
#endif

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerImpl"};
constexpr int32_t API_VERSION_14 = 14;
static int32_t apiVersion_ = -1;
constexpr int64_t OVERTIME_WARNING_MS = 10;
constexpr int64_t CREATE_AVPLAYER_WARNING_MS = 30;
constexpr int64_t RESET_WARNING_MS = 30;
constexpr int64_t RELEASE_WARNING_MS = 200;
const int32_t TIME_OUT_SECOND = 6;
}

namespace OHOS {
namespace Media {

std::shared_ptr<Player> PlayerFactory::CreatePlayer()
{
    ScopedTimer timer("CreatePlayer", CREATE_AVPLAYER_WARNING_MS);
    MEDIA_LOGD("PlayerImpl: CreatePlayer in");
    std::shared_ptr<PlayerImpl> impl = std::make_shared<PlayerImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new PlayerImpl");

    int32_t ret = MSERR_OK;
    LISTENER(ret = impl->Init(), "CreatePlayer", false, TIME_OUT_SECOND);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init PlayerImpl");

    return impl;
}

int32_t PlayerImpl::Init()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Init in", FAKE_POINTER(this));
    HiviewDFX::HiTraceChain::SetId(traceId_);
    playerService_ = MediaServiceFactory::GetInstance().CreatePlayerService();
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_UNKNOWN, "failed to create player service");
    return MSERR_OK;
}

PlayerImpl::PlayerImpl()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    ResetSeekVariables();
    traceId_ = HiviewDFX::HiTraceChain::Begin("PlayerImpl", HITRACE_FLAG_DEFAULT);
}

PlayerImpl::~PlayerImpl()
{
    if (playerService_ != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyPlayerService(playerService_);
        playerService_ = nullptr;
    }
    ResetSeekVariables();
    HiviewDFX::HiTraceChain::End(traceId_);
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
    LISTENER(return playerService_->SetMediaMuted(mediaType, isMuted), "SetMediaMuted", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    ScopedTimer timer("SetSource dataSrc", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSource in(dataSrc)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(dataSrc != nullptr, MSERR_INVALID_VAL, "failed to create data source");
    LISTENER(return playerService_->SetSource(dataSrc), "SetSource dataSrc", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetSource(const std::string &url)
{
    ScopedTimer timer("SetSource url", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{private}06" PRIXPTR " SetSource in(url): %{private}s", FAKE_POINTER(this), url.c_str());
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!url.empty(), MSERR_INVALID_VAL, "url is empty..");
    LISTENER(return playerService_->SetSource(url), "SetSource url", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetSource(int32_t fd, int64_t offset, int64_t size)
{
    ScopedTimer timer("SetSource fd", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSource in(fd)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetSource(fd, offset, size), "SetSource fd", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::AddSubSource(const std::string &url)
{
    ScopedTimer timer("AddSubSource url", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{private}06" PRIXPTR " AddSubSource in(url): %{private}s",
        FAKE_POINTER(this), url.c_str());
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!url.empty(), MSERR_INVALID_VAL, "url is empty..");
    LISTENER(return playerService_->AddSubSource(url), "AddSubSource url", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::AddSubSource(int32_t fd, int64_t offset, int64_t size)
{
    ScopedTimer timer("AddSubSource fd", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " AddSubSource in(fd)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->AddSubSource(fd, offset, size), "AddSubSource fd", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::Play()
{
    ScopedTimer timer("Play", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Play in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->Play(), "Play", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetPlayRange(int64_t start, int64_t end)
{
    ScopedTimer timer("SetPlayRange", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlayRange in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetPlayRange(start, end), "SetPlayRange", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    ScopedTimer timer("SetPlayRangeWithMode", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetPlayRangeWithMode in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(
        return playerService_->SetPlayRangeWithMode(start, end, mode), "SetPlayRangeWithMode", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::Prepare()
{
    ScopedTimer timer("Prepare", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Prepare in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->Prepare(), "Prepare", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetRenderFirstFrame(bool display)
{
    ScopedTimer timer("SetRenderFirstFrame", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetRenderFirstFrame in, display %{public}d",
         FAKE_POINTER(this), display);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetRenderFirstFrame(display), "SetRenderFirstFrame", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::PrepareAsync()
{
    ScopedTimer timer("PrepareAsync", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " PrepareAsync in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->PrepareAsync(), "PrepareAsync", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::Pause()
{
    ScopedTimer timer("Pause", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Pause in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->Pause(), "Pause", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::Stop()
{
    ScopedTimer timer("Stop", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Stop in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    ResetSeekVariables();
    LISTENER(return playerService_->Stop(), "Stop", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::Reset()
{
    ScopedTimer timer("Reset", RESET_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " Reset in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    ResetSeekVariables();
    LISTENER(return playerService_->Reset(), "Reset", false, TIME_OUT_SECOND);
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
    LISTENER(return playerService_->SetVolumeMode(mode), "SetVolumeMode", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetVolume(float leftVolume, float rightVolume)
{
    ScopedTimer timer("SetVolume", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetVolume(%{public}f, %{public}f) in",
        FAKE_POINTER(this), leftVolume, rightVolume);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetVolume(leftVolume, rightVolume), "SetVolume", false, TIME_OUT_SECOND);
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
        return playerService_->Seek(mSeconds, mode);
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

void PlayerImpl::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    HandleSeekDoneInfo(type, extra);
    std::shared_ptr<PlayerCallback> callback;
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        callback = callback_;
    }

    CHECK_AND_RETURN_LOG(callback != nullptr, "callback is nullptr.");
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

int32_t PlayerImpl::GetCurrentTime(int32_t &currentTime)
{
    ScopedTimer timer("GetCurrentTime", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetCurrentTime in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetCurrentTime(currentTime), "GetCurrentTime", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetPlaybackPosition(int32_t &playbackPosition)
{
    ScopedTimer timer("GetPlaybackPosition", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackPosition in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(
        return playerService_->GetPlaybackPosition(playbackPosition), "GetPlaybackPosition", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    ScopedTimer timer("GetVideoTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetVideoTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetVideoTrackInfo(videoTrack), "GetVideoTrackInfo", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetPlaybackInfo(Format &playbackInfo)
{
    ScopedTimer timer("GetPlaybackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetPlaybackInfo(playbackInfo), "GetPlaybackInfo", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    ScopedTimer timer("GetAudioTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetAudioTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetAudioTrackInfo(audioTrack), "GetAudioTrackInfo", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
{
    ScopedTimer timer("GetSubtitleTrackInfo", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetSubtitleTrackInfo in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(
        return playerService_->GetSubtitleTrackInfo(subtitleTrack), "GetSubtitleTrackInfo", false, TIME_OUT_SECOND);
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
    LISTENER(return playerService_->SetPlaybackSpeed(mode), "SetPlaybackSpeed", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    ScopedTimer timer("SetMediaSource", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetMediaSource in(dataSrc)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr!");
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetMediaSource(mediaSource, strategy), "SetMediaSource", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    ScopedTimer timer("GetPlaybackSpeed", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetPlaybackSpeed in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetPlaybackSpeed(mode), "GetPlaybackSpeed", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SelectBitRate(uint32_t bitRate)
{
    ScopedTimer timer("SelectBitRate", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SelectBitRate(%{public}d) in", FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SelectBitRate(bitRate), "SelectBitRate", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetDuration(int32_t &duration)
{
    ScopedTimer timer("GetDuration", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetDuration in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetDuration(duration), "GetDuration", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetApiVersion(int32_t &apiVersion)
{
    ScopedTimer timer("GetApiVersion", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetApiVersion in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetApiVersion(apiVersion), "GetApiVersion", false, TIME_OUT_SECOND);
}

#ifdef SUPPORT_VIDEO
int32_t PlayerImpl::SetVideoSurface(sptr<Surface> surface)
{
    ScopedTimer timer("SetVideoSurface", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetVideoSurface in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_VAL, "surface is nullptr");
    surface_ = surface;
    LISTENER(return playerService_->SetVideoSurface(surface), "SetVideoSurface", false, TIME_OUT_SECOND);
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

    return playerService_->IsLooping();
}

int32_t PlayerImpl::SetLooping(bool loop)
{
    ScopedTimer timer("SetLooping", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetLooping in, loop %{public}d", FAKE_POINTER(this), loop);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->SetLooping(loop), "SetLooping", false, TIME_OUT_SECOND);
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
    LISTENER(return playerService_->SetParameter(param), "SetParameter", false, TIME_OUT_SECOND);
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
    LISTENER(return playerService_->SelectTrack(index, mode), "SelectTrack", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::DeselectTrack(int32_t index)
{
    ScopedTimer timer("DeselectTrack", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " DeselectTrack in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->DeselectTrack(index), "DeselectTrack", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    ScopedTimer timer("GetCurrentTrack", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " GetCurrentTrack in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    LISTENER(return playerService_->GetCurrentTrack(trackType, index), "GetCurrentTrack", false, TIME_OUT_SECOND);
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
    LISTENER(
        return playerService_->SetPlaybackStrategy(playbackStrategy), "SetPlaybackStrategy", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetSuperResolution(bool enabled)
{
    ScopedTimer timer("SetSuperResolution", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSuperResolution in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetSuperResolution(enabled), "SetSuperResolution", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetVideoWindowSize(int32_t width, int32_t height)
{
    ScopedTimer timer("SetVideoWindowSize", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR "SetVideoWindowSize  in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetVideoWindowSize(width, height), "SetVideoWindowSize", false, TIME_OUT_SECOND);
}

int32_t PlayerImpl::SetMaxAmplitudeCbStatus(bool status)
{
    ScopedTimer timer("SetMaxAmplitudeCbStatus", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetMaxAmplitudeCbStatus in, status is %{public}d",
        FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetMaxAmplitudeCbStatus(status), "SetMaxAmplitudeCbStatus", false, TIME_OUT_SECOND);
}

bool PlayerImpl::IsSeekContinuousSupported()
{
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " IsSeekContinuousSupported in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, false, "player service does not exist.");
    return playerService_->IsSeekContinuousSupported();
}

int32_t PlayerImpl::SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
{
    ScopedTimer timer("SetSeiMessageCbStatus", OVERTIME_WARNING_MS);
    MEDIA_LOGD("PlayerImpl:0x%{public}06" PRIXPTR " SetSeiMessageCbStatus in, status is %{public}d",
        FAKE_POINTER(this), status);
    CHECK_AND_RETURN_RET_LOG(playerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    LISTENER(return playerService_->SetSeiMessageCbStatus(status, payloadTypes),
        "SetSeiMessageCbStatus", false, TIME_OUT_SECOND);
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

} // namespace Media
} // namespace OHOS
