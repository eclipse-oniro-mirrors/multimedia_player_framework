/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "player_server_mock.h"
#include <fcntl.h>
#include <sys/stat.h>
#include "media_errors.h"
#include "transaction/rs_transaction.h"
#include "ui/rs_surface_node.h"
#include "window_option.h"

using namespace OHOS::Media::PlayerTestParam;

namespace OHOS {
namespace Media {
void PlayerCallbackTest::SetState(PlayerStates state)
{
    state_ = state;
}

void PlayerCallbackTest::SetSeekDoneFlag(bool seekDoneFlag)
{
    seekDoneFlag_ = seekDoneFlag;
}

void PlayerCallbackTest::SetSpeedDoneFlag(bool speedDoneFlag)
{
    speedDoneFlag_ = speedDoneFlag;
}

void PlayerCallbackTest::SetRateDoneFlag(bool rateDoneFlag)
{
    rateDoneFlag_ = rateDoneFlag;
}

void PlayerCallbackTest::SetSeekPosition(int32_t seekPosition)
{
    seekPosition_ = seekPosition;
}

void PlayerCallbackTest::SetTrackDoneFlag(bool trackDoneFlag)
{
    std::unique_lock<std::mutex> lockSpeed(mutexCond_);
    trackDoneFlag_ = trackDoneFlag;
    trackChange_ = trackDoneFlag;
}

int32_t PlayerCallbackTest::PrepareSync()
{
    if (state_ != PLAYER_PREPARED) {
        std::unique_lock<std::mutex> lockPrepare(mutexCond_);
        condVarPrepare_.wait_for(lockPrepare, std::chrono::seconds(waitsecond));
        if (state_ != PLAYER_PREPARED) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::PlaySync()
{
    if (state_ != PLAYER_STARTED) {
        std::unique_lock<std::mutex> lockPlay(mutexCond_);
        condVarPlay_.wait_for(lockPlay, std::chrono::seconds(waitsecond));
        if (state_ != PLAYER_STARTED && state_ != PLAYER_PLAYBACK_COMPLETE) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::PauseSync()
{
    if (state_ != PLAYER_PAUSED) {
        std::unique_lock<std::mutex> lockPause(mutexCond_);
        condVarPause_.wait_for(lockPause, std::chrono::seconds(waitsecond));
        if (state_ != PLAYER_PAUSED) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::StopSync()
{
    if (state_ != PLAYER_STOPPED) {
        std::unique_lock<std::mutex> lockStop(mutexCond_);
        condVarStop_.wait_for(lockStop, std::chrono::seconds(waitsecond));
        if (state_ != PLAYER_STOPPED) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::ResetSync()
{
    if (state_ != PLAYER_IDLE) {
        std::unique_lock<std::mutex> lockReset(mutexCond_);
        condVarReset_.wait_for(lockReset, std::chrono::seconds(waitsecond));
        if (state_ != PLAYER_IDLE) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::SeekSync()
{
    if (seekDoneFlag_ == false) {
        std::unique_lock<std::mutex> lockSeek(mutexCond_);
        condVarSeek_.wait_for(lockSeek, std::chrono::seconds(waitsecond));
        if (seekDoneFlag_ == false) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::SpeedSync()
{
    if (speedDoneFlag_ == false) {
        std::unique_lock<std::mutex> lockSpeed(mutexCond_);
        condVarSpeed_.wait_for(lockSpeed, std::chrono::seconds(waitsecond));
        if (speedDoneFlag_ == false) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::RateSync()
{
    if (rateDoneFlag_ == false) {
        std::unique_lock<std::mutex> lockRate(mutexCond_);
        condVarRate_.wait_for(lockRate, std::chrono::seconds(waitsecond));
        if (rateDoneFlag_== false) {
            return -1;
        }
    }
    return MSERR_OK;
}

int32_t PlayerCallbackTest::TrackSync(bool &trackChange)
{
    if (trackDoneFlag_ == false) {
        std::unique_lock<std::mutex> lockTrackDone(mutexCond_);
        condVarTrackDone_.wait_for(lockTrackDone, std::chrono::seconds(waitsecond));
        if (trackDoneFlag_ == false) {
            return -1;
        }
    }

    trackChange = trackChange_;

    return MSERR_OK;
}

int32_t PlayerCallbackTest::TrackInfoUpdateSync()
{
    if (trackInfoUpdate_ == false) {
        std::unique_lock<std::mutex> lock(mutexCond_);
        condVarTrackInfoUpdate_.wait_for(lock, std::chrono::seconds(waitsecond), [this]() {
            return trackInfoUpdate_;
        });
        if (trackInfoUpdate_ == false) {
            return -1;
        }
    }
    trackInfoUpdate_ = false;
    return MSERR_OK;
}

void PlayerCallbackTest::HandleTrackChangeCallback(int32_t extra, const Format &infoBody)
{
    (void)extra;
    trackChange_ = true;
    trackDoneFlag_ = true;
    int32_t index;
    int32_t isSelect;
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), index);
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_IS_SELECT), isSelect);
    std::cout << "INFO_TYPE_TRACKCHANGE: index " << index << " isSelect " << isSelect << std::endl;
    condVarTrackDone_.notify_all();
}

void PlayerCallbackTest::HandleSubtitleCallback(int32_t extra, const Format &infoBody)
{
    (void)extra;
    infoBody.GetStringValue(std::string(PlayerKeys::SUBTITLE_TEXT), text_);
    std::cout << "text = " << text_ << std::endl;
    textUpdate_ = true;
    condVarText_.notify_all();
}

void PlayerCallbackTest::HandleTrackInfoCallback(int32_t extra, const Format &infoBody)
{
    (void)extra;
    std::cout << "track info update" << std::endl;
    trackInfoUpdate_ = true;
    condVarTrackInfoUpdate_.notify_all();
}

void PlayerCallbackTest::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    switch (type) {
        case INFO_TYPE_SEEKDONE:
            SetSeekDoneFlag(true);
            SeekNotify(extra, infoBody);
            break;
        case INFO_TYPE_STATE_CHANGE:
            state_ = static_cast<PlayerStates>(extra);
            SetState(state_);
            Notify(state_);
            break;
        case INFO_TYPE_RATEDONE:
            SetRateDoneFlag(true);
            condVarRate_.notify_all();
            break;
        case INFO_TYPE_SPEEDDONE:
            SetSpeedDoneFlag(true);
            condVarSpeed_.notify_all();
            break;
        case INFO_TYPE_POSITION_UPDATE:
            std::cout << "cur position is " << static_cast<uint64_t>(extra) << std::endl;
            break;
        case INFO_TYPE_BITRATE_COLLECT:
            std::cout << "INFO_TYPE_BITRATE_COLLECT: " << extra << std::endl;
            break;
        case INFO_TYPE_INTERRUPT_EVENT:
            std::cout << "INFO_TYPE_INTERRUPT_EVENT: " << extra << std::endl;
            break;
        case INFO_TYPE_RESOLUTION_CHANGE:
            std::cout << "INFO_TYPE_RESOLUTION_CHANGE: " << extra << std::endl;
            break;
        case INFO_TYPE_TRACKCHANGE:
            HandleTrackChangeCallback(extra, infoBody);
            break;
        case INFO_TYPE_ERROR_MSG: {
            errInfo_ = true;
            break;
        }
        default:
            break;
    }
}

std::string PlayerCallbackTest::SubtitleTextUpdate(std::string text)
{
    std::unique_lock<std::mutex> lock(subtitleMutex_);
    std::cout << "wait for text update" <<std::endl;
    condVarText_.wait_for(lock, std::chrono::seconds(waitsecond), [&, this]() {
        if (text_ != text) {
            return textUpdate_ = false;
        }
        return textUpdate_;
    });
    std::cout << "text updated" <<std::endl;
    textUpdate_ = false;
    return text_;
}

PlayerStates PlayerCallbackTest::GetState()
{
    return state_;
}

void PlayerCallbackTest::OnError(int32_t errorCode, const std::string &errorMsg)
{
    if (!trackDoneFlag_) {
        trackDoneFlag_ = true;
        condVarTrackDone_.notify_all();
    }
    std::cout << "Error received, errorCode: " << errorCode << " errorMsg: " << errorMsg << std::endl;
}

void PlayerCallbackTest::Notify(PlayerStates currentState)
{
    if (currentState == PLAYER_PREPARED) {
        condVarPrepare_.notify_all();
    } else if (currentState == PLAYER_STARTED) {
        condVarPlay_.notify_all();
    } else if (currentState == PLAYER_PAUSED) {
        condVarPause_.notify_all();
    } else if (currentState == PLAYER_STOPPED) {
        condVarStop_.notify_all();
    } else if (currentState == PLAYER_IDLE) {
        condVarReset_.notify_all();
    }
}

void PlayerCallbackTest::SeekNotify(int32_t extra, const Format &infoBody)
{
    if (seekMode_ == PlayerSeekMode::SEEK_CLOSEST) {
        if (seekPosition_ == extra) {
            condVarSeek_.notify_all();
        }
    } else if (seekMode_ == PlayerSeekMode::SEEK_PREVIOUS_SYNC) {
        if (seekPosition_ - extra < DELTA_TIME && extra - seekPosition_ >= 0) {
            condVarSeek_.notify_all();
        }
    } else if (seekMode_ == PlayerSeekMode::SEEK_NEXT_SYNC) {
        if (extra - seekPosition_ < DELTA_TIME && seekPosition_ - extra >= 0) {
            condVarSeek_.notify_all();
        }
    } else if (abs(seekPosition_ - extra) <= DELTA_TIME) {
        condVarSeek_.notify_all();
    } else {
        SetSeekDoneFlag(false);
    }
}

sptr<Surface> PlayerServerMock::GetVideoSurface()
{
    sptr<Rosen::WindowOption> option = new Rosen::WindowOption();
    option->SetWindowRect({ 0, 0, width_, height_ });
    option->SetWindowType(Rosen::WindowType::WINDOW_TYPE_TOAST);
    option->SetWindowMode(Rosen::WindowMode::WINDOW_MODE_FLOATING);
    previewWindow_ = Rosen::Window::Create("xcomponent_window", option);
    if (previewWindow_ == nullptr || previewWindow_->GetSurfaceNode() == nullptr) {
        return nullptr;
    }

    previewWindow_->Show();
    auto surfaceNode = previewWindow_->GetSurfaceNode();
    surfaceNode->SetFrameGravity(Rosen::Gravity::RESIZE);
    Rosen::RSTransaction::FlushImplicitTransaction();
    return surfaceNode->GetSurface();
}

PlayerServerMock::PlayerServerMock(std::shared_ptr<PlayerCallbackTest> &callback)
{
    callback_ = callback;
}

PlayerServerMock::~PlayerServerMock()
{
    if (previewWindow_ != nullptr) {
        previewWindow_->Destroy();
        previewWindow_ = nullptr;
    }
    
    if (previewWindowNext_ != nullptr) {
        previewWindowNext_->Destroy();
        previewWindowNext_ = nullptr;
    }
}

bool PlayerServerMock::CreatePlayer()
{
    player_ = PlayerServer::Create();
    return player_ != nullptr;
}

int32_t PlayerServerMock::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetMediaSource(mediaSource, strategy);
}

int32_t PlayerServerMock::Freeze()
{
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->Freeze();
}

int32_t PlayerServerMock::UnFreeze()
{
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->UnFreeze();
}

int32_t PlayerServerMock::SetSource(const std::string url)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int32_t ret = player_->SetSource(url);
    return ret;
}

int32_t PlayerServerMock::SetSource(int32_t fd, int64_t offset, int64_t size)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetSource(fd, offset, size);
}

int32_t PlayerServerMock::SetSource(const std::string &path, int64_t offset, int64_t size)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::string rawFile = path.substr(strlen("file://"));
    int32_t fd = open(rawFile.c_str(), O_RDONLY);
    if (fd <= 0) {
        std::cout << "Open file failed" << std::endl;
        return -1;
    }

    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        std::cout << "Get file state failed" << std::endl;
        (void)close(fd);
        return -1;
    }
    int64_t length = static_cast<int64_t>(st.st_size);
    if (size > 0) {
        length = size;
    }
    int32_t ret = player_->SetSource(fd, offset, length);
    if (ret != 0) {
        (void)close(fd);
        return -1;
    }

    (void)close(fd);
    return ret;
}

int32_t PlayerServerMock::Prepare()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int32_t ret = player_->Prepare();
    if (ret == MSERR_OK) {
        return callback_->PrepareSync();
    }
    return ret;
}

int32_t PlayerServerMock::PrepareAsync()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        return callback_->PrepareSync();
    }
    return ret;
}

int32_t PlayerServerMock::Play()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int32_t ret = player_->Play();
    if (ret == MSERR_OK) {
        return callback_->PlaySync();
    }
    return ret;
}

int32_t PlayerServerMock::Pause()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int32_t ret = player_->Pause();
    if (ret == MSERR_OK) {
        return callback_->PauseSync();
    }
    return ret;
}

int32_t PlayerServerMock::Stop()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    int32_t ret = player_->Stop();
    if (ret == MSERR_OK) {
        return callback_->StopSync();
    }
    return ret;
}

void PlayerServerMock::SeekPrepare(int32_t &mseconds, PlayerSeekMode &mode)
{
    UNITTEST_CHECK_AND_RETURN_LOG(player_ != nullptr && callback_ != nullptr, "player or callback is nullptr");
    int32_t duration = 0;
    int32_t seekPosition = 0;
    callback_->SetSeekDoneFlag(false);
    player_->GetDuration(duration);
    if (mseconds < 0) {
        seekPosition = 0;
    } else if (mseconds > duration) {
        seekPosition = duration;
    } else {
        seekPosition = mseconds;
    }
    callback_->SetSeekPosition(seekPosition);
}

int32_t PlayerServerMock::Seek(int32_t mseconds, PlayerSeekMode mode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    SeekPrepare(mseconds, mode);
    int32_t ret = player_->Seek(mseconds, mode);
    if (ret == MSERR_OK) {
        return callback_->SeekSync();
    }
    return ret;
}

int32_t PlayerServerMock::Reset()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    int32_t ret = player_->Reset();
    if (ret == MSERR_OK) {
        return callback_->ResetSync();
    }
    return ret;
}

int32_t PlayerServerMock::Release()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    if (previewWindow_ != nullptr) {
        previewWindow_->Destroy();
        previewWindow_ = nullptr;
    }
    callback_ = nullptr;
    return player_->Release();
}

int32_t PlayerServerMock::ReleaseSync()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    if (previewWindow_ != nullptr) {
        previewWindow_->Destroy();
        previewWindow_ = nullptr;
    }
    callback_ = nullptr;
    return player_->ReleaseSync();
}

int32_t PlayerServerMock::SetVolume(float leftVolume, float rightVolume)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetVolume(leftVolume, rightVolume);
}

int32_t PlayerServerMock::SetLooping(bool loop)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetLooping(loop);
}

int32_t PlayerServerMock::GetCurrentTime(int32_t &currentTime)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->GetCurrentTime(currentTime);
}

int32_t PlayerServerMock::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetVideoTrackInfo(videoTrack);
}

int32_t PlayerServerMock::GetPlaybackInfo(Format &playbackInfo)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetPlaybackInfo(playbackInfo);
}

int32_t PlayerServerMock::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetAudioTrackInfo(audioTrack);
}

int32_t PlayerServerMock::GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetSubtitleTrackInfo(subtitleTrack);
}

int32_t PlayerServerMock::GetVideoWidth()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetVideoWidth();
}

int32_t PlayerServerMock::GetVideoHeight()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetVideoHeight();
}

int32_t PlayerServerMock::GetDuration(int32_t &duration)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetDuration(duration);
}

int32_t PlayerServerMock::SetPlaybackSpeed(PlaybackRateMode mode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    callback_->SetSpeedDoneFlag(false);
    int32_t ret = player_->SetPlaybackSpeed(mode);
    if (ret == MSERR_OK) {
        return callback_->SpeedSync();
    }
    return player_->SetPlaybackSpeed(mode);
}

int32_t PlayerServerMock::SetPlaybackRate(float rate)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    callback_->SetRateDoneFlag(false);
    int32_t ret = player_->SetPlaybackRate(rate);
    if (ret == MSERR_OK) {
        return callback_->RateSync();
    }
    return player_->SetPlaybackRate(rate);
}

int32_t PlayerServerMock::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetPlaybackSpeed(mode);
}

int32_t PlayerServerMock::SelectBitRate(uint32_t bitRate)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SelectBitRate(bitRate);
}

bool PlayerServerMock::IsPlaying()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->IsPlaying();
}

bool PlayerServerMock::IsLooping()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->IsLooping();
}

int32_t PlayerServerMock::SetParameter(const Format &param)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SetParameter(param);
}

int32_t PlayerServerMock::SetVolumeMode(int32_t mode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SetVolumeMode(mode);
}

int32_t PlayerServerMock::SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetPlayerCallback(callback);
}

int32_t PlayerServerMock::SetVideoSurface(sptr<Surface> surface)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetVideoSurface(surface);
}

int32_t PlayerServerMock::SelectTrack(int32_t index, bool &trackChange)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    callback_->SetTrackDoneFlag(false);
    int32_t ret = player_->SelectTrack(index, PlayerSwitchMode::SWITCH_SMOOTH);
    if (callback_->TrackSync(trackChange) != MSERR_OK) {
        return -1;
    }
    return ret;
}

int32_t PlayerServerMock::DeselectTrack(int32_t index, bool &trackChange)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    callback_->SetTrackDoneFlag(false);
    int32_t ret = player_->DeselectTrack(index);
    if (callback_->TrackSync(trackChange) != MSERR_OK) {
        return -1;
    }
    return ret;
}

int32_t PlayerServerMock::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->GetCurrentTrack(trackType, index);
}

int32_t PlayerServerMock::AddSubSource(const std::string &url)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    (void)player_->AddSubSource(url);
    std::cout << "wait for track info callback" << std::endl;
    return callback_->TrackInfoUpdateSync();
}

int32_t PlayerServerMock::AddSubSource(const std::string &path, int64_t offset, int64_t size)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr && callback_ != nullptr, -1, "player or callback is nullptr");
    std::string rawFile = path.substr(strlen("file://"));
    int32_t fileDescriptor = open(rawFile.c_str(), O_RDONLY);
    if (fileDescriptor <= 0) {
        std::cout << "Open file failed." << std::endl;
        return -1;
    }

    struct stat64 st;
    if (fstat64(fileDescriptor, &st) != 0) {
        std::cout << "Get file state failed" << std::endl;
        (void)close(fileDescriptor);
        return -1;
    }
    int64_t stLen = static_cast<int64_t>(st.st_size);
    if (size > 0) {
        stLen = size;
    }
    int32_t ret = player_->AddSubSource(fileDescriptor, offset, stLen);
    if (ret != 0) {
        (void)close(fileDescriptor);
        return -1;
    }
    (void)close(fileDescriptor);
    std::cout << "wait for track info callback" << std::endl;
    return callback_->TrackInfoUpdateSync();
}

std::string PlayerServerMock::GetSubtitleText(std::string text)
{
    return callback_->SubtitleTextUpdate(text);
}

sptr<Surface> PlayerServerMock::GetVideoSurfaceNext()
{
    sptr<Rosen::WindowOption> option = new Rosen::WindowOption();
    option->SetWindowRect({ 0, 0, nextSurfaceWidth_, nextSurfaceHeight_ });
    option->SetWindowType(Rosen::WindowType::WINDOW_TYPE_TOAST);
    option->SetWindowMode(Rosen::WindowMode::WINDOW_MODE_FLOATING);
    previewWindowNext_ = Rosen::Window::Create("xcomponent_window_next", option);
    if (previewWindowNext_ == nullptr || previewWindowNext_->GetSurfaceNode() == nullptr) {
        return nullptr;
    }

    previewWindowNext_->Show();
    auto surfaceNode = previewWindowNext_->GetSurfaceNode();
    surfaceNode->SetFrameGravity(Rosen::Gravity::RESIZE);
    Rosen::RSTransaction::FlushImplicitTransaction();
    return surfaceNode->GetSurface();
}

PlayerStates PlayerServerMock::GetState()
{
    return callback_->GetState();
}

int32_t PlayerServerMock::SetPlayRange(int64_t start, int64_t end)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetPlayRange(start, end);
}

int32_t PlayerServerMock::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetPlayRangeWithMode(start, end, mode);
}

int32_t PlayerServerMock::SeekContinuous(int32_t mseconds)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->Seek(mseconds, PlayerSeekMode::SEEK_CONTINOUS);
}

int32_t PlayerServerMock::SetMaxAmplitudeCbStatus(bool status)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SetMaxAmplitudeCbStatus(status);
}

int32_t PlayerServerMock::SetPlaybackStrategy(AVPlayStrategy strategy)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetPlaybackStrategy(strategy);
}

int32_t PlayerServerMock::SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    std::unique_lock<std::mutex> lock(mutex_);
    return player_->SetMediaMuted(mediaType, isMuted);
}

int32_t PlayerServerMock::SetDeviceChangeCbStatus(bool status)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SetDeviceChangeCbStatus(status);
}

int32_t PlayerServerMock::SetRenderFirstFrame(bool display)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->SetRenderFirstFrame(display);
}

int32_t PlayerServerMock::EnableReportMediaProgress(bool enable)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->EnableReportMediaProgress(enable);
}

int32_t PlayerServerMock::GetPlaybackPosition(int32_t &playbackPosition)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(player_ != nullptr, -1, "player_ == nullptr");
    return player_->GetPlaybackPosition(playbackPosition);
}

int32_t PlayerMediaDataSourceMock::ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos)
{
    return MSERR_OK;
}

int32_t PlayerMediaDataSourceMock::GetSize(int64_t &size)
{
    size = size_;
    return MSERR_OK;
}

int32_t PlayerMediaDataSourceMock::ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    return MSERR_OK;
}

int32_t PlayerMediaDataSourceMock::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetSource(const std::string &url)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetObs(const std::weak_ptr<IPlayerEngineObs> &obs)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Play()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::PrepareAsync()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Pause(bool isSystemOperation)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Stop()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Reset()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Freeze(bool &isNoNeedToFreeze)
{
    isNoNeedToFreeze = true;
    return MSERR_OK;
}

int32_t PlayerEngineMock::UnFreeze()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetVolume(float leftVolume, float rightVolume)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetVolumeMode(int32_t mode)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetCurrentTime(int32_t &currentTime)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetPlaybackInfo(Format &playbackInfo)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetVideoWidth()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetVideoHeight()
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetDuration(int32_t &duration)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetPlaybackSpeed(PlaybackRateMode mode)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetPlaybackRate(float rate)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetVideoSurface(sptr<Surface> surface)
{
    return MSERR_OK;
}

float PlayerEngineMock::GetMaxAmplitude()
{
    return 0.0;
}

int32_t PlayerEngineMock::SetLooping(bool loop)
{
    return MSERR_OK;
}

int32_t PlayerEngineMock::SetParameter(const Format &param)
{
    return MSERR_OK;
}

bool PlayerEngineMock::IsFlvLive()
{
    return true;
}

int32_t PlayerEngineMock::GetPlaybackPosition(int32_t &playbackPosition)
{
    return MSERR_OK;
}

bool PlayerEngineMock::IsNeedChangePlaySpeed(PlaybackRateMode &mode, bool &isXSpeedPlay)
{
    mode = PlaybackRateMode::SPEED_FORWARD_1_20_X;
    return isXSpeedPlay;
}
} // namespace Media
} // namespace OHOS