/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cj_avplayer.h"

#include "media_log.h"
#ifdef SUPPORT_VIDEO
#include "surface_utils.h"
#endif

using namespace OHOS::AudioStandard;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CJAVPlayer"};
}

template <typename T, typename = std::enable_if_t<std::is_same_v<int64_t, T> || std::is_same_v<int32_t, T>>>
bool StrToInt(const std::string_view &str, T &value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front()) || (str.front() == '-')), false);
    std::string valStr(str);
    char *end = nullptr;
    errno = 0;
    const char *addr = valStr.c_str();
    long long result = strtoll(addr, &end, 10); /* 10 means decimal */
    CHECK_AND_RETURN_RET_LOG(result >= LLONG_MIN && result <= LLONG_MAX, false,
                             "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != addr && end[0] == '\0' && errno != ERANGE, false,
                             "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
    if constexpr (std::is_same<int32_t, T>::value) {
        CHECK_AND_RETURN_RET_LOG(result >= INT_MIN && result <= INT_MAX, false,
                                 "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
        value = static_cast<int32_t>(result);
        return true;
    }
    value = result;
    return true;
}

namespace OHOS {
namespace Media {
CJAVPlayer::CJAVPlayer()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ctor", FAKE_POINTER(this));
}

CJAVPlayer::~CJAVPlayer()
{
}

bool CJAVPlayer::Constructor()
{
    player_ = PlayerFactory::CreatePlayer();
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr, false, "failed to CreatePlayer");

    playerCb_ = std::make_shared<CJAVPlayerCallback>(this);
    (void)player_->SetPlayerCallback(playerCb_);
    return true;
}

void CJAVPlayer::NotifyDuration(int32_t duration)
{
    duration_ = duration;
}

void CJAVPlayer::NotifyPosition(int32_t position)
{
    position_ = position;
}

void CJAVPlayer::NotifyState(PlayerStates state)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    if (state_ != state) {
        state_ = state;
        MEDIA_LOGI("0x%{public}06" PRIXPTR " notify %{public}s", FAKE_POINTER(this), GetCurrentState().c_str());
        stateChangeCond_.notify_all();
    }
}

void CJAVPlayer::NotifyVideoSize(int32_t width, int32_t height)
{
    width_ = width;
    height_ = height;
}

void CJAVPlayer::NotifyIsLiveStream()
{
    isLiveStream_ = true;
}

void CJAVPlayer::NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos)
{
    MEDIA_LOGD("NotifyDrmInfoUpdated");
    for (auto &newItem : infos) {
        auto pos = localDrmInfos_.equal_range(newItem.first);
        if (pos.first == pos.second && pos.first == localDrmInfos_.end()) {
            localDrmInfos_.insert(newItem);
            continue;
        }
        bool isSame = false;
        for (; pos.first != pos.second; ++pos.first) {
            if (newItem.second == pos.first->second) {
                isSame = true;
                break;
            }
        }
        if (!isSame) {
            localDrmInfos_.insert(newItem);
        }
    }
}

char *CJAVPlayer::GetUrl()
{
    return MallocCString(url_.c_str());
}

void CJAVPlayer::SetUrl(char *url)
{
    MEDIA_LOGD("SetUrl In");
    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return;
    }

    StartListenCurrentResource(); // Listen to the events of the current resource

    url_ = url;
    MEDIA_LOGD("SetUrl url: %{private}s", url_.c_str());
    SetSource(url_);
    MEDIA_LOGD("SetUrl Out");
}

CAVFileDescriptor CJAVPlayer::GetAVFileDescriptor()
{
    return CAVFileDescriptor{
        .fd = fileDescriptor_.fd, .offset = fileDescriptor_.offset, .length = fileDescriptor_.length};
}

void CJAVPlayer::SetAVFileDescriptor(CAVFileDescriptor fileDescriptor)
{
    MEDIA_LOGI("SetAVFileDescriptor In");
    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set fd");
        return;
    }

    StartListenCurrentResource(); // Listen to the events of the current resource
    fileDescriptor_.fd = fileDescriptor.fd;
    fileDescriptor_.offset = fileDescriptor.offset;
    fileDescriptor_.length = fileDescriptor.length;

    if (player_ != nullptr) {
        auto playerFd = fileDescriptor_;
        MEDIA_LOGI("SetAVFileDescriptor fd: %{public}d, offset: %{public}" PRId64 ", size: %{public}" PRId64,
                   playerFd.fd, playerFd.offset, playerFd.length);
        if (player_->SetSource(playerFd.fd, playerFd.offset, playerFd.length) != MSERR_OK) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource FileDescriptor failed");
        }
    }

    MEDIA_LOGI("SetAVFileDescriptor Out");
}

CAVDataSrcDescriptor CJAVPlayer::GetDataSrc()
{
    MEDIA_LOGI("GetDataSrc In");

    int64_t fileSize;
    if (dataSrcCb_ == nullptr) {
        return CAVDataSrcDescriptor{.fileSize = -1, .callback = -1};
    }
    (void)dataSrcCb_->GetSize(fileSize);
    int32_t callbackId = dataSrcCb_->GetCallbackId();

    MEDIA_LOGI("GetDataSrc Out");
    return CAVDataSrcDescriptor{.fileSize = fileSize, .callback = callbackId};
}

void CJAVPlayer::SetDataSrc(CAVDataSrcDescriptor dataSrcDescriptor)
{
    MEDIA_LOGI("SetDataSrc In");

    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set dataSrc");
        return;
    }
    StartListenCurrentResource(); // Listen to the events of the current resource

    if (dataSrcDescriptor.fileSize < -1 || dataSrcDescriptor.fileSize == 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check parameter fileSize");
        return;
    }
    MEDIA_LOGD("Recvive filesize is %{public}" PRId64 "", dataSrcDescriptor.fileSize);
    dataSrcCb_ = std::make_shared<CJMediaDataSourceCallback>(dataSrcDescriptor.fileSize);
    dataSrcCb_->SetCallback(dataSrcDescriptor.callback);

    if (player_ != nullptr) {
        if (player_->SetSource(dataSrcCb_) != MSERR_OK) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource DataSrc failed");
        } else {
            state_ = PlayerStates::PLAYER_INITIALIZED;
        }
        int64_t fileSize;
        (void)dataSrcCb_->GetSize(fileSize);
        if (fileSize == -1) {
            isLiveStream_ = true;
        }
    }

    MEDIA_LOGI("SetDataSrc Out");
}

char *CJAVPlayer::GetSurfaceID()
{
    return MallocCString(surface_.c_str());
}

void CJAVPlayer::SetSurfaceID(char *surfaceId)
{
    MEDIA_LOGD("SetSurfaceID In");

    std::string curState = GetCurrentState();
    bool setSurfaceFirst = curState == AVPlayerState::STATE_INITIALIZED;
    bool switchSurface = curState == AVPlayerState::STATE_PREPARED || curState == AVPlayerState::STATE_PLAYING ||
                         curState == AVPlayerState::STATE_PAUSED || curState == AVPlayerState::STATE_STOPPED ||
                         curState == AVPlayerState::STATE_COMPLETED;

    if (setSurfaceFirst) {
        MEDIA_LOGI("SetSurfaceID set surface first in %{public}s state", curState.c_str());
    } else if (switchSurface) {
        MEDIA_LOGI("SetSurfaceID switch surface in %{public}s state", curState.c_str());
        std::string oldSurface = std::string(surface_);
        if (oldSurface.empty()) {
            OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "switch surface with no old surface");
            return;
        }
    } else {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "the attribute(SurfaceID) can only be set in the initialized state");
        return;
    }
    surface_ = surfaceId;
    SetSurface(std::string(surface_));
}

bool CJAVPlayer::GetLoop()
{
    return loop_;
}

void CJAVPlayer::SetLoop(bool loop)
{
    MEDIA_LOGI("SetLoop In");
    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support loop");
        return;
    }

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport loop operation");
        return;
    }

    loop_ = loop;

    if (player_ != nullptr) {
        (void)player_->SetLooping(loop_);
    }
}

int32_t CJAVPlayer::GetVideoScaleType()
{
    return videoScaleType_;
}

void CJAVPlayer::SetVideoScaleType(int32_t videoScaleType)
{
    MEDIA_LOGI("SetVideoScaleType In");

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport video scale operation");
        return;
    }

    videoScaleType_ = videoScaleType;

    if (player_ != nullptr) {
        Format format;
        (void)format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, videoScaleType);
        (void)player_->SetParameter(format);
    }
    MEDIA_LOGI("SetVideoScaleType Out");
}

int32_t CJAVPlayer::GetAudioInterruptMode()
{
    return interruptMode_;
}

void CJAVPlayer::SetAudioInterruptMode(int32_t interruptMode)
{
    MEDIA_LOGI("SetAudioInterruptMode In");

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport audio interrupt operation");
        return;
    }

    if (interruptMode < AudioStandard::InterruptMode::SHARE_MODE ||
        interruptMode > AudioStandard::InterruptMode::INDEPENDENT_MODE) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input interrupt Mode");
        return;
    }
    interruptMode_ = static_cast<AudioStandard::InterruptMode>(interruptMode);

    if (player_ != nullptr) {
        Format format;
        (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, interruptMode_);
        (void)player_->SetParameter(format);
    }
    MEDIA_LOGI("SetAudioInterruptMode Out");
}

CAudioRendererInfo CJAVPlayer::GetAudioRendererInfo()
{
    MEDIA_LOGI("GetAudioRendererInfo In");

    CAudioRendererInfo info;
    info.usage = static_cast<int32_t>(audioRendererInfo_.streamUsage);
    info.rendererFlags = audioRendererInfo_.rendererFlags;
    MEDIA_LOGI("GetAudioRendererInfo Out");
    return info;
}

void CJAVPlayer::SetAudioRendererInfo(CAudioRendererInfo info)
{
    MEDIA_LOGI("SetAudioRendererInfo In");

    if (GetCurrentState() != AVPlayerState::STATE_INITIALIZED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not initialized, unsupport to set audio renderer info");
        return;
    }
    if (!HandleParameter(info)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input audio renderer info");
        return;
    }
    if (player_ != nullptr) {
        Format format;
        (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, audioRendererInfo_.streamUsage);
        (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, audioRendererInfo_.rendererFlags);
        (void)player_->SetParameter(format);
    }
    MEDIA_LOGI("SetAudioRendererInfo Out");
}

int32_t CJAVPlayer::GetAudioEffectMode()
{
    return audioEffectMode_;
}

void CJAVPlayer::SetAudioEffectMode(int32_t effectMode)
{
    MEDIA_LOGI("SetAudioEffectMode In");

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport audio effect mode operation");
        return;
    }

    if (effectMode > OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT ||
        effectMode < OHOS::AudioStandard::AudioEffectMode::EFFECT_NONE) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                  "invalid audioEffectMode, please check the input audio effect Mode");
        return;
    }

    if (audioEffectMode_ == effectMode) {
        MEDIA_LOGI("Same effectMode parameter");
        return;
    }

    audioEffectMode_ = effectMode;

    if (player_ != nullptr) {
        Format format;
        (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, effectMode);
        (void)player_->SetParameter(format);
    }
    MEDIA_LOGI("SetAudioEffectMode Out");
}

char *CJAVPlayer::GetState()
{
    std::string curState = GetCurrentState();
    return MallocCString(curState.c_str());
}

int32_t CJAVPlayer::GetCurrentTime()
{
    MEDIA_LOGD("GetCurrentTime In");

    int32_t currentTime = -1;
    if (IsControllable()) {
        currentTime = position_;
    }

    if (IsLiveSource() && dataSrcCb_ == nullptr) {
        currentTime = -1;
    }
    std::string curState = GetCurrentState();
    if (currentTime != -1) {
        MEDIA_LOGI("GetCurrenTime Out, state %{public}s, time: %{public}d", curState.c_str(), currentTime);
    }
    return currentTime;
}

int32_t CJAVPlayer::GetDuration()
{
    MEDIA_LOGD("GetDuration In");

    int32_t duration = -1;
    if (IsControllable() && !IsLiveSource()) {
        duration = duration_;
    }

    std::string curState = GetCurrentState();
    MEDIA_LOGD("GetDuration Out, state %{public}s, duration %{public}d", curState.c_str(), duration);
    return duration;
}

int32_t CJAVPlayer::GetWidth()
{
    int32_t width = 0;
    if (IsControllable()) {
        width = width_;
    }
    return width;
}

int32_t CJAVPlayer::GetHeight()
{
    int32_t height = 0;
    if (IsControllable()) {
        height = height_;
    }
    return height;
}

int32_t CJAVPlayer::PrepareTask()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task In", FAKE_POINTER(this));
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_STOPPED) {
        int32_t ret = player_->PrepareAsync();
        if (ret != MSERR_OK) {
            auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
            return errCode;
        }

        if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
            return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
        }
    } else if (state == AVPlayerState::STATE_PREPARED) {
        MEDIA_LOGI("current state is prepared, invalid operation");
    } else {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task Out", FAKE_POINTER(this));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Prepare()
{
    MEDIA_LOGI("Prepare In");
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_INITIALIZED && state != AVPlayerState::STATE_STOPPED &&
        state != AVPlayerState::STATE_PREPARED) {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        return PrepareTask();
    }
}

int32_t CJAVPlayer::PlayTask()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task In", FAKE_POINTER(this));
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PAUSED ||
        state == AVPlayerState::STATE_COMPLETED) {
        int32_t ret = player_->Play();
        if (ret != MSERR_OK) {
            return MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
        }

        if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
            return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
        }
    } else if (state == AVPlayerState::STATE_PLAYING) {
        MEDIA_LOGI("current state is playing, invalid operation");
    } else {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task Out", FAKE_POINTER(this));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Play()
{
    MEDIA_LOGI("Play In");
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_PREPARED && state != AVPlayerState::STATE_PAUSED &&
        state != AVPlayerState::STATE_COMPLETED && state != AVPlayerState::STATE_PLAYING) {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else if (state == AVPlayerState::STATE_COMPLETED && IsLiveSource()) {
        return MSERR_EXT_API9_UNSUPPORT_CAPABILITY;
    } else {
        return PlayTask();
    }
}

int32_t CJAVPlayer::PauseTask()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task In", FAKE_POINTER(this));
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PLAYING) {
        int32_t ret = player_->Pause();
        if (ret != MSERR_OK) {
            auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
            return errCode;
        }
    } else if (state == AVPlayerState::STATE_PAUSED) {
        MEDIA_LOGI("current state is paused, invalid operation");
    } else {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task Out", FAKE_POINTER(this));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Pause()
{
    MEDIA_LOGI("Pause In");
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_PLAYING && state != AVPlayerState::STATE_PAUSED) {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        return PauseTask();
    }
}

int32_t CJAVPlayer::StopTask()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task In", FAKE_POINTER(this));
    std::unique_lock<std::mutex> lock(taskMutex_);
    if (IsControllable()) {
        int32_t ret = player_->Stop();
        if (ret != MSERR_OK) {
            auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
            return errCode;
        }
    } else if (GetCurrentState() == AVPlayerState::STATE_STOPPED) {
        MEDIA_LOGI("current state is stopped, invalid operation");
    } else {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task Out", FAKE_POINTER(this));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Stop()
{
    MEDIA_LOGI("Stop In");
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_IDLE || state == AVPlayerState::STATE_INITIALIZED ||
        state == AVPlayerState::STATE_RELEASED || state == AVPlayerState::STATE_ERROR) {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        return StopTask();
    }
}

int32_t CJAVPlayer::ResetTask()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task In", FAKE_POINTER(this));
    PauseListenCurrentResource(); // Pause event listening for the current resource
    ResetUserParameters();
    {
        isInterrupted_.store(false);
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
            return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
        } else if (GetCurrentState() == AVPlayerState::STATE_IDLE) {
            MEDIA_LOGI("current state is idle, invalid operation");
        } else {
            int32_t ret = player_->Reset();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return errCode;
            }
        }
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task Out", FAKE_POINTER(this));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Reset()
{
    MEDIA_LOGI("Reset In");
    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        int32_t res = ResetTask();
        if (dataSrcCb_ != nullptr) {
            dataSrcCb_->ClearCallbackReference();
            dataSrcCb_ = nullptr;
        }
        isLiveStream_ = false;
        return res;
    }
}

int32_t CJAVPlayer::ReleaseTask()
{
    if (!isReleased_.load()) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Release Task In", FAKE_POINTER(this));
        PauseListenCurrentResource(); // Pause event listening for the current resource
        ResetUserParameters();
        {
            std::lock_guard<std::mutex> lock(syncMutex_);
            if (player_ != nullptr) {
                (void)player_->ReleaseSync();
                player_ = nullptr;
            }
        }

        if (playerCb_ != nullptr) {
            playerCb_->Release();
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Release Task Out", FAKE_POINTER(this));
        isReleased_.store(true);
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::Release()
{
    MEDIA_LOGI("Release In");
    int32_t res = ReleaseTask();
    if (dataSrcCb_ != nullptr) {
        dataSrcCb_->ClearCallbackReference();
        dataSrcCb_ = nullptr;
    }
    return res;
}

void CJAVPlayer::SeekTask(int32_t time, int32_t mode)
{
    if (player_ != nullptr) {
        (void)player_->Seek(time, TransferSeekMode(mode));
    }
}

void CJAVPlayer::Seek(int32_t time, int32_t mode)
{
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport seek operation");
    }
    SeekTask(time, mode);
}

int32_t CJAVPlayer::OnStateChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(char *stateStr, int32_t reason)>(callbackId);
    playerCb_->stateChangeCallback = [lambda = CJLambda::Create(cFunc)](std::string &stateStr, int32_t reason) -> void {
        auto cstr = MallocCString(stateStr);
        lambda(cstr, reason);
        free(cstr);
    };
    playerCb_->stateChangeCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffStateChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->stateChangeCallbackId == callbackId) {
        playerCb_->stateChangeCallbackId = INVALID_ID;
        playerCb_->stateChangeCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffStateChangeAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->stateChangeCallbackId = INVALID_ID;
    playerCb_->stateChangeCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnError(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t errorCode, const char *errorMsg)>(callbackId);
    playerCb_->errorCallback = [lambda = CJLambda::Create(cFunc)](int32_t errorCode,
                                                                  const std::string &errorMsg) -> void {
        auto cstr = MallocCString(errorMsg);
        lambda(errorCode, cstr);
        free(cstr);
    };
    playerCb_->errorCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffError(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->errorCallbackId == callbackId) {
        playerCb_->errorCallbackId = INVALID_ID;
        playerCb_->errorCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffErrorAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->errorCallbackId = INVALID_ID;
    playerCb_->errorCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnSeekDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t currentPositon)>(callbackId);
    playerCb_->seekDoneCallback = [lambda = CJLambda::Create(cFunc)](int32_t currentPositon) -> void {
        lambda(currentPositon);
    };
    playerCb_->seekDoneCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSeekDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->seekDoneCallbackId == callbackId) {
        playerCb_->seekDoneCallbackId = INVALID_ID;
        playerCb_->seekDoneCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSeekDoneAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->seekDoneCallbackId = INVALID_ID;
    playerCb_->seekDoneCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnSpeedDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t speedMode)>(callbackId);
    playerCb_->speedDoneCallback = [lambda = CJLambda::Create(cFunc)](int32_t speedMode) -> void { lambda(speedMode); };
    playerCb_->speedDoneCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSpeedDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->speedDoneCallbackId == callbackId) {
        playerCb_->speedDoneCallbackId = INVALID_ID;
        playerCb_->speedDoneCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSpeedDoneAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->speedDoneCallbackId = INVALID_ID;
    playerCb_->speedDoneCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnBitRateDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t bitRate)>(callbackId);
    playerCb_->bitRateDoneCallback = [lambda = CJLambda::Create(cFunc)](int32_t bitRate) -> void { lambda(bitRate); };
    playerCb_->bitRateDoneCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffBitRateDone(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->bitRateDoneCallbackId == callbackId) {
        playerCb_->bitRateDoneCallbackId = INVALID_ID;
        playerCb_->bitRateDoneCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffBitRateDoneAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->bitRateDoneCallbackId = INVALID_ID;
    playerCb_->bitRateDoneCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnAvailableBitrates(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(CArrI32 bitrateVec)>(callbackId);
    playerCb_->availableBitratesCallback = [lambda = CJLambda::Create(cFunc)](std::vector<int32_t> bitrateVec) -> void {
        auto carr = Convert2CArrI32(bitrateVec);
        lambda(carr);
        free(carr.head);
    };
    playerCb_->availableBitratesCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAvailableBitrates(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->availableBitratesCallbackId == callbackId) {
        playerCb_->availableBitratesCallbackId = INVALID_ID;
        playerCb_->availableBitratesCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAvailableBitratesAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->availableBitratesCallbackId = INVALID_ID;
    playerCb_->availableBitratesCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnMediaKeySystemInfoUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(CArrCMediaKeySystemInfo drmInfoMap)>(callbackId);
    playerCb_->mediaKeySystemInfoUpdateCallback =
        [lambda = CJLambda::Create(cFunc)](CArrCMediaKeySystemInfo drmInfoMap) -> void {
        lambda(drmInfoMap);
    };
    playerCb_->mediaKeySystemInfoUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffMediaKeySystemInfoUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->mediaKeySystemInfoUpdateCallbackId == callbackId) {
        playerCb_->mediaKeySystemInfoUpdateCallbackId = INVALID_ID;
        playerCb_->mediaKeySystemInfoUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffMediaKeySystemInfoUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->mediaKeySystemInfoUpdateCallbackId = INVALID_ID;
    playerCb_->mediaKeySystemInfoUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnVolumeChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(float volumeLevel)>(callbackId);
    playerCb_->volumeChangeCallback = [lambda = CJLambda::Create(cFunc)](float volumeLevel) -> void {
        lambda(volumeLevel);
    };
    playerCb_->volumeChangeCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffVolumeChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->volumeChangeCallbackId == callbackId) {
        playerCb_->volumeChangeCallbackId = INVALID_ID;
        playerCb_->volumeChangeCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffVolumeChangeAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->volumeChangeCallbackId = INVALID_ID;
    playerCb_->volumeChangeCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnEndOfStream(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    playerCb_->endOfStreamCallback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    playerCb_->endOfStreamCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffEndOfStream(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->endOfStreamCallbackId == callbackId) {
        playerCb_->endOfStreamCallbackId = INVALID_ID;
        playerCb_->endOfStreamCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffEndOfStreamAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->endOfStreamCallbackId = INVALID_ID;
    playerCb_->endOfStreamCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnTimeUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t position)>(callbackId);
    playerCb_->timeUpdateCallback = [lambda = CJLambda::Create(cFunc)](int32_t position) -> void { lambda(position); };
    playerCb_->timeUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTimeUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->timeUpdateCallbackId == callbackId) {
        playerCb_->timeUpdateCallbackId = INVALID_ID;
        playerCb_->timeUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTimeUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->timeUpdateCallbackId = INVALID_ID;
    playerCb_->timeUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnDurationUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t duration)>(callbackId);
    playerCb_->durationUpdateCallback = [lambda = CJLambda::Create(cFunc)](int32_t duration) -> void {
        lambda(duration);
    };
    playerCb_->durationUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffDurationUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->durationUpdateCallbackId == callbackId) {
        playerCb_->durationUpdateCallbackId = INVALID_ID;
        playerCb_->durationUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffDurationUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->durationUpdateCallbackId = INVALID_ID;
    playerCb_->durationUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnBufferingUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t bufferingType, int32_t val)>(callbackId);
    playerCb_->bufferingUpdateCallback =
        [lambda = CJLambda::Create(cFunc)](int32_t bufferingType, int32_t val) -> void { lambda(bufferingType, val); };
    playerCb_->bufferingUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffBufferingUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->bufferingUpdateCallbackId == callbackId) {
        playerCb_->bufferingUpdateCallbackId = INVALID_ID;
        playerCb_->bufferingUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffBufferingUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->bufferingUpdateCallbackId = INVALID_ID;
    playerCb_->bufferingUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnStartRenderFrame(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    playerCb_->startRenderFrameCallback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    playerCb_->startRenderFrameCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffStartRenderFrame(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->startRenderFrameCallbackId == callbackId) {
        playerCb_->startRenderFrameCallbackId = INVALID_ID;
        playerCb_->startRenderFrameCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffStartRenderFrameAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->startRenderFrameCallbackId = INVALID_ID;
    playerCb_->startRenderFrameCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnVideoSizeChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t width, int32_t height)>(callbackId);
    playerCb_->videoSizeChangeCallback = [lambda = CJLambda::Create(cFunc)](int32_t width, int32_t height) -> void {
        lambda(width, height);
    };
    playerCb_->videoSizeChangeCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffVideoSizeChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->videoSizeChangeCallbackId == callbackId) {
        playerCb_->videoSizeChangeCallbackId = INVALID_ID;
        playerCb_->videoSizeChangeCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffVideoSizeChangeAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->videoSizeChangeCallbackId = INVALID_ID;
    playerCb_->videoSizeChangeCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnAudioInterrupt(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t eventType, int32_t forceType, int32_t hintType)>(callbackId);
    playerCb_->audioInterruptCallback = [lambda = CJLambda::Create(cFunc)](int32_t eventType, int32_t forceType,
                                                                           int32_t hintType) -> void {
        lambda(eventType, forceType, hintType);
    };
    playerCb_->audioInterruptCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAudioInterrupt(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->audioInterruptCallbackId == callbackId) {
        playerCb_->audioInterruptCallbackId = INVALID_ID;
        playerCb_->audioInterruptCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAudioInterruptAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->audioInterruptCallbackId = INVALID_ID;
    playerCb_->audioInterruptCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnAudioDeviceChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(AudioStandard::CAudioStreamDeviceChangeInfo info)>(callbackId);
    playerCb_->audioDeviceChangeCallback =
        [lambda = CJLambda::Create(cFunc)](AudioStandard::AudioDeviceDescriptor deviceInfo, int32_t reason) -> void {
        AudioStandard::CArrDeviceDescriptor arr;
        int32_t errCode = SUCCESS_CODE;
        AudioStandard::Convert2CArrDeviceDescriptorByDeviceInfo(arr, deviceInfo, &errCode);
        if (errCode != SUCCESS_CODE) {
            return;
        }
        lambda(AudioStandard::CAudioStreamDeviceChangeInfo{.changeReason = reason, .deviceDescriptors = arr});
        FreeCArrDeviceDescriptor(arr);
    };
    playerCb_->audioDeviceChangeCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAudioDeviceChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->audioDeviceChangeCallbackId == callbackId) {
        playerCb_->audioDeviceChangeCallbackId = INVALID_ID;
        playerCb_->audioDeviceChangeCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAudioDeviceChangeAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->audioDeviceChangeCallbackId = INVALID_ID;
    playerCb_->audioDeviceChangeCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnSubtitleUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(CSubtitleInfo info)>(callbackId);
    playerCb_->subtitleUpdateCallback = [lambda = CJLambda::Create(cFunc)](std::string text, int32_t pts,
                                                                           int32_t duration) -> void {
        auto info = Convert2CSubtitleInfo(text, pts, duration);
        lambda(info);
        free(info.text);
    };
    playerCb_->subtitleUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSubtitleUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->subtitleUpdateCallbackId == callbackId) {
        playerCb_->subtitleUpdateCallbackId = INVALID_ID;
        playerCb_->subtitleUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffSubtitleUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->subtitleUpdateCallbackId = INVALID_ID;
    playerCb_->subtitleUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnTrackChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(int32_t index, bool isSelect)>(callbackId);
    playerCb_->trackChangeCallback = [lambda = CJLambda::Create(cFunc)](int32_t index, int32_t isSelect) -> void {
        lambda(index, static_cast<bool>(isSelect));
    };
    playerCb_->trackChangeCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTrackChange(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->trackChangeCallbackId == callbackId) {
        playerCb_->trackChangeCallbackId = INVALID_ID;
        playerCb_->trackChangeCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTrackChangeAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->trackChangeCallbackId = INVALID_ID;
    playerCb_->trackChangeCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnTrackInfoUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(CArrCMediaDescription trackInfo)>(callbackId);
    playerCb_->trackInfoUpdateCallback = [lambda = CJLambda::Create(cFunc)](CArrCMediaDescription trackInfo) -> void {
        lambda(trackInfo);
        free(trackInfo.head);
    };
    playerCb_->trackInfoUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTrackInfoUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->trackInfoUpdateCallbackId == callbackId) {
        playerCb_->trackInfoUpdateCallbackId = INVALID_ID;
        playerCb_->trackInfoUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffTrackInfoUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->trackInfoUpdateCallbackId = INVALID_ID;
    playerCb_->trackInfoUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OnAmplitudeUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cFunc = reinterpret_cast<void (*)(CArrFloat arr)>(callbackId);
    playerCb_->amplitudeUpdateCallback = [lambda =
                                              CJLambda::Create(cFunc)](std::vector<float> MaxAmplitudeVec) -> void {
        auto vec = Convert2CArrFloat(MaxAmplitudeVec);
        lambda(vec);
        free(vec.head);
    };
    playerCb_->amplitudeUpdateCallbackId = callbackId;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAmplitudeUpdate(int64_t callbackId)
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    if (playerCb_->amplitudeUpdateCallbackId == callbackId) {
        playerCb_->amplitudeUpdateCallbackId = INVALID_ID;
        playerCb_->amplitudeUpdateCallback = nullptr;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::OffAmplitudeUpdateAll()
{
    if (playerCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    playerCb_->amplitudeUpdateCallbackId = INVALID_ID;
    playerCb_->amplitudeUpdateCallback = nullptr;
    return MSERR_EXT_API9_OK;
}

std::string CJAVPlayer::GetCurrentState()
{
    if (isReleased_.load()) {
        return AVPlayerState::STATE_RELEASED;
    }

    std::string curState = AVPlayerState::STATE_ERROR;
    static const std::map<PlayerStates, std::string> stateMap = {
        {PLAYER_IDLE, AVPlayerState::STATE_IDLE},
        {PLAYER_INITIALIZED, AVPlayerState::STATE_INITIALIZED},
        {PLAYER_PREPARED, AVPlayerState::STATE_PREPARED},
        {PLAYER_STARTED, AVPlayerState::STATE_PLAYING},
        {PLAYER_PAUSED, AVPlayerState::STATE_PAUSED},
        {PLAYER_STOPPED, AVPlayerState::STATE_STOPPED},
        {PLAYER_PLAYBACK_COMPLETE, AVPlayerState::STATE_COMPLETED},
        {PLAYER_STATE_ERROR, AVPlayerState::STATE_ERROR},
    };

    if (stateMap.find(state_) != stateMap.end()) {
        curState = stateMap.at(state_);
    }
    return curState;
}

void CJAVPlayer::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->OnErrorCb(errorCode, errorMsg);
    }
}

void CJAVPlayer::StartListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Start();
    }
}

void CJAVPlayer::SetSource(std::string url)
{
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        EnqueueNetworkTask(url);
    } else if (isFd) {
        std::string inputFd = url.substr(sizeof("fd://") - 1);
        int32_t fd = -1;
        if (!StrToInt(inputFd, fd) || fd < 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                      "invalid parameters, The input parameter is not a fd://+numeric string");
            return;
        }
        EnqueueFdTask(fd);
    } else {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                  "invalid parameters, The input parameter is not fd:// or network address");
    }
}

void CJAVPlayer::EnqueueNetworkTask(const std::string url)
{
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return;
    }
    if (player_ != nullptr) {
        if (player_->SetSource(url) != MSERR_OK) {
            QueueOnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to SetSourceNetWork");
            return;
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Set source network out", FAKE_POINTER(this));
    }
}

void CJAVPlayer::EnqueueFdTask(const int32_t fd)
{
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set source fd");
        return;
    }
    if (player_ != nullptr) {
        if (player_->SetSource(fd, 0, -1) != MSERR_OK) {
            QueueOnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to SetSourceFd");
            return;
        }
        MEDIA_LOGI("Set source fd out");
    }
}

void CJAVPlayer::QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN(!isReleased_.load());
    OnErrorCb(errorCode, errorMsg);
}

bool CJAVPlayer::IsLiveSource() const
{
    return isLiveStream_;
}

bool CJAVPlayer::IsControllable()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PLAYING ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    } else {
        return false;
    }
}

void CJAVPlayer::PauseListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Pause();
    }
}

void CJAVPlayer::ResetUserParameters()
{
    url_.clear();
    fileDescriptor_.fd = 0;
    fileDescriptor_.offset = 0;
    fileDescriptor_.length = -1;
    width_ = 0;
    height_ = 0;
    position_ = -1;
    duration_ = -1;
    loop_ = false;
}

PlayerSeekMode CJAVPlayer::TransferSeekMode(int32_t mode)
{
    MEDIA_LOGI("Seek Task TransferSeekMode, mode: %{public}d", mode);
    PlayerSeekMode seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    switch (mode) {
        case 0: // Seek to the next sync frame of the given timestamp.
            seekMode = PlayerSeekMode::SEEK_NEXT_SYNC;
            break;
        case 1: // Seek to the previous sync frame of the given timestamp.
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
        case 2: // Seek to the closest frame of the given timestamp. 2 refers SeekMode in @ohos.multimedia.media.d.ts
            seekMode = PlayerSeekMode::SEEK_CLOSEST;
            break;
        case 3: // Seek continous of the given timestamp. 3 refers SeekMode in @ohos.multimedia.media.d.ts
            seekMode = PlayerSeekMode::SEEK_CONTINOUS;
            break;
        default:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
    }
    return seekMode;
}

int32_t CJAVPlayer::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set mediaSource");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    StartListenCurrentResource(); // Listen to the events of the current resource
    return player_->SetMediaSource(mediaSource, strategy);
}

int32_t CJAVPlayer::SetPlaybackStrategy(AVPlayStrategy strategy)
{
    std::string currentState = GetCurrentState();
    if (currentState != AVPlayerState::STATE_INITIALIZED && currentState != AVPlayerState::STATE_STOPPED) {
        MEDIA_LOGE("current state is not initialized / stopped, unsupport set playback strategy");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    if (strategy.mutedMediaType != MediaType::MEDIA_TYPE_AUD) {
        MEDIA_LOGE("only support mute media type audio now");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    } else {
        AVPlayStrategy playStrategy;
        std::string state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_STOPPED) {
            int32_t ret = player_->SetPlaybackStrategy(playStrategy);
            if (ret != MSERR_OK) {
                MEDIA_LOGE("failed to set playback strategy");
                return MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
            }
            MEDIA_LOGD("SetPlaybackStrategy Success");
            return MSERR_EXT_API9_OK;
        }
        MEDIA_LOGE("current state is not initialized or stopped, unsupport set playback strategy operation");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
}

int32_t CJAVPlayer::SetMediaMuted(int32_t mediaType, bool muted)
{
    auto curState = GetCurrentState();
    bool canSetMute = curState == AVPlayerState::STATE_PREPARED || curState == AVPlayerState::STATE_PLAYING ||
                      curState == AVPlayerState::STATE_PAUSED || curState == AVPlayerState::STATE_COMPLETED;
    if (!canSetMute) {
        MEDIA_LOGE("current state is not initialized / stopped, unsupport set playback strategy operation");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || IsControllable()) {
        int32_t ret = player_->SetMediaMuted(static_cast<MediaType>(mediaType), muted);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("failed to set muted");
            return MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
        }
        MEDIA_LOGD("SetMediaMuted Success");
        return MSERR_EXT_API9_OK;
    }
    MEDIA_LOGE("current state is not stopped or initialized, unsupport prepare operation");
    return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
}

int32_t CJAVPlayer::GetSelectedTracks(std::vector<int32_t> &trackIndex)
{
    if (IsControllable()) {
        int32_t videoIndex = -1;
        (void)player_->GetCurrentTrack(MediaType::MEDIA_TYPE_VID, videoIndex);
        if (videoIndex != -1) {
            trackIndex.push_back(videoIndex);
        }

        int32_t audioIndex = -1;
        (void)player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, audioIndex);
        if (audioIndex != -1) {
            trackIndex.push_back(audioIndex);
        }

        int32_t subtitleIndex = -1;
        (void)player_->GetCurrentTrack(MediaType::MEDIA_TYPE_SUBTITLE, subtitleIndex);
        if (subtitleIndex != -1) {
            trackIndex.push_back(subtitleIndex);
        }
        return MSERR_EXT_API9_OK;
    }
    MEDIA_LOGE("current state unsupport get current selections");
    return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
}

PlayerSwitchMode TransferSwitchMode(int32_t mode)
{
    MEDIA_LOGI("TransferSwitchMode, mode: %{public}d", mode);
    PlayerSwitchMode switchMode = PlayerSwitchMode::SWITCH_CLOSEST;
    switch (mode) {
        case 0:
            switchMode = PlayerSwitchMode::SWITCH_SMOOTH;
            break;
        case 1:
            switchMode = PlayerSwitchMode::SWITCH_SEGMENT;
            break;
        default:
            break;
    }
    return switchMode;
}

int32_t CJAVPlayer::SelectTrack(int32_t index, int32_t mode)
{
    if (index < 0) {
        MEDIA_LOGE("invalid parameters, please check the track index");
        return MSERR_EXT_API9_INVALID_PARAMETER;
    }
    if (!IsControllable()) {
        MEDIA_LOGE("current state is not prepared/playing/paused/completed, unsupport selectTrack operation");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return player_->SelectTrack(index, TransferSwitchMode(mode));
}

int32_t CJAVPlayer::DeselectTrack(int32_t index)
{
    if (index < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the track index");
        return MSERR_EXT_API9_INVALID_PARAMETER;
    }
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport deselecttrack operation");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return player_->DeselectTrack(index);
}

std::multimap<std::string, std::vector<uint8_t>> CJAVPlayer::GetMediaKeySystemInfos()
{
    return localDrmInfos_;
}

void CJAVPlayer::SetSpeed(int32_t speed)
{
    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support speed");
        return;
    }

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport speed operation");
        return;
    }

    (void)player_->SetPlaybackSpeed(static_cast<PlaybackRateMode>(speed));
}

void CJAVPlayer::SetBitrate(int32_t bitrate)
{
    if (bitrate < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input bitrate");
        return;
    }
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport select bitrate operation");
        return;
    }
    (void)player_->SelectBitRate(static_cast<uint32_t>(bitrate));
}

void CJAVPlayer::SetVolume(float volume)
{
    if (playerCb_->isSetVolume_) {
        MEDIA_LOGI("SetVolume is processing, skip this task until onVolumeChangedCb");
    }
    playerCb_->isSetVolume_ = true;

    if (volume < 0.0f || volume > 1.0f) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check volume level");
        return;
    }

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                  "current state is not prepared/playing/paused/completed, unsupport volume operation");
        return;
    }
    (void)player_->SetVolume(volume, volume);
}

int32_t CJAVPlayer::AddSubtitleFromFd(int32_t fd, int64_t offset, int64_t length)
{
    if (player_->AddSubSource(fd, offset, length) != MSERR_OK) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleAVFileDescriptor");
        return MSERR_EXT_API9_INVALID_PARAMETER;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::AddSubtitleFromUrl(std::string url)
{
    MEDIA_LOGI("input url is %{private}s!", url.c_str());
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        if (player_->AddSubSource(url) != MSERR_OK) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleNetworkSource");
            return MSERR_EXT_API9_INVALID_PARAMETER;
        }
    } else if (isFd) {
        const std::string fdHead = "fd://";
        std::string inputFd = url.substr(fdHead.size());
        int32_t fd = -1;
        if (!StrToInt(inputFd, fd) || fd < 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                      "invalid parameters, The input parameter is not a fd://+numeric string");
            return MSERR_EXT_API9_INVALID_PARAMETER;
        }

        if (player_->AddSubSource(fd, 0, -1) != MSERR_OK) {
            OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to AddSubtitleFdSource");
            return MSERR_EXT_API9_INVALID_PARAMETER;
        }
    } else {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                  "invalid parameters, The input parameter is not fd:// or network address");
        return MSERR_EXT_API9_INVALID_PARAMETER;
    }
    return MSERR_EXT_API9_OK;
}

int32_t CJAVPlayer::GetPlaybackInfo(Format &format)
{
    if (IsControllable()) {
        return player_->GetPlaybackInfo(format);
    }
    MEDIA_LOGE("current state unsupport get playback info");
    return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
}

int32_t CJAVPlayer::GetTrackDescription(std::vector<Format> &trackInfos)
{
    if (IsControllable()) {
        (void)player_->GetVideoTrackInfo(trackInfos);
        (void)player_->GetAudioTrackInfo(trackInfos);
        (void)player_->GetSubtitleTrackInfo(trackInfos);
        return MSERR_EXT_API9_OK;
    }
    MEDIA_LOGE("current state unsupport get track description");
    return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
}

bool CJAVPlayer::HandleParameter(CAudioRendererInfo info)
{
    int32_t content = CONTENT_TYPE_UNKNOWN;
    int32_t usage = info.usage;
    int32_t rendererFlags = info.rendererFlags;
    MEDIA_LOGI("content = %{public}d, usage = %{public}d, rendererFlags = %{public}d", content, usage, rendererFlags);
    std::vector<int32_t> contents = {CONTENT_TYPE_UNKNOWN, CONTENT_TYPE_SPEECH,       CONTENT_TYPE_MUSIC,
                                     CONTENT_TYPE_MOVIE,   CONTENT_TYPE_SONIFICATION, CONTENT_TYPE_RINGTONE};
    std::vector<int32_t> usages = {STREAM_USAGE_UNKNOWN,
                                   STREAM_USAGE_MEDIA,
                                   STREAM_USAGE_MUSIC,
                                   STREAM_USAGE_VOICE_COMMUNICATION,
                                   STREAM_USAGE_VOICE_ASSISTANT,
                                   STREAM_USAGE_ALARM,
                                   STREAM_USAGE_VOICE_MESSAGE,
                                   STREAM_USAGE_NOTIFICATION_RINGTONE,
                                   STREAM_USAGE_RINGTONE,
                                   STREAM_USAGE_NOTIFICATION,
                                   STREAM_USAGE_ACCESSIBILITY,
                                   STREAM_USAGE_SYSTEM,
                                   STREAM_USAGE_MOVIE,
                                   STREAM_USAGE_GAME,
                                   STREAM_USAGE_AUDIOBOOK,
                                   STREAM_USAGE_NAVIGATION,
                                   STREAM_USAGE_DTMF,
                                   STREAM_USAGE_ENFORCED_TONE,
                                   STREAM_USAGE_ULTRASONIC,
                                   STREAM_USAGE_VIDEO_COMMUNICATION,
                                   STREAM_USAGE_ULTRASONIC};
    if (std::find(contents.begin(), contents.end(), content) == contents.end() ||
        std::find(usages.begin(), usages.end(), usage) == usages.end()) {
        return false;
    }

    if (audioRendererInfo_.contentType != content || audioRendererInfo_.streamUsage != usage) {
        audioEffectMode_ = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    }

    audioRendererInfo_ = AudioStandard::AudioRendererInfo{
        static_cast<AudioStandard::ContentType>(content),
        static_cast<AudioStandard::StreamUsage>(usage),
        rendererFlags,
    };
    return true;
}

#ifdef SUPPORT_VIDEO
void CJAVPlayer::SetSurface(const std::string &surfaceStr)
{
    MEDIA_LOGI("get surface, surfaceStr = %{public}s", surfaceStr.c_str());
    uint64_t surfaceId = 0;
    if (surfaceStr.empty() || surfaceStr[0] < '0' || surfaceStr[0] > '9') {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                  "Please obtain the surface from XComponentController.getXComponentSurfaceId");
        return;
    }
    surfaceId = std::stoull(surfaceStr);
    MEDIA_LOGI("get surface, surfaceId = (%{public}" PRIu64 ")", surfaceId);

    auto surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SurfaceUtils cannot convert ID to Surface");
        return;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetSurface Task", FAKE_POINTER(this));
    if (player_ != nullptr) {
        (void)player_->SetVideoSurface(surface);
    }
}
#else
void CJAVPlayer::SetSurface(const std::string &surfaceStr)
{
    (void)surfaceStr;
    OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The music player does not need to support (Surface)");
}
#endif
} // namespace Media
} // namespace OHOS