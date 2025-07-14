/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "avplayer_taihe.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_taihe_utils.h"
#include "media_dfx.h"
#ifdef SUPPORT_VIDEO
#include "surface_utils.h"
#endif
#include "fd_utils.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

using namespace ANI::Media;
using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVPlayerTaihe"};
    constexpr uint32_t TASK_TIME_LIMIT_MS = 2000; // ms
    static int32_t g_apiVersion = -1;
    constexpr int32_t DECIMAL = 10;
    constexpr int32_t SEEK_CONTINUOUS_TS_ENUM_NUM = 3;
}

namespace ANI::Media {

template<typename T, typename = std::enable_if_t<std::is_same_v<int64_t, T> || std::is_same_v<int32_t, T>>>
bool StrToInt(const std::string_view& str, T& value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front()) || (str.front() == '-')), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    const char* addr = valStr.c_str();
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

AVPlayerImpl::AVPlayerImpl()
{
    player_ = OHOS::Media::PlayerFactory::CreatePlayer();
    taskQue_ = std::make_unique<OHOS::Media::TaskQueue>("OS_AVPlayerTaihe");
    (void)taskQue_->Start();

    playerCb_ = std::make_shared<AVPlayerCallback>(this);
    (void)player_->SetPlayerCallback(playerCb_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(this));
}

optional<string> AVPlayerImpl::GetUrl()
{
    OHOS::Media::MediaTrace trace("AVPlayerTaihe::get url");
    MEDIA_LOGD("GetUrl In");
    string url = MediaTaiheUtils::ToTaiheString(url_);
    MEDIA_LOGD("GetUrl Out Current Url: %{private}s", url_.c_str());
    return optional<string>(std::in_place_t{}, url);
}

void AVPlayerImpl::SetUrl(optional_view<string> url)
{
    OHOS::Media::MediaTrace trace("AVPlayerTaihe::set url");
    MEDIA_LOGD("SetUrl In");
    if (this->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return;
    }
    this->StartListenCurrentResource();
    if (url.has_value()) {
        url_ = std::string(url.value());
    }
    MEDIA_LOGD("SetUrl url: %{private}s", url_.c_str());
    this->SetSource(url_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetUrl Out", FAKE_POINTER(this));
}

int32_t AVPlayerImpl::GetWidth()
{
    MediaTrace trace("AVPlayerTaihe::get width");
    MEDIA_LOGI("TaiheGetWidth");

    int32_t width = 0;
    if (this->IsControllable()) {
        width = width_;
    }

    return width;
}

int32_t AVPlayerImpl::GetHeight()
{
    MediaTrace trace("AVPlayerTaihe::get height");
    MEDIA_LOGI("TaiheGetHeight");

    int32_t height = 0;
    if (this->IsControllable()) {
        height = height_;
    }

    return height;
}

string AVPlayerImpl::GetState()
{
    MediaTrace trace("AVPlayerTaihe::get state");
    MEDIA_LOGD("TaiheGetState In");

    std::string curState = GetCurrentState();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheGetState curState: %{public}s ",
        FAKE_POINTER(this), curState.c_str());
    MEDIA_LOGD("TaiheGetState Out");
    return curState;
}

int32_t AVPlayerImpl::GetDuration()
{
    MediaTrace trace("AVPlayerTaihe::get duration");
    MEDIA_LOGD("TaiheGetDuration In");

    int32_t duration = -1;
    if (this->IsControllable() && !this->IsLiveSource()) {
        duration = duration_;
    }

    std::string curState = this->GetCurrentState();
    MEDIA_LOGD("TaiheGetDuration Out, state %{public}s, duration %{public}d", curState.c_str(), duration);
    return duration;
}

int32_t AVPlayerImpl::GetCurrentTime()
{
    MediaTrace trace("AVPlayerTaihe::get currentTime");
    MEDIA_LOGD("TaiheGetCurrentTime In");

    int32_t currentTime = -1;
    if (this->IsControllable()) {
        currentTime = position_;
    }

    if (this->IsLiveSource() && dataSrcCb_ == nullptr) {
        currentTime = -1;
    }
    std::string curState = this->GetCurrentState();
    if (currentTime != -1) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheGetCurrentTime Out, state %{public}s, time: %{public}d",
            FAKE_POINTER(this), curState.c_str(), currentTime);
    }
    return currentTime;
}

void AVPlayerImpl::SetVolume(double volume)
{
    MediaTrace trace("AVPlayerImpl::setVolume");
    MEDIA_LOGI("TaiheSetVolume In");

    if (playerCb_->isSetVolume_) {
        MEDIA_LOGI("SetVolume is processing, skip this task until onVolumeChangedCb");
    }
    playerCb_->isSetVolume_ = true;

    double volumeLevel = 1.0f;
    if (volume < 0.0f || volume > 1.0f) {
        this->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check volume level");
        return;
    }
    volumeLevel = volume;

    if (!this->IsControllable()) {
        this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport volume operation");
        return;
    }
    auto task = std::make_shared<TaskHandler<void>>([this, volumeLevel]() {
        MEDIA_LOGD("SetVolume Task");
        if (player_ != nullptr) {
            (void)player_->SetVolume(volumeLevel, volumeLevel);
        }
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("TaiheSetVolume Out");
    return;
}

optional<AVDataSrcDescriptor> AVPlayerImpl::GetDataSrc()
{
    MediaTrace trace("AVPlayerImpl::getDataSrc");
    MEDIA_LOGI("TaiheGetDataSrc In");

    if (dataSrcCb_ == nullptr) {
        std::shared_ptr<uintptr_t> ptr = std::make_shared<uintptr_t>();
        int64_t errFileSize = -1;
        auto errorCallback = std::reinterpret_pointer_cast<DataSrcCallback>(ptr);
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to check dataSrcCb_");
        return optional<AVDataSrcDescriptor>(std::in_place_t{},
            AVDataSrcDescriptor{std::move(errFileSize), std::move(*errorCallback)});
    }
    int64_t fileSize;
    (void)dataSrcCb_->GetSize(fileSize);
    std::shared_ptr<uintptr_t> callback;
    int32_t ret = dataSrcCb_->GetCallback(READAT_CALLBACK_NAME, callback);
    if (ret != OHOS::Media::MSERR_OK) {
        std::shared_ptr<uintptr_t> ptr = std::make_shared<uintptr_t>();
        int64_t errFileSize = -1;
        auto errorCallback = std::reinterpret_pointer_cast<DataSrcCallback>(ptr);
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to GetCallback");
        return optional<AVDataSrcDescriptor>(std::in_place_t{},
            AVDataSrcDescriptor{std::move(errFileSize), std::move(*errorCallback)});
    }

    auto cacheCallback = std::reinterpret_pointer_cast<DataSrcCallback>(callback);
    AVDataSrcDescriptor fdSrc = AVDataSrcDescriptor{std::move(fileSize), std::move(*cacheCallback)};
    MEDIA_LOGI("TaiheGetDataSrc Out");
    return optional<AVDataSrcDescriptor>(std::in_place_t{}, fdSrc);
}

void AVPlayerImpl::SetDataSrc(optional_view<AVDataSrcDescriptor> dataSrc)
{
    OHOS::Media::MediaTrace trace("AVPlayerTaihe::set dataSrc");
    MEDIA_LOGI("TaiheSetDataSrc In");

    if (this->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set dataSrc");
        return;
    }
    this->StartListenCurrentResource();

    ani_env *env = taihe::get_env();
    if (dataSrc.has_value()) {
        dataSrcDescriptor_.fileSize = dataSrc.value().fileSize;
        if (dataSrcDescriptor_.fileSize < -1 || dataSrcDescriptor_.fileSize == 0) {
            this->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check parameter fileSize");
            return;
        }
        MEDIA_LOGI("Recvive filesize is %{public}" PRId64 "", dataSrcDescriptor_.fileSize);
        dataSrcCb_ = std::make_shared<MediaDataSourceCallback>(dataSrcDescriptor_.fileSize);
        auto callbackPtr = std::make_shared<DataSrcCallback>(dataSrc.value().callback);
        std::shared_ptr<uintptr_t> callback = std::reinterpret_pointer_cast<uintptr_t>(callbackPtr);
        dataSrcDescriptor_.callback = callback;
        std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, dataSrcDescriptor_.callback);
        dataSrcCb_->SaveCallbackReference(READAT_CALLBACK_NAME, autoRef);
        if (player_ != nullptr) {
            if (player_->SetSource(dataSrcCb_) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource DataSrc failed");
            } else {
                state_ = PlayerStates::PLAYER_INITIALIZED;
            }
            if (dataSrcDescriptor_.fileSize == -1) {
                isLiveStream_ = true;
            }
        }
        MEDIA_LOGI("TaiheSetDataSrc Out");
    }
}

optional<string> AVPlayerImpl::GetSurfaceId()
{
    MediaTrace trace("AVPlayerTaihe::get surface");
    MEDIA_LOGD("TaiheGetSurfaceID In");

    string surfaceId = MediaTaiheUtils::ToTaiheString(surface_);
    MEDIA_LOGI("TaiheGetSurfaceID Out Current SurfaceID: %{public}s", surface_.c_str());
    return optional<string>(std::in_place_t{}, surfaceId);
}

bool __attribute__((visibility("default"))) StrToULL(const std::string &str, uint64_t &value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front())), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    unsigned long long result = strtoull(valStr.c_str(), &end, DECIMAL);
    // end will not be nullptr here
    CHECK_AND_RETURN_RET_LOG(result <= ULLONG_MAX, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != valStr.c_str() && end[0] == '\0' && errno != ERANGE, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    value = result;
    return true;
}

#ifdef SUPPORT_VIDEO
void AVPlayerImpl::SetSurface(const std::string &surfaceStr)
{
    MEDIA_LOGI("get surface, surfaceStr = %{public}s", surfaceStr.c_str());
    uint64_t surfaceId = 0;
    if (surfaceStr.empty() || surfaceStr[0] < '0' || surfaceStr[0] > '9') {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "Please obtain the surface from XComponentController.getXComponentSurfaceId");
        return;
    }
    if (!StrToULL(surfaceStr, surfaceId)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, failed to obtain surfaceId");
        return;
    }
    MEDIA_LOGI("get surface, surfaceId = (%{public}" PRIu64 ")", surfaceId);

    auto surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SurfaceUtils cannot convert ID to Surface");
        return;
    }

    auto task = std::make_shared<TaskHandler<void>>([this, surface]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " SetSurface Task", FAKE_POINTER(this));
        if (player_ != nullptr) {
            (void)player_->SetVideoSurface(surface);
        }
    });
    (void)taskQue_->EnqueueTask(task);
}
#else
void AVPlayerImpl::SetSurface(const std::string &surfaceStr)
{
    (void)surfaceStr;
    OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The music player does not need to support (Surface)");
}
#endif

void AVPlayerImpl::SetSurfaceId(optional_view<string> surfaceId)
{
    MediaTrace trace("AVPlayerTaihe::set surface");
    MEDIA_LOGD("TaiheSetSurfaceID In");

    std::string curState = this->GetCurrentState();
    bool setSurfaceFirst = curState == AVPlayerState::STATE_INITIALIZED;
    bool switchSurface = curState == AVPlayerState::STATE_PREPARED ||
        curState == AVPlayerState::STATE_PLAYING ||
        curState == AVPlayerState::STATE_PAUSED ||
        curState == AVPlayerState::STATE_STOPPED ||
        curState == AVPlayerState::STATE_COMPLETED;

    if (setSurfaceFirst) {
        MEDIA_LOGI("TaiheSetSurfaceID set surface first in %{public}s state", curState.c_str());
    } else if (switchSurface) {
        MEDIA_LOGI("TaiheSetSurfaceID switch surface in %{public}s state", curState.c_str());
        std::string oldSurface = surface_;
        if (oldSurface.empty()) {
            this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "switch surface with no old surface");
            return;
        }
    } else {
        this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "the attribute(SurfaceID) can only be set in the initialized state");
        return;
    }

    if (surfaceId.has_value()) {
        surface_ = std::string(surfaceId.value());
    }
    SetSurface(surface_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetSurfaceID Out", FAKE_POINTER(this));
    return;
}

bool AVPlayerImpl::GetLoop()
{
    MediaTrace trace("AVPlayerTaihe::get loop");
    MEDIA_LOGI("TaiheGetLoop In");

    MEDIA_LOGI("TaiheGetLoop Out Current Loop: %{public}d", loop_);
    return loop_;
}

void AVPlayerImpl::SetLoop(bool loop)
{
    MediaTrace trace("AVPlayerTaihe::set loop");
    MEDIA_LOGI("TaiheSetLoop In");

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

    auto task = std::make_shared<TaskHandler<void>>([this]() {
        MEDIA_LOGD("SetLooping Task");
        if (player_ != nullptr) {
            (void)player_->SetLooping(loop_);
        }
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetLoop Out", FAKE_POINTER(this));
    return;
}

optional<ohos::multimedia::media::AVFileDescriptor> AVPlayerImpl::GetFdSrc()
{
    MediaTrace trace("AVPlayerTaihe::get fd");
    MEDIA_LOGI("TaiheGetAVFileDescriptor In");

    ohos::multimedia::media::AVFileDescriptor fdSrc;
    fdSrc.fd = fileDescriptor_.fd;
    fdSrc.offset = optional<int64_t>(std::in_place_t{}, fileDescriptor_.offset);
    fdSrc.length = optional<int64_t>(std::in_place_t{}, fileDescriptor_.length);
    MEDIA_LOGI("TaiheGetAVFileDescriptor Out");
    return optional<ohos::multimedia::media::AVFileDescriptor>(std::in_place_t{}, fdSrc);
}

void AVPlayerImpl::SetFdSrc(optional_view<ohos::multimedia::media::AVFileDescriptor> fdSrc)
{
    MediaTrace trace("AVPlayerTaihe::set fd");
    MEDIA_LOGI("TaiheSetAVFileDescriptor In");

    if (this->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        this->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set fd");
        return;
    }

    this->StartListenCurrentResource();

    if (fdSrc.has_value()) {
        fileDescriptor_.fd = fdSrc.value().fd;
        fileDescriptor_.offset = fdSrc.value().offset.has_value() ? fdSrc.value().offset.value() : 0;
        fileDescriptor_.length = fdSrc.value().length.has_value() ? fdSrc.value().length.value() : -1;
    }

    auto task = std::make_shared<TaskHandler<void>>([this]() {
        MEDIA_LOGI("SetAVFileDescriptor Task");
        if (player_ != nullptr) {
            auto playerFd = fileDescriptor_;
#ifdef __linux__
            FILE *reopenFile = nullptr;
            auto res = FdUtils::ReOpenFd(playerFd.fd, reopenFile);
            playerFd.fd = res == MSERR_OK ? fileno(reopenFile) : playerFd.fd;
#endif
            MEDIA_LOGI("TaiheSetAVFileDescriptor fd: %{public}d, offset: %{public}"
                PRId64 ", size: %{public}" PRId64, playerFd.fd, playerFd.offset, playerFd.length);
            if (player_->SetSource(playerFd.fd, playerFd.offset, playerFd.length) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource FileDescriptor failed");
            }
#ifdef __linux__
            if (reopenFile != nullptr) {
                fclose(reopenFile);
            }
#endif
        }
    });
    (void)taskQue_->EnqueueTask(task);

    MEDIA_LOGI("TaiheSetAVFileDescriptor Out");
    return;
}

void AVPlayerImpl::SetSpeed(PlaybackSpeed speed)
{
    MediaTrace trace("AVPlayerTaihe::setSpeed");
    MEDIA_LOGI("TaiheSetSpeed In");

    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support speed");
        return;
    }

    int32_t mode = SPEED_FORWARD_1_00_X;
    mode = static_cast<int32_t>(speed.get_key());
    if (mode < SPEED_FORWARD_0_75_X || mode > SPEED_FORWARD_0_125_X) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the speed mode");
        return;
    }

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport speed operation");
        return;
    }

    auto task = std::make_shared<TaskHandler<void>>([this, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            (void)player_->SetPlaybackSpeed(static_cast<PlaybackRateMode>(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task Out", FAKE_POINTER(this));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetSpeed EnqueueTask In", FAKE_POINTER(this));
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetSpeed Out", FAKE_POINTER(this));
    return;
}

PlayerSeekMode AVPlayerImpl::TransferSeekMode(int32_t mode)
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

void AVPlayerImpl::SeekEnqueueTask(AVPlayerImpl *taihePlayer, int32_t time, int32_t mode)
{
    auto task = std::make_shared<TaskHandler<void>>([taihePlayer, time, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSeek Task In", FAKE_POINTER(taihePlayer));
        if (taihePlayer->player_ != nullptr) {
            (void)taihePlayer->player_->Seek(time, taihePlayer->TransferSeekMode(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSeek Task Out", FAKE_POINTER(taihePlayer));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSeek EnqueueTask In", FAKE_POINTER(taihePlayer));
    (void)taihePlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSeek Out", FAKE_POINTER(taihePlayer));
}

void AVPlayerImpl::Seek(int32_t timeMs, optional_view<SeekMode> mode)
{
    MediaTrace trace("AVPlayerTaihe::seek");
    MEDIA_LOGI("TaiheSeek in");
    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support seek");
        return;
    }
    int32_t time = timeMs;

    if (time < 0 && !mode.has_value()) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
        return;
    }
    int32_t seekMode = SEEK_PREVIOUS_SYNC;
    if (mode.has_value()) {
        seekMode = static_cast<int32_t>(mode.value().get_key());
        if (seekMode < SEEK_NEXT_SYNC || seekMode > SEEK_CONTINUOUS_TS_ENUM_NUM) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek mode");
            return;
        }
        bool isNegativeTime = time < 0;
        bool isExitSeekContinuous = time == -1 && seekMode == SEEK_CONTINUOUS_TS_ENUM_NUM;
        if (isNegativeTime && !isExitSeekContinuous) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
            return;
        }
    }
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport seek operation");
        return;
    }
    SeekEnqueueTask(this, time, seekMode);
    return;
}

optional<VideoScaleType> AVPlayerImpl::GetVideoScaleType()
{
    MediaTrace trace("AVPlayerTaihe::get videoScaleType");
    MEDIA_LOGI("TaiheGetVideoScaleType In");

    VideoScaleType::key_t key;
    MediaTaiheUtils::GetEnumKeyByValue<VideoScaleType>(videoScaleType_, key);
    VideoScaleType videoScaleType = VideoScaleType(key);
    MEDIA_LOGI("TaiheGetVideoScaleType Out Current VideoScale: %{public}d", videoScaleType_);
    return optional<VideoScaleType>(std::in_place_t{}, videoScaleType);
}

void AVPlayerImpl::SetVideoScaleType(optional_view<VideoScaleType> videoScaleType)
{
    MediaTrace trace("AVPlayerTaihe::set videoScaleType");
    MEDIA_LOGI("TaiheSetVideoScaleType In");

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video scale operation");
        return;
    }

    int32_t scaleType = 0;
    if (videoScaleType.has_value()) {
        scaleType = static_cast<int32_t>(videoScaleType.value().get_value());
    }
    if (scaleType < static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT)
        || scaleType > static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT_CROP)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input scale type");
        return;
    }
    videoScaleType_ = scaleType;

    auto task = std::make_shared<TaskHandler<void>>([this, scaleType]() {
        MEDIA_LOGI("SetVideoScaleType Task");
        if (player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, scaleType);
            (void)player_->SetParameter(format);
        }
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("TaiheSetVideoScaleType Out");
    return;
}

bool AVPlayerImpl::IsSeekContinuousSupported()
{
    MediaTrace trace("AVPlayerTaihe::isSeekContinuousSupported");
    MEDIA_LOGI("TaiheIsSeekContinuousSupported In");
    bool isSeekContinuousSupported = false;

    if (player_ != nullptr) {
        isSeekContinuousSupported = player_->IsSeekContinuousSupported();
    }
    MEDIA_LOGI("TaiheIsSeekContinuousSupported Out");
    return isSeekContinuousSupported;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::GetTrackDescriptionTask(const std::shared_ptr<AVPlayerContext>
                                                                            &Ctx)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, &trackInfo = Ctx->trackInfoVec_]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetTrackDescription Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        trackInfo.clear();
        if (IsControllable()) {
            (void)player_->GetVideoTrackInfo(trackInfo);
            (void)player_->GetAudioTrackInfo(trackInfo);
            (void)player_->GetSubtitleTrackInfo(trackInfo);
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                           "current state unsupport get track description");
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetTrackDescription Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

array<map<string, MediaDescriptionValue>> AVPlayerImpl::GetTrackDescriptionSync()
{
    MediaTrace trace("AVPlayer::get trackDescription");
    MEDIA_LOGI("GetTrackDescription In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetTrackDescription EnqueueTask In", FAKE_POINTER(this));
    context->asyncTask = GetTrackDescriptionTask(context);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetTrackDescription EnqueueTask Out", FAKE_POINTER(this));
    auto result = context->asyncTask->GetResult();
    if (!result.HasResult()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "task has been cleared");
    }
    if (result.Value().first != MSERR_EXT_API9_OK) {
        set_business_error(result.Value().first, result.Value().second);
    }
    auto vec = context->trackInfoVec_;
    std::vector<map<string, MediaDescriptionValue>> tdResult;
    for (size_t index = 0; index < vec.size(); ++index) {
        map<string, MediaDescriptionValue> description;
        description = MediaTaiheUtils::CreateFormatBuffer(vec[index]);
        tdResult[index] = description;
    }
    return array<map<string, MediaDescriptionValue>>(tdResult);
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::StopTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (IsControllable()) {
            int32_t ret = player_->Stop();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Stop");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
        } else if (GetCurrentState() == AVPlayerState::STATE_STOPPED) {
            MEDIA_LOGE("current state is stopped, invalid operation");
        }  else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not prepared/playing/paused/completed, unsupport stop operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::AddSubtitleFromFdSync(int32_t fd, int64_t offset, int64_t length)
{
    MEDIA_LOGI("AddSubtitleAVFileDescriptor In");
    auto task = std::make_shared<TaskHandler<void>>([this, fd, offset, length]() {
        if (player_ != nullptr) {
            if (player_->AddSubSource(fd, offset, length) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleAVFileDescriptor");
            }
        }
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("AddSubtitleAVFileDescriptor Out");
}

void AVPlayerImpl::AddSubtitleFromUrlSync(::taihe::string_view url)
{
    MEDIA_LOGI("AddSubtitleFromUrlSync In");
    std::string url_ = std::string(url.data(), url.size());

    player_->AddSubSource(url_);
    MEDIA_LOGI("AddSubtitleFromUrlSync Out");
}

void AVPlayerImpl::DeselectTrackSync(int32_t index)
{
    MEDIA_LOGI("deselectTrack In");
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video scale operation");
        return;
    }
    auto task = std::make_shared<TaskHandler<void>>([this, index]() {
        MEDIA_LOGI("deselectTrack Task");
        if (player_ != nullptr) {
            (void)player_->DeselectTrack(index);
        }
        MEDIA_LOGI("deselectTrack Task end");
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("deselectTrack Out");
}

int32_t AVPlayerImpl::getPlaybackPosition()
{
    MEDIA_LOGD("getPlaybackPosition In");
    std::string curState = this->GetCurrentState();
    if (curState == AVPlayerState::STATE_PLAYING &&
        curState == AVPlayerState::STATE_PAUSED &&
        curState == AVPlayerState::STATE_PREPARED &&
        curState == AVPlayerState::STATE_COMPLETED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video playback position");
        return 0;
    }
    int32_t playbackPosition = 0;
    (void)player_->GetPlaybackPosition(playbackPosition);
    if (playbackPosition != 0) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetPlaybackPosition Out", FAKE_POINTER(this));
    }
    return playbackPosition;
}

void AVPlayerImpl::setBitrate(int32_t bitrate)
{
    MEDIA_LOGI("SelectBitrate In");
    if (bitrate < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input bitrate");
        return ;
    }
    if (IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport select bitrate operation");
        return ;
    }
    auto task = std::make_shared<TaskHandler<void>>([this, bitrate]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " SelectBitrate Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            player_->SelectBitRate(static_cast<uint32_t>(bitrate));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " SelectBitrate Task Out", FAKE_POINTER(this));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SelectBitrate EnqueueTask In", FAKE_POINTER(this));
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SelectBitrate Out", FAKE_POINTER(this));
}

void AVPlayerImpl::StopSync()
{
    MediaTrace trace("AVPlayerTaihe::stop");
    MEDIA_LOGI("TaiheStop In");

    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_IDLE ||
        state == AVPlayerState::STATE_INITIALIZED ||
        state == AVPlayerState::STATE_RELEASED ||
        state == AVPlayerState::STATE_ERROR) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport stop operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheStop EnqueueTask In", FAKE_POINTER(this));
        context->asyncTask = StopTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheStop EnqueueTask Out", FAKE_POINTER(this));
    }
    MEDIA_LOGI("Wait TaiheStop Task Start");
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    MEDIA_LOGI("Wait TaiheStop Task End");
    return;
}

bool AVPlayerImpl::IsSystemApp()
{
    static bool isSystemApp = false;
#ifndef CROSS_PLATFORM
    static std::once_flag once;
    std::call_once(once, [] {
        uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
        isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    });
#endif
    return isSystemApp;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::PlayTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_PREPARED ||
            state == AVPlayerState::STATE_PAUSED ||
            state == AVPlayerState::STATE_COMPLETED) {
            int32_t ret = player_->Play();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Play");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() {
                return stopWait_.load() || isInterrupted_.load() || avplayerExit_;
            });

            if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "failed to play, avplayer enter error status, please check error callback messages!");
            }
        } else if (state == AVPlayerState::STATE_PLAYING) {
            if (IsSystemApp()) {
                player_->Seek(-1, SEEK_CONTINOUS);
            }
            MEDIA_LOGE("current state is playing, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not prepared/paused/completed, unsupport play operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::PlaySync()
{
    MediaTrace trace("AVPlayerTaihe::play");
    MEDIA_LOGI("TaihePlay In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_PREPARED &&
        state != AVPlayerState::STATE_PAUSED &&
        state != AVPlayerState::STATE_COMPLETED &&
        state != AVPlayerState::STATE_PLAYING) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/paused/completed, unsupport play operation");
    } else if (state == AVPlayerState::STATE_COMPLETED && IsLiveSource()) {
        set_business_error(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "In live mode, replay not be allowed.");
    } else {
        context->asyncTask = PlayTask();
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePlay EnqueueTask In", FAKE_POINTER(this));
    auto t1 = std::thread([context]() {
        context->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
    });
    t1.detach();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePlay Out", FAKE_POINTER(this));
}

void AVPlayerImpl::PauseListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Pause();
    }
}

void AVPlayerImpl::ResetUserParameters()
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

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::ResetTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task In", FAKE_POINTER(this));
        PauseListenCurrentResource(); // Pause event listening for the current resource
        ResetUserParameters();
        {
            isInterrupted_.store(false);
            std::unique_lock<std::mutex> lock(taskMutex_);
            if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "current state is not playing, unsupport pause operation");
            } else if (GetCurrentState() == AVPlayerState::STATE_IDLE) {
                MEDIA_LOGE("current state is idle, invalid operation");
            } else {
                int32_t ret = player_->Reset();
                if (ret != MSERR_OK) {
                    auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                    return TaskRet(errCode, "failed to Reset");
                }
                stopWait_ = false;
                stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            }
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task, true); // CancelNotExecutedTask
    isInterrupted_.store(true);
    stateChangeCond_.notify_all();
    return task;
}

void AVPlayerImpl::ResetSync()
{
    MediaTrace trace("AVPlayerTaihe::reset");
    MEDIA_LOGI("TaiheReset In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is released, unsupport reset operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheReset EnqueueTask In", FAKE_POINTER(this));
        context->asyncTask = ResetTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheReset EnqueueTask Out", FAKE_POINTER(this));
        if (dataSrcCb_ != nullptr) {
            dataSrcCb_->ClearCallbackReference();
            dataSrcCb_ = nullptr;
        }
        isLiveStream_ = false;
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheReset Out", FAKE_POINTER(this));
}

void AVPlayerImpl::StopTaskQue()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " StopTaskQue In", FAKE_POINTER(this));
    {
        std::unique_lock<std::mutex> lock(taskMutex_);
        avplayerExit_ = true;
    }
    stateChangeCond_.notify_all();
    taskQue_->Stop();
    std::unique_lock<std::mutex> lock(mutex_);
    taskQueStoped_ = true;
    stopTaskQueCond_.notify_all();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " StopTaskQue Out", FAKE_POINTER(this));
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::ReleaseTask()
{
    std::shared_ptr<TaskHandler<TaskRet>> task = nullptr;
    if (!isReleased_.load()) {
        task = std::make_shared<TaskHandler<TaskRet>>([this]() {
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
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Release Task Out", FAKE_POINTER(this));
            std::thread([this] () -> void { StopTaskQue(); }).detach();
            return TaskRet(MSERR_EXT_API9_OK, "Success");
        });

        isReleased_.store(true);
        (void)taskQue_->EnqueueTask(task, true); // CancelNotExecutedTask
        if (taskQue_->IsTaskExecuting()) {
            MEDIA_LOGW("0x%{public}06" PRIXPTR " Cancel Executing Task, ReleaseTask Report Error", FAKE_POINTER(this));
            NotifyState(PlayerStates::PLAYER_STATE_ERROR);
        }
    }
    return task;
}

void AVPlayerImpl::ReleaseSync()
{
    MediaTrace trace("AVPlayerTaihe::release");
    MEDIA_LOGI("TaiheRelease In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheRelease EnqueueTask In", FAKE_POINTER(this));
    context->asyncTask = ReleaseTask();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheRelease EnqueueTask Out", FAKE_POINTER(this));
    if (dataSrcCb_ != nullptr) {
        dataSrcCb_->ClearCallbackReference();
        dataSrcCb_ = nullptr;
    }

    auto t1 = std::thread([context]() {
        context->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
    });
    t1.detach();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheRelease Out", FAKE_POINTER(this));
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::PauseTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_PLAYING) {
            int32_t ret = player_->Pause();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Pause");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
        } else if (state == AVPlayerState::STATE_PAUSED) {
            MEDIA_LOGE("current state is paused, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not playing, unsupport pause operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::PauseSync()
{
    MediaTrace trace("AVPlayerTaihe::pause");
    MEDIA_LOGI("TaihePause In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_PLAYING && state != AVPlayerState::STATE_PAUSED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not playing, unsupport pause operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePause EnqueueTask In", FAKE_POINTER(this));
        context->asyncTask = PauseTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePause EnqueueTask Out", FAKE_POINTER(this));
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePause Out", FAKE_POINTER(this));
    return;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::PrepareTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED ||
            state == AVPlayerState::STATE_STOPPED) {
            int32_t ret = player_->PrepareAsync();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to prepare");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() {
                return stopWait_.load() || isInterrupted_.load() || avplayerExit_;
            });
            if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "failed to prepare, avplayer enter error status, please check error callback messages!");
            }
        } else if (state == AVPlayerState::STATE_PREPARED) {
            MEDIA_LOGE("current state is prepared, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not stopped or initialized, unsupport prepare operation");
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::PrepareSync()
{
    MediaTrace trace("AVPlayerTaihe::prepare");
    MEDIA_LOGI("TaihePrepare In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    auto state = GetCurrentState();
    if (state != AVPlayerState::STATE_INITIALIZED &&
        state != AVPlayerState::STATE_STOPPED &&
        state != AVPlayerState::STATE_PREPARED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not stopped or initialized, unsupport prepare operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePrepare EnqueueTask In", FAKE_POINTER(this));
        context->asyncTask = PrepareTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePrepare EnqueueTask Out", FAKE_POINTER(this));
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
    });
    t1.detach();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaihePrepare Out", FAKE_POINTER(this));
}

void AVPlayerImpl::SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[callbackName] = ref;
    if (playerCb_ != nullptr) {
        playerCb_->SaveCallbackReference(callbackName, ref);
    }
}

void AVPlayerImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnError");
    MEDIA_LOGD("TaiheOnError In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference("error", autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnError callbackName: error success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnStateChange(callback_view<void(string_view, ohos::multimedia::media::StateChangeReason)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnStateChange");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(string_view, ohos::multimedia::media::StateChangeReason)>> taiheCallback =
        std::make_shared<taihe::callback<void(string_view, ohos::multimedia::media::StateChangeReason)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_STATE_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnStateChange callbackName: stateChange success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnMediaKeySystemInfoUpdate(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnMediaKeySystemInfoUpdate");
    MEDIA_LOGD("OnMediaKeySystemInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_DRM_INFO_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR
        " TaiheOnMediaKeySystemInfoUpdate callbackName: mediaKeySystemInfoUpdate success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnEndOfStream(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnEndOfStream");
    MEDIA_LOGD("TaiheOnEndOfStream In");
    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_END_OF_STREAM, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnEndOfStream callbackName: endOfStream success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnStartRenderFrame(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnStartRenderFrame");
    MEDIA_LOGD("TaiheOnStartRenderFrame In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_START_RENDER_FRAME, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnStartRenderFrame callbackName: startRenderFrame success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSeekDone(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnSeekDone");
    MEDIA_LOGD("TaiheOnSeekDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_SEEK_DONE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnSeekDone callbackName: seekDone success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnDurationUpdate(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnDurationUpdate");
    MEDIA_LOGD("TaiheOnDurationUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_DURATION_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnDurationUpdate callbackName: durationUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnTimeUpdate(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnTimeUpdate");
    MEDIA_LOGD("TaiheOnTimeUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_TIME_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnTimeUpdate callbackName: timeUpdate success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnVolumeChange(callback_view<void(double)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnVolumeChange");
    MEDIA_LOGD("TaiheOnVolumeChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(double)>> taiheCallback =
            std::make_shared<taihe::callback<void(double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_VOLUME_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnVolumeChange callbackName: volumeChange success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSpeedDone(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnSpeedDone");
    MEDIA_LOGD("TaiheOnSpeedDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_SPEED_DONE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnSpeedDone callbackName: speedDone success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnBitrateDone(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnBitrateDone");
    MEDIA_LOGD("TaiheOnBitrateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_BITRATE_DONE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnBitrateDone callbackName: bitrateDone success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnAvailableBitrates(callback_view<void(array_view<int32_t>)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnBitrateDone");
    MEDIA_LOGD("TaiheOnBitrateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<int32_t>)>> taiheCallback =
            std::make_shared<taihe::callback<void(array_view<int32_t>)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_AVAILABLE_BITRATES, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnAvailableBitrates callbackName: availableBitrates success",
        FAKE_POINTER(this));
    return;
}
void AVPlayerImpl::OnAmplitudeUpdate(callback_view<void(array_view<float>)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnBitrateDone");
    MEDIA_LOGD("TaiheOnBitrateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<float>)>> taiheCallback =
            std::make_shared<taihe::callback<void(array_view<float>)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnAmplitudeUpdate callbackName: amplitudeUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnBufferingUpdate(callback_view<void(ohos::multimedia::media::BufferingInfoType, int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnBufferingUpdate");
    MEDIA_LOGD("TaiheOnBufferingUpdate In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(ohos::multimedia::media::BufferingInfoType, int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(ohos::multimedia::media::BufferingInfoType, int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_BUFFERING_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnBufferingUpdate callbackName: bufferingUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnVideoSizeChange(callback_view<void(int32_t, int32_t)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnVideoSizeChange");
    MEDIA_LOGD("TaiheOnVideoSizeChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t, int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t, int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnVideoSizeChange callbackName: videoSizeChange success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnTrackChange(callback_view<void(int32_t, bool)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnTrackChange");
    MEDIA_LOGD("TaiheOnTrackChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(int32_t, bool)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t, bool)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_TRACKCHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnTrackChange callbackName: trackChange success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSubtitleUpdate(callback_view<void(::ohos::multimedia::media::SubtitleInfo const&)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnSubtitleUpdate");
    MEDIA_LOGD("TaiheOnSubtitleUpdate In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::ohos::multimedia::media::SubtitleInfo const&)>> taiheCallback =
            std::make_shared<taihe::callback<void(::ohos::multimedia::media::SubtitleInfo const&)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_SUBTITLE_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnSubtitleUpdate callbackName: subtitleUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSuperResolutionChanged(callback_view<void(bool)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnSuperResolutionChanged");
    MEDIA_LOGD("TaiheOnSuperResolutionChanged In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(bool)>> taiheCallback =
            std::make_shared<taihe::callback<void(bool)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnSuperResolutionChanged callbackName: superResolutionChanged success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnTrackInfoUpdate(callback_view<void(array_view<map<string, MediaDescriptionValue>>)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnTrackInfoUpdate");
    MEDIA_LOGD("TaiheOnTrackInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<map<string, MediaDescriptionValue>>)>> taiheCallback =
            std::make_shared<taihe::callback<void(array_view<map<string, MediaDescriptionValue>>)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnTrackInfoUpdate callbackName: trackInfoUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSeiMessageReceived(array_view<int32_t> payloadTypes,
    callback_view<void(array_view<SeiMessage>, optional_view<int32_t>)> callback)
{
    MediaTrace trace("AVPlayerTaihe::OnSeiMessageReceived");
    MEDIA_LOGD("TaiheOnSeiMessageReceived In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    bool seiMessageCallbackflag_ = true;

    if (player_ != nullptr && seiMessageCallbackflag_) {
        MEDIA_LOGI("seiMessageCallbackflag_ = %{public}d", seiMessageCallbackflag_);
        std::vector<int32_t> payloadTypesInt;
        payloadTypesInt.reserve(payloadTypes.size());
        for (int32_t value : payloadTypes) {
            payloadTypesInt.push_back(value);
        }
        player_->SetSeiMessageCbStatus(seiMessageCallbackflag_, payloadTypesInt);
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<SeiMessage>, optional_view<int32_t>)>> taiheCallback =
            std::make_shared<taihe::callback<void(array_view<SeiMessage>, optional_view<int32_t>)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnSeiMessageReceived callbackName: seiMessageReceived success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffError");
    MEDIA_LOGD("TaiheOffError In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    std::string callbackName = "error";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffError End");
}

void AVPlayerImpl::OffStateChange(optional_view<callback<void(string_view,
    ohos::multimedia::media::StateChangeReason)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffStateChange");
    MEDIA_LOGD("OffStateChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "stateChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffStateChange End");
}

void AVPlayerImpl::OffMediaKeySystemInfoUpdate(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffMediaKeySystemInfoUpdate");
    MEDIA_LOGD("OffMediaKeySystemInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "mediaKeySystemInfoUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffMediaKeySystemInfoUpdate End");
}

void AVPlayerImpl::OffEndOfStream(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffEndOfStream");
    MEDIA_LOGD("OffEndOfStream In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "endOfStream";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffEndOfStream End");
}
void AVPlayerImpl::OffStartRenderFrame(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffStartRenderFrame");
    MEDIA_LOGD("OffStartRenderFrame In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "startRenderFrame";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffStartRenderFrame End");
}
void AVPlayerImpl::OffSeekDone(optional_view<callback<void(int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffSeekDone");
    MEDIA_LOGD("OffSeekDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "seekDone";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffSeekDone End");
}
void AVPlayerImpl::OffDurationUpdate(optional_view<callback<void(int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffDurationUpdate");
    MEDIA_LOGD("OffDurationUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "durationUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffDurationUpdate End");
}
void AVPlayerImpl::OffTimeUpdate(optional_view<callback<void(int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffTimeUpdate");
    MEDIA_LOGD("OffTimeUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "timeUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffTimeUpdate End");
}
void AVPlayerImpl::OffVolumeChange(optional_view<callback<void(double)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffVolumeChange");
    MEDIA_LOGD("OffVolumeChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "volumeChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffVolumeChange End");
}
void AVPlayerImpl::OffSpeedDone(optional_view<callback<void(int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffSpeedDone");
    MEDIA_LOGD("OffSpeedDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "speedDone";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffSpeedDone End");
}
void AVPlayerImpl::OffBitrateDone(optional_view<callback<void(int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffBitrateDone");
    MEDIA_LOGD("OffBitrateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "bitrateDone";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffBitrateDone End");
}
void AVPlayerImpl::OffAvailableBitrates(optional_view<callback<void(array_view<int32_t>)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffAvailableBitrates");
    MEDIA_LOGD("OffAvailableBitrates In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "availableBitrates";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffAvailableBitrates End");
}
void AVPlayerImpl::OffAmplitudeUpdate(optional_view<callback<void(array_view<float>)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffAmplitudeUpdate");
    MEDIA_LOGD("OffAmplitudeUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "amplitudeUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffAmplitudeUpdate End");
}

void AVPlayerImpl::OffBufferingUpdate(optional_view<callback<void(ohos::multimedia::media::BufferingInfoType,
    int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffBufferingUpdate");
    MEDIA_LOGD("OffBufferingUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "bufferingUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffBufferingUpdate End");
}
void AVPlayerImpl::OffVideoSizeChange(optional_view<callback<void(int32_t, int32_t)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffVideoSizeChange");
    MEDIA_LOGD("OffVideoSizeChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "videoSizeChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffVideoSizeChange End");
}

void AVPlayerImpl::OffTrackChange(optional_view<callback<void(int32_t, bool)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffTrackChange");
    MEDIA_LOGD("OffTrackChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "trackChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffTrackChange End");
}

void AVPlayerImpl::OffSubtitleUpdate(optional_view<callback<void(SubtitleInfo const&)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffSubtitleUpdate");
    MEDIA_LOGD("OffSubtitleUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "subtitleUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffSubtitleUpdate End");
}

void AVPlayerImpl::OffSuperResolutionChanged(optional_view<callback<void(bool)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffSuperResolutionChanged");
    MEDIA_LOGD("OffSuperResolutionChanged In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "superResolutionChanged";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffSuperResolutionChanged End");
}
void AVPlayerImpl::OffTrackInfoUpdate(optional_view<callback<void(array_view<map<string, int32_t>>)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffTrackInfoUpdate");
    MEDIA_LOGD("OffTrackInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "trackInfoUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffTrackInfoUpdate End");
}

void AVPlayerImpl::OffSeiMessageReceived(array_view<int32_t> payloadTypes,
    optional_view<callback<void(array_view<::ohos::multimedia::media::SeiMessage>,
    optional_view<int32_t>)>> callback)
{
    MediaTrace trace("AVPlayerTaihe::OffSeiMessageReceived");
    MEDIA_LOGD("OffSeiMessageReceived In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "seiMessageReceived";
    std::vector<int32_t> payloadTypeVec;
    payloadTypeVec.reserve(payloadTypes.size());
    for (int32_t value : payloadTypes) {
        payloadTypeVec.push_back(static_cast<int32_t>(value));
    }
    if (!payloadTypes.empty()) {
        SeiMessageCallbackOff(callbackName, payloadTypeVec);
        ClearCallbackReference(callbackName);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " OffSeiMessageReceived success", FAKE_POINTER(this));
        return;
    }

    SeiMessageCallbackOff(callbackName, payloadTypeVec);
    MEDIA_LOGI("OffSeiMessageReceived End");
    return;
}

bool AVPlayerImpl::GetIntArrayArgument(std::vector<int32_t> &vec, const std::vector<int32_t> &inputArray)
{
    if (inputArray.empty()) {
        return false;
    }

    for (const auto &element : inputArray) {
        vec.push_back(element);
    }

    return true;
}

void AVPlayerImpl::SeiMessageCallbackOff(std::string &callbackName, const std::vector<int32_t> &payloadTypes)
{
    if (!seiMessageCallbackflag_ || callbackName != "seiMessageReceived") {
        return;
    }
    seiMessageCallbackflag_ = false;
    if (player_ == nullptr) {
        return;
    }
    (void)player_->SetSeiMessageCbStatus(seiMessageCallbackflag_, payloadTypes);
}

void AVPlayerImpl::MaxAmplitudeCallbackOff(std::string callbackName)
{
    if (calMaxAmplitude_ && callbackName == "amplitudeUpdate") {
        calMaxAmplitude_ = false;
        if (player_ != nullptr) {
            player_->SetMaxAmplitudeCbStatus(calMaxAmplitude_);
        }
    }
}

void AVPlayerImpl::ClearCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->ClearCallbackReference(callbackName);
    }
    refMap_.erase(callbackName);
}

void AVPlayerImpl::NotifyDuration(int32_t duration)
{
    duration_ = duration;
}

void AVPlayerImpl::NotifyPosition(int32_t position)
{
    position_ = position;
}

bool AVPlayerImpl::IsControllable()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PLAYING ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    } else {
        return false;
    }
}

std::string AVPlayerImpl::GetCurrentState()
{
    if (isReleased_.load()) {
        return AVPlayerState::STATE_RELEASED;
    }
    std::string curState = AVPlayerState::STATE_ERROR;
    static const std::map<OHOS::Media::PlayerStates, std::string> stateMap = {
        {OHOS::Media::PLAYER_IDLE, AVPlayerState::STATE_IDLE},
        {OHOS::Media::PLAYER_INITIALIZED, AVPlayerState::STATE_INITIALIZED},
        {OHOS::Media::PLAYER_PREPARED, AVPlayerState::STATE_PREPARED},
        {OHOS::Media::PLAYER_STARTED, AVPlayerState::STATE_PLAYING},
        {OHOS::Media::PLAYER_PAUSED, AVPlayerState::STATE_PAUSED},
        {OHOS::Media::PLAYER_STOPPED, AVPlayerState::STATE_STOPPED},
        {OHOS::Media::PLAYER_PLAYBACK_COMPLETE, AVPlayerState::STATE_COMPLETED},
        {OHOS::Media::PLAYER_STATE_ERROR, AVPlayerState::STATE_ERROR},
    };
    if (stateMap.find(state_) != stateMap.end()) {
        curState = stateMap.at(state_);
    }
    return curState;
}

void AVPlayerImpl::NotifyState(OHOS::Media::PlayerStates state)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    if (state_ != state) {
        state_ = state;
        MEDIA_LOGI("0x%{public}06" PRIXPTR " notify %{public}s", FAKE_POINTER(this), GetCurrentState().c_str());
        stopWait_ = true;
        stateChangeCond_.notify_all();
    }
}

void AVPlayerImpl::NotifyVideoSize(int32_t width, int32_t height)
{
    width_ = width;
    height_ = height;
}

void AVPlayerImpl::NotifyIsLiveStream()
{
    isLiveStream_ = true;
}

void AVPlayerImpl::NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos)
{
    MEDIA_LOGD("NotifyDrmInfoUpdated");
    std::unique_lock<std::shared_mutex> lock(drmMutex_);
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

bool AVPlayerImpl::IsLiveSource() const
{
    return isLiveStream_;
}

int32_t AVPlayerImpl::GetJsApiVersion()
{
    if (player_ != nullptr && getApiVersionFlag_) {
        getApiVersionFlag_ = false;
        player_->GetApiVersion(g_apiVersion);
        MEDIA_LOGI("apiVersion is: %{public}d", g_apiVersion);
    }
    return g_apiVersion;
}

void AVPlayerImpl::SetSource(std::string url)
{
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        this->EnqueueNetworkTask(url);
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

void AVPlayerImpl::EnqueueFdTask(const int32_t fd)
{
    auto task = std::make_shared<TaskHandler<void>>([this, fd]() {
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
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            MEDIA_LOGI("Set source fd out");
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerImpl::EnqueueNetworkTask(const std::string url)
{
    auto task = std::make_shared<TaskHandler<void>>([this, url]() {
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
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() {
                return stopWait_.load() || avplayerExit_;
            });
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Set source network out", FAKE_POINTER(this));
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerImpl::QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN(!isReleased_.load());
    auto task = std::make_shared<TaskHandler<void>>([this, errorCode, errorMsg] {
        OnErrorCb(errorCode, errorMsg);
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerImpl::StartListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Start();
    }
}

void AVPlayerContext::SignError(int32_t code, const std::string &message)
{
    set_business_error(code, message);
    MEDIA_LOGE("SignError: %{public}s", message.c_str());
}

void AVPlayerImpl::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->OnErrorCb(errorCode, errorMsg);
    }
}

AVPlayer CreateAVPlayerSync()
{
    return make_holder<AVPlayerImpl, AVPlayer>();
}
}
TH_EXPORT_CPP_API_CreateAVPlayerSync(CreateAVPlayerSync);