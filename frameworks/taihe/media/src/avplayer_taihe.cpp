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
#ifdef SUPPORT_AVPLAYER_DRM
#include "key_session_taihe.h"
#endif
#ifdef SUPPORT_VIDEO
#include "surface_utils.h"
#endif
#include "fd_utils.h"
#include "media_source_taihe.h"
#ifndef CROSS_PLATFORM
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#endif

using namespace ANI::Media;
using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVPlayerTaihe"};
    constexpr uint32_t TASK_TIME_LIMIT_MS = 2000; // ms
    static int32_t g_apiVersion = -1;
    constexpr int32_t DECIMAL = 10;
    constexpr int32_t SEEK_CONTINUOUS_TS_ENUM_NUM = 3;
    constexpr int32_t PLAY_RANGE_DEFAULT_VALUE = -1;
    constexpr int32_t SEEK_MODE_CLOSEST = 2;
    constexpr int32_t API_VERSION_18 = 18;
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
    if (player_ == nullptr) {
        MEDIA_LOGE("failed to CreatePlayer");
        MediaTaiheUtils::ThrowExceptionError("failed to CreatePlayer");
        return;
    }
    taskQue_ = std::make_unique<OHOS::Media::TaskQueue>("OS_AVPlayerTaihe");
    (void)taskQue_->Start();

    playerCb_ = std::make_shared<AVPlayerCallback>(this);
    (void)player_->SetPlayerCallback(playerCb_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(this));
}

optional<string> AVPlayerImpl::GetUrl()
{
    OHOS::Media::MediaTrace trace("AVPlayerImpl::get url");
    MEDIA_LOGD("GetUrl In");
    string url = MediaTaiheUtils::ToTaiheString(url_);
    MEDIA_LOGD("GetUrl Out Current Url: %{private}s", url_.c_str());
    return optional<string>(std::in_place_t{}, url);
}

void AVPlayerImpl::SetUrl(optional_view<string> url)
{
    OHOS::Media::MediaTrace trace("AVPlayerImpl::set url");
    MEDIA_LOGD("SetUrl In");
    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return;
    }
    StartListenCurrentResource();
    if (url.has_value()) {
        url_ = std::string(url.value());
    }
    MEDIA_LOGD("SetUrl url: %{private}s", url_.c_str());
    SetSource(url_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetUrl Out", FAKE_POINTER(this));
}

optional<ohos::multimedia::audio::AudioEffectMode> AVPlayerImpl::GetAudioEffectMode()
{
    MediaTrace trace("AVPlayerImpl::GetAudioEffectMode");
    MEDIA_LOGI("TaiheGetAudioEffectMode In");
    ohos::multimedia::audio::AudioEffectMode::key_t audioEffectModeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEffectMode>(audioEffectMode_, audioEffectModeKey);
    ohos::multimedia::audio::AudioEffectMode audioEffectMode = ohos::multimedia::audio::AudioEffectMode(
        audioEffectModeKey);

    MEDIA_LOGI("TaiheGetAudioEffectMode Out");
    return optional<ohos::multimedia::audio::AudioEffectMode>(std::in_place_t{}, audioEffectMode);
}

void AVPlayerImpl::SetAudioEffectMode(optional_view<ohos::multimedia::audio::AudioEffectMode> audioEffectMode)
{
    MediaTrace trace("AVPlayerImpl::SetAudioEffectMode");
    MEDIA_LOGI("TaiheSetAudioEffectMode In");

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport audio effect mode operation");
        return;
    }
    int32_t effectMode = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    if (audioEffectMode.has_value()) {
        effectMode = static_cast<int32_t>(audioEffectMode.value());
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
    auto task = std::make_shared<TaskHandler<void>>([this, effectMode]() {
        MEDIA_LOGI("TaiheSetAudioEffectMode Task in");
        if (player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, effectMode);
            (void)player_->SetParameter(format);
        }
        MEDIA_LOGI("TaiheSetAudioEffectMode Task out");
    });
    (void)taskQue_->EnqueueTask(task);
    
    MEDIA_LOGI("TaiheSetAudioEffectMode Out");
    return;
}

int32_t AVPlayerImpl::GetWidth()
{
    MediaTrace trace("AVPlayerImpl::get width");
    MEDIA_LOGI("TaiheGetWidth");

    int32_t width = 0;
    if (IsControllable()) {
        width = width_;
    }

    return width;
}

int32_t AVPlayerImpl::GetHeight()
{
    MediaTrace trace("AVPlayerImpl::get height");
    MEDIA_LOGI("TaiheGetHeight");

    int32_t height = 0;
    if (IsControllable()) {
        height = height_;
    }

    return height;
}

string AVPlayerImpl::GetState()
{
    MediaTrace trace("AVPlayerImpl::get state");
    MEDIA_LOGD("TaiheGetState In");

    std::string curState = GetCurrentState();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheGetState curState: %{public}s ",
        FAKE_POINTER(this), curState.c_str());
    MEDIA_LOGD("TaiheGetState Out");
    return curState;
}

int32_t AVPlayerImpl::GetDuration()
{
    MediaTrace trace("AVPlayerImpl::get duration");
    MEDIA_LOGD("TaiheGetDuration In");

    int32_t duration = -1;
    if (IsControllable() && !IsLiveSource()) {
        duration = duration_;
    }

    std::string curState = GetCurrentState();
    MEDIA_LOGD("TaiheGetDuration Out, state %{public}s, duration %{public}d", curState.c_str(), duration);
    return duration;
}

int32_t AVPlayerImpl::GetCurrentTime()
{
    MediaTrace trace("AVPlayerImpl::get currentTime");
    MEDIA_LOGD("TaiheGetCurrentTime In");

    int32_t currentTime = -1;
    if (IsControllable()) {
        currentTime = position_;
    }

    if (IsLiveSource() && dataSrcCb_ == nullptr) {
        currentTime = -1;
    }
    std::string curState = GetCurrentState();
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
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check volume level");
        return;
    }
    volumeLevel = volume;

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
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

optional<ohos::multimedia::audio::AudioRendererInfo> AVPlayerImpl::GetAudioRendererInfo()
{
    MediaTrace trace("AVPlayerImpl::get audioRendererInfo");
    MEDIA_LOGI("TaiheGetAudioRendererInfo In");
    ohos::multimedia::audio::StreamUsage::key_t streamUsageKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::StreamUsage>(audioRendererInfo_.streamUsage,
        streamUsageKey);
    ohos::multimedia::audio::StreamUsage streamUsage = ohos::multimedia::audio::StreamUsage(streamUsageKey);
    int32_t rendererFlags = audioRendererInfo_.rendererFlags;
    ohos::multimedia::audio::AudioVolumeMode::key_t volumeModeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioVolumeMode>(audioRendererInfo_.volumeMode,
        volumeModeKey);
    ohos::multimedia::audio::AudioVolumeMode volumeMode = ohos::multimedia::audio::AudioVolumeMode(volumeModeKey);

    ohos::multimedia::audio::AudioRendererInfo result = {
        std::move(streamUsage), std::move(rendererFlags),
        optional<ohos::multimedia::audio::AudioVolumeMode>(std::in_place_t{}, volumeMode)
    };
    MEDIA_LOGI("GetAudioRendererInfo Out");

    return optional<ohos::multimedia::audio::AudioRendererInfo>(std::in_place_t{}, result);
}

bool AVPlayerImpl::HandleParameter(ohos::multimedia::audio::AudioRendererInfo src,
    OHOS::AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    int32_t content = OHOS::AudioStandard::CONTENT_TYPE_UNKNOWN;
    int32_t usage = -1;
    int32_t rendererFlags = -1;
    int32_t volumeMode = -1;
    std::vector<int32_t> contents = {
        OHOS::AudioStandard::CONTENT_TYPE_UNKNOWN, OHOS::AudioStandard::CONTENT_TYPE_SPEECH,
        OHOS::AudioStandard::CONTENT_TYPE_MUSIC, OHOS::AudioStandard::CONTENT_TYPE_MOVIE,
        OHOS::AudioStandard::CONTENT_TYPE_SONIFICATION, OHOS::AudioStandard::CONTENT_TYPE_RINGTONE
    };
    std::vector<int32_t> usages = {
        OHOS::AudioStandard::STREAM_USAGE_UNKNOWN, OHOS::AudioStandard::STREAM_USAGE_MEDIA,
        OHOS::AudioStandard::STREAM_USAGE_MUSIC, OHOS::AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION,
        OHOS::AudioStandard::STREAM_USAGE_VOICE_ASSISTANT, OHOS::AudioStandard::STREAM_USAGE_ALARM,
        OHOS::AudioStandard::STREAM_USAGE_VOICE_MESSAGE, OHOS::AudioStandard::STREAM_USAGE_NOTIFICATION_RINGTONE,
        OHOS::AudioStandard::STREAM_USAGE_RINGTONE, OHOS::AudioStandard::STREAM_USAGE_NOTIFICATION,
        OHOS::AudioStandard::STREAM_USAGE_ACCESSIBILITY, OHOS::AudioStandard::STREAM_USAGE_SYSTEM,
        OHOS::AudioStandard::STREAM_USAGE_MOVIE, OHOS::AudioStandard::STREAM_USAGE_GAME,
        OHOS::AudioStandard::STREAM_USAGE_AUDIOBOOK, OHOS::AudioStandard::STREAM_USAGE_NAVIGATION,
        OHOS::AudioStandard::STREAM_USAGE_DTMF, OHOS::AudioStandard::STREAM_USAGE_ENFORCED_TONE,
        OHOS::AudioStandard::STREAM_USAGE_ULTRASONIC, OHOS::AudioStandard::STREAM_USAGE_VIDEO_COMMUNICATION
    };
    std::vector<int32_t> systemUsages = { OHOS::AudioStandard::STREAM_USAGE_VOICE_CALL_ASSISTANT };
    usages.insert(usages.end(), systemUsages.begin(), systemUsages.end());

    usage = src.usage.get_value();
    rendererFlags = src.rendererFlags;
    if (src.volumeMode.has_value()) {
        volumeMode = src.volumeMode.value();
    }

    if (std::find(systemUsages.begin(), systemUsages.end(), usage) != systemUsages.end() && !IsSystemApp()) {
        MEDIA_LOGI("The caller is not a system app, usage = %{public}d", usage);
        return false;
    }
    if (std::find(contents.begin(), contents.end(), content) == contents.end() ||
        std::find(usages.begin(), usages.end(), usage) == usages.end()) {
        return false;
    }

    if (audioRendererInfo.contentType != content ||
        audioRendererInfo.streamUsage != usage) {
        audioEffectMode_ = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    }

    audioRendererInfo =  OHOS::AudioStandard::AudioRendererInfo {
        static_cast< OHOS::AudioStandard::ContentType>(content),
        static_cast< OHOS::AudioStandard::StreamUsage>(usage), rendererFlags,
        static_cast< OHOS::AudioStandard::AudioVolumeMode>(volumeMode)
    };
    return true;
}

void AVPlayerImpl::SetAudioRendererInfo(optional_view<ohos::multimedia::audio::AudioRendererInfo> audioRendererInfo)
{
    MediaTrace trace("AVPlayerImpl::set audioRendererInfo");
    MEDIA_LOGI("TaiheSetAudioRendererInfo In");

    if (GetCurrentState() != AVPlayerState::STATE_INITIALIZED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized, unsupport to set audio renderer info");
        return;
    }

    if (audioRendererInfo.has_value()) {
        if (!HandleParameter(audioRendererInfo.value(), audioRendererInfo_)) {
            set_business_error(MSERR_EXT_API9_INVALID_PARAMETER,
                "invalid parameters, please check the input audio renderer info");
            return;
        }
        auto task = std::make_shared<TaskHandler<void>>([this]() {
            MEDIA_LOGI("SetAudioRendererInfo Task");
            if (player_ != nullptr) {
                Format format;
                (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, audioRendererInfo_.contentType);
                (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, audioRendererInfo_.streamUsage);
                (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, audioRendererInfo_.rendererFlags);
                (void)format.PutIntValue(PlayerKeys::VOLUME_MODE, audioRendererInfo_.volumeMode);
                (void)player_->SetParameter(format);
            }
        });
        (void)taskQue_->EnqueueTask(task);
    } else {
        set_business_error(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input");
    }
    MEDIA_LOGI("SetAudioRendererInfo Out");
}

optional<::ohos::multimedia::audio::InterruptMode> AVPlayerImpl::GetAudioInterruptMode()
{
    MediaTrace trace("AVPlayerImpl::get audioInterruptMode");
    MEDIA_LOGI("TaiheGetAudioInterruptMode In");
    ohos::multimedia::audio::InterruptMode::key_t interruptModeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::InterruptMode>(interruptMode_, interruptModeKey);
    ::ohos::multimedia::audio::InterruptMode changeReason =
    static_cast<::ohos::multimedia::audio::InterruptMode>(interruptModeKey);
    ::ohos::multimedia::audio::InterruptMode interruptMode = {
        changeReason,
    };

    return optional<ohos::multimedia::audio::InterruptMode>(std::in_place_t{}, interruptMode);
}

void AVPlayerImpl::SetAudioInterruptMode(::ohos::multimedia::audio::InterruptMode audioInterruptMode)
{
    MediaTrace trace("AVPlayerImpl::set audioInterruptMode");
    MEDIA_LOGI("TaiheSetAudioInterruptMode In");
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport audio interrupt operation");
        return;
    }
        int32_t interruptMode = audioInterruptMode;
        if (interruptMode < OHOS::AudioStandard::InterruptMode::SHARE_MODE ||
            interruptMode > OHOS::AudioStandard::InterruptMode::INDEPENDENT_MODE) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                    "invalid parameters, please check the input interrupt Mode");
                return;
        }
        interruptMode_ = static_cast<OHOS::AudioStandard::InterruptMode>(interruptMode);
        auto task = std::make_shared<TaskHandler<void>>([this]() {
            if (player_ != nullptr) {
                Format format;
                (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, interruptMode_);
                (void)player_->SetParameter(format);
            }
        });
        (void)taskQue_->EnqueueTask(task);
        MEDIA_LOGI("TaiheSetAudioInterruptMode Out");
}

optional<AVDataSrcDescriptor> AVPlayerImpl::GetDataSrc()
{
    MediaTrace trace("AVPlayerImpl::getDataSrc");
    MEDIA_LOGI("TaiheGetDataSrc In");

    CHECK_AND_RETURN_RET_LOG(dataSrcCb_ != nullptr,
        optional<AVDataSrcDescriptor>(std::nullopt), "failed to check dataSrcCb_");
    int64_t fileSize;
    (void)dataSrcCb_->GetSize(fileSize);
    std::shared_ptr<uintptr_t> callback;
    int32_t ret = dataSrcCb_->GetCallback(READAT_CALLBACK_NAME, callback);

    CHECK_AND_RETURN_RET_LOG(ret == OHOS::Media::MSERR_OK,
        optional<AVDataSrcDescriptor>(std::nullopt), "failed to GetCallback");

    auto cacheCallback = std::reinterpret_pointer_cast<DataSrcCallback>(callback);
    AVDataSrcDescriptor fdSrc = AVDataSrcDescriptor{std::move(fileSize), std::move(*cacheCallback)};
    MEDIA_LOGI("TaiheGetDataSrc Out");
    return optional<AVDataSrcDescriptor>(std::in_place_t{}, fdSrc);
}

void AVPlayerImpl::SetDataSrc(optional_view<AVDataSrcDescriptor> dataSrc)
{
    OHOS::Media::MediaTrace trace("AVPlayerImpl::set dataSrc");
    MEDIA_LOGI("TaiheSetDataSrc In");

    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set dataSrc");
        return;
    }
    StartListenCurrentResource();

    ani_env *env = taihe::get_env();
    if (dataSrc.has_value()) {
        dataSrcDescriptor_.fileSize = dataSrc.value().fileSize;
        if (dataSrcDescriptor_.fileSize < -1 || dataSrcDescriptor_.fileSize == 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check parameter fileSize");
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
    MediaTrace trace("AVPlayerImpl::get surface");
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
    MediaTrace trace("AVPlayerImpl::set surface");
    MEDIA_LOGD("TaiheSetSurfaceID In");

    std::string curState = GetCurrentState();
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
            OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "switch surface with no old surface");
            return;
        }
    } else {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
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
    MediaTrace trace("AVPlayerImpl::get loop");
    MEDIA_LOGI("TaiheGetLoop In");

    MEDIA_LOGI("TaiheGetLoop Out Current Loop: %{public}d", loop_);
    return loop_;
}

void AVPlayerImpl::SetLoop(bool loop)
{
    MediaTrace trace("AVPlayerImpl::set loop");
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
    MediaTrace trace("AVPlayerImpl::get fd");
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
    MediaTrace trace("AVPlayerImpl::set fd");
    MEDIA_LOGI("TaiheSetAVFileDescriptor In");

    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set fd");
        return;
    }

    StartListenCurrentResource();

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
    MediaTrace trace("AVPlayerImpl::setSpeed");
    MEDIA_LOGI("TaiheSetSpeed In");

    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support speed");
        return;
    }

    int32_t mode = static_cast<int32_t>(speed.get_value());
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
    MediaTrace trace("AVPlayerImpl::seek");
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
    MediaTrace trace("AVPlayerImpl::get videoScaleType");
    MEDIA_LOGI("TaiheGetVideoScaleType In");

    VideoScaleType::key_t key;
    MediaTaiheUtils::GetEnumKeyByValue<VideoScaleType>(videoScaleType_, key);
    VideoScaleType videoScaleType = VideoScaleType(key);
    MEDIA_LOGI("TaiheGetVideoScaleType Out Current VideoScale: %{public}d", videoScaleType_);
    return optional<VideoScaleType>(std::in_place_t{}, videoScaleType);
}

void AVPlayerImpl::SetVideoScaleType(optional_view<VideoScaleType> videoScaleType)
{
    MediaTrace trace("AVPlayerImpl::set videoScaleType");
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
    MediaTrace trace("AVPlayerImpl::isSeekContinuousSupported");
    MEDIA_LOGI("TaiheIsSeekContinuousSupported In");
    bool isSeekContinuousSupported = false;

    if (player_ != nullptr) {
        isSeekContinuousSupported = player_->IsSeekContinuousSupported();
    }
    MEDIA_LOGI("TaiheIsSeekContinuousSupported Out");
    return isSeekContinuousSupported;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::GetTrackDescriptionTask(const std::unique_ptr<AVPlayerContext> &Ctx)
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
    std::unique_ptr<AVPlayerContext> context = std::make_unique<AVPlayerContext>();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetTrackDescription EnqueueTask In", FAKE_POINTER(this));
    context->asyncTask = GetTrackDescriptionTask(context);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetTrackDescription EnqueueTask Out", FAKE_POINTER(this));
    auto result = context->asyncTask->GetResult();
    std::vector<map<string, MediaDescriptionValue>> tdResult;
    if (!result.HasResult()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "task has been cleared");
        return array<map<string, MediaDescriptionValue>>(tdResult);
    }
    if (result.Value().first != MSERR_EXT_API9_OK) {
        set_business_error(result.Value().first, result.Value().second);
        return array<map<string, MediaDescriptionValue>>(tdResult);
    }
    auto vec = context->trackInfoVec_;
    for (size_t index = 0; index < vec.size(); ++index) {
        map<string, MediaDescriptionValue> description;
        description = MediaTaiheUtils::CreateFormatBuffer(vec[index]);
        tdResult.push_back(description);
    }
    context.release();
    MEDIA_LOGI("GetTrackDescription Out");
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

std::shared_ptr<AVMediaSource> AVPlayerImpl::GetAVMediaSource(ohos::multimedia::media::weak::MediaSource src,
    std::shared_ptr<AVMediaSourceTmp> &srcTmp)
{
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(srcTmp->url, srcTmp->header);
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, nullptr, "create mediaSource failed!");
    mediaSource->SetMimeType(srcTmp->GetMimeType());
    mediaSource->mediaSourceLoaderCb_ = MediaSourceImpl::GetSourceLoader(src);
    if (mediaSource->mediaSourceLoaderCb_ == nullptr) {
        MEDIA_LOGI("mediaSourceLoaderCb_ nullptr");
    }
    return mediaSource;
}

void AVPlayerImpl::AddMediaStreamToAVMediaSource(
    const std::shared_ptr<AVMediaSourceTmp> &srcTmp, std::shared_ptr<AVMediaSource> &mediaSource)
{
    for (const auto &mediaStreamTmp : srcTmp->getAVPlayMediaStreamTmpList()) {
        AVPlayMediaStream mediaStream;
        mediaStream.url = mediaStreamTmp.url;
        mediaStream.width = mediaStreamTmp.width;
        mediaStream.height = mediaStreamTmp.height;
        mediaStream.bitrate = mediaStreamTmp.bitrate;
        mediaSource->AddMediaStream(mediaStream);
    }
}

void AVPlayerImpl::GetDefaultStrategy(AVPlayStrategyTmp &playStrategy)
{
    playStrategy.preferredWidth = 0;
    playStrategy.preferredHeight = 0;
    playStrategy.preferredBufferDuration = 0;
    playStrategy.preferredHdr = 0;
    playStrategy.showFirstFrameOnPrepare = false;
    playStrategy.enableSuperResolution = false;
    playStrategy.mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_MAX_COUNT;
    playStrategy.preferredAudioLanguage = "";
    playStrategy.preferredSubtitleLanguage = "";
    playStrategy.preferredBufferDurationForPlaying = 0;
    playStrategy.isSetBufferDurationForPlaying = false;
    playStrategy.thresholdForAutoQuickPlay = -1;
    playStrategy.isSetThresholdForAutoQuickPlay = false;
}

void AVPlayerImpl::GetPlayStrategy(AVPlayStrategyTmp &playStrategy, PlaybackStrategy strategy)
{
    if (strategy.preferredWidth.has_value()) {
        playStrategy.preferredWidth = strategy.preferredWidth.value();
    }
    if (strategy.preferredHeight.has_value()) {
        playStrategy.preferredHeight = strategy.preferredHeight.value();
    }
    if (strategy.preferredBufferDuration.has_value()) {
        playStrategy.preferredBufferDuration = strategy.preferredBufferDuration.value();
    }
    if (strategy.preferredHdr.has_value()) {
        playStrategy.preferredHdr = strategy.preferredHdr.value();
    }
    if (strategy.showFirstFrameOnPrepare.has_value()) {
        playStrategy.showFirstFrameOnPrepare = strategy.showFirstFrameOnPrepare.value();
    }
    if (strategy.enableSuperResolution.has_value()) {
        playStrategy.enableSuperResolution = strategy.enableSuperResolution.value();
    }
    if (strategy.mutedMediaType.has_value()) {
        playStrategy.mutedMediaType = strategy.mutedMediaType.value().get_value();
    }
    if (strategy.preferredAudioLanguage.has_value()) {
        playStrategy.preferredAudioLanguage = strategy.preferredAudioLanguage.value();
    }
    if (strategy.preferredSubtitleLanguage.has_value()) {
        playStrategy.preferredSubtitleLanguage = strategy.preferredSubtitleLanguage.value();
    }
    if (strategy.preferredBufferDurationForPlaying.has_value()) {
        playStrategy.preferredBufferDurationForPlaying = strategy.preferredBufferDurationForPlaying.value();
        playStrategy.isSetBufferDurationForPlaying = true;
    }
    if (strategy.thresholdForAutoQuickPlay.has_value()) {
        playStrategy.thresholdForAutoQuickPlay = strategy.thresholdForAutoQuickPlay.value();
        playStrategy.isSetThresholdForAutoQuickPlay = true;
    }
}

void AVPlayerImpl::EnqueueMediaSourceTask(const std::shared_ptr<AVMediaSource> &mediaSource,
    const struct AVPlayStrategy &strategy)
{
    auto task = std::make_shared<TaskHandler<void>>([this, mediaSource, strategy]() {
        if (player_ != nullptr) {
            (void)player_->SetMediaSource(mediaSource, strategy);
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerImpl::SetMediaSourceSync(ohos::multimedia::media::weak::MediaSource src,
    optional_view<PlaybackStrategy> strategy)
{
    MediaTrace trace("AVPlayerImpl::setMediaSource");
    MEDIA_LOGI("SetMediaSourceSync In");
    if (GetCurrentState() != AVPlayerState::STATE_IDLE) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set mediaSource");
        return;
    }
    StartListenCurrentResource(); // Listen to the events of the current resource
    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceImpl::GetMediaSource(src);
    CHECK_AND_RETURN_LOG(srcTmp != nullptr, "get GetMediaSource argument failed!");

    std::shared_ptr<AVMediaSource> mediaSource = GetAVMediaSource(src, srcTmp);
    CHECK_AND_RETURN_LOG(mediaSource != nullptr, "create mediaSource failed!");
    AddMediaStreamToAVMediaSource(srcTmp, mediaSource);

    struct AVPlayStrategyTmp strategyTmp;
    struct AVPlayStrategy strategyRes;
    GetDefaultStrategy(strategyTmp);
    if (strategy.has_value()) {
        GetPlayStrategy(strategyTmp, strategy.value());
    }
    if (!IsPalyingDurationValid(strategyTmp)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "playing duration is invalid");
        return;
    } else if (!IsLivingMaxDelayTimeValid(strategyTmp)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "thresholdForAutoQuickPlay is invalid");
        return;
    }
    GetAVPlayStrategyFromStrategyTmp(strategyRes, strategyTmp);
    if (GetJsApiVersion() < API_VERSION_18) {
        strategyRes.mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_MAX_COUNT;
    }
    EnqueueMediaSourceTask(mediaSource, strategyRes);
}

void AVPlayerImpl::AddSubtitleFromFdSync(int32_t fd, optional_view<int64_t> offset, optional_view<int64_t> length)
{
    MEDIA_LOGI("AddSubtitleAVFileDescriptor In");
    int64_t offsetLocal = -1;
    int64_t lengthLocal = -1;
    if (offset.has_value()) {
        offsetLocal = static_cast<int64_t>(offset.value());
    }
    if (length.has_value()) {
        lengthLocal = static_cast<int64_t>(length.value());
    }
    auto task = std::make_shared<TaskHandler<void>>([this, fd, offsetLocal, lengthLocal]() {
        if (player_ != nullptr) {
            if (player_->AddSubSource(fd, offsetLocal, lengthLocal) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleAVFileDescriptor");
            }
        }
    });
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("AddSubtitleAVFileDescriptor Out");
}

void AVPlayerImpl::AddSubSource(std::string url)
{
    MEDIA_LOGI("input url is %{private}s!", url.c_str());
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        auto task = std::make_shared<TaskHandler<void>>([this, url]() {
            MEDIA_LOGI("AddSubtitleNetworkSource Task");
            CHECK_AND_RETURN_LOG(player_ != nullptr, "player_ is nullptr");
            if (player_->AddSubSource(url) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleNetworkSource");
            }
        });
        (void)taskQue_->EnqueueTask(task);
    } else if (isFd) {
        const std::string fdHead = "fd://";
        std::string inputFd = url.substr(fdHead.size());
        int32_t fd = -1;
        if (!StrToInt(inputFd, fd) || fd < 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                "invalid parameters, The input parameter is not a fd://+numeric string");
            return;
        }

        auto task = std::make_shared<TaskHandler<void>>([this, fd]() {
            MEDIA_LOGI("AddSubtitleFdSource Task");
            CHECK_AND_RETURN_LOG(player_ != nullptr, "player_ is nullptr");
            if (player_->AddSubSource(fd, 0, -1) != MSERR_OK) {
                OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to AddSubtitleFdSource");
            }
        });
        (void)taskQue_->EnqueueTask(task);
    } else {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, The input parameter is not fd:// or network address");
    }
}

void AVPlayerImpl::AddSubtitleFromUrlSync(::taihe::string_view url)
{
    MediaTrace trace("AVPlayerImpl::addSubtitleUrl");
    MEDIA_LOGI("AddSubtitleFromUrlSync In");
    std::string url_(url);

    AddSubSource(url_);
    MEDIA_LOGI("AddSubtitleFromUrlSync Out");
}

map<string, PlaybackInfoValue> AVPlayerImpl::GetPlaybackInfoSync()
{
    MediaTrace trace("AVPlayerImpl::GetPlaybackInfoSync");
    MEDIA_LOGI("GetPlaybackInfoSync In");
    Format &playbackInfo = playbackInfo_;
    if (IsControllable() && player_ != nullptr) {
        (void)player_->GetPlaybackInfo(playbackInfo);
    } else {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state unsupport get playback info");
        map<string, PlaybackInfoValue> playbackInfo;
        return playbackInfo;
    }

    MEDIA_LOGI("GetPlaybackInfoSync Out");
    return MediaTaiheUtils::CreateFormatBufferByRef(playbackInfo);
}

void AVPlayerImpl::DeselectTrackSync(int32_t index)
{
    MediaTrace trace("AVPlayerImpl::deselectTrack");
    MEDIA_LOGI("deselectTrack In");
    if (index < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the track index");
        return;
    }
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

void AVPlayerImpl::SelectTrackSync(int32_t index, optional_view<SwitchMode> mode)
{
    MediaTrace trace("AVPlayerImpl::selectTrack");
    MEDIA_LOGI("SelectTrack In");
    if (!IsControllable()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport selectTrack operation");
        return;
    }

    HandleSelectTrack(index, mode);

    auto task = std::make_shared<TaskHandler<void>>([this, index = index_, mode = mode_]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSelectTrack Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            (void)player_->SelectTrack(index, TransferSwitchMode(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSelectTrack Task Out", FAKE_POINTER(this));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSelectTrack EnqueueTask In", FAKE_POINTER(this));
    (void)taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSelectTrack Out", FAKE_POINTER(this));
    MEDIA_LOGI("SelectTrack Out");
}

void AVPlayerImpl::HandleSelectTrack(int32_t index, optional_view<SwitchMode> mode)
{
    index_ = index;
    if (index_ < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the track index");
        return;
    }

    if (mode.has_value()) {
        mode_ = static_cast<int32_t>(mode.value().get_value());
        if (mode_ < SWITCH_SMOOTH || mode_ > SWITCH_CLOSEST) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please switch seek mode");
            return;
        }
    }

    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport selectTrack operation");
        return;
    }
}

PlayerSwitchMode AVPlayerImpl::TransferSwitchMode(int32_t mode)
{
    MEDIA_LOGI("Seek Task TransferSeekMode, mode: %{public}d", mode);
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

array<int32_t> AVPlayerImpl::GetSelectedTracksSync()
{
    MediaTrace trace("AVPlayerImpl::get selected tracks");
    MEDIA_LOGI("TaiheGetSelectedTracks In");
    std::vector<int32_t> trackIndex;
    if (IsControllable()) {
        int32_t videoIndex = -1;
        (void)player_->GetCurrentTrack(OHOS::Media::MediaType::MEDIA_TYPE_VID, videoIndex);
        if (videoIndex != -1) {
            trackIndex.push_back(videoIndex);
        }

        int32_t audioIndex = -1;
        (void)player_->GetCurrentTrack(OHOS::Media::MediaType::MEDIA_TYPE_AUD, audioIndex);
        if (audioIndex != -1) {
            trackIndex.push_back(audioIndex);
        }

        int32_t subtitleIndex = -1;
        (void)player_->GetCurrentTrack(OHOS::Media::MediaType::MEDIA_TYPE_SUBTITLE, subtitleIndex);
        if (subtitleIndex != -1) {
            trackIndex.push_back(subtitleIndex);
        }
    } else {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state unsupport get current selections");
    }
    MEDIA_LOGI("TaiheGetSelectedTracks Out");
    return array<int32_t>(copy_data_t{}, trackIndex.data(), trackIndex.size());
}

void AVPlayerImpl::SetVideoWindowSizeSync(int32_t width, int32_t height)
{
    MediaTrace trace("AVPlayerImpl::setVideoWindowSize");
    MEDIA_LOGI("TaiheSetVideoWindowSize In");
    auto promiseCtx = std::make_unique<AVPlayerContext>();

    if (!CanSetSuperResolution()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/playing/paused/completed/stopped, "
            "unsupport set video window size");
    } else {
        promiseCtx->asyncTask = SetVideoWindowSizeTask(width, height);
    }
    promiseCtx->CheckTaskResult();
    MEDIA_LOGI("TaiheSetVideoWindowSize Out");
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::SetVideoWindowSizeTask(int32_t width, int32_t height)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, width, height]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (CanSetSuperResolution()) {
            int32_t ret = player_->SetVideoWindowSize(width, height);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set super resolution");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized/prepared/playing/paused/completed/stopped, "
                "unsupport set super resolution operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

bool AVPlayerImpl::CanSetSuperResolution()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_PREPARED ||
        state == AVPlayerState::STATE_PLAYING || state == AVPlayerState::STATE_PAUSED ||
        state == AVPlayerState::STATE_STOPPED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    }
    return false;
}

void AVPlayerImpl::SetSuperResolutionSync(bool enabled)
{
    MediaTrace trace("AVPlayerImpl::setSuperResolution");
    MEDIA_LOGI("TaiheSetSuperResolution In");
    auto promiseCtx = std::make_unique<AVPlayerContext>();
    if (!CanSetSuperResolution()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/playing/paused/completed/stopped, "
            "unsupport set super resolution operation");
    } else {
        promiseCtx->asyncTask = SetSuperResolutionTask(enabled);
    }
    promiseCtx->CheckTaskResult();
    MEDIA_LOGI("TaiheSetSuperResolution Out");
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::SetSuperResolutionTask(bool enable)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, enable]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (CanSetSuperResolution()) {
            int32_t ret = player_->SetSuperResolution(enable);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set super resolution");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized/prepared/playing/paused/completed/stopped, "
                "unsupport set super resolution operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

int32_t AVPlayerImpl::GetPlaybackPosition()
{
    MediaTrace trace("AVPlayerImpl::get playbackPosition");
    MEDIA_LOGD("getPlaybackPosition In");
    int32_t playbackPosition = -1;
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr, playbackPosition, "failed to check player_");
    std::string curState = GetCurrentState();
    if (curState == AVPlayerState::STATE_PLAYING &&
        curState == AVPlayerState::STATE_PAUSED &&
        curState == AVPlayerState::STATE_PREPARED &&
        curState == AVPlayerState::STATE_COMPLETED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video playback position");
        return playbackPosition;
    }
    (void)player_->GetPlaybackPosition(playbackPosition);
    if (playbackPosition != 0) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetPlaybackPosition Out, state %{public}s, time: %{public}d",
            FAKE_POINTER(this), curState.c_str(), playbackPosition);
    }
    return playbackPosition;
}

int64_t AVPlayerImpl::GetCurrentPresentationTimestamp()
{
    MediaTrace trace("AVPlayerImpl::get currentPresentationTimestamp");
    MEDIA_LOGD("getCurrentPresentationTimestamp In");
    int32_t currentPresentation = -1;
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr, currentPresentation, "failed to check player_");
    std::string curState = GetCurrentState();
    if (curState != AVPlayerState::STATE_PLAYING &&
        curState != AVPlayerState::STATE_PAUSED &&
        curState != AVPlayerState::STATE_COMPLETED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not playing/paused/completed, unsupport video current presentation timestamp");
        return currentPresentation;
    }
    (void)player_->GetCurrentPresentationTimestamp(currentPresentation);
    if (currentPresentation != 0) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGettCurrentPresentationTimestamp Out, state %{public}s,
            time: (%{public}" PRIu64 ")", FAKE_POINTER(this), curState.c_str(), currentPresentation);
    }
    return currentPresentation;
}

void AVPlayerImpl::SetBitrate(int32_t bitrate)
{
    MediaTrace trace("AVPlayerImpl::setBitrate");
    MEDIA_LOGI("SelectBitrate In");
    if (bitrate < 0) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input bitrate");
        return;
    }
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport select bitrate operation");
        return;
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

void AVPlayerImpl::SetPlaybackRate(double rate)
{
    MediaTrace trace("AVPlayerImpl::setRate");
    MEDIA_LOGI("TaiheSetRate In");

    if (IsLiveSource()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "The stream is live stream, not support rate");
        return;
    }
    if (!IsRateValid(rate)) {
        OnErrorCb(MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE,
            "invalid parameters, please check the rate");
        return;
    }
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport rate operation");
        return;
    }
    auto task = std::make_shared<TaskHandler<void>>([this, rate]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetRate Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            (void)player_->SetPlaybackRate(static_cast<float>(rate));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetRate Task Out", FAKE_POINTER(this));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetRate EnqueueTask In", FAKE_POINTER(this));
    if (player_ != nullptr) {
        (void)taskQue_->EnqueueTask(task);
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheSetRate Out", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::SetPlaybackRangeSync(int32_t startTimeMs, int32_t endTimeMs,
    optional_view<::ohos::multimedia::media::SeekMode> mode)
{
    MediaTrace trace("AVPlayerImpl::setPlaybackRange");
    MEDIA_LOGI("TaiheSetPlaybackRange In");
    auto promiseCtx = std::make_unique<AVPlayerContext>();
    int32_t modeTmp = SEEK_PREVIOUS_SYNC;
    if (mode.has_value()) {
        modeTmp = static_cast<int32_t>(mode.value().get_value());
    }
    if (!CanSetPlayRange()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/paused/stopped/completed, unsupport setPlaybackRange operation");
    } else if (startTimeMs < PLAY_RANGE_DEFAULT_VALUE || endTimeMs < PLAY_RANGE_DEFAULT_VALUE) {
        set_business_error(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check start or end time");
    } else if (modeTmp < SEEK_PREVIOUS_SYNC || modeTmp > SEEK_MODE_CLOSEST) {
        set_business_error(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid seek mode, please check seek mode");
    } else {
        promiseCtx->asyncTask = EqueueSetPlayRangeTask(startTimeMs, endTimeMs, modeTmp);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " taiheSetPlaybackRange EnqueueTask Out", FAKE_POINTER(this));
    }
    promiseCtx->CheckTaskResult();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " taiheSetPlaybackRange Out", FAKE_POINTER(this));
}

#ifdef SUPPORT_AVPLAYER_DRM
void AVPlayerImpl::SetDecryptionConfig(ohos::multimedia::drm::weak::MediaKeySession mediaKeySession,
    bool secureVideoPath)
{
    MediaTrace trace("AVPlayerImpl::SetDecryptionConfig");
    MEDIA_LOGI("SetDecryptionConfig In");
    OHOS::DrmStandard::MediaKeySessionImpl* keySessionImpl =
        reinterpret_cast<OHOS::DrmStandard::MediaKeySessionImpl*>(mediaKeySession->GetMediaKeySessionNative());
    if (keySessionImpl != nullptr) {
        OHOS::sptr<OHOS::DrmStandard::IMediaKeySessionService> keySessionServiceProxy =
            keySessionImpl->GetMediaKeySessionServiceProxy();
        MEDIA_LOGD("And it's count is: %{public}d", keySessionServiceProxy->GetSptrRefCount());
        {
            std::lock_guard<std::mutex> lock(syncMutex_);
            CHECK_AND_RETURN_LOG((player_ != nullptr), "SetDecryptConfig player_ nullptr");
            (void)player_->SetDecryptConfig(keySessionServiceProxy, secureVideoPath);
        }
    } else {
        MEDIA_LOGE("SetDecryptConfig keySessionImpl is nullptr!");
    }
}
#else
void AVPlayerImpl::SetDecryptionConfig(ohos::multimedia::drm::weak::MediaKeySession mediaKeySession,
    bool secureVideoPath)
{
    MEDIA_LOGI("SetDecryptConfig is not surpport.");
    (void)mediaKeySession;
    (void)secureVideoPath;
    return;
}
#endif

array<MediaKeySystemInfo> AVPlayerImpl::GetMediaKeySystemInfos()
{
    MediaTrace trace("AVPlayerImpl::GetMediaKeySystemInfos");
    std::vector<MediaKeySystemInfo> infoArray;
    
    MEDIA_LOGI("GetMediaKeySystemInfos In");

    CHECK_AND_RETURN_RET_LOG(!localDrmInfos_.empty(), array<MediaKeySystemInfo>(copy_data_t{},
        infoArray.data(), infoArray.size()), "localDrmInfo is empty");

    for (auto item : localDrmInfos_) {
        MediaKeySystemInfo info{
            item.first,
            array<uint8_t>(copy_data_t{}, item.second.data(), item.second.size())
        };
        infoArray.push_back(info);
    }
    return array<MediaKeySystemInfo>(copy_data_t{}, infoArray.data(), infoArray.size());
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::EqueueSetPlayRangeTask(int32_t start, int32_t end, int32_t mode)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, start, end, mode]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " taiheSetPlaybackRange Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            auto ret = player_->SetPlayRangeWithMode(start, end, TransferSeekMode(mode));
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to setPlaybackRange");
            }
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " taiheSetPlaybackRange Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

bool AVPlayerImpl::CanSetPlayRange()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_PREPARED ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_STOPPED ||
        state == AVPlayerState::STATE_COMPLETED) {
        return true;
    }
    return false;
}

void AVPlayerImpl::SetMediaMutedSync(::ohos::multimedia::media::MediaType mediaType, bool muted)
{
    MediaTrace trace("AVPlayerImpl::TaiheMediaMuted");
    MEDIA_LOGI("TaiheSetMediaMuted In");
    auto promiseCtx = std::make_unique<AVPlayerContext>();
    if (!IsControllable()) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport set media muted operation");
    }
    int32_t mediaTypeTmp = static_cast<int32_t>(mediaType.get_value());
    auto curState = GetCurrentState();
    bool canSetMute = curState == AVPlayerState::STATE_PREPARED || curState == AVPlayerState::STATE_PLAYING ||
                      curState == AVPlayerState::STATE_PAUSED || curState == AVPlayerState::STATE_COMPLETED;
    if (!canSetMute) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized / stopped, unsupport set playback strategy operation");
    } else {
        promiseCtx->asyncTask = SetMediaMutedTask(static_cast<::OHOS::Media::MediaType>(mediaTypeTmp), muted);
    }
    promiseCtx->CheckTaskResult();
    MEDIA_LOGI("TaiheSetMediaMuted Out");
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::SetMediaMutedTask(::OHOS::Media::MediaType type, bool isMuted)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, type, isMuted]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED || IsControllable()) {
            int32_t ret = player_->SetMediaMuted(type, isMuted);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set muted");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not stopped or initialized, unsupport prepare operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::SetPlaybackStrategySync(::ohos::multimedia::media::PlaybackStrategy const& strategy)
{
    MediaTrace trace("AVPlayerImpl::JsSetPlaybackStrategy");
    MEDIA_LOGI("TaiheSetPlaybackStrategy In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    std::string currentState = GetCurrentState();
    if (currentState != AVPlayerState::STATE_INITIALIZED && currentState != AVPlayerState::STATE_STOPPED) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized / stopped, unsupport set playback strategy");
    } else {
        AVPlayStrategyTmp strategyTmp;
        GetDefaultStrategy(strategyTmp);
        GetPlayStrategy(strategyTmp, strategy);
        if ((GetJsApiVersion() < API_VERSION_18) &&
            (strategyTmp.mutedMediaType != OHOS::Media::MediaType::MEDIA_TYPE_AUD)) {
            set_business_error(MSERR_EXT_API9_INVALID_PARAMETER, "only support mute media type audio now");
        } else if (!IsPalyingDurationValid(strategyTmp)) {
            set_business_error(MSERR_EXT_API9_INVALID_PARAMETER,
                "playing duration is above buffer duration or below zero");
        } else if (!IsLivingMaxDelayTimeValid(strategyTmp)) {
            set_business_error(MSERR_EXT_API9_INVALID_PARAMETER, "thresholdForAutoQuickPlay is invalid");
        } else {
            AVPlayStrategy strategyRes;
            GetAVPlayStrategyFromStrategyTmp(strategyRes, strategyTmp);
            context->asyncTask = SetPlaybackStrategyTask(strategyRes);
        }
    }
    context->CheckTaskResult();
    MEDIA_LOGI("TaiheSetPlaybackStrategy Out");
}

bool AVPlayerImpl::IsPalyingDurationValid(const AVPlayStrategyTmp &strategyTmp)
{
    if ((strategyTmp.preferredBufferDuration > 0 && strategyTmp.preferredBufferDurationForPlaying > 0 &&
                   strategyTmp.preferredBufferDurationForPlaying > strategyTmp.preferredBufferDuration) ||
                   strategyTmp.preferredBufferDurationForPlaying < 0) {
        return false;
    }
    return true;
}

bool AVPlayerImpl::IsLivingMaxDelayTimeValid(const AVPlayStrategyTmp &strategyTmp)
{
    if (!strategyTmp.isSetThresholdForAutoQuickPlay) {
        return true;
    }
    if (strategyTmp.thresholdForAutoQuickPlay < AVPlayStrategyConstant::BUFFER_DURATION_FOR_PLAYING_SECONDS ||
        strategyTmp.thresholdForAutoQuickPlay < strategyTmp.preferredBufferDurationForPlaying) {
            return false;
        }
    return true;
}

bool AVPlayerImpl::IsRateValid(double rate)
{
    const double minRate = 0.125f;
    const double maxRate = 4.0f;
    const double eps = 1e-15;
    if ((rate < minRate - eps) || (rate > maxRate + eps)) {
        return false;
    }
    return true;
}

void AVPlayerImpl::GetAVPlayStrategyFromStrategyTmp(AVPlayStrategy &strategy, const AVPlayStrategyTmp &strategyTmp)
{
    strategy.preferredWidth = strategyTmp.preferredWidth;
    strategy.preferredHeight = strategyTmp.preferredHeight;
    strategy.preferredBufferDuration = strategyTmp.preferredBufferDuration;
    strategy.preferredHdr = strategyTmp.preferredHdr;
    strategy.showFirstFrameOnPrepare = strategyTmp.showFirstFrameOnPrepare;
    strategy.enableSuperResolution = strategyTmp.enableSuperResolution;
    strategy.mutedMediaType = static_cast<OHOS::Media::MediaType>(strategyTmp.mutedMediaType);
    strategy.preferredAudioLanguage = strategyTmp.preferredAudioLanguage;
    strategy.preferredSubtitleLanguage = strategyTmp.preferredSubtitleLanguage;
    strategy.preferredBufferDurationForPlaying = strategyTmp.isSetBufferDurationForPlaying ?
        strategyTmp.preferredBufferDurationForPlaying : -1;
    strategy.thresholdForAutoQuickPlay = strategyTmp.isSetThresholdForAutoQuickPlay ?
        strategyTmp.thresholdForAutoQuickPlay : -1;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerImpl::SetPlaybackStrategyTask(AVPlayStrategy playStrategy)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, playStrategy]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_STOPPED) {
            int32_t ret = player_->SetPlaybackStrategy(playStrategy);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set playback strategy");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized or stopped, unsupport set playback strategy operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerImpl::StopSync()
{
    MediaTrace trace("AVPlayerImpl::stop");
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
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheStop Out", FAKE_POINTER(this));
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
    MediaTrace trace("AVPlayerImpl::play");
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
    MediaTrace trace("AVPlayerImpl::reset");
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
    context->CheckTaskResult();
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

            if (playerCb_ != nullptr) {
                playerCb_->Release();
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
    MediaTrace trace("AVPlayerImpl::release");
    MEDIA_LOGI("TaiheRelease In");
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();

    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheRelease EnqueueTask In", FAKE_POINTER(this));
    context->asyncTask = ReleaseTask();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheRelease EnqueueTask Out", FAKE_POINTER(this));
    if (dataSrcCb_ != nullptr) {
        dataSrcCb_->ClearCallbackReference();
        dataSrcCb_ = nullptr;
    }

    context->CheckTaskResult();
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
    MediaTrace trace("AVPlayerImpl::pause");
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
    MediaTrace trace("AVPlayerImpl::prepare");
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
    MediaTrace trace("AVPlayerImpl::OnError");
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

void AVPlayerImpl::OnMediaKeySystemInfoUpdate(callback_view<void(array_view<MediaKeySystemInfo> data)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnMediaKeySystemInfoUpdate");
    MEDIA_LOGD("TaiheOnMediaKeySystemInfoUpdate In");
    
    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<MediaKeySystemInfo> data)>> taiheCallback =
        std::make_shared<taihe::callback<void(array_view<MediaKeySystemInfo> data)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_DRM_INFO_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR
        " TaiheOnMediaKeySystemInfoUpdate callbackName: mediaKeySystemInfoUpdate success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnStateChange(callback_view<void(string_view, ohos::multimedia::media::StateChangeReason)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnStateChange");

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

void AVPlayerImpl::OnAudioInterrupt(callback_view<void(::ohos::multimedia::audio::InterruptEvent const&)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnAudioInterrupt");
    MEDIA_LOGD("TaiheOnAudioInterrupt In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::ohos::multimedia::audio::InterruptEvent const&)>> taiheCallback =
            std::make_shared<taihe::callback<void(::ohos::multimedia::audio::InterruptEvent const&)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_AUDIO_INTERRUPT, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnAudioInterrupt callbackName: audioInterrupt success",
        FAKE_POINTER(this));
    return;
}
void AVPlayerImpl::OnAudioOutputDeviceChangeWithInfo(callback_view<void(
    ::ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnAudioOutputDeviceChangeWithInfo");
    MEDIA_LOGD("TaiheOnAudioOutputDeviceChangeWithInfo In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>> taiheCallback =
        std::make_shared<taihe::callback<void(ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR
        " TaiheOnAudioOutputDeviceChangeWithInfo callbackName: audioOutputDeviceChange success", FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnEndOfStream(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnEndOfStream");
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
    MediaTrace trace("AVPlayerImpl::OnStartRenderFrame");
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
    MediaTrace trace("AVPlayerImpl::OnSeekDone");
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
    MediaTrace trace("AVPlayerImpl::OnDurationUpdate");
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
    MediaTrace trace("AVPlayerImpl::OnTimeUpdate");
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
    MediaTrace trace("AVPlayerImpl::OnVolumeChange");
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
    MediaTrace trace("AVPlayerImpl::OnSpeedDone");
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
    MediaTrace trace("AVPlayerImpl::OnBitrateDone");
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
    MediaTrace trace("AVPlayerImpl::OnBitrateDone");
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
void AVPlayerImpl::OnAmplitudeUpdate(callback_view<void(array_view<double>)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnBitrateDone");
    MEDIA_LOGD("TaiheOnBitrateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    calMaxAmplitude_ = true;
    if (player_ != nullptr) {
        (void)player_->SetMaxAmplitudeCbStatus(calMaxAmplitude_);
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(array_view<double>)>> taiheCallback =
            std::make_shared<taihe::callback<void(array_view<double>)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnAmplitudeUpdate callbackName: amplitudeUpdate success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnBufferingUpdate(callback_view<void(ohos::multimedia::media::BufferingInfoType, int32_t)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnBufferingUpdate");
    MEDIA_LOGD("TaiheOnBufferingUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
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
    MediaTrace trace("AVPlayerImpl::OnVideoSizeChange");
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
    MediaTrace trace("AVPlayerImpl::OnTrackChange");
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
    MediaTrace trace("AVPlayerImpl::OnSubtitleUpdate");
    MEDIA_LOGD("TaiheOnSubtitleUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
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

void AVPlayerImpl::OnPlaybackRateDone(callback_view<void(double)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnPlaybackRateDone");
    MEDIA_LOGD("TaiheOnPlaybackRateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(double)>> taiheCallback =
            std::make_shared<taihe::callback<void(double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVPlayerEvent::EVENT_RATE_DONE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR "TaiheOnPlaybackRateDone callbackName: playbackRateDone success",
        FAKE_POINTER(this));
    return;
}

void AVPlayerImpl::OnSuperResolutionChanged(callback_view<void(bool)> callback)
{
    MediaTrace trace("AVPlayerImpl::OnSuperResolutionChanged");
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
    MediaTrace trace("AVPlayerImpl::OnTrackInfoUpdate");
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
    MediaTrace trace("AVPlayerImpl::OnSeiMessageReceived");
    MEDIA_LOGD("TaiheOnSeiMessageReceived In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }
    seiMessageCallbackflag_ = true;

    if (player_ != nullptr) {
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
    MediaTrace trace("AVPlayerImpl::OffError");
    MEDIA_LOGD("TaiheOffError In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    std::string callbackName = "error";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffError End");
}

void AVPlayerImpl::OffMediaKeySystemInfoUpdate(optional_view<callback<void(
    array_view<MediaKeySystemInfo> data)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffMediaKeySystemInfoUpdate");
    MEDIA_LOGD("OffMediaKeySystemInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "mediaKeySystemInfoUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffMediaKeySystemInfoUpdate End");
}

void AVPlayerImpl::OffStateChange(optional_view<callback<void(string_view,
    ohos::multimedia::media::StateChangeReason)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffStateChange");
    MEDIA_LOGD("OffStateChange In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "stateChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffStateChange End");
}

void AVPlayerImpl::OffAudioInterrupt(optional_view<callback<void(
    ::ohos::multimedia::audio::InterruptEvent const&)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffAudioInterrupt");
    MEDIA_LOGD("OffAudioInterrupt In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "audioInterrupt";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffAudioInterrupt End");
}

void AVPlayerImpl::OffAudioOutputDeviceChangeWithInfo(::taihe::optional_view<::taihe::callback<void
    (::ohos::multimedia::audio::AudioStreamDeviceChangeInfo const&)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffAudioOutputDeviceChangeWithInfo");
    MEDIA_LOGD("OffAudioOutputDeviceChangeWithInfo In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "audioOutputDeviceChange";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffAudioOutputDeviceChangeWithInfo End");
}

void AVPlayerImpl::OffEndOfStream(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffEndOfStream");
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
    MediaTrace trace("AVPlayerImpl::OffStartRenderFrame");
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
    MediaTrace trace("AVPlayerImpl::OffSeekDone");
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
    MediaTrace trace("AVPlayerImpl::OffDurationUpdate");
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
    MediaTrace trace("AVPlayerImpl::OffTimeUpdate");
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
    MediaTrace trace("AVPlayerImpl::OffVolumeChange");
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
    MediaTrace trace("AVPlayerImpl::OffSpeedDone");
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
    MediaTrace trace("AVPlayerImpl::OffBitrateDone");
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
    MediaTrace trace("AVPlayerImpl::OffAvailableBitrates");
    MEDIA_LOGD("OffAvailableBitrates In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "availableBitrates";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffAvailableBitrates End");
}
void AVPlayerImpl::OffAmplitudeUpdate(optional_view<callback<void(array_view<double>)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffAmplitudeUpdate");
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
    MediaTrace trace("AVPlayerImpl::OffBufferingUpdate");
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
    MediaTrace trace("AVPlayerImpl::OffVideoSizeChange");
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
    MediaTrace trace("AVPlayerImpl::OffTrackChange");
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
    MediaTrace trace("AVPlayerImpl::OffSubtitleUpdate");
    MEDIA_LOGD("OffSubtitleUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "subtitleUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffSubtitleUpdate End");
}

void AVPlayerImpl::OffPlaybackRateDone(optional_view<callback<void(double)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffPlaybackRateDone");
    MEDIA_LOGD("OffPlaybackRateDone In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "playbackRateDone";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffPlaybackRateDone End");
}

void AVPlayerImpl::OffSuperResolutionChanged(optional_view<callback<void(bool)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffSuperResolutionChanged");
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
    MediaTrace trace("AVPlayerImpl::OffTrackInfoUpdate");
    MEDIA_LOGD("OffTrackInfoUpdate In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "trackInfoUpdate";
    MaxAmplitudeCallbackOff(callbackName);
    ClearCallbackReference(callbackName);
    MEDIA_LOGI("OffTrackInfoUpdate End");
}

void AVPlayerImpl::OffSeiMessageReceived(optional_view<array<int32_t>> payloadTypes,
    optional_view<callback<void(array_view<::ohos::multimedia::media::SeiMessage>,
    optional_view<int32_t>)>> callback)
{
    MediaTrace trace("AVPlayerImpl::OffSeiMessageReceived");
    MEDIA_LOGI("OffSeiMessageReceived In");

    if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }

    std::string callbackName = "seiMessageReceived";

    if (payloadTypes.has_value()) {
        if (payloadTypes.value().size() == 0) {
            MEDIA_LOGD("The array is empty, no processing is performed.");
            return;
        } else {
            std::vector<int32_t> payloadTypeVec(payloadTypes.value().begin(), payloadTypes.value().end());
            SeiMessageCallbackOff(callbackName, payloadTypeVec);
            ClearCallbackReference(callbackName);
            MEDIA_LOGI("0x%{public}06" PRIXPTR " OffSeiMessageReceived success", FAKE_POINTER(this));
            return;
        }
    } else {
        SeiMessageCallbackOff(callbackName, {});
        ClearCallbackReference(callbackName);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " OffSeiMessageReceived success", FAKE_POINTER(this));
        return;
    }

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

optional<AVPlayer> CreateAVPlayerSync()
{
    auto res = make_holder<AVPlayerImpl, AVPlayer>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVPlayer failed!");
        taihe::reset_error();
        return optional<AVPlayer>(std::nullopt);
    }
    return optional<AVPlayer>(std::in_place, res);
}
}
TH_EXPORT_CPP_API_CreateAVPlayerSync(CreateAVPlayerSync);