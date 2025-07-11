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
#include <array>
#include <iostream>
#include <memory>
#include "avplayer_ani.h"
#include "avimagegenerator_enum.h"
#include "media_ani_common.h"
#include "image_type.h"
#include "media_log.h"
#ifdef SUPPORT_VIDEO
#include "surface_utils.h"
#endif
#include "uri_helper.h"
#ifndef CROSS_PLATFORM
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#endif

using namespace OHOS::AudioStandard;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerAni" };
    constexpr uint32_t TASK_TIME_LIMIT_MS = 2000; // ms
    static int32_t g_apiVersion = -1;
    constexpr int32_t DECIMAL = 10;
    constexpr int32_t SEEK_CONTINUOUS_TS_ENUM_NUM = 3;
}

namespace OHOS {
namespace Media {

AVPlayerAni::AVPlayerAni() {};

AVPlayerAni::~AVPlayerAni() {};

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
        "call StrToInt func false, input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != addr && end[0] == '\0' && errno != ERANGE, false,
        "call StrToInt func false, input str is: %{public}s!", valStr.c_str());
    if constexpr (std::is_same<int32_t, T>::value) {
        CHECK_AND_RETURN_RET_LOG(result >= INT_MIN && result <= INT_MAX, false,
            "call StrToInt func false, input str is: %{public}s!", valStr.c_str());
        value = static_cast<int32_t>(result);
        return true;
    }
    value = result;
    return true;
}

void AVPlayerAni::ResetUserParameters()
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

void AVPlayerAni::StartListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Start();
    }
}

bool AVPlayerAni::IsSystemApp()
{
    static bool isSystemApp = false;
#ifndef CROSS_PLATFORM
    static std::once_flag once;
    std::call_once(once, [] {
        uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
        isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    });
#endif
    return isSystemApp;
}

void AVPlayerAni::PauseListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Pause();
    }
}

static void CompleteCallback(ani_env *env, std::shared_ptr<AVPlayerContext> &context)
{
    if (context == nullptr) {
        MEDIA_LOGE("context is nullptr");
        return;
    }
    if (context->errFlag) {
        ani_object errorObj {};
        MEDIA_LOGE("async callback failed");
        MediaAniUtils::CreateError(env, context->errCode, context->errMessage, errorObj);
        env->ThrowError(static_cast<ani_error>(errorObj));
    }
}

static void CompleteCallback(ani_env *env, std::shared_ptr<AVPlayerContext> &context, ani_object &resultObj)
{
    if (context == nullptr) {
        MEDIA_LOGE("context is nullptr");
        return;
    }
    if (context->errFlag) {
        ani_object errorObj {};
        MEDIA_LOGE("async callback failed");
        MediaAniUtils::CreateError(env, context->errCode, context->errMessage, errorObj);
        env->ThrowError(static_cast<ani_error>(errorObj));
    } else {
        if (context->aniResult != nullptr) {
            context->aniResult->GetAniResult(env, resultObj);
        }
    }
}

void AVPlayerContext::SignError(int32_t code, const std::string &message, bool del)
{
    errMessage = message;
    errCode = code;
    errFlag = true;
    delFlag = del;
    MEDIA_LOGE("SignError: %{public}s", message.c_str());
}

void AVPlayerAni::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->OnErrorCb(errorCode, errorMsg);
    }
}

void AVPlayerAni::SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[callbackName] = ref;
    if (playerCb_ != nullptr) {
        playerCb_->SaveCallbackReference(callbackName, ref);
    }
}

void AVPlayerAni::ClearCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->ClearCallbackReference(callbackName);
    }
    refMap_.erase(callbackName);
}

bool AVPlayerAni::IsLiveSource()
{
    return isLiveStream_;
}

bool AVPlayerAni::IsControllable()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PLAYING ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    } else {
        return false;
    }
}

std::string AVPlayerAni::GetCurrentState()
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

ani_status AVPlayerAni::AVPlayerAniInit(ani_env *env)
{
    static const char *className = "@ohos.multimedia.media.media.AVPlayerHandle";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        MEDIA_LOGE("Failed to find class: %{public}s", className);
        return (ani_status)ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"setSpeed", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetSpeed)},
        ani_native_function {"setVolume", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetVolume)},
        ani_native_function {"getTrackDescriptionSync", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::GetTrackDescriptionSync)},
        ani_native_function {"seekmode", nullptr, reinterpret_cast<void *>(AVPlayerAni::Seekmode)},
        ani_native_function {"seekWithoutmode", nullptr, reinterpret_cast<void *>(AVPlayerAni::SeekWithoutmode)},
        ani_native_function {"prepareSync", nullptr, reinterpret_cast<void *>(AVPlayerAni::PrepareSync)},
        ani_native_function {"pauseSync", nullptr, reinterpret_cast<void *>(AVPlayerAni::PauseSync)},
        ani_native_function {"playSync", nullptr, reinterpret_cast<void *>(AVPlayerAni::PlaySync)},
        ani_native_function {"resetSync", nullptr, reinterpret_cast<void *>(AVPlayerAni::ResetSync)},
        ani_native_function {"stopSync", nullptr, reinterpret_cast<void *>(AVPlayerAni::StopSync)},
        ani_native_function {"on", nullptr, reinterpret_cast<void *>(AVPlayerAni::OnSync)},
        ani_native_function {"off", nullptr, reinterpret_cast<void *>(AVPlayerAni::OffSync)},
        ani_native_function {"setDataSrc", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetDataSrc)},
        ani_native_function {"getDataSrc", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetDataSrc)},
        ani_native_function {"setAudioInterruptMode", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::SetAudioInterruptMode)},
        ani_native_function {"getAudioInterruptMode", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::GetAudioInterruptMode)},
        ani_native_function {"setLoop", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetLoop)},
        ani_native_function {"getLoop", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetLoop)},
        ani_native_function {"getCurrentTime", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetCurrentTime)},
        ani_native_function {"getDuration", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetDuration)},
        ani_native_function {"setVideoScaleType", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetVideoScaleType)},
        ani_native_function {"getVideoScaleType", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetVideoScaleType)},
        ani_native_function {"setAudioRendererInfo", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::SetAudioRendererInfo)},
        ani_native_function {"getAudioRendererInfo", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::GetAudioRendererInfo)},
        ani_native_function {"getstate", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetState)},
        ani_native_function {"setSurfaceId", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetSurfaceId)},
        ani_native_function {"getSurfaceId", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetSurfaceId)},
        ani_native_function {"setUrl", nullptr, reinterpret_cast<void *>(AVPlayerAni::SetUrl)},
        ani_native_function {"getUrl", nullptr, reinterpret_cast<void *>(AVPlayerAni::GetUrl)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        MEDIA_LOGE("Failed to bind native methods to: %{public}s", className);
        return (ani_status)ANI_ERROR;
    };
    return ANI_OK;
}

ani_object AVPlayerAni::Constructor([[maybe_unused]] ani_env *env)
{
    std::unique_ptr<AVPlayerAni> nativeAVPlayerAni = std::make_unique<AVPlayerAni>();
    CHECK_AND_RETURN_RET_LOG(nativeAVPlayerAni != nullptr, nullptr, "failed to new AVPlayerAni");

    nativeAVPlayerAni->env_ = env;
    nativeAVPlayerAni->player_ = PlayerFactory::CreatePlayer();
    CHECK_AND_RETURN_RET_LOG(nativeAVPlayerAni->player_ != nullptr, nullptr, "failed to CreatePlayer");

    nativeAVPlayerAni->taskQue_ = std::make_unique<TaskQueue>("OS_AVPlayerNapi");
    (void)nativeAVPlayerAni->taskQue_->Start();

    nativeAVPlayerAni->playerCb_ = std::make_shared<AniAVPlayerCallback>(env, nativeAVPlayerAni.get());
    (void)nativeAVPlayerAni->player_->SetPlayerCallback(nativeAVPlayerAni->playerCb_);

    static const char *className = "@ohos.multimedia.media.media.AVPlayerHandle";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        MEDIA_LOGE("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        MEDIA_LOGE("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object AVPlayer_object;
    if (ANI_OK != env->Object_New(cls, ctor, &AVPlayer_object,
        reinterpret_cast<ani_long>(nativeAVPlayerAni.release()))) {
        MEDIA_LOGE("New Media Fail");
        return nullptr;
    }
    return AVPlayer_object;
}

AVPlayerAni* AVPlayerAni::Unwrapp(ani_env *env, ani_object object)
{
    ani_long helper;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeAVPlayer", &helper)) {
        return nullptr;
    }
    return reinterpret_cast<AVPlayerAni*>(helper);
}

void AVPlayerAni::SetDataSrc(ani_env *env, ani_object object, ani_object dataObj)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    CHECK_AND_RETURN_LOG(
        MediaAniUtils::ParseAVDataSrcDescriptor(env, dataObj, aVPlayerAni->dataSrcDescriptor_) == ANI_OK,
        "ParseAVDataSrcDescriptor failed");
    if (aVPlayerAni->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set dataSrc");
        return;
    }
    aVPlayerAni->StartListenCurrentResource();
    aVPlayerAni->dataSrcCb_ = std::make_shared<MediaDataSourceCallbackAni>(env,
        (aVPlayerAni->dataSrcDescriptor_.fileSize));
        std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, aVPlayerAni->dataSrcDescriptor_.callback);
    aVPlayerAni->dataSrcCb_->SaveCallbackReference(READAT_CALLBACK_NAME, autoRef);
    if (aVPlayerAni->player_ != nullptr) {
        if (aVPlayerAni->player_->SetSource(aVPlayerAni->dataSrcCb_) != MSERR_OK) {
            aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource DataSrc failed");
        } else {
            aVPlayerAni->state_ = PlayerStates::PLAYER_INITIALIZED;
        }
        if (aVPlayerAni->dataSrcDescriptor_.fileSize == -1) {
            aVPlayerAni->isLiveStream_ = true;
        }
    }
    return;
}

ani_object AVPlayerAni::GetDataSrc(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return nullptr;
    }
    CHECK_AND_RETURN_RET_LOG(aVPlayerAni->dataSrcCb_ != nullptr, nullptr, "failed to check dataSrcCb_");
    AVDataSrcDescriptor avData;
    (void)aVPlayerAni->dataSrcCb_->GetSize(avData.fileSize);
    int32_t ret = aVPlayerAni->dataSrcCb_->GetCallback(READAT_CALLBACK_NAME, avData.callback);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to GetCallback");
    return MediaAniUtils::CreateAVDataSrcDescriptor(env, avData);
}

void AVPlayerAni::SetAudioInterruptMode(ani_env *env, ani_object object, ani_enum_item mode)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport audio interrupt operation");
        return;
    }
    ani_int aniInt {};
    CHECK_AND_RETURN_LOG(env->EnumItem_GetValue_Int(mode, &aniInt) == ANI_OK, "EnumItem_GetValue_Int failed");
    int32_t interruptMode = static_cast<int32_t>(aniInt);
    if (interruptMode < AudioStandard::InterruptMode::SHARE_MODE ||
        interruptMode > AudioStandard::InterruptMode::INDEPENDENT_MODE) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input interrupt Mode");
        return;
    }
    aVPlayerAni->interruptMode_ = static_cast<AudioStandard::InterruptMode>(interruptMode);
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni]() {
        if (aVPlayerAni->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, aVPlayerAni->interruptMode_);
            (void)aVPlayerAni->player_->SetParameter(format);
        }
    });
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    return;
}

ani_enum_item AVPlayerAni::GetAudioInterruptMode(ani_env *env, ani_object object)
{
    ani_enum_item mode {};
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return mode;
    }
    CHECK_AND_RETURN_RET_LOG(MediaAniUtils::ToAniEnum(env, aVPlayerAni->interruptMode_, mode) == ANI_OK, mode,
        "Get interruptMode index fail");
    return mode;
}

void AVPlayerAni::SetLoop(ani_env *env, ani_object object, ani_boolean isLoop)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->IsLiveSource()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support loop");
        return;
    }
    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport loop operation");
        return;
    }
    aVPlayerAni->loop_ = static_cast<bool>(isLoop);
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni]() {
        if (aVPlayerAni->player_ != nullptr) {
            (void)aVPlayerAni->player_->SetLooping(aVPlayerAni->loop_);
        }
    });
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    return;
}

ani_boolean AVPlayerAni::GetLoop(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return false;
    }
    return static_cast<ani_boolean>(aVPlayerAni->loop_);
}

ani_double AVPlayerAni::GetCurrentTime(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return false;
    }

    int32_t currentTime = -1;
    if (aVPlayerAni->IsControllable()) {
        currentTime = aVPlayerAni->position_;
    }
    if (aVPlayerAni->IsLiveSource() && aVPlayerAni->dataSrcCb_ == nullptr) {
        currentTime = -1;
    }
    ani_double value = {};
    MediaAniUtils::ToAniDouble(env, currentTime, value);
    std::string curState = aVPlayerAni->GetCurrentState();
    if (currentTime != -1) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetCurrenTime Out, state %{public}s, time: %{public}d",
            FAKE_POINTER(aVPlayerAni), curState.c_str(), currentTime);
    }
    return value;
}

ani_double AVPlayerAni::GetDuration(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return false;
    }

    int32_t duration = -1;
    if (aVPlayerAni->IsControllable() && !aVPlayerAni->IsLiveSource()) {
        duration = aVPlayerAni->duration_;
    }
    ani_double value = {};
    MediaAniUtils::ToAniDouble(env, duration, value);
    std::string curState = aVPlayerAni->GetCurrentState();
    MEDIA_LOGD("GetDuration Out, state %{public}s, duration %{public}d", curState.c_str(), duration);
    return value;
}

ani_double AVPlayerAni::GetVideoScaleType(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return false;
    }

    ani_double value = {};
    MediaAniUtils::ToAniDouble(env, aVPlayerAni->videoScaleType_, value);
    MEDIA_LOGI("GetVideoScaleType Out Current VideoScale: %{public}d", aVPlayerAni->videoScaleType_);
    return value;
}

void AVPlayerAni::SetVideoScaleType(ani_env *env, ani_object object, ani_enum_item videoScaleType)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video scale operation");
        return;
    }
    int32_t type = 0;
    AVImageGeneratorEnumAni::EnumGetValueInt32(env, videoScaleType, type);
    aVPlayerAni->videoScaleType_ = type;
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni, type]() {
        MEDIA_LOGI("SetVideoScaleType Task");
        if (aVPlayerAni->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, type);
            (void)aVPlayerAni->player_->SetParameter(format);
        }
    });
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("SetVideoScaleType Out");
}

ani_object AVPlayerAni::GetAudioRendererInfo(ani_env *env, ani_object object)
{
    ani_object result = {};
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return result;
    }

    result = MediaAniUtils::CreateAudioRendererInfo(env, aVPlayerAni->audioRendererInfo_);
    MEDIA_LOGI("GetAudioRendererInfo Out");
    return result;
}

void AVPlayerAni::SetAudioRendererInfo(ani_env *env, ani_object object, ani_object infoObj)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->GetCurrentState() != AVPlayerState::STATE_INITIALIZED) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized, unsupport to set audio renderer info");
        return;
    }

    MediaAniUtils::ParseAudioRendererInfo(env, infoObj, aVPlayerAni->audioRendererInfo_);
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni]() {
        MEDIA_LOGI("SetAudioRendererInfo Task");
        if (aVPlayerAni->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, aVPlayerAni->audioRendererInfo_.contentType);
            (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, aVPlayerAni->audioRendererInfo_.streamUsage);
            (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, aVPlayerAni->audioRendererInfo_.rendererFlags);
            (void)format.PutIntValue(PlayerKeys::VOLUME_MODE, aVPlayerAni->audioRendererInfo_.volumeMode);
            (void)aVPlayerAni->player_->SetParameter(format);
        }
    });
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("SetAudioRendererInfo Out");
}

void AVPlayerAni::SetSpeed(ani_env *env, ani_object object, ani_enum_item speed)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    int32_t mode = SPEED_FORWARD_1_00_X;
    if (aVPlayerAni->IsLiveSource()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY,
            "The stream is live stream, not support speed");
        return;
    }
    ani_status status = AVImageGeneratorEnumAni::EnumGetValueInt32(env, speed, mode);
    if (status != ANI_OK || mode < SPEED_FORWARD_0_75_X || mode > SPEED_FORWARD_0_125_X) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY,
            "The stream is live stream, not support speed");
        return;
    }
    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport speed operation");
        return;
    }
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task In", FAKE_POINTER(aVPlayerAni));
        if (aVPlayerAni->player_ != nullptr) {
            (void)aVPlayerAni->player_->SetPlaybackSpeed(static_cast<PlaybackRateMode>(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task Out", FAKE_POINTER(aVPlayerAni));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSpeed EnqueueTask In", FAKE_POINTER(aVPlayerAni));
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSpeed Out", FAKE_POINTER(aVPlayerAni));
}

void AVPlayerAni::SetVolume(ani_env *env, ani_object object, ani_double volume)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->playerCb_->isSetVolume_) {
        MEDIA_LOGI("SetVolume is processing, skip this task until onVolumeChangedCb");
    }
    aVPlayerAni->playerCb_->isSetVolume_ = true;

    double volumeValue;
    ani_status status = MediaAniUtils::GetDouble(env, volume, volumeValue);
    if (status != ANI_OK || volumeValue < 0.0f || volumeValue > 1.0f) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check volume level");
        return;
    }

    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport volume operation");
        return;
    }
    auto task = std::make_shared<TaskHandler<void>>([aVPlayerAni, volumeValue]() {
        MEDIA_LOGI("SetVolume Task");
        if (aVPlayerAni->player_ != nullptr) {
            (void)aVPlayerAni->player_->SetVolume(volumeValue, volumeValue);
        }
    });
    (void)aVPlayerAni->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetVolume Out");
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::GetTrackDescriptionTask(const std::shared_ptr<AVPlayerContext>
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

ani_object AVPlayerAni::GetTrackDescriptionSync(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return nullptr;
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetTrackDescription EnqueueTask In", FAKE_POINTER(aVPlayerAni));
    context->asyncTask = aVPlayerAni->GetTrackDescriptionTask(context);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetTrackDescription EnqueueTask Out", FAKE_POINTER(aVPlayerAni));
    auto result = context->asyncTask->GetResult();
    if (!result.HasResult()) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "task has been cleared");
    }
    if (result.Value().first != MSERR_EXT_API9_OK) {
        context->SignError(result.Value().first, result.Value().second);
    }
    context->aniResult = std::make_unique<MediaAniResultArray>(context->trackInfoVec_);
    ani_object resultObj {};
    CompleteCallback(env, context, resultObj);
    return resultObj;
}

void AVPlayerAni::Seekmode(ani_env *env, ani_object object, ani_double timeMs, ani_enum_item mode)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    if (aVPlayerAni->IsLiveSource()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY,
            "The stream is live stream, not support seek");
        return;
    }

    int32_t time = -1;
    time = static_cast<int32_t>(timeMs);

    int32_t modeValue = SEEK_PREVIOUS_SYNC;
    ani_status status = AVImageGeneratorEnumAni::EnumGetValueInt32(env, mode, modeValue);
    if (status != ANI_OK || modeValue < SEEK_NEXT_SYNC || modeValue > SEEK_CONTINUOUS_TS_ENUM_NUM) {
        MEDIA_LOGE("invalid parameters, please check seek mode");
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek mode");
        return;
    }

    bool isNegativeTime = time < 0;
    bool isExitSeekContinuous = time == -1 && modeValue == SEEK_CONTINUOUS_TS_ENUM_NUM;
    if (isNegativeTime && !isExitSeekContinuous) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
        return;
    }

    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport seek operation");
        return;
    }
    SeekEnqueueTask(aVPlayerAni, time, modeValue);
}

void AVPlayerAni::SeekEnqueueTask(AVPlayerAni *aniPlayer, int32_t time, int32_t mode)
{
    auto task = std::make_shared<TaskHandler<void>>([aniPlayer, time, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Task In", FAKE_POINTER(aniPlayer));
        if (aniPlayer->player_ != nullptr) {
            (void)aniPlayer->player_->Seek(time, aniPlayer->TransferSeekMode(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Task Out", FAKE_POINTER(aniPlayer));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek EnqueueTask In", FAKE_POINTER(aniPlayer));
    (void)aniPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Out", FAKE_POINTER(aniPlayer));
}

void AVPlayerAni::SeekWithoutmode(ani_env *env, ani_object object, ani_double timeMs)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    int32_t time = static_cast<int32_t>(timeMs);
    PlayerSeekMode modeValue = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    if (aVPlayerAni->IsLiveSource()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY,
            "The stream is live stream, not support seek");
        return;
    }

    if (time < 0) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
        MEDIA_LOGE("invalid parameters, please check seek time");
        return;
    }

    if (!aVPlayerAni->IsControllable()) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport seek operation");
        return;
    }
    SeekEnqueueTask(aVPlayerAni, time, modeValue);
}

PlayerSeekMode AVPlayerAni::TransferSeekMode(int32_t mode)
{
    PlayerSeekMode seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    switch (mode) {
        case SeekMode::SEEK_MODE_ZERO:
            seekMode = PlayerSeekMode::SEEK_NEXT_SYNC;
            break;
        case SeekMode::SEEK_MODE_ONE:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
        case SeekMode::SEEK_MODE_TWO:
            seekMode = PlayerSeekMode::SEEK_CLOSEST;
            break;
        case SeekMode::SEEK_MODE_THREE:
            seekMode = PlayerSeekMode::SEEK_CONTINOUS;
            break;
        default:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
    }
    return seekMode;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::ResetTask()
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

void AVPlayerAni::ResetSync(ani_env *env, ani_object object)
{
    auto avPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (avPlayerAni == nullptr || avPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    if (avPlayerAni->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is released, unsupport reset operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsReset EnqueueTask In", FAKE_POINTER(avPlayerAni));
        context->asyncTask = avPlayerAni->ResetTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsReset EnqueueTask Out", FAKE_POINTER(avPlayerAni));
        if (avPlayerAni->dataSrcCb_ != nullptr) {
            avPlayerAni->dataSrcCb_->ClearCallbackReference();
            avPlayerAni->dataSrcCb_ = nullptr;
        }
        avPlayerAni->isLiveStream_ = false;
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    CompleteCallback(env, context);
    return;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::PrepareTask()
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
            MEDIA_LOGI("current state is prepared, invalid operation");
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

void AVPlayerAni::PrepareSync(ani_env *env, ani_object object)
{
    auto avPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (avPlayerAni == nullptr || avPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    auto state = avPlayerAni->GetCurrentState();
    if (state != AVPlayerState::STATE_INITIALIZED &&
        state != AVPlayerState::STATE_STOPPED &&
        state != AVPlayerState::STATE_PREPARED) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not stopped or initialized, unsupport prepare operation");
    } else {
        context->asyncTask = avPlayerAni->PrepareTask();
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
    });
    t1.detach();
    CompleteCallback(env, context);
    return;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::PauseTask()
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

        MEDIA_LOGE("0x%{public}06" PRIXPTR " Pause Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

void AVPlayerAni::PauseSync(ani_env *env, ani_object object)
{
    auto avPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (avPlayerAni == nullptr || avPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    auto state = avPlayerAni->GetCurrentState();
    if (state != AVPlayerState::STATE_PLAYING && state != AVPlayerState::STATE_PAUSED) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not playing, unsupport pause operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPause EnqueueTask In", FAKE_POINTER(avPlayerAni));
        context->asyncTask = avPlayerAni->PauseTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPause EnqueueTask Out", FAKE_POINTER(avPlayerAni));
    }
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    CompleteCallback(env, context);
    return;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::PlayTask()
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
            MEDIA_LOGI("current state is playing, invalid operation");
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

void AVPlayerAni::PlaySync(ani_env *env, ani_object object)
{
    auto avPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (avPlayerAni == nullptr || avPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    auto state = avPlayerAni->GetCurrentState();
    if (state != AVPlayerState::STATE_PREPARED &&
        state != AVPlayerState::STATE_PAUSED &&
        state != AVPlayerState::STATE_COMPLETED &&
        state != AVPlayerState::STATE_PLAYING) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/paused/completed, unsupport play operation");
    } else if (state == AVPlayerState::STATE_COMPLETED && avPlayerAni->IsLiveSource()) {
        context->SignError(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "In live mode, replay not be allowed.");
    } else {
        context->asyncTask = avPlayerAni->PlayTask();
    }
    MEDIA_LOGI("Wait JsPlay Task Start");
    auto t1 = std::thread([context]() {
        context->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
    });
    t1.detach();
    MEDIA_LOGI("Wait JsPlay Task End");
    CompleteCallback(env, context);
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerAni::StopTask()
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

void AVPlayerAni::StopSync(ani_env *env, ani_object object)
{
    auto avPlayerAni = AVPlayerAni::Unwrapp(env, object);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    if (avPlayerAni == nullptr || avPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }

    auto state = avPlayerAni->GetCurrentState();
    if (state == AVPlayerState::STATE_IDLE ||
        state == AVPlayerState::STATE_INITIALIZED ||
        state == AVPlayerState::STATE_RELEASED ||
        state == AVPlayerState::STATE_ERROR) {
        context->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport stop operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsStop EnqueueTask In", FAKE_POINTER(avPlayerAni));
        context->asyncTask = avPlayerAni->StopTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsStop EnqueueTask Out", FAKE_POINTER(avPlayerAni));
    }
    MEDIA_LOGI("Wait JsStop Task Start");
    auto t1 = std::thread([context]() {
        context->CheckTaskResult();
    });
    t1.detach();
    MEDIA_LOGI("Wait JsStop Task End");
    CompleteCallback(env, context);
    return;
}

void AVPlayerAni::OnSync(ani_env *env, ani_object object, ani_string type, ani_object callbackOn)
{
    MEDIA_LOGI("AVPlayer OnSync start");
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is released, unsupport to on event");
        return;
    }
    std::string callbackName;
    MediaAniUtils::GetString(env, type, callbackName);
    aVPlayerAni->MaxAmplitudeCallbackOn(aVPlayerAni, callbackName);

    ani_ref cbOnRef = static_cast<ani_ref>(callbackOn);
    ani_ref cbInner = {};
    env->GlobalReference_Create(cbOnRef, &cbInner);
    std::shared_ptr<AutoRef> aniRef = std::make_shared<AutoRef>(env, cbInner);
    aVPlayerAni->SaveCallbackReference(callbackName, aniRef);

    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetOnCallback callbackName: %{public}s success",
        FAKE_POINTER(aVPlayerAni), callbackName.c_str());
}

void AVPlayerAni::MaxAmplitudeCallbackOn(AVPlayerAni *AVPlayer, std::string callbackName)
{
    if (AVPlayer == nullptr) {
        calMaxAmplitude_ = false;
        return;
    }
    if (callbackName == "amplitudeUpdate") {
        calMaxAmplitude_ = true;
    }
    if (AVPlayer->player_ != nullptr && calMaxAmplitude_) {
        (void)AVPlayer->player_->SetMaxAmplitudeCbStatus(calMaxAmplitude_);
    }
}

void AVPlayerAni::OffSync(ani_env *env, ani_object object, ani_string type)
{
    MEDIA_LOGI("AVPlayer OffSync start");
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    std::string callbackName;
    MediaAniUtils::GetString(env, type, callbackName);
    aVPlayerAni->MaxAmplitudeCallbackOff(aVPlayerAni, callbackName);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " set callbackName: %{public}s", FAKE_POINTER(aVPlayerAni),
        callbackName.c_str());

    aVPlayerAni->ClearCallbackReference(callbackName);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsClearOnCallback success", FAKE_POINTER(aVPlayerAni));
}

void AVPlayerAni::MaxAmplitudeCallbackOff(AVPlayerAni *AVPlayer, std::string callbackName)
{
    if (AVPlayer != nullptr && calMaxAmplitude_ && callbackName == "amplitudeUpdate") {
        calMaxAmplitude_ = false;
        if (AVPlayer->player_ != nullptr) {
            (void)AVPlayer->player_->SetMaxAmplitudeCbStatus(calMaxAmplitude_);
        }
    }
}

void AVPlayerAni::NotifyDuration(int32_t duration)
{
    duration_ = duration;
}

void AVPlayerAni::NotifyPosition(int32_t position)
{
    position_ = position;
}

void AVPlayerAni::NotifyState(PlayerStates state)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    if (state_ != state) {
        state_ = state;
        MEDIA_LOGI("0x%{public}06" PRIXPTR " notify %{public}s", FAKE_POINTER(this), GetCurrentState().c_str());
        stopWait_ = true;
        stateChangeCond_.notify_all();
    }
}

void AVPlayerAni::NotifyVideoSize(int32_t width, int32_t height)
{
    width_ = width;
    height_ = height;
}

void AVPlayerAni::NotifyIsLiveStream()
{
    isLiveStream_ = true;
}

void AVPlayerAni::NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos)
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

int32_t AVPlayerAni::GetJsApiVersion()
{
    if (player_ != nullptr && getApiVersionFlag_) {
        getApiVersionFlag_ = false;
        player_->GetApiVersion(g_apiVersion);
        MEDIA_LOGI("apiVersion is: %{public}d", g_apiVersion);
    }
    return g_apiVersion;
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

ani_string AVPlayerAni::GetState(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return nullptr;
    }
    std::string curState = aVPlayerAni->GetCurrentState();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsGetState curState: %{public}s ",
        FAKE_POINTER(aVPlayerAni), curState.c_str());
    ani_string value = {};
    MediaAniUtils::ToAniString(env, curState, value);
    return value;
}

#ifdef SUPPORT_VIDEO
void AVPlayerAni::SetSurface(const std::string &surfaceStr)
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

    auto surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
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
void AVPlayerAni::SetSurface(const std::string &surfaceStr)
{
    (void)surfaceStr;
    OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The music player does not need to support (Surface)");
}
#endif

void AVPlayerAni::SetSurfaceId(ani_env *env, ani_object object, ani_string surfaceId)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    std::string curState = aVPlayerAni->GetCurrentState();
    bool setSurfaceFirst = curState == AVPlayerState::STATE_INITIALIZED;
    bool switchSurface = curState == AVPlayerState::STATE_PREPARED ||
        curState == AVPlayerState::STATE_PLAYING ||
        curState == AVPlayerState::STATE_PAUSED ||
        curState == AVPlayerState::STATE_STOPPED ||
        curState == AVPlayerState::STATE_COMPLETED;
    if (setSurfaceFirst) {
        MEDIA_LOGI("JsSetSurfaceID set surface first in %{public}s state", curState.c_str());
    } else if (switchSurface) {
        MEDIA_LOGI("JsSetSurfaceID switch surface in %{public}s state", curState.c_str());
        std::string oldSurface = aVPlayerAni->surface_;
        if (oldSurface.empty()) {
            aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "switch surface with no old surface");
            return;
        }
    } else {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "the attribute(SurfaceID) can only be set in the initialized state");
        return;
    }
    std::string surFace;
    MediaAniUtils::GetString(env, surfaceId, surFace);
    aVPlayerAni->surface_ = surFace;
    aVPlayerAni->SetSurface(aVPlayerAni->surface_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSurfaceID Out", FAKE_POINTER(aVPlayerAni));
}

ani_string AVPlayerAni::GetSurfaceId(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return nullptr;
    }
    ani_string value = {};
    MediaAniUtils::ToAniString(env, aVPlayerAni->surface_, value);
    return value;
}

void AVPlayerAni::SetUrl(ani_env *env, ani_object object, ani_string url)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return;
    }
    if (aVPlayerAni->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        aVPlayerAni->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return;
    }
    aVPlayerAni->StartListenCurrentResource();
    std::string curUrl;
    MediaAniUtils::GetString(env, url, curUrl);
    aVPlayerAni->url_ = curUrl;

    aVPlayerAni->SetSource(aVPlayerAni->url_);
}

void AVPlayerAni::SetSource(std::string url)
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

void AVPlayerAni::EnqueueFdTask(const int32_t fd)
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

void AVPlayerAni::EnqueueNetworkTask(const std::string url)
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
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Set source network out", FAKE_POINTER(this));
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerAni::QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN_LOG(!isReleased_.load(), "load success");
    auto task = std::make_shared<TaskHandler<void>>([this, errorCode, errorMsg] {
        OnErrorCb(errorCode, errorMsg);
    });
    (void)taskQue_->EnqueueTask(task);
}


ani_string AVPlayerAni::GetUrl(ani_env *env, ani_object object)
{
    auto aVPlayerAni = AVPlayerAni::Unwrapp(env, object);
    if (aVPlayerAni == nullptr || aVPlayerAni->player_ == nullptr) {
        MEDIA_LOGE("AVPlayerAni is nullptr");
        return nullptr;
    }
    ani_string value = {};
    MediaAniUtils::ToAniString(env, aVPlayerAni->url_, value);
    return value;
}

ani_status MediaAniResultArray::GetAniResult(ani_env *env, ani_object &result)
{
    ani_class cls {};
    static const std::string className = "escompat.Array";
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        MEDIA_LOGE("Can't find escompat.Array");
        return status;
    }
    ani_method arrayConstructor {};
    status = env->Class_FindMethod(cls, "<ctor>", "i:", &arrayConstructor);
    if (status != ANI_OK) {
        MEDIA_LOGE("Can't find method <ctor> in escompat.Array");
        return status;
    }
    status = env->Object_New(cls, arrayConstructor, &result, value_.size());
    if (status != ANI_OK) {
        MEDIA_LOGE("New aniArray failed");
        return status;
    }
    ani_method setMethod {};
    status = env->Class_FindMethod(cls, "$_set", "iC{std.core.Object}:", &setMethod);
    if (status != ANI_OK) {
        MEDIA_LOGE("Can't find method $_set in escompat.Array.");
        return status;
    }
    auto vecSize = value_.size();
    for (size_t index = 0; index < vecSize; ++index) {
        ani_object description = nullptr;
        description = CommonAni::CreateFormatBuffer(env, value_[index]);
        if (description == nullptr || env->Object_CallMethod_Void(result, setMethod, index, description) != ANI_OK) {
            return ANI_ERROR;
        }
    }
    return ANI_OK;
}

}
}
