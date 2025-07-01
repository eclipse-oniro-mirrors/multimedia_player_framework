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
#include "sound_pool_taihe.h"
#include "media_log.h"
#include "ability.h"
#include "ani_base_context.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "media_taihe_utils.h"
#include "sound_pool_callback_taihe.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPoolTaihe"};
}

namespace ANI {
namespace Media {
int32_t SoundPoolImpl::maxStreams = 0;
OHOS::AudioStandard::AudioRendererInfo SoundPoolImpl::rendererInfo;

SoundPoolImpl::SoundPoolImpl(int32_t maxStreams, uintptr_t audioRendererInfo)
{
    ani_env *env = taihe::get_env();
    SoundPoolImpl::ParseAudioRendererInfo(env, reinterpret_cast<ani_object>(audioRendererInfo),
        SoundPoolImpl::rendererInfo);
    soundPool_ = OHOS::Media::SoundPoolFactory::CreateSoundPool(maxStreams, SoundPoolImpl::rendererInfo);
    if (soundPool_ == nullptr) {
        MEDIA_LOGE("failed to CreateSoundPool");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateSoundPool");
        return;
    } else {
        callbackTaihe_ =  std::make_shared<SoundPoolCallBackTaihe>();
        (void)soundPool_->SetSoundPoolCallback(callbackTaihe_);
    }
}

void SoundPoolImpl::ParseAudioRendererInfo(ani_env *env, ani_object src,
    OHOS::AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    static const char *className = "@ohos.multimedia.audio.audio.AudioRendererInfo";
    ani_class cls {};
    CHECK_AND_RETURN_LOG(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);
    ani_method contentGetter {};
    CHECK_AND_RETURN_LOG(env->Class_FindMethod(cls, "<get>content", nullptr, &contentGetter),
        "Failed to find method: <get>content");
    ani_int content {};
    CHECK_AND_RETURN_LOG(env->Object_CallMethod_Int(src, contentGetter, &content), "<get>content fail");
    audioRendererInfo.contentType = static_cast<OHOS::AudioStandard::ContentType>(content);

    ani_method usageGetter {};
    CHECK_AND_RETURN_LOG(env->Class_FindMethod(cls, "<get>usage", nullptr, &usageGetter),
        "Failed to find method: <get>usage");
    ani_int usage {};
    CHECK_AND_RETURN_LOG(env->Object_CallMethod_Int(src, usageGetter, &usage), "<get>usage fail");
    audioRendererInfo.streamUsage = static_cast<OHOS::AudioStandard::StreamUsage>(usage);

    ani_method rendererFlagsGetter {};
    CHECK_AND_RETURN_LOG(env->Class_FindMethod(cls, "<get>rendererFlags", nullptr, &rendererFlagsGetter),
        "Failed to find method: <get>rendererFlags");
    ani_int rendererFlags {};
    CHECK_AND_RETURN_LOG(env->Object_CallMethod_Int(src, rendererFlagsGetter, &rendererFlags),
        "<get>rendererFlags fail");
    audioRendererInfo.rendererFlags = static_cast<int32_t>(rendererFlags);
}

RetInfo GetRetInfo(int32_t errCode, const std::string &operate, const std::string &param, const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d", operate.c_str(), param.c_str(), errCode);
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    if (errCode == MSERR_UNSUPPORT_VID_PARAMS) {
        return RetInfo(err, "The video parameter is not supported. Please check the type and range.");
    }

    if (errCode == MSERR_UNSUPPORT_AUD_PARAMS) {
        return RetInfo(err, "The audio parameter is not supported. Please check the type and range.");
    }

    std::string message;
    if (err == MSERR_EXT_API9_INVALID_PARAMETER) {
        message = MSExtErrorAPI9ToString(err, param, "") + add;
    } else {
        message = MSExtErrorAPI9ToString(err, operate, "") + add;
    }

    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, message.c_str());
    return RetInfo(err, message);
}

optional<SoundPool> CreateSoundPoolSync(double maxStreams, uintptr_t audioRendererInfo)
{
    auto res = make_holder<SoundPoolImpl, SoundPool>(maxStreams, audioRendererInfo);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create SoundPool failed!");
        taihe::reset_error();
        return optional<SoundPool>(std::nullopt);
    }
    return optional<SoundPool>(std::in_place, res);
}

double SoundPoolImpl::PlaySync(double soundID, optional_view<PlayParameters> params)
{
    MediaTrace trace("SoundPool::TaihePlay");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlay");

    soundId_ = soundID;
    CHECK_AND_RETURN_RET(soundId_ > 0,
        (SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId"), MSERR_INVALID_VAL));
    if (params.has_value()) {
        int32_t ret = ParserPlayOption(params.value());
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, 0, "failed to SendEvent, ret = %{public}d", ret);
    }
    CHECK_AND_RETURN_RET_LOG(soundPool_ != nullptr, 0, "soundPool_ is nullptr!");
    int32_t streamId = soundPool_->Play(soundId_, playParameters_);
    if (streamId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
    }
    MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
    return streamId;
}

double SoundPoolImpl::PlayWithoutParam(double soundID)
{
    MediaTrace trace("SoundPool::TaihePlayWithoutParam");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlayWithoutParam");
    soundId_ = soundID;
    CHECK_AND_RETURN_RET(soundId_ > 0,
        (SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId"), MSERR_INVALID_VAL));

    if (soundPool_ == nullptr) {
        MEDIA_LOGE("soundPool_ is nullptr!");
        return -1;
    }
    int32_t streamId = soundPool_->Play(soundId_, playParameters_);
    if (streamId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
    }
    MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
    return streamId;
}

double SoundPoolImpl::PlayWithParam(double soundID, PlayParameters const& params)
{
    MediaTrace trace("SoundPool::TaihePlayWithParam");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlayWithParam");
        soundId_ = soundID;
    CHECK_AND_RETURN_RET(soundId_ > 0,
        (SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId"), MSERR_INVALID_VAL));
    int32_t ret = ParserPlayOption(params);
    MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);

    if (soundPool_ == nullptr) {
        MEDIA_LOGE("soundPool_ is nullptr!");
        return -1;
    }
    int32_t streamId = soundPool_->Play(soundId_, playParameters_);
    if (streamId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
    }
    MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
    return streamId;
}

static std::shared_ptr<OHOS::AbilityRuntime::Context> GetAbilityContext(ani_env *env)
{
    auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        MEDIA_LOGE("Failed to obtain ability in FA mode");
        return nullptr;
    }
    auto faContext = ability->GetAbilityContext();
    if (faContext == nullptr) {
        MEDIA_LOGE("GetAbilityContext returned null in FA model");
        return nullptr;
    }
    return faContext;
}

int32_t SoundPoolImpl::ParserPlayOption(const PlayParameters &params)
{
    if (params.loop.has_value()) {
        playParameters_.loop = static_cast<int32_t>(params.loop.value());
    }
    if (params.rate.has_value()) {
        playParameters_.rate = static_cast<int32_t>(params.rate.value());
    }
    if (params.leftVolume.has_value()) {
        playParameters_.leftVolume = static_cast<float>(params.leftVolume.value());
    }
    if (params.rightVolume.has_value()) {
        playParameters_.rightVolume = static_cast<float>(params.rightVolume.value());
    }
    if (params.priority.has_value()) {
        playParameters_.priority = static_cast<int32_t>(params.priority.value());
    }
    if (params.parallelPlayFlag.has_value()) {
        playParameters_.parallelPlayFlag = static_cast<bool>(params.parallelPlayFlag.value());
    }
    std::shared_ptr<OHOS::AbilityRuntime::Context> abilityContext = GetAbilityContext(get_env());
    if (abilityContext != nullptr) {
        playParameters_.cacheDir = abilityContext->GetCacheDir();
    } else {
        playParameters_.cacheDir = "/data/storage/el2/base/temp";
    }
    MEDIA_LOGI("playParameters_ loop:%{public}d, rate:%{public}d, leftVolume:%{public}f, rightvolume:%{public}f,"
        "priority:%{public}d, parallelPlayFlag:%{public}d", playParameters_.loop, playParameters_.rate,
        playParameters_.leftVolume, playParameters_.rightVolume, playParameters_.priority,
        playParameters_.parallelPlayFlag);
    return MSERR_OK;
}

double SoundPoolImpl::LoadSync(string_view uri)
{
    MediaTrace trace("SoundPool::TaiheLoad");
    MEDIA_LOGI("SoundPoolNapi::TaiheLoad");
    int32_t soundId = 0;
    url_ = static_cast<std::string>(uri);
    CHECK_AND_RETURN_RET(url_ != "",
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "geturl", "url"), soundId));
    soundId = soundPool_->Load(url_);
    if (soundId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "load sound failed");
    }
    return soundId;
}

double SoundPoolImpl::LoadWithFdSync(double fd, double offset, double length)
{
    MediaTrace trace("SoundPool::TaiheLoad");
    MEDIA_LOGI("SoundPoolNapi::TaiheLoad");
    int32_t soundId = 0;
    fd_ = fd;
    CHECK_AND_RETURN_RET(fd_ > 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getfd", "fd"), soundId));
    offset_ = static_cast<int64_t>(offset);
    CHECK_AND_RETURN_RET(offset_ >= 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getoffset", "offset"), soundId));
    length_ = static_cast<int64_t>(length);
    CHECK_AND_RETURN_RET(length_ > 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getlength", "length"), soundId));
    soundId =
        soundPool_->Load(fd, offset_, length_);
    if (soundId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "load sound failed");
    }
    return soundId;
}

void SoundPoolImpl::StopSync(double streamID)
{
    MediaTrace trace("SoundPool::TaiheStop");
    MEDIA_LOGI("SoundPoolNapi::TaiheStop");
    streamId_ = streamID;
    CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
    if (streamId_ <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "stop streamId failed, invaild value");
    }
    int32_t ret = soundPool_->Stop(streamId_);
    if (ret != MSERR_OK) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "stop streamId failed");
    }
    MEDIA_LOGI("The taihe thread of stop finishes execution and returns");
}

void SoundPoolImpl::SetLoopSync(double streamID, double loop)
{
    MediaTrace trace("SoundPool::TaiheSetLoop");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetLoop");
    streamId_ = streamID;
    if (streamId_ <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetLoop streamId failed,invaild value");
    }
    loop_ = loop;
    if (streamId_ > 0) {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetLoop(streamId_, loop_);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "setLoop streamId failed");
        }
        MEDIA_LOGI("The Taihe thread of SetLoop finishes execution and returns");
    }
}

void SoundPoolImpl::SetPrioritySync(double streamID, double priority)
{
    MediaTrace trace("SoundPool::TaiheSetPriority");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetPriority");
    streamId_ = streamID;
    if (streamId_ <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetPriority streamId failed");
    }
    priority_ = priority;
    if (priority_ < 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetPriority priority failed");
    }
    if (streamId_ > 0) {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetPriority(streamId_, priority_);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "SetPriority streamId failed");
        }
        MEDIA_LOGI("The taihe thread of SetPriority finishes execution and returns");
    }
}

void SoundPoolImpl::SetVolumeSync(double streamID, double leftVolume, double rightVolume)
{
    MediaTrace trace("SoundPool::TaiheSetVolume");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetVolume");
    streamId_ = streamID;
    if (streamId_ <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getvolumestreamId", "streamId");
    }
    leftVolume_ = static_cast<float>(leftVolume);
    rightVolume_ = static_cast<float>(rightVolume);
    if (streamId_ > 0) {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetVolume(streamId_, leftVolume_, rightVolume_);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "setVolume streamId failed");
        }
        MEDIA_LOGI("The taihe thread of SetVolume finishes execution and returns");
    }
}

void SoundPoolImpl::UnloadSync(double soundID)
{
    MediaTrace trace("SoundPool::TaiheUnload");
    MEDIA_LOGI("SoundPoolNapi::TaiheUnload");
    soundId_ = soundID;
    CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
    if (soundId_ <= 0) {
        SignError(MSERR_EXT_API9_IO, "unLoad failed,inavild value");
    }
    int32_t ret = soundPool_->Unload(soundId_);
    if (ret != MSERR_OK) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "unLoad soundID failed");
    }
    MEDIA_LOGI("The taihe thread of Unload finishes execution and returns, soundID: %{public}d",
        soundId_);
}

void SoundPoolImpl::ReleaseSync()
{
    MediaTrace trace("SoundPool::TaiheRelease");
    MEDIA_LOGI("SoundPoolNapi::TaiheRelease");
    CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
    int32_t ret = soundPool_->Release();
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "Release failed!");
    CHECK_AND_RETURN_LOG(callbackTaihe_ != nullptr, "release callbackTaihe_ is nullptr!");
    CancelCallback(callbackTaihe_);
}

void SoundPoolImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVTranscoderImpl::OnError");
    MEDIA_LOGI("OnError Start");

    std::string callbackName = SoundPoolEvent::EVENT_ERROR;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnError End");
}

void SoundPoolImpl::OffError()
{
    MediaTrace trace("SoundPoolImpl::OffError");
    MEDIA_LOGI("OffError Start");

    std::string callbackName = SoundPoolEvent::EVENT_ERROR;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffError End");
}

void SoundPoolImpl::OnPlayFinishedWithStreamId(callback_view<void(double)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnPlayFinishedWithStreamId");
    MEDIA_LOGI("OnPlayFinishedWithStreamId Start");
    std::string callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(double)>> taiheCallback =
            std::make_shared<taihe::callback<void(double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
}

void SoundPoolImpl::OffPlayFinishedWithStreamId()
{
    MediaTrace trace("SoundPoolImpl::OffPlayFinishedWithStreamId");
    MEDIA_LOGI("OffPlayFinishedWithStreamId Start");

    std::string callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffPlayFinishedWithStreamId End");
}

void SoundPoolImpl::OnLoadComplete(callback_view<void(double)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnLoadComplete");
    MEDIA_LOGI("OnLoadComplete Start");
    std::string callbackName = SoundPoolEvent::EVENT_LOAD_COMPLETED;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(double)>> taiheCallback =
            std::make_shared<taihe::callback<void(double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
}

void SoundPoolImpl::OffLoadComplete()
{
    MediaTrace trace("SoundPoolImpl::OffLoadComplete");
    MEDIA_LOGI("OffLoadComplete Start");

    std::string callbackName = SoundPoolEvent::EVENT_LOAD_COMPLETED;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffLoadComplete End");
}

void SoundPoolImpl::OnPlayFinished(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnPlayFinished");
    MEDIA_LOGI("OnPlayFinished Start");

    std::string callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnPlayFinished End");
}

void SoundPoolImpl::OffPlayFinished()
{
    MediaTrace trace("SoundPoolImpl::OffPlayFinished");
    MEDIA_LOGI("OffPlayFinished Start");

    std::string callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffPlayFinished End");
}

void SoundPoolImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(callbackTaihe_ != nullptr, "soundpoolCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<SoundPoolCallBackTaihe>(callbackTaihe_);
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void SoundPoolImpl::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(callbackTaihe_ != nullptr, "soundpoolCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<SoundPoolCallBackTaihe>(callbackTaihe_);
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}

void SoundPoolImpl::CancelCallback(std::shared_ptr<ISoundPoolCallback> callback)
{
    CHECK_AND_RETURN_LOG(callback != nullptr, "soundpoolCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<SoundPoolCallBackTaihe>(callback);
    taiheCb->ClearCallbackReference();
}

void SoundPoolImpl::SignError(int32_t code, const std::string &message, bool del)
{
    errMessage = message;
    errCode = code;
    errFlag = true;
    delFlag = del;
    MEDIA_LOGE("SignError: %{public}s", message.c_str());
    set_business_error(errCode, errMessage);
}

void SoundPoolImpl::SoundPoolAsyncSignError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add)
{
    RetInfo retInfo = GetRetInfo(errCode, operate, param, add);
    SignError(retInfo.first, retInfo.second);
}

}
}

TH_EXPORT_CPP_API_CreateSoundPoolSync(ANI::Media::CreateSoundPoolSync);
