/*
 * Copyright (C) 2025 Huawei Device Co., Ltd. 2025-2025. All rights reserved.
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

SoundPoolImpl::SoundPoolImpl(int32_t maxStreams, ohos::multimedia::audio::AudioRendererInfo const& audioRendererInfo)
{
    OHOS::AudioStandard::AudioRendererInfo rendererInfo;
    rendererInfo.streamUsage = static_cast<OHOS::AudioStandard::StreamUsage>(audioRendererInfo.usage.get_value());
    rendererInfo.rendererFlags = audioRendererInfo.rendererFlags;
    soundPool_ = OHOS::Media::SoundPoolFactory::CreateSoundPool(maxStreams, rendererInfo);
    if (soundPool_ == nullptr) {
        MEDIA_LOGE("failed to CreateSoundPool");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateSoundPool");
        return;
    } else {
        callbackTaihe_ =  std::make_shared<SoundPoolCallBackTaihe>();
        (void)soundPool_->SetSoundPoolCallback(callbackTaihe_);
    }
}

SoundPoolImpl::SoundPoolImpl(int32_t maxStreams, ohos::multimedia::audio::AudioRendererInfo const& audioRendererInfo,
    const bool isParallel)
{
    OHOS::AudioStandard::AudioRendererInfo rendererInfo;
    rendererInfo.streamUsage = static_cast<OHOS::AudioStandard::StreamUsage>(audioRendererInfo.usage.get_value());
    rendererInfo.rendererFlags = audioRendererInfo.rendererFlags;
    soundPool_ = isParallel
        ? OHOS::Media::SoundPoolFactory::CreateParallelSoundPool(maxStreams, rendererInfo)
        : OHOS::Media::SoundPoolFactory::CreateSoundPool(maxStreams, rendererInfo);
    if (soundPool_ == nullptr) {
        MEDIA_LOGE("failed to CreateSoundPool");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateSoundPool");
        return;
    } else {
        callbackTaihe_ =  std::make_shared<SoundPoolCallBackTaihe>();
        (void)soundPool_->SetSoundPoolCallback(callbackTaihe_);
    }
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

optional<SoundPool> CreateSoundPoolSync(int32_t maxStreams,
    ohos::multimedia::audio::AudioRendererInfo const& audioRendererInfo)
{
    auto res = make_holder<SoundPoolImpl, SoundPool>(maxStreams, audioRendererInfo, false);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create SoundPool failed!");
        taihe::reset_error();
        return optional<SoundPool>(std::nullopt);
    }
    return optional<SoundPool>(std::in_place, res);
}

optional<SoundPool> CreateParallelSoundPoolSync(int32_t maxStreams,
    ohos::multimedia::audio::AudioRendererInfo const& audioRendererInfo)
{
    if (!MediaTaiheUtils::IsSystemApp()) {
        MEDIA_LOGE("Create Parallel SoundPool failed! Not system app.");
        return optional<SoundPool>(std::nullopt);
    }
    auto res = make_holder<SoundPoolImpl, SoundPool>(maxStreams, audioRendererInfo, true);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create Parallel SoundPool failed!");
        taihe::reset_error();
        return optional<SoundPool>(std::nullopt);
    }
    return optional<SoundPool>(std::in_place, res);
}

int32_t SoundPoolImpl::PlaySync(int32_t soundID, optional_view<PlayParameters> params)
{
    MediaTrace trace("SoundPool::TaihePlay");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlay");

    if (soundID <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId");
        return 0;
    } else {
        PlayParams playParameters;
        if (params.has_value()) {
            int32_t ret = ParserPlayOption(params.value(), playParameters);
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, 0, "failed to SendEvent, ret = %{public}d", ret);
        }
        CHECK_AND_RETURN_RET_LOG(soundPool_ != nullptr, 0, "soundPool_ is nullptr!");
        int32_t streamId = soundPool_->Play(soundID, playParameters);
        if (streamId < 0) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
        }
        MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
        return streamId;
    }
}

int32_t SoundPoolImpl::PlayWithoutParam(int32_t soundID)
{
    MediaTrace trace("SoundPool::TaihePlayWithoutParam");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlayWithoutParam");
    if (soundID <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId");
        return 0;
    } else {
        if (soundPool_ == nullptr) {
            MEDIA_LOGE("soundPool_ is nullptr!");
            return 0;
        }
        PlayParams playParameters;
        int32_t streamId = soundPool_->Play(soundID, playParameters);
        if (streamId < 0) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
            return 0;
        }
        MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
        return streamId;
    }
}

int32_t SoundPoolImpl::PlayWithParam(int32_t soundID, PlayParameters const& params)
{
    MediaTrace trace("SoundPool::TaihePlayWithParam");
    MEDIA_LOGI("SoundPoolTaihe::TaihePlayWithParam");
    if (soundID <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getplaysoundId", "soundId");
        return 0;
    } else {
        PlayParams playParameters;
        int32_t ret = ParserPlayOption(params, playParameters);
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);

        if (soundPool_ == nullptr) {
            MEDIA_LOGE("soundPool_ is nullptr!");
            return 0;
        }
        int32_t streamId = soundPool_->Play(soundID, playParameters);
        if (streamId < 0) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "play sound failed");
            return 0;
        }
        MEDIA_LOGI("The taihe thread of play finishes execution and returns, streamId: %{public}d", streamId);
        return streamId;
    }
}

int32_t SoundPoolImpl::ParserPlayOption(const PlayParameters &params, PlayParams &playParameters)
{
    if (params.loop.has_value()) {
        playParameters.loop = static_cast<int32_t>(params.loop.value());
    }
    if (params.rate.has_value()) {
        playParameters.rate = static_cast<int32_t>(params.rate.value());
    }
    if (params.leftVolume.has_value()) {
        playParameters.leftVolume = static_cast<float>(params.leftVolume.value());
    }
    if (params.rightVolume.has_value()) {
        playParameters.rightVolume = static_cast<float>(params.rightVolume.value());
    }
    if (params.priority.has_value()) {
        playParameters.priority = static_cast<int32_t>(params.priority.value());
    }
    if (params.parallelPlayFlag.has_value()) {
        playParameters.parallelPlayFlag = static_cast<bool>(params.parallelPlayFlag.value());
    }
    playParameters.cacheDir = "/data/storage/el2/base/temp";
    MEDIA_LOGI("playParameters loop:%{public}d, rate:%{public}d, leftVolume:%{public}f, rightvolume:%{public}f,"
        "priority:%{public}d, parallelPlayFlag:%{public}d", playParameters.loop, playParameters.rate,
        playParameters.leftVolume, playParameters.rightVolume, playParameters.priority,
        playParameters.parallelPlayFlag);
    return MSERR_OK;
}

int32_t SoundPoolImpl::LoadSync(string_view uri)
{
    MediaTrace trace("SoundPool::TaiheLoad");
    MEDIA_LOGI("SoundPoolNapi::TaiheLoad");
    int32_t soundId = 0;
    std::string url = static_cast<std::string>(uri);
    CHECK_AND_RETURN_RET(url != "",
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "geturl", "url"), soundId));
    soundId = soundPool_->Load(url);
    if (soundId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "load sound failed");
    }
    return soundId;
}

int32_t SoundPoolImpl::LoadWithFdSync(int32_t fd, int64_t offset, int64_t length)
{
    MediaTrace trace("SoundPool::TaiheLoad");
    MEDIA_LOGI("SoundPoolNapi::TaiheLoad");
    int32_t soundId = 0;
    CHECK_AND_RETURN_RET(fd > 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getfd", "fd"), soundId));
    CHECK_AND_RETURN_RET(offset >= 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getoffset", "offset"), soundId));
    CHECK_AND_RETURN_RET(length > 0,
        (SoundPoolAsyncSignError(MSERR_OPEN_FILE_FAILED, "getlength", "length"), soundId));
    soundId = soundPool_->Load(fd, offset, length);
    if (soundId < 0) {
        SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "load sound failed");
    }
    return soundId;
}

void SoundPoolImpl::StopSync(int32_t streamID)
{
    MediaTrace trace("SoundPool::TaiheStop");
    MEDIA_LOGI("SoundPoolNapi::TaiheStop");
    CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
    if (streamID <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "stop streamId failed, invaild value");
    } else {
        int32_t ret = soundPool_->Stop(streamID);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "stop streamId failed");
        }
        MEDIA_LOGI("The taihe thread of stop finishes execution and returns");
    }
}

void SoundPoolImpl::SetLoopSync(int32_t streamID, int32_t loop)
{
    MediaTrace trace("SoundPool::TaiheSetLoop");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetLoop");
    if (streamID <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetLoop streamId failed,invaild value");
    } else {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetLoop(streamID, loop);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "setLoop streamId failed");
        }
        MEDIA_LOGI("The Taihe thread of SetLoop finishes execution and returns");
    }
}

void SoundPoolImpl::SetPrioritySync(int32_t streamID, int32_t priority)
{
    MediaTrace trace("SoundPool::TaiheSetPriority");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetPriority");
    if (streamID <= 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetPriority streamId failed");
    } else if (priority < 0) {
        SignError(MSERR_EXT_API9_INVALID_PARAMETER, "SetPriority priority failed");
    } else {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetPriority(streamID, priority);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "SetPriority streamId failed");
        }
        MEDIA_LOGI("The taihe thread of SetPriority finishes execution and returns");
    }
}

void SoundPoolImpl::SetRateSync(int32_t streamID, ::ohos::multimedia::audio::AudioRendererRate rate)
{
    MediaTrace trace("SoundPool::TaiheSetRate");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetRate");
    if (streamID <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getratestreamId", "streamId");
    } else {
        OHOS::AudioStandard::AudioRendererRate renderRate =
            static_cast<OHOS::AudioStandard::AudioRendererRate>(rate.get_value());
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetRate(streamID, renderRate);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "SetRate streamId failed");
        }
        MEDIA_LOGI("The taihe thread of SetRate finishes execution and returns");
    }
}

void SoundPoolImpl::SetVolumeSync(int32_t streamID, double leftVolume, double rightVolume)
{
    MediaTrace trace("SoundPool::TaiheSetVolume");
    MEDIA_LOGI("SoundPoolNapi::TaiheSetVolume");
    if (streamID <= 0) {
        SoundPoolAsyncSignError(MSERR_INVALID_VAL, "getvolumestreamId", "streamId");
    } else {
        CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
        int32_t ret = soundPool_->SetVolume(streamID,
            static_cast<float>(leftVolume), static_cast<float>(rightVolume));
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "setVolume streamId failed");
        }
        MEDIA_LOGI("The taihe thread of SetVolume finishes execution and returns");
    }
}

void SoundPoolImpl::UnloadSync(int32_t soundID)
{
    MediaTrace trace("SoundPool::TaiheUnload");
    MEDIA_LOGI("SoundPoolNapi::TaiheUnload");
    CHECK_AND_RETURN_LOG(soundPool_ != nullptr, "soundPool_ is nullptr!");
    if (soundID <= 0) {
        SignError(MSERR_EXT_API9_IO, "unLoad failed,inavild value");
    } else {
        int32_t ret = soundPool_->Unload(soundID);
        if (ret != MSERR_OK) {
            SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "unLoad soundID failed");
        }
        MEDIA_LOGI("The taihe thread of Unload finishes execution and returns, soundID: %{public}d",
            soundID);
    }
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

void SoundPoolImpl::OnPlayFinishedWithStreamId(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnPlayFinishedWithStreamId");
    MEDIA_LOGI("OnPlayFinishedWithStreamId Start");
    std::string callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
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

void SoundPoolImpl::OnLoadComplete(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnLoadComplete");
    MEDIA_LOGI("OnLoadComplete Start");
    std::string callbackName = SoundPoolEvent::EVENT_LOAD_COMPLETED;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
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

void SoundPoolImpl::OnErrorOccurred(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("SoundPoolImpl::OnErrorOccurred");
    MEDIA_LOGI("OnErrorOccurred Start");
    std::string callbackName = SoundPoolEvent::EVENT_ERROR_OCCURRED;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnErrorOccurred End");
}

void SoundPoolImpl::OffErrorOccurred(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("SoundPoolImpl::OffErrorOccurred");
    MEDIA_LOGI("OffErrorOccurred Start");

    std::string callbackName = SoundPoolEvent::EVENT_ERROR_OCCURRED;
    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffErrorOccurred End");
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
TH_EXPORT_CPP_API_CreateParallelSoundPoolSync(ANI::Media::CreateParallelSoundPoolSync);