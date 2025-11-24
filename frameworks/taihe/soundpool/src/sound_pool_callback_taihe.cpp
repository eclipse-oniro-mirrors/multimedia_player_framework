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

#include "sound_pool_callback_taihe.h"
#include "media_errors.h"
#include "media_log.h"
#include "scope_guard.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPoolCallBackTaihe"};
}

namespace ANI {
namespace Media {
uintptr_t SoundPoolCallBackTaihe::GetUndefined(ani_env* env) const
{
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    ani_object undefinedObject = static_cast<ani_object>(undefinedRef);
    return reinterpret_cast<uintptr_t>(undefinedObject);
}

ani_object SoundPoolCallBackTaihe::ToBusinessError(ani_env *env, int32_t code, const std::string &message) const
{
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass(CLASS_NAME_BUSINESSERROR, &cls) == ANI_OK, err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":", &ctor) == ANI_OK, err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &error) == ANI_OK, err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Int(error, "code", static_cast<ani_int>(code)) == ANI_OK, err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_AND_RETURN_RET_LOG(env->String_NewUTF8(message.c_str(), message.size(), &messageRef) == ANI_OK, err,
        "new message string failed");
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)) == ANI_OK, err,
        "set property BusinessError.message failed");
    return error;
}

ani_object ToErrorInfo(ani_env *env, int32_t code, const std::string &message,
    ERROR_TYPE errorType, int32_t soundId, int32_t streamId) const;
{
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass(CLASS_NAME_ERRORINFO, &cls) == ANI_OK, err,
        "find class %{public}s failed", CLASS_NAME_ERRORINFO);
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":", &ctor) == ANI_OK, err,
        "find method ErrorInfo constructor failed");
    ani_object errorInfo {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &errorInfo) == ANI_OK, err,
        "new object %{public}s failed", CLASS_NAME_ERRORINFO);
    ani_object errorCode = ToBusinessError(taihe::get_env(), code, message);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(errorInfo, "errorCode", static_cast<ani_ref>(errorCode)) == ANI_OK, err,
        "set property ErrorInfo.errorCode failed");
    ani_enum_item errorTypeItem {};
    CHECK_AND_RETURN_RET_LOG(ToAniEnum(env, errorType, errorTypeItem) == ANI_OK, err,
        "convert errorType to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(errorInfo, "errorType", static_cast<ani_ref>(errorTypeItem)) == ANI_OK, err,
        "set property ErrorInfo.errorType failed");
    ani_object soundIdObj = IntToObject(env, soundId);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(errorInfo, "soundId", static_cast<ani_ref>(soundId)) == ANI_OK, err,
        "set property ErrorInfo.soundId failed");
    ani_object streamIdObj = IntToObject(env, streamId);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(errorInfo, "streamId", static_cast<ani_ref>(streamId)) == ANI_OK, err,
        "set property ErrorInfo.streamId failed");
    return errorInfo;
}

ani_status SoundPoolCallBackTaihe::ToAniEnum(ani_env *env, ERROR_TYPE errorType, ani_enum_item &aniEnumItem) const
{
    ani_int enumIndex = static_cast<ani_int>(errorType);
    ani_enum aniEnum{};
    CHECK_AND_RETURN_RET_LOG(env->FindEnum(ENUM_NAME_ERRORTYPE, &aniEnum) == ANI_OK,
        ANI_ERROR, "Find Enum failed");
    CHECK_AND_RETURN_RET_LOG(env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem) == ANI_OK,
        ANI_ERROR, "Find Enum failed");
    return ANI_OK;
}

ani_status SoundPoolCallBackTaihe::IntToAniObject(ani_env *env, int32_t value) const
{
    static constexpr const char *className = "std.core.Int";
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass(CLASS_NAME_ERRORINFO, &cls) == ANI_OK, err,
        "find class %{public}s failed", "std.core.Int");
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":", &ctor) == ANI_OK, err,
        "find method ErrorInfo constructor failed");
    ani_object intObject {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &intObject, static_cast<ani_int>(value)) == ANI_OK, err,
        "new object %{public}s failed", "std.core.Int");
    return intObject;
}

void SoundPoolCallBackTaihe::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("OnLoadCompleted recived soundId:%{public}d", soundId);
    SendLoadCompletedCallback(soundId);
}

void SoundPoolCallBackTaihe::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("OnPlayFinished recived");
    SendPlayCompletedCallback(streamID);
}

void SoundPoolCallBackTaihe::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError recived:error:%{public}d", errorCode);
    if (errorCode == MSERR_INVALID_OPERATION) {
        SendErrorCallback(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "The soundpool timed out. Please confirm that the input stream is normal.");
    } else if (errorCode == MSERR_NO_MEMORY) {
        SendErrorCallback(MSERR_EXT_API9_NO_MEMORY, "soundpool memery error.");
    } else if (errorCode == MSERR_SERVICE_DIED) {
        SendErrorCallback(MSERR_EXT_API9_SERVICE_DIED, "releated server died");
    } else {
        SendErrorCallback(MSERR_EXT_API9_IO, "IO error happened.");
    }
}

void SoundPoolCallBackTaihe::OnErrorOccurred(Format &errorInfo)
{
    MEDIA_LOGI("OnErrorOccurred recived");
    int32_t errorCode;
    errorInfo.GetIntValue(SoundPoolKeys::ERROR_CODE, errorCode);
    if (errorCode == MSERR_INVALID_OPERATION) {
        errorInfo.PutIntValue(SoundPoolKeys::ERROR_CODE, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
        errorInfo.PutStringValue(SoundPoolKeys::ERROR_MESSAGE,
            "The soundpool timed out. Please confirm that the input stream is normal.");
        SendErrorOccurredCallback(errorInfo);
    } else if (errorCode == MSERR_NO_MEMORY) {
        errorInfo.PutIntValue(SoundPoolKeys::ERROR_CODE, MSERR_EXT_API9_NO_MEMORY);
        errorInfo.PutStringValue(SoundPoolKeys::ERROR_MESSAGE, "soundpool memery error.");
        SendErrorOccurredCallback(errorInfo);
    } else if (errorCode == MSERR_SERVICE_DIED) {
        errorInfo.PutIntValue(SoundPoolKeys::ERROR_CODE, MSERR_EXT_API9_SERVICE_DIED);
        errorInfo.PutStringValue(SoundPoolKeys::ERROR_MESSAGE, "releated server died");
        SendErrorOccurredCallback(errorInfo);
    } else {
        errorInfo.PutIntValue(SoundPoolKeys::ERROR_CODE, MSERR_EXT_API9_IO);
        errorInfo.PutStringValue(SoundPoolKeys::ERROR_MESSAGE, "IO error happened.");
        SendErrorOccurredCallback(errorInfo);
    }
}

void SoundPoolCallBackTaihe::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
    MEDIA_LOGI("ClearCallback!");
}

void SoundPoolCallBackTaihe::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void SoundPoolCallBackTaihe::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
        MEDIA_LOGI("mainHandler_ is nullptr, set it");
    }
}

void SoundPoolCallBackTaihe::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    SoundPoolTaiheCallBack *cb = new(std::nothrow) SoundPoolTaiheCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(SoundPoolEvent::EVENT_ERROR);
    cb->callbackName = SoundPoolEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    auto task = [this, cb]() {
        this->OnTaiheErrorCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void SoundPoolCallBackTaihe::SendErrorOccurredCallback(const Format &errorInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_ERROR_OCCURRED) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    SoundPoolTaiheCallBack *cb = new(std::nothrow) SoundPoolTaiheCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    int32_t errorCode;
    std::string msg;
    errorInfo.GetIntValue(SoundPoolKeys::ERROR_CODE, errorCode);
    errorInfo.GetStringValue(SoundPoolKeys::ERROR_MESSAGE, msg);
    if (errorInfo.ContainKey(SoundPoolKeys::STREAM_ID)) {
        int32_t streamId;
        errorInfo.GetIntValue(SoundPoolKeys::STREAM_ID, streamId);
        cb->playFinishedStreamID = streamId;
    }
    if (errorInfo.ContainKey(SoundPoolKeys::ERROR_TYPE_FLAG)) {
        int32_t errorType;
        errorInfo.GetIntValue(SoundPoolKeys::ERROR_TYPE_FLAG, errorType);
        cb->errorType = static_cast<ERROR_TYPE>(errorType);
    }
    if (errorInfo.ContainKey(SoundPoolKeys::SOUND_ID)) {
        int32_t soundId;
        errorInfo.GetIntValue(SoundPoolKeys::SOUND_ID, soundId);
        cb->loadSoundId = soundId;
    }
    cb->autoRef = refMap_.at(SoundPoolEvent::EVENT_ERROR_OCCURRED);
    cb->callbackName = SoundPoolEvent::EVENT_ERROR_OCCURRED;
    cb->errorCode = errorCode;
    cb->errorMsg = msg;
    auto task = [this, cb]() {
        this->OnTaiheErrorOccurredCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnErrorOccurred", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void SoundPoolCallBackTaihe::SendLoadCompletedCallback(int32_t soundId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_LOAD_COMPLETED) == refMap_.end()) {
        MEDIA_LOGW("can not find loadcompleted callback!");
        return;
    }

    SoundPoolTaiheCallBack *cb = new(std::nothrow) SoundPoolTaiheCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(SoundPoolEvent::EVENT_LOAD_COMPLETED);
    cb->callbackName = SoundPoolEvent::EVENT_LOAD_COMPLETED;
    cb->loadSoundId = soundId;
    auto task = [this, cb]() {
        this->OnTaiheloadCompletedCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnLoadComplete", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void SoundPoolCallBackTaihe::SendPlayCompletedCallback(int32_t streamID)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED) == refMap_.end() &&
        refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID) == refMap_.end()) {
        MEDIA_LOGW("can not find playfinished callback!");
        return;
    }

    SoundPoolTaiheCallBack *cb = new(std::nothrow) SoundPoolTaiheCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    std::weak_ptr<AutoRef> autoRefFinished;
    std::weak_ptr<AutoRef> autoRefFinishedStreamID;
    auto it = refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED);
    if (it != refMap_.end()) {
        autoRefFinished = it->second;
    }
    auto itStreamId = refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID);
    if (itStreamId != refMap_.end()) {
        autoRefFinishedStreamID = itStreamId->second;
    }

    if (std::shared_ptr<AutoRef> ref = autoRefFinishedStreamID.lock()) {
        cb->autoRef = autoRefFinishedStreamID;
        cb->callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID;
        cb->playFinishedStreamID = streamID;
    } else {
        cb->autoRef = autoRefFinished;
        cb->callbackName = SoundPoolEvent::EVENT_PLAY_FINISHED;
    }
    auto task = [this, cb]() {
        this->OnTaiheplayCompletedCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnPlayFinishedWithStreamId", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void SoundPoolCallBackTaihe::OnTaiheErrorCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheErrorCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "%{public}s failed to get callback", request.c_str());
        auto err = ToBusinessError(taihe::get_env(), taiheCb->errorCode, taiheCb->errorMsg);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    } while (0);
    delete taiheCb;
}

void SoundPoolCallBackTaihe::OnTaiheErrorOccurredCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    MEDIA_LOGI("errorOccurredCallback event: errorMsg %{public}s, errorCode %{public}d, soundId %{public}d,"
        "streamId %{public}d", taiheCb->errorMsg.c_str(), taiheCb->errorCode, taiheCb->loadSoundId,
        taiheCb->playFinishedStreamID);
    std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
    CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
    auto func = ref->callbackRef_;
    CHECK_AND_RETURN_LOG(func != nullptr, "%{public}s failed to get callback", request.c_str());
    auto err = ToErrorInfo(taihe::get_env(), taiheCb->errorCode, taiheCb->errorMsg, taiheCb->errorType,
        taiheCb->loadSoundId, taiheCb->playFinishedStreamID);
    std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
        std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
    (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    delete taiheCb;
}

void SoundPoolCallBackTaihe::OnTaiheloadCompletedCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheloadCompletedCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "%{public}s failed to get callback", request.c_str());
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
        (*cacheCallback)(taiheCb->loadSoundId);
    } while (0);
    delete taiheCb;
}

void SoundPoolCallBackTaihe::OnTaiheplayCompletedCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        if (request == SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID) {
            MEDIA_LOGD("OnTaiheloadCompletedCallBackWithStreamID is called");
            std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            auto func = ref->callbackRef_;
            CHECK_AND_BREAK_LOG(func != nullptr, "%{public}s failed to get callback", request.c_str());
            std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
            (*cacheCallback)(taiheCb->playFinishedStreamID);
        } else if (request == SoundPoolEvent::EVENT_PLAY_FINISHED) {
            MEDIA_LOGD("OnTaiheloadCompletedCallBack is called");
            std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            auto func = ref->callbackRef_;
            uintptr_t undefined = GetUndefined(get_env());
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            (*cacheCallback)(static_cast<uintptr_t>(undefined));
        }
    } while (0);
    delete taiheCb;
}
}
}
