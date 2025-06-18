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
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":V", &ctor) == ANI_OK, err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &error) == ANI_OK, err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Double(error, "code", static_cast<ani_double>(code)) == ANI_OK, err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_AND_RETURN_RET_LOG(env->String_NewUTF8(message.c_str(), message.size(), &messageRef) == ANI_OK, err,
        "new message string failed");
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)) == ANI_OK, err,
        "set property BusinessError.message failed");
    return error;
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
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
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
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
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
    mainHandler_->PostTask(task, "OnLoadComplete", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
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
    mainHandler_->PostTask(task, "OnPlayFinishedWithStreamId", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SoundPoolCallBackTaihe::OnTaiheErrorCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheErrorCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();

        auto func = ref->callbackRef_;
        auto err = ToBusinessError(taihe::get_env(), taiheCb->errorCode, taiheCb->errorMsg);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    } while (0);
    delete taiheCb;
}

void SoundPoolCallBackTaihe::OnTaiheloadCompletedCallBack(SoundPoolTaiheCallBack *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheloadCompletedCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();

        auto func = ref->callbackRef_;
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
    
            auto func = ref->callbackRef_;
            std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
            (*cacheCallback)(taiheCb->playFinishedStreamID);
        } else if (request == SoundPoolEvent::EVENT_PLAY_FINISHED) {
            MEDIA_LOGD("OnTaiheloadCompletedCallBack is called");
            std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();

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