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

#include "avtranscoder_callback_taihe.h"
#include "media_errors.h"
#include "scope_guard.h"
#include "media_log.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVTransCoderCallback"};
}

namespace ANI {
namespace Media {
void AVTransCoderCallback::SendCompleteCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVTransCoderEvent::EVENT_COMPLETE) == refMap_.end()) {
        MEDIA_LOGW("can not find statechange callback!");
        return;
    }

    AVTransCoderTaiheCallback *cb = new(std::nothrow) AVTransCoderTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVTransCoderEvent::EVENT_COMPLETE);
    cb->callbackName = AVTransCoderEvent::EVENT_COMPLETE;
}

void AVTransCoderCallback::SendProgressUpdateCallback(int32_t progress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVTransCoderEvent::EVENT_PROGRESS_UPDATE) == refMap_.end()) {
        MEDIA_LOGW("can not find progressupdate callback!");
        return;
    }
    AVTransCoderTaiheCallback *cb = new(std::nothrow) AVTransCoderTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVTransCoderEvent::EVENT_PROGRESS_UPDATE);
    cb->callbackName = AVTransCoderEvent::EVENT_PROGRESS_UPDATE;
    cb->progress = progress;
}

void AVTransCoderCallback::OnError(int32_t errCode, const std::string &errorMsg)
{
    MEDIA_LOGE("AVTransCoderCallback::OnError: %{public}d, %{public}s", errCode, errorMsg.c_str());
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    SendErrorCallback(errorCodeApi9, errorMsg);
    SendStateCallback(AVTransCoderState::STATE_ERROR, OHOS::Media::StateChangeReason::BACKGROUND);
}

void AVTransCoderCallback::OnInfo(int32_t type, int32_t extra)
{
    if (type == TransCoderOnInfoType::INFO_TYPE_TRANSCODER_COMPLETED) {
        SendCompleteCallback();
    } else if (type == TransCoderOnInfoType::INFO_TYPE_PROGRESS_UPDATE) {
        SendProgressUpdateCallback(extra);
    }
}

std::string AVTransCoderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void AVTransCoderCallback::SendStateCallback(const std::string &state, const OHOS::Media::StateChangeReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("StateChange, currentState: %{public}s to state: %{public}s", currentState_.c_str(), state.c_str());
    currentState_ = state;
}

void AVTransCoderCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void AVTransCoderCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
    MEDIA_LOGI("ClearCallback!");
}

void AVTransCoderCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
}

void AVTransCoderCallback::SendErrorCallback(MediaServiceExtErrCodeAPI9 errCode, const std::string &msg)
{
    std::string message = MSExtAVErrorToString(errCode) + msg;
    MEDIA_LOGE("SendErrorCallback:errorCode %{public}d, errorMsg %{public}s", errCode, message.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVTransCoderEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    AVTransCoderTaiheCallback *cb = new(std::nothrow) AVTransCoderTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVTransCoderEvent::EVENT_ERROR);
    cb->callbackName = AVTransCoderEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = message;
    auto task = [this, cb]() {
        this->OnTaiheErrorCallBack(cb);
    };
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void AVTransCoderCallback::OnTaiheErrorCallBack(AVTransCoderTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheErrorCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        auto func = ref->callbackRef_;
        auto err = MediaTaiheUtils::ToBusinessError(get_env(), taiheCb->errorCode, taiheCb->errorMsg);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    } while (0);
    delete taiheCb;
}

void AVTransCoderCallback::OnTaiheProgressUpdateCallback(AVTransCoderTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheProgressUpdateCallback is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

        auto func = ref->callbackRef_;
        std::shared_ptr<taihe::callback<void(double)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(double)>>(func);
        (*cacheCallback)(static_cast<double>(taiheCb->progress));
    } while (0);
    delete taiheCb;
}

void AVTransCoderCallback::OnTaiheCompleteCallBack(AVTransCoderTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheCompleteCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

        auto func = ref->callbackRef_;
        uintptr_t undefined = MediaTaiheUtils::GetUndefined(get_env());
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(static_cast<uintptr_t>(undefined));
    } while (0);
    delete taiheCb;
}
}
}