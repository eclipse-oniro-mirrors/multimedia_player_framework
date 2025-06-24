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

#include "avscreen_capture_callback_taihe.h"
#include "scope_guard.h"
#include "media_log.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "AVScreenCaptureCallback"};
}

namespace ANI {
namespace Media {
AVScreenCaptureCallback::AVScreenCaptureCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

AVScreenCaptureCallback::~AVScreenCaptureCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void AVScreenCaptureCallback::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errorCode);
    SendErrorCallback(errorCode, "Screen capture failed.");
}

void AVScreenCaptureCallback::OnStateChange(OHOS::Media::AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("OnStateChange() is called, stateCode: %{public}d", stateCode);
    SendStateCallback(stateCode);
}

void AVScreenCaptureCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVScreenCaptureEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    AVScreenCaptureTaiheCallback *cb = new(std::nothrow) AVScreenCaptureTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVScreenCaptureEvent::EVENT_ERROR);
    cb->callbackName = AVScreenCaptureEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    auto task = [this, cb]() {
        this->OnTaiheErrorCallBack(cb);
    };
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void AVScreenCaptureCallback::SendStateCallback(OHOS::Media::AVScreenCaptureStateCode stateCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVScreenCaptureEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find stateChange callback!");
        return;
    }

    AVScreenCaptureTaiheCallback *cb = new(std::nothrow) AVScreenCaptureTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVScreenCaptureEvent::EVENT_STATE_CHANGE);
    cb->callbackName = AVScreenCaptureEvent::EVENT_STATE_CHANGE;
    cb->stateCode = stateCode;
    auto task = [this, cb]() {
        this->OnTaiheStateChangeCallBack(cb);
    };
    mainHandler_->PostTask(task, "OnStateChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void AVScreenCaptureCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void AVScreenCaptureCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void AVScreenCaptureCallback::OnTaiheErrorCallBack(AVScreenCaptureTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheErrorCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        auto func = ref->callbackRef_;
        auto err = MediaTaiheUtils::ToBusinessError(taihe::get_env(), 0, "OnErrorCallback is OK");
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    } while (0);
    delete taiheCb;
}

void AVScreenCaptureCallback::OnTaiheStateChangeCallBack(AVScreenCaptureTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheCaptureCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();

        auto func = ref->callbackRef_;
        std::shared_ptr<taihe::callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>> cacheCallback = std::
            reinterpret_pointer_cast<taihe::callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>>(func);
            (*cacheCallback)(static_cast<ohos::multimedia::media::AVScreenCaptureStateCode::key_t>(taiheCb->stateCode));
    } while (0);
    delete taiheCb;
}
}
}