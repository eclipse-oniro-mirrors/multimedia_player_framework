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

#include "media_errors.h"
#include "media_log.h"
#include "recoder_callback_taihe.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderCallbackTaihe"};
}

using namespace OHOS::Media;

namespace ANI {
namespace Media {
RecorderCallbackTaihe::RecorderCallbackTaihe(bool isVideo): isVideo_(isVideo)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderCallbackTaihe::~RecorderCallbackTaihe()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void RecorderCallbackTaihe::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGD("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
    if (isVideo_) {
        return;
    } else {
        return;
    }
}

void RecorderCallbackTaihe::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGD("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
}

void RecorderCallbackTaihe::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    (void)audioRecorderChangeInfo;
}

void RecorderCallbackTaihe::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
}

void RecorderCallbackTaihe::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void RecorderCallbackTaihe::SendErrorCallback(int32_t errCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(ERROR_CALLBACK_NAME) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    RecordTaiheCallback *cb = new(std::nothrow) RecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(ERROR_CALLBACK_NAME);
    cb->callbackName = ERROR_CALLBACK_NAME;
    if (isVideo_) {
        cb->errorMsg = MSExtErrorAPI9ToString(static_cast<MediaServiceExtErrCodeAPI9>(errCode), "", "");
    } else {
        cb->errorMsg = MSExtErrorToString(static_cast<MediaServiceExtErrCode>(errCode));
    }
    cb->errorCode = errCode;
    auto task = [this, cb]() {
        this->OnTaiheErrorCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void RecorderCallbackTaihe::SendStateCallback(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(callbackName) == refMap_.end()) {
        MEDIA_LOGW("can not find %{public}s callback!", callbackName.c_str());
        return;
    }

    RecordTaiheCallback *cb = new(std::nothrow) RecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(callbackName);
    cb->callbackName = callbackName;

    auto task = [this, cb]() {
        this->OnTaiheStateCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnStatechange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void RecorderCallbackTaihe::OnTaiheStateCallBack(RecordTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheStateCallBack is called");
        std::shared_ptr<AutoRef> stateChangeRef = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(stateChangeRef != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = stateChangeRef->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(taihe::string_view)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(taihe::string_view)>>(func);
        (*cacheCallback)(taihe::string_view(request));
    } while (0);
    delete taiheCb;
}

void RecorderCallbackTaihe::OnTaiheErrorCallBack(RecordTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheErrorCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");
        auto err = MediaTaiheUtils::ToBusinessError(taihe::get_env(), 0, "OnErrorCallback is OK");
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    } while (0);
    delete taiheCb;
}
}
}