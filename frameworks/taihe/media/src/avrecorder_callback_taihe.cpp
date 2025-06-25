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
#include "scope_guard.h"
#include "media_log.h"
#include "avrecorder_callback_taihe.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderCallback"};
}

using namespace OHOS::Media;

namespace ANI {
namespace Media {
AVRecorderCallback::AVRecorderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

AVRecorderCallback::~AVRecorderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void AVRecorderCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_ERROR);
    cb->callbackName = AVRecorderEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    OnTaiheErrorCallBack(cb);
}

void AVRecorderCallback::OnTaiheErrorCallBack(AVRecordTaiheCallback *taiheCb) const
{
    auto task = [event = taiheCb]() {
        std::string request = event->callbackName;
        do {
            MEDIA_LOGD("OnTaiheErrorCallBack is called");
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "ref is nullptr");
            auto func = ref->callbackRef_;
            auto err = MediaTaiheUtils::ToBusinessError(taihe::get_env(), 0, "OnErrorCallback is OK");
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
        } while (0);
        delete event;
    };
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void AVRecorderCallback::SendStateCallback(const std::string &state, const OHOS::Media::StateChangeReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_ = state;
    if (refMap_.find(AVRecorderEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find statechange callback!");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_STATE_CHANGE);
    cb->callbackName = AVRecorderEvent::EVENT_STATE_CHANGE;
    cb->reason = reason;
    cb->state = state;

    OnTaiheStateCallBack(cb);
}

void AVRecorderCallback::OnTaiheStateCallBack(AVRecordTaiheCallback *taiheCb) const
{
    auto task = [event = taiheCb]() {
        std::string request = event->callbackName;
        do {
            MEDIA_LOGD("OnTaiheStateCallBack is called");
            std::shared_ptr<AutoRef> stateChangeRef = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(stateChangeRef != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            std::shared_ptr<taihe::callback<StateChangeCallback>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<StateChangeCallback>>(stateChangeRef->callbackRef_);
            ohos::multimedia::media::StateChangeReason::key_t key;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::StateChangeReason>(event->reason, key);
            (*cacheCallback)(taihe::string_view(event->state), ohos::multimedia::media::StateChangeReason(key));
        } while (0);
        delete event;
    };
    mainHandler_->PostTask(task, "OnStatechange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void AVRecorderCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void AVRecorderCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void AVRecorderCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
    MEDIA_LOGI("ClearCallback!");
}

std::string AVRecorderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void AVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
    SendStateCallback(AVRecorderState::STATE_ERROR, OHOS::Media::StateChangeReason::BACKGROUND);
    if (errCode == MSERR_DATA_SOURCE_IO_ERROR) {
        SendErrorCallback(MSERR_EXT_API9_TIMEOUT,
            "The video input stream timed out. Please confirm that the input stream is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_OBTAIN_MEM_ERROR) {
        SendErrorCallback(MSERR_EXT_API9_TIMEOUT,
            "Read data from audio timeout, please confirm whether the audio module is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_ERROR_UNKNOWN) {
        SendErrorCallback(MSERR_EXT_API9_IO, "Video input data is abnormal."
            " Please confirm that the pts, width, height, size and other data are normal.");
    } else if (errCode == MSERR_AUD_INTERRUPT) {
        SendErrorCallback(MSERR_EXT_API9_AUDIO_INTERRUPTED,
            "Record failed by audio interrupt.");
    } else {
        SendErrorCallback(MSERR_EXT_API9_IO, "IO error happened.");
    }
}

void AVRecorderCallback::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGI("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
    if (type == RecorderInfoType::RECORDER_INFO_MAX_DURATION_REACHED) {
        MEDIA_LOGI("OnInfo() type = MAX_DURATION_REACHED, type: %{public}d, extra: %{public}d", type, extra);
        SendStateCallback(AVRecorderState::STATE_STOPPED, OHOS::Media::StateChangeReason::BACKGROUND);
    }
}
}
}