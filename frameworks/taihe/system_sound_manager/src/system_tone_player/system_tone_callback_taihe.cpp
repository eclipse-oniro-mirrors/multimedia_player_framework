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
#include "system_sound_log.h"
#include "system_tone_callback_taihe.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerCallbackTaihe"};

const std::string PLAY_FINISHED_CALLBACK_NAME = "playFinished";
const std::string ERROR_CALLBACK_NAME = "error";
const int32_t ALL_STREAMID = 0;
const int32_t NUM_0 = 0;
}

using namespace ANI::Media;

namespace ANI::Media {
SystemTonePlayerCallbackTaihe::SystemTonePlayerCallbackTaihe()
{
    MEDIA_LOGD("SystemTonePlayerCallbackTaihe: instance create");
}

SystemTonePlayerCallbackTaihe::~SystemTonePlayerCallbackTaihe()
{
    MEDIA_LOGD("SystemTonePlayerCallbackTaihe: instance destroy");
}

bool SystemTonePlayerCallbackTaihe::IsSameRef(std::shared_ptr<AutoRef> src, std::shared_ptr<AutoRef> dst)
{
    CHECK_AND_RETURN_RET_LOG(dst != nullptr, true, "%{public}s: dst is null", __func__);
    CHECK_AND_RETURN_RET_LOG(src != nullptr, false, "%{public}s: src is null", __func__);
    std::shared_ptr<taihe::callback<void()>> srcPtr =
        std::reinterpret_pointer_cast<taihe::callback<void()>>(src->callbackRef_);
    std::shared_ptr<taihe::callback<void()>> dstPtr =
        std::reinterpret_pointer_cast<taihe::callback<void()>>(dst->callbackRef_);
    CHECK_AND_RETURN_RET_LOG(dstPtr != nullptr, true, "%{public}s: dstPtr is null", __func__);
    CHECK_AND_RETURN_RET_LOG(srcPtr != nullptr, false, "%{public}s: srcPtr is null", __func__);
    return *srcPtr == *dstPtr;
}

bool SystemTonePlayerCallbackTaihe::IsExistCallback(const std::list<std::shared_ptr<AutoRef>> &cbList,
    std::shared_ptr<AutoRef> autoRef)
{
    if (cbList.empty()) {
        MEDIA_LOGD("cbList is empty");
        return false;
    }
    for (auto &cb : cbList) {
        if (IsSameRef(cb, autoRef)) {
            return true;
        }
    }
    return false;
}

void SystemTonePlayerCallbackTaihe::SavePlayFinishedCallbackReference(const std::string &callbackName,
    std::shared_ptr<AutoRef> autoRef, int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName != PLAY_FINISHED_CALLBACK_NAME) {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    if (playFinishedCallbackMap_.count(streamId) != 0 && IsExistCallback(playFinishedCallbackMap_[streamId], autoRef)) {
        MEDIA_LOGI("playFinished cb exist streamId: %{public}d", streamId);
        return;
    }

    playFinishedCallbackMap_[streamId].emplace_back(autoRef);
    MEDIA_LOGI("SavePlayFinishedCallbackReference: callbackName: %{public}s", callbackName.c_str());

    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void SystemTonePlayerCallbackTaihe::SaveCallbackReference(const std::string &callbackName,
    std::shared_ptr<AutoRef> autoRef)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName != ERROR_CALLBACK_NAME) {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    if (IsExistCallback(errorCallback_, autoRef)) {
        MEDIA_LOGI("error cb exist");
        return;
    }

    errorCallback_.emplace_back(autoRef);
    MEDIA_LOGI("SaveCallbackReference: callbackName: %{public}s", callbackName.c_str());

    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void SystemTonePlayerCallbackTaihe::RemovePlayFinishedCallbackReference(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playFinishedCallbackMap_.count(streamId) != 0) {
        MEDIA_LOGI("Remove PlayFinished Callback streamId:%{public}d", streamId);
        playFinishedCallbackMap_.erase(streamId);
    } else {
        MEDIA_LOGI("Remove PlayFinished Callback streamId:%{public}d not exist", streamId);
    }
}

void SystemTonePlayerCallbackTaihe::RemoveCallbackReference(const std::string &callbackName,
    std::shared_ptr<AutoRef> autoRef)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName == PLAY_FINISHED_CALLBACK_NAME) {
        if (autoRef == nullptr) {
            playFinishedCallbackMap_.clear();
            MEDIA_LOGI("remove playFinished all cb succeed");
            return;
        }
        for (auto &playFinishedCallback : playFinishedCallbackMap_) {
            auto it = std::find_if(playFinishedCallback.second.begin(), playFinishedCallback.second.end(),
                                   [&autoRef, this](const auto& cb) { return IsSameRef(cb, autoRef); });
            if (it != playFinishedCallback.second.end()) {
                playFinishedCallback.second.erase(it);
                MEDIA_LOGI("remove playFinished cb succeed");
            } else {
                MEDIA_LOGE("remove playFinished cb failed");
            }
        }
    } else if (callbackName == ERROR_CALLBACK_NAME) {
        if (autoRef == nullptr) {
            errorCallback_.clear();
            MEDIA_LOGI("remove error all cb succeed");
            return;
        }
        auto it = std::find_if(errorCallback_.begin(), errorCallback_.end(),
                               [&autoRef, this](const auto& cb) { return IsSameRef(cb, autoRef); });
        if (it != errorCallback_.end()) {
            errorCallback_.erase(it);
            MEDIA_LOGI("remove error cb succeed");
        } else {
            MEDIA_LOGE("remove error cb failed");
        }
    } else {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
    }
}

void SystemTonePlayerCallbackTaihe::OnEndOfStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(playFinishedCallbackMap_.count(streamId) != 0 ||
        playFinishedCallbackMap_.count(ALL_STREAMID) != 0,
        "Cannot find the reference of playFinised callback, streamId: %{public}d", streamId);
    MEDIA_LOGI("OnEndOfStream is called, streamId: %{public}d", streamId);

    ProcessFinishedCallbacks(streamId, streamId);
    ProcessFinishedCallbacks(ALL_STREAMID, streamId);
}

void SystemTonePlayerCallbackTaihe::ProcessFinishedCallbacks(int32_t listenerId, int32_t streamId)
{
    if (playFinishedCallbackMap_.count(listenerId) == 0) {
        MEDIA_LOGD("Cannot find the reference of playFinised callback, listenerId: %{public}d", listenerId);
        return;
    }
    for (auto &callback : playFinishedCallbackMap_[listenerId]) {
        if (callback == nullptr) {
            MEDIA_LOGE("%{public}s: callback is null, listenerId: %{public}d", __func__, listenerId);
            continue;
        }
        auto cb = std::make_shared<SystemTonePlayerTaiheCallback>();
        CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
        cb->callback = callback;
        cb->callbackName = PLAY_FINISHED_CALLBACK_NAME;
        cb->streamId = streamId;
        OnTaiheCallbackPlayFinished(cb);
    }
}

void SystemTonePlayerCallbackTaihe::OnTaiheCallbackPlayFinished(std::shared_ptr<SystemTonePlayerTaiheCallback> &cb)
{
    if (cb == nullptr) {
        MEDIA_LOGE("OnTaiheCallbackPlayFinished: cb is null");
        return;
    }

    auto task = [event = cb]() {
        std::string request = event->callbackName;
        auto func = event->callback->callbackRef_;
        CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
        (*cacheCallback)(event->streamId);
    };
    if (mainHandler_ == nullptr ||
        !mainHandler_->PostTask(task, cb->callbackName, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        MEDIA_LOGE("Failed to PostTask!");
    }
}

void SystemTonePlayerCallbackTaihe::OnError(int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(!errorCallback_.empty(), "Cannot find the reference of error callback");
    MEDIA_LOGI("OnError is calleerrorCallback_d, errorCode: %{public}d", errorCode);

    for (auto &callback : errorCallback_) {
        if (callback == nullptr) {
            MEDIA_LOGE("%{public}s: callback is null", __func__);
            continue;
        }
        auto cb = std::make_shared<SystemTonePlayerTaiheCallback>();
        CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
        cb->callback = callback;
        cb->callbackName = ERROR_CALLBACK_NAME;
        cb->errorCode = errorCode;
        OnTaiheCallbackError(cb);
    }
}

void SystemTonePlayerCallbackTaihe::OnTaiheCallbackError(std::shared_ptr<SystemTonePlayerTaiheCallback> &cb)
{
    if (cb == nullptr) {
        MEDIA_LOGE("OnTaiheCallbackError: cb is null");
        return;
    }

    auto task = [event = cb]() {
        std::string request = event->callbackName;
        auto func = event->callback->callbackRef_;
        CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(func);
        ani_object err = CommonTaihe::ToBusinessError(taihe::get_env(), NUM_0, "Callback is OK");
        (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
    };
    if (mainHandler_ == nullptr ||
        !mainHandler_->PostTask(task, cb->callbackName, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        MEDIA_LOGE("Failed to PostTask!");
    }
}
} // namespace ANI::Media