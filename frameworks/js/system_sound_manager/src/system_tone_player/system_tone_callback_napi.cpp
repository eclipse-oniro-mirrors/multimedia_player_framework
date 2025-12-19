/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "system_tone_callback_napi.h"
#include "media_errors.h"
#include "system_sound_log.h"

namespace {
const std::string PLAY_FINISHED_CALLBACK_NAME = "playFinished";
const std::string ERROR_CALLBACK_NAME = "error";
const int32_t ALL_STREAMID = 0;

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayerCallbackNapi"};
}

namespace OHOS {
namespace Media {
SystemTonePlayerCallbackNapi::SystemTonePlayerCallbackNapi(napi_env env)
    : env_(env)
{
    MEDIA_LOGD("SystemTonePlayerCallbackNapi: instance create");
}

SystemTonePlayerCallbackNapi::~SystemTonePlayerCallbackNapi()
{
    MEDIA_LOGD("SystemTonePlayerCallbackNapi: instance destroy");
}

bool SystemTonePlayerCallbackNapi::IsSameCallback(std::shared_ptr<AutoRef> cb, const napi_value args)
{
    if (args == nullptr) {
        MEDIA_LOGE("args is null");
        return true;
    }
    if (cb == nullptr) {
        MEDIA_LOGE("cb is null");
        return false;
    }
    napi_value callback = nullptr;
    napi_get_reference_value(env_, cb->cb_, &callback);
    bool isEquals = false;
    CHECK_AND_RETURN_RET_LOG(napi_strict_equals(env_, args, callback, &isEquals) == napi_ok, false,
        "get napi_strict_equals failed");
    return isEquals;
}

bool SystemTonePlayerCallbackNapi::IsExistCallback(const std::list<std::shared_ptr<AutoRef>> &cbList,
    const napi_value args)
{
    if (args == nullptr) {
        MEDIA_LOGE("args is null");
        return true;
    }
    if (cbList.empty()) {
        MEDIA_LOGD("cbList is empty");
        return false;
    }
    for (auto &cb : cbList) {
        if (IsSameCallback(cb, args)) {
            return true;
        }
    }
    return false;
}

void SystemTonePlayerCallbackNapi::SavePlayFinishedCallbackReference(const std::string &callbackName, napi_value args,
    int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName != PLAY_FINISHED_CALLBACK_NAME) {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    if (playFinishedCallbackMap_.count(streamId) != 0 && IsExistCallback(playFinishedCallbackMap_[streamId], args)) {
        MEDIA_LOGI("playFinished cb exist streamId: %{public}d", streamId);
        return;
    }

    napi_ref callback = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, args, refCount, &callback);
    CHECK_AND_RETURN_LOG(status == napi_ok && callback != nullptr, "creating reference for callback fail");

    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callback);
    playFinishedCallbackMap_[streamId].emplace_back(cb);
}

void SystemTonePlayerCallbackNapi::SaveCallbackReference(const std::string &callbackName, napi_value args)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName != ERROR_CALLBACK_NAME) {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    if (IsExistCallback(errorCallback_, args)) {
        MEDIA_LOGI("error cb exist");
        return;
    }

    napi_ref callback = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, args, refCount, &callback);
    CHECK_AND_RETURN_LOG(status == napi_ok && callback != nullptr, "creating reference for callback fail");

    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callback);
    errorCallback_.emplace_back(cb);
}

void SystemTonePlayerCallbackNapi::RemovePlayFinishedCallbackReference(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playFinishedCallbackMap_.count(streamId) != 0) {
        MEDIA_LOGI("Remove PlayFinished Callback streamId:%{public}d", streamId);
        playFinishedCallbackMap_.erase(streamId);
    } else {
        MEDIA_LOGI("Remove PlayFinished Callback streamId:%{public}d not exist", streamId);
    }
}

void SystemTonePlayerCallbackNapi::RemoveCallbackReference(const std::string &callbackName, const napi_value &args)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName == PLAY_FINISHED_CALLBACK_NAME) {
        if (args == nullptr) {
            playFinishedCallbackMap_.clear();
            MEDIA_LOGI("remove playFinished all cb succeed");
            return;
        }
        for (auto &playFinishedCallback : playFinishedCallbackMap_) {
            auto it = std::find_if(playFinishedCallback.second.begin(), playFinishedCallback.second.end(),
                                   [&args, this](const auto& cb) { return IsSameCallback(cb, args); });
            if (it != playFinishedCallback.second.end()) {
                playFinishedCallback.second.erase(it);
                MEDIA_LOGI("remove playFinished cb succeed");
            } else {
                MEDIA_LOGE("remove playFinished cb failed");
            }
        }
    } else if (callbackName == ERROR_CALLBACK_NAME) {
        if (args == nullptr) {
            errorCallback_.clear();
            MEDIA_LOGI("remove error all cb succeed");
            return;
        }
        auto it = std::find_if(errorCallback_.begin(), errorCallback_.end(),
                               [&args, this](const auto& cb) { return IsSameCallback(cb, args); });
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

void SystemTonePlayerCallbackNapi::OnEndOfStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(playFinishedCallbackMap_.count(streamId) != 0 ||
        playFinishedCallbackMap_.count(ALL_STREAMID) != 0,
        "Cannot find the reference of playFinised callback, streamId: %{public}d", streamId);
    MEDIA_LOGI("OnEndOfStream is called, streamId: %{public}d", streamId);

    ProcessFinishedCallbacks(streamId, streamId);
    ProcessFinishedCallbacks(ALL_STREAMID, streamId);
}

void SystemTonePlayerCallbackNapi::ProcessFinishedCallbacks(int32_t listenerId, int32_t streamId)
{
    if (playFinishedCallbackMap_.count(listenerId) == 0) {
        MEDIA_LOGD("Cannot find the reference of playFinised callback, listenerId: %{public}d", listenerId);
        return;
    }
    for (auto &callback : playFinishedCallbackMap_[listenerId]) {
        auto cb = std::make_shared<SystemTonePlayerJsCallback>();
        CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
        cb->callback = callback;
        cb->callbackName = PLAY_FINISHED_CALLBACK_NAME;
        cb->streamId = streamId;
        OnJsCallbackPlayFinished(cb);
    }
}

void SystemTonePlayerCallbackNapi::OnJsCallbackPlayFinished(std::shared_ptr<SystemTonePlayerJsCallback> &jsCb)
{
    if (jsCb == nullptr) {
        MEDIA_LOGE("OnJsCallbackPlayFinished: jsCb is null");
        return;
    }
    auto task = [event = std::move(jsCb)]() {
        std::string request = event->callbackName;
        napi_env env = event->callback->env_;
        napi_ref callback = event->callback->cb_;
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(env, &scope);
        CHECK_AND_RETURN_LOG(status == napi_ok && scope != nullptr, "open handle scope failed!");
        MEDIA_LOGI("JsCallBack %{public}s, uv_queue_work start", request.c_str());
        do {
            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(env, callback, &jsCallback);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s get reference value fail", request.c_str());

            // Call back function
            napi_value args[1] = { nullptr };
            napiStatus = napi_create_int32(env, event->streamId, &args[0]);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok && args[0] != nullptr,
                "%{public}s fail to create PlayFinished callback", request.c_str());

            const size_t argCount = 1;
            napi_value result = nullptr;
            napiStatus = napi_call_function(env, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        } while (0);
        napi_close_handle_scope(env, scope);
    };
    auto ret = napi_send_event(env_, task, napi_eprio_high, "playFinished");
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent, ret = %{public}d", ret);
    }
}

void SystemTonePlayerCallbackNapi::OnError(int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(!errorCallback_.empty(), "Cannot find the reference of error callback");
    MEDIA_LOGI("OnError is calleerrorCallback_d, errorCode: %{public}d", errorCode);

    for (auto &callback : errorCallback_) {
        auto cb = std::make_shared<SystemTonePlayerJsCallback>();
        CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
        cb->callback = callback;
        cb->callbackName = ERROR_CALLBACK_NAME;
        cb->errorCode = errorCode;
        cb->errorMsg = "error";
        OnJsCallbackError(cb);
    }
}

void SystemTonePlayerCallbackNapi::OnJsCallbackError(std::shared_ptr<SystemTonePlayerJsCallback> &jsCb)
{
    if (jsCb == nullptr) {
        MEDIA_LOGE("OnJsCallbackError: jsCb is null");
        return;
    }
    auto task = [event = std::move(jsCb)]() {
        std::string request = event->callbackName;
        napi_env env = event->callback->env_;
        napi_ref callback = event->callback->cb_;
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(env, &scope);
        CHECK_AND_RETURN_LOG(status == napi_ok && scope != nullptr, "open handle scope failed!");
        MEDIA_LOGI("JsCallBack %{public}s, uv_queue_work start", request.c_str());
        do {
            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(env, callback, &jsCallback);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s get reference value fail", request.c_str());

            // Call back function
            napi_value msgValStr = nullptr;
            napiStatus = napi_create_string_utf8(env, event->errorMsg.c_str(), NAPI_AUTO_LENGTH, &msgValStr);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok && msgValStr != nullptr, "create error message str fail");

            napi_value args[1] = { nullptr };
            napiStatus = napi_create_error(env, nullptr, msgValStr, &args[0]);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok && args[0] != nullptr, "create error callback fail");

            napiStatus = CommonNapi::FillErrorArgs(env, event->errorCode, args[0]);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok, "create error callback fail");

            napi_value result = nullptr;
            napiStatus = napi_call_function(env, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        } while (0);
        napi_close_handle_scope(env, scope);
    };
    auto ret = napi_send_event(env_, task, napi_eprio_high, "error");
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent, ret = %{public}d", ret);
    }
}
}  // namespace Media
}  // namespace OHOS