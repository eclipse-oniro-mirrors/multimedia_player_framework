/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "recorder_callback_napi.h"
#include <uv.h>
#include "media_errors.h"
#include "media_log.h"
#include "scope_guard.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderCallbackNapi"};
}

namespace OHOS {
namespace Media {
RecorderCallbackNapi::RecorderCallbackNapi(napi_env env, bool isVideo)
    : env_(env), isVideo_(isVideo)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderCallbackNapi::~RecorderCallbackNapi()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void RecorderCallbackNapi::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void RecorderCallbackNapi::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
}

void RecorderCallbackNapi::SendErrorCallback(int32_t errCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(ERROR_CALLBACK_NAME) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    RecordJsCallback *cb = new(std::nothrow) RecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(ERROR_CALLBACK_NAME);
    cb->callbackName = ERROR_CALLBACK_NAME;
    if (isVideo_) {
        cb->errorMsg = MSExtErrorAPI9ToString(static_cast<MediaServiceExtErrCodeAPI9>(errCode), "", "");
    } else {
        cb->errorMsg = MSExtErrorToString(static_cast<MediaServiceExtErrCode>(errCode));
    }
    cb->errorCode = errCode;
    return OnJsErrorCallBack(cb);
}

void RecorderCallbackNapi::SendStateCallback(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(callbackName) == refMap_.end()) {
        MEDIA_LOGW("can not find %{public}s callback!", callbackName.c_str());
        return;
    }

    RecordJsCallback *cb = new(std::nothrow) RecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(callbackName);
    cb->callbackName = callbackName;
    return OnJsStateCallBack(cb);
}

void RecorderCallbackNapi::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGD("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
    if (isVideo_) {
        MediaServiceExtErrCode err = MSErrorToExtError(static_cast<MediaServiceErrCode>(errCode));
        return SendErrorCallback(err);
    } else {
        MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
        return SendErrorCallback(err);
    }
}

void RecorderCallbackNapi::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGD("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
}

void RecorderCallbackNapi::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    (void)audioRecorderChangeInfo;
}

void RecorderCallbackNapi::OnJsStateCallBack(RecordJsCallback *jsCb) const
{
    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, 0, nullptr, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate,
        RecorderCallbackNapiTask::ON_JS_STATE_CALLBACK.c_str());
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");
}

void RecorderCallbackNapi::OnJsErrorCallBack(RecordJsCallback *jsCb) const
{
    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) { napi_close_handle_scope(ref->env_, scope); };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            napi_value msgValStr = nullptr;
            nstatus = napi_create_string_utf8(ref->env_, event->errorMsg.c_str(), NAPI_AUTO_LENGTH, &msgValStr);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && msgValStr != nullptr, "%{public}s failed to get error code value",
                request.c_str());

            napi_value args[1] = { nullptr };
            nstatus = napi_create_error(ref->env_, nullptr, msgValStr, &args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr, "%{public}s failed to create error callback",
                request.c_str());

            nstatus = CommonNapi::FillErrorArgs(ref->env_, event->errorCode, args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "create error callback failed");

            // Call back function
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate,
        RecorderCallbackNapiTask::ON_JS_ERROR_CALLBACK.c_str());
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");
}
} // namespace Media
} // namespace OHOS