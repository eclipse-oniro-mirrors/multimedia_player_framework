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

#include "soundpool_callback_napi.h"
#include <uv.h>
#include "media_errors.h"
#include "media_log.h"
#include "scope_guard.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPoolCallBackNapi"};
}

namespace OHOS {
namespace Media {
static const std::unordered_map<int32_t, int32_t> errorCodeMap = {
    {MSERR_INVALID_OPERATION, MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_NO_MEMORY, MSERR_EXT_API9_NO_MEMORY},
    {MSERR_SERVICE_DIED, MSERR_EXT_API9_SERVICE_DIED},
    {MSERR_UNSUPPORT_FILE, MSERR_EXT_API9_IO},
    {MSERR_INVALID_VAL, MSERR_EXT_API9_IO}
};
 
static const std::unordered_map<int32_t, std::string> errorMessageMap = {
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, "The soundpool timed out. Please confirm that the input stream is normal."},
    {MSERR_EXT_API9_NO_MEMORY, "soundpool memery error."},
    {MSERR_EXT_API9_SERVICE_DIED, "releated server died"},
    {MSERR_EXT_API9_IO, "IO error happened."}
};

SoundPoolCallBackNapi::SoundPoolCallBackNapi(napi_env env)
{
    env_ = env;
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

void SoundPoolCallBackNapi::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("OnLoadCompleted recived soundId:%{public}d", soundId);
    SendLoadCompletedCallback(soundId);
}

void SoundPoolCallBackNapi::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("OnPlayFinished recived");
    SendPlayCompletedCallback(streamID);
}

void SoundPoolCallBackNapi::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError recived:error:%{public}d", errorCode);
    int32_t externalsErrorCode = GetExternalErrorCode(errorCode);
    std::string errorMsg = GetErrorMsg(externalsErrorCode);
    SendErrorCallback(externalsErrorCode, errorMsg);
}

void SoundPoolCallBackNapi::OnErrorOccurred(Format &errorInfo)
{
    MEDIA_LOGI("OnErrorOccurred recived");
    int32_t errorCode;
    errorInfo.GetIntValue(SoundPoolKeys::ERROR_CODE, errorCode);
    int32_t externalsErrorCode = GetExternalErrorCode(errorCode);
    std::string errorMsg = GetErrorMsg(externalsErrorCode);
    errorInfo.PutIntValue(SoundPoolKeys::ERROR_CODE, externalsErrorCode);
    errorInfo.PutStringValue(SoundPoolKeys::ERROR_MESSAGE, errorMsg);
    SendErrorOccurredCallback(errorInfo);
}

int32_t SoundPoolCallBackNapi::GetExternalErrorCode(int32_t internalCode)
{
    auto it = errorCodeMap.find(internalCode);
    if (it != errorCodeMap.end()) {
        return it->second;
    }
    return MSERR_EXT_API9_IO;
}
 
std::string SoundPoolCallBackNapi::GetErrorMsg(int32_t errorCode)
{
    auto it = errorMessageMap.find(errorCode);
    if (it != errorMessageMap.end()) {
        return it->second;
    }
    return "unknown error";
}

void SoundPoolCallBackNapi::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
}

void SoundPoolCallBackNapi::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void SoundPoolCallBackNapi::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
    MEDIA_LOGI("ClearCallback!");
}

void SoundPoolCallBackNapi::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    SoundPoolJsCallBack *cb = new(std::nothrow) SoundPoolJsCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(SoundPoolEvent::EVENT_ERROR);
    cb->callbackName = SoundPoolEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    return OnJsErrorCallBack(cb);
}

void SoundPoolCallBackNapi::SendErrorOccurredCallback(const Format &errorInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_ERROR_OCCURRED) == refMap_.end()) {
        MEDIA_LOGW("can not find errorOccurred callback!");
        return;
    }
    SoundPoolJsCallBack *cb = new(std::nothrow) SoundPoolJsCallBack();
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
    return OnJsErrorOccurredCallBack(cb);
}

void SoundPoolCallBackNapi::SendLoadCompletedCallback(int32_t soundId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_LOAD_COMPLETED) == refMap_.end()) {
        MEDIA_LOGW("can not find loadcompleted callback!");
        return;
    }

    SoundPoolJsCallBack *cb = new(std::nothrow) SoundPoolJsCallBack();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(SoundPoolEvent::EVENT_LOAD_COMPLETED);
    cb->callbackName = SoundPoolEvent::EVENT_LOAD_COMPLETED;
    cb->loadSoundId = soundId;
    return OnJsloadCompletedCallBack(cb);
}

void SoundPoolCallBackNapi::SendPlayCompletedCallback(int32_t streamID)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED) == refMap_.end() &&
        refMap_.find(SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID) == refMap_.end()) {
        MEDIA_LOGW("can not find playfinished callback!");
        return;
    }

    SoundPoolJsCallBack *cb = new(std::nothrow) SoundPoolJsCallBack();
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
    return OnJsplayCompletedCallBack(cb);
}

void SoundPoolCallBackNapi::OnJsErrorCallBack(SoundPoolJsCallBack *jsCb) const
{
    auto task = [event = jsCb]() {
        event->RunJsErrorCallBackTask(event);
        delete event;
    };
    std::string taskname = "OnJsErrorCallBack";
    auto ret = napi_send_event(env_, task, napi_eprio_immediate, taskname.c_str());
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent CallBack, ret = %{public}d", ret);
        delete jsCb;
    }
}

void SoundPoolCallBackNapi::OnJsErrorOccurredCallBack(SoundPoolJsCallBack *jsCb) const
{
    auto task = [event = jsCb]() {
        event->RunJsErrorOccurredCallBackTask(event);
        delete event;
    };
    std::string taskname = "OnJsErrorOccurredCallBack";
    auto ret = napi_send_event(env_, task, napi_eprio_immediate, taskname.c_str());
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent CallBack, ret = %{public}d", ret);
        delete jsCb;
    }
}

void SoundPoolCallBackNapi::SoundPoolJsCallBack::RunJsErrorCallBackTask(SoundPoolJsCallBack *event)
{
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
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
            request.c_str());

        napi_value msgValStr = nullptr;
        nstatus = napi_create_string_utf8(ref->env_, event->errorMsg.c_str(), NAPI_AUTO_LENGTH, &msgValStr);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && msgValStr != nullptr, "create error message str fail");

        napi_value args[1] = { nullptr };
        nstatus = napi_create_error(ref->env_, nullptr, msgValStr, &args[0]);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr, "create error callback fail");
        
        nstatus = CommonNapi::FillErrorArgs(ref->env_, event->errorCode, args[0]);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok, "create error callback fail");
        // Call back function
        napi_value result = nullptr;
        nstatus = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
    } while (0);
}

void SoundPoolCallBackNapi::SoundPoolJsCallBack::RunJsErrorOccurredCallBackTask(SoundPoolJsCallBack *event)
{
    std::string request = event->callbackName;
    MEDIA_LOGI("errorOccurredCallback event: errorMsg %{public}s, errorCode %{public}d, soundId %{public}d,"
        "streamId %{public}d", event->errorMsg.c_str(), event->errorCode, event->loadSoundId,
        event->playFinishedStreamID);
    std::shared_ptr<AutoRef> ref = event->autoRef.lock();
    CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(ref->env_, &scope);
    CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
    ON_SCOPE_EXIT(0) {
        napi_close_handle_scope(ref->env_, scope);
    };
    napi_value jsCallback = nullptr;
    napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
    CHECK_AND_RETURN_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
        request.c_str());
    constexpr size_t argCount = 1;
    napi_value args[argCount] = {};
    napi_create_object(ref->env_, &args[0]);

    napi_value errCode = nullptr;
    int status = CommonNapi::CreateError(ref->env_, event->errorCode, event->errorMsg, errCode);
    CHECK_AND_RETURN_LOG(status == napi_ok && errCode != nullptr,
        " fail to convert to errorCode");
    napi_set_named_property(ref->env_, args[0], "errorCode", errCode);
    bool res = CommonNapi::SetPropertyInt32(ref->env_, args[0], "errorType", event->errorType);
    CHECK_AND_RETURN_LOG(res, " fail to convert to errorType");
    res = CommonNapi::SetPropertyInt32(ref->env_, args[0], "soundId", event->loadSoundId);
    CHECK_AND_RETURN_LOG(res, " fail to convert to soundId");
    if (event->playFinishedStreamID > 0) {
        res = CommonNapi::SetPropertyInt32(ref->env_, args[0], "streamId", event->playFinishedStreamID);
        CHECK_AND_RETURN_LOG(res, " fail to convert to streamId");
    }

    napi_value result = nullptr;
    nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
    CHECK_AND_RETURN_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
}

void SoundPoolCallBackNapi::OnJsloadCompletedCallBack(SoundPoolJsCallBack *jsCb) const
{
    auto task = [event = jsCb]() {
        event->RunJsloadCompletedCallBackTask(event);
        delete event;
    };
    std::string taskname = "OnJsloadCompletedCallBack";
    auto ret = napi_send_event(env_, task, napi_eprio_immediate, taskname.c_str());
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent CallBack, ret = %{public}d", ret);
        delete jsCb;
    }
}

void SoundPoolCallBackNapi::SoundPoolJsCallBack::RunJsloadCompletedCallBackTask(SoundPoolJsCallBack *event)
{
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
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
            request.c_str());
        napi_value args[1] = { nullptr };
        nstatus = napi_create_int32(ref->env_, event->loadSoundId, &args[0]);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr,
            "%{public}s fail to create callback", request.c_str());
        const size_t argCount = 1;
        napi_value result = nullptr;
        nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
        CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
    } while (0);
}

void SoundPoolCallBackNapi::OnJsplayCompletedCallBack(SoundPoolJsCallBack *jsCb) const
{
    auto task = [event = jsCb]() {
        event->RunJsplayCompletedCallBackTask(event);
        delete event;
    };
    std::string taskname = "OnJsplayCompletedCallBack";
    auto ret = napi_send_event(env_, task, napi_eprio_immediate, taskname.c_str());
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("Failed to SendEvent CallBack, ret = %{public}d", ret);
        delete jsCb;
    }
}

void SoundPoolCallBackNapi::SoundPoolJsCallBack::RunJsplayCompletedCallBackTask(SoundPoolJsCallBack *event)
{
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
        CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
            request.c_str());

        if (request == SoundPoolEvent::EVENT_PLAY_FINISHED_WITH_STREAM_ID) {
            napi_value args[1] = { nullptr };
            nstatus = napi_create_int32(ref->env_, event->playFinishedStreamID, &args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr,
                "%{public}s fail to create callback", request.c_str());
            const size_t argCount = 1;
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        } else {
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, 0, nullptr, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        }
    } while (0);
}

} // namespace Media
} // namespace OHOS