/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avtranscoder_callback.h"
#include "media_core.h"
#include "scope_guard.h"
#include "cj_lambda.h"

namespace OHOS {
namespace Media {

std::unordered_map<CJAVTranscoderEvent, const char *, EnumClassHash> EVENT2CSTR = {
    {CJAVTranscoderEvent::EVENT_PROGRESS_UPDATE, "progressUpdate"},
    {CJAVTranscoderEvent::EVENT_COMPLETE, "complete"},
    {CJAVTranscoderEvent::EVENT_ERROR, "error"}
};

CJAVTranscoderCallback::CJAVTranscoderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

CJAVTranscoderCallback::~CJAVTranscoderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void CJAVTranscoderCallback::SaveCallbackReference(CJAVTranscoderEvent event, int64_t callbackId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (event == CJAVTranscoderEvent::EVENT_PROGRESS_UPDATE) {
        auto func = reinterpret_cast<void (*)(int32_t)>(callbackId);
        onprogressfunc = [lambda = CJLambda::Create(func)](int32_t progress) {
            lambda(progress);
        };
    } else if (event == CJAVTranscoderEvent::EVENT_COMPLETE) {
        auto func = reinterpret_cast<void (*)(void)>(callbackId);
        oncompletefunc = [lambda = CJLambda::Create(func)]() {
            lambda();
        };
    } else if (event == CJAVTranscoderEvent::EVENT_ERROR) {
        auto func = reinterpret_cast<void (*)(int32_t, const char*)>(callbackId);
        onerrorfunc = [lambda = CJLambda::Create(func)](int32_t errCode, const char* msg) {
            lambda(errCode, msg);
        };
    }

    if (EVENT2CSTR.find(event) != EVENT2CSTR.end()) {
        MEDIA_LOGI("Set callback type: %{public}s", EVENT2CSTR.at(event));
    } else {
        MEDIA_LOGW("event %{public}d is not in EVENT2CSTR", static_cast<int32_t>(event));
    }
}

void CJAVTranscoderCallback::CancelCallbackReference(CJAVTranscoderEvent event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (event == CJAVTranscoderEvent::EVENT_PROGRESS_UPDATE) {
        onprogressfunc = nullptr;
    } else if (event == CJAVTranscoderEvent::EVENT_COMPLETE) {
        oncompletefunc = nullptr;
    } else if (event == CJAVTranscoderEvent::EVENT_ERROR) {
        onerrorfunc = nullptr;
    }

    if (EVENT2CSTR.find(event) != EVENT2CSTR.end()) {
        MEDIA_LOGI("Cancel callback type: %{public}s", EVENT2CSTR.at(event));
    } else {
        MEDIA_LOGW("event %{public}d is not in EVENT2CSTR", static_cast<int32_t>(event));
    }
}

void CJAVTranscoderCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    onprogressfunc = nullptr;
    oncompletefunc = nullptr;
    onerrorfunc = nullptr;
    MEDIA_LOGI("ClearCallback!");
}

void CJAVTranscoderCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onerrorfunc == nullptr) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }
    onerrorfunc(errCode, msg.c_str());
}

void CJAVTranscoderCallback::SendStateCallback(CjAVTransCoderState state, const StateChangeReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_ = state;
}

void CJAVTranscoderCallback::SendCompleteCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (oncompletefunc == nullptr) {
        MEDIA_LOGW("can not find complete callback!");
        return;
    }
    oncompletefunc();
}

void CJAVTranscoderCallback::SendProgressUpdateCallback(int32_t progress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onprogressfunc == nullptr) {
        MEDIA_LOGW("can not find progress callback!");
        return;
    }
    onprogressfunc(progress);
}

CjAVTransCoderState CJAVTranscoderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void CJAVTranscoderCallback::OnError(int32_t errCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 extErr = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    MEDIA_LOGE("CJAVTranscoderCallback::OnError: %{public}d, %{public}s", extErr, errorMsg.c_str());
    SendErrorCallback(extErr, errorMsg);
    SendStateCallback(CjAVTransCoderState::STATE_ERROR, StateChangeReason::BACKGROUND);
}

void CJAVTranscoderCallback::OnInfo(int32_t type, int32_t extra)
{
    if (type == TransCoderOnInfoType::INFO_TYPE_TRANSCODER_COMPLETED) {
        SendCompleteCallback();
    } else if (type == TransCoderOnInfoType::INFO_TYPE_PROGRESS_UPDATE) {
        SendProgressUpdateCallback(extra);
    }
}
}
}
