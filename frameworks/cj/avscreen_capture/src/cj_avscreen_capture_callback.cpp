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

#include "cj_avscreen_capture_callback.h"
#include "media_core.h"
#include "scope_guard.h"
#include "cj_lambda.h"

namespace OHOS {
namespace Media {
CJAVScreenCaptureCallback::CJAVScreenCaptureCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

CJAVScreenCaptureCallback::~CJAVScreenCaptureCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void CJAVScreenCaptureCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onerrorfunc == nullptr) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }
    onerrorfunc(errCode, msg);
}

void CJAVScreenCaptureCallback::SendStateCallback(AVScreenCaptureStateCode stateCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onstatechangefunc == nullptr) {
        MEDIA_LOGW("can not find stateChange callback!");
        return;
    }
    onstatechangefunc(stateCode);
}

void CJAVScreenCaptureCallback::SaveCallbackReference(const std::string &name, int64_t callbackId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (name == CJAVScreenCaptureEvent::EVENT_ERROR) {
        auto func = reinterpret_cast<void (*)(int32_t, const std::string &)>(callbackId);
        onerrorfunc = [lambda = CJLambda::Create(func)](int32_t errCode, const std::string &msg) {
            lambda(errCode, msg);
        };
    } else {
        auto func = reinterpret_cast<void (*)(AVScreenCaptureStateCode)>(callbackId);
        onstatechangefunc = [lambda = CJLambda::Create(func)](AVScreenCaptureStateCode stateCode) {
            lambda(stateCode);
        };
    }
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
}

void CJAVScreenCaptureCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (name == CJAVScreenCaptureEvent::EVENT_ERROR) {
        onerrorfunc = nullptr;
    } else {
        onstatechangefunc = nullptr;
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void CJAVScreenCaptureCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    onerrorfunc = nullptr;
    onstatechangefunc = nullptr;
    MEDIA_LOGI("ClearCallback!");
}

void CJAVScreenCaptureCallback::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errorCode);
    SendErrorCallback(errorCode, "Screen capture failed.");
}

void CJAVScreenCaptureCallback::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("OnStateChange() is called, stateCode: %{public}d", stateCode);
    SendStateCallback(stateCode);
}

}
}
