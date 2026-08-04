/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "screen_capture_callback_proxy.h"

#include "media_log.h"

namespace OHOS {
namespace Media {

void ScreenCaptureCallbackProxy::SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    screenCaptureCb_ = callback;
    bufferActive_ = true;
}

void ScreenCaptureCallbackProxy::SetBufferActive(bool active)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    bufferActive_ = active;
}

void ScreenCaptureCallbackProxy::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnError(errorType, errorCode);
    }
}

void ScreenCaptureCallbackProxy::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (!bufferActive_) {
            return;
        }
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnAudioBufferAvailable(isReady, type);
    }
}

void ScreenCaptureCallbackProxy::OnVideoBufferAvailable(bool isReady)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (!bufferActive_) {
            return;
        }
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnVideoBufferAvailable(isReady);
    }
}

void ScreenCaptureCallbackProxy::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    if (stateCode == AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID) {
        return;
    }
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnStateChange(stateCode);
    }
}

void ScreenCaptureCallbackProxy::OnDisplaySelected(uint64_t displayId)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnDisplaySelected(displayId);
    }
}

void ScreenCaptureCallbackProxy::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect *area)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnCaptureContentChanged(event, area);
    }
}

void ScreenCaptureCallbackProxy::OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnUserSelected(selectionInfo);
    }
}

void ScreenCaptureCallbackProxy::OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect)
{
    std::shared_ptr<ScreenCaptureCallBack> cb;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        cb = screenCaptureCb_;
    }
    if (cb != nullptr) {
        cb->OnPrivacyProtect(privacyProtect);
    }
}
} // namespace Media
} // namespace OHOS
