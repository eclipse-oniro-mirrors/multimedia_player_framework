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

#include "screen_capture_listener_callback.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
ScreenCaptureListenerCallback::ScreenCaptureListenerCallback(const sptr<IStandardScreenCaptureListener> &listener)
    : listener_(listener)
{
}

ScreenCaptureListenerCallback::~ScreenCaptureListenerCallback() = default;

void ScreenCaptureListenerCallback::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    if (listener_ != nullptr) {
        listener_->OnError(errorType, errorCode);
    }
}

void ScreenCaptureListenerCallback::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    if (listener_ != nullptr) {
        listener_->OnAudioBufferAvailable(isReady, type);
    }
}

void ScreenCaptureListenerCallback::OnVideoBufferAvailable(bool isReady)
{
    if (listener_ != nullptr) {
        listener_->OnVideoBufferAvailable(isReady);
    }
}

void ScreenCaptureListenerCallback::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    if (listener_ != nullptr) {
        listener_->OnStateChange(stateCode);
    }
}

void ScreenCaptureListenerCallback::OnDisplaySelected(uint64_t displayId)
{
    if (listener_ != nullptr) {
        listener_->OnDisplaySelected(displayId);
    }
}

void ScreenCaptureListenerCallback::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect *area)
{
    if (listener_ != nullptr) {
        listener_->OnCaptureContentChanged(event, area);
    }
}

void ScreenCaptureListenerCallback::OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    if (listener_ != nullptr) {
        listener_->OnUserSelected(selectionInfo);
    }
}

void ScreenCaptureListenerCallback::OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect)
{
    if (listener_ != nullptr) {
        listener_->OnPrivacyProtect(privacyProtect);
    }
}
} // namespace Media
} // namespace OHOS
