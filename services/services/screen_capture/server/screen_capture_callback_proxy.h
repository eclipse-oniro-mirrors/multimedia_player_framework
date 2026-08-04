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

#ifndef SCREEN_CAPTURE_CALLBACK_PROXY_H
#define SCREEN_CAPTURE_CALLBACK_PROXY_H

#include <memory>
#include <shared_mutex>

#include "nocopyable.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {

class ScreenCaptureCallbackProxy : public ScreenCaptureCallBack, public NoCopyable {
public:
    void SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback);
    void SetBufferActive(bool active);
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override;
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override;
    void OnVideoBufferAvailable(bool isReady) override;
    void OnStateChange(AVScreenCaptureStateCode stateCode) override;
    void OnDisplaySelected(uint64_t displayId) override;
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area) override;
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override;
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) override;

private:
    std::shared_mutex mutex_;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    bool bufferActive_ = false;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_CALLBACK_PROXY_H
