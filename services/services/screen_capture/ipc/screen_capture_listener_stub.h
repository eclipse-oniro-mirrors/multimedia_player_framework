/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_LISTENER_STUB_H
#define SCREEN_CAPTURE_LISTENER_STUB_H

#include "i_standard_screen_capture_listener.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {
class ScreenCaptureListenerStub : public IRemoteStub<IStandardScreenCaptureListener> {
public:
    ScreenCaptureListenerStub();
    virtual ~ScreenCaptureListenerStub();
    int32_t OnCaptureContentChangedStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnUserSelectedStub(MessageParcel &data, MessageParcel &reply);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override;
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override;
    void OnVideoBufferAvailable(bool isReady) override;
    void OnStateChange(AVScreenCaptureStateCode stateCode) override;
    void OnDisplaySelected(uint64_t displayId) override;
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area) override;
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override;
    void SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback);

private:
    std::shared_ptr<ScreenCaptureCallBack> callback_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_LISTENER_STUB_H