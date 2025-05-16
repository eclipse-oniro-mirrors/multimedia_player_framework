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

#ifndef I_STANDARD_SCREEN_CAPTURE_LISTENER_H
#define I_STANDARD_SCREEN_CAPTURE_LISTENER_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {
class IStandardScreenCaptureListener : public IRemoteBroker {
public:
    virtual ~IStandardScreenCaptureListener() = default;
    virtual void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) = 0;
    virtual void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) = 0;
    virtual void OnVideoBufferAvailable(bool isReady) = 0;
    virtual void OnStateChange(AVScreenCaptureStateCode stateCode) = 0;
    virtual void OnDisplaySelected(uint64_t displayId) = 0;
    virtual void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area) = 0;
    /**
     * IPC code ID
     */
    enum ScreenCaptureListenerMsg {
        ON_ERROR = 0,
        ON_AUDIO_AVAILABLE = 1,
        ON_VIDEO_AVAILABLE = 2,
        ON_STAGE_CHANGE = 3,
        ON_DISPLAY_SELECTED = 4,
        ON_CONTENT_CHANGED = 5
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardScreenCaptureListener");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_SCREEN_CAPTURE_LISTENER_H