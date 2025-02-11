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

#ifndef CJ_AVSCREEN_CAPTURE_CALLBACK_H
#define CJ_AVSCREEN_CAPTURE_CALLBACK_H

#include "screen_capture.h"
#include "screen_capture_controller.h"
#include "media_log.h"
#include "cj_avscreen_capture.h"
#include <shared_mutex>
#include <mutex>

namespace OHOS {
namespace Media {
class CJAVScreenCaptureCallback : public ScreenCaptureCallBack {
public:
    explicit CJAVScreenCaptureCallback();
    virtual ~CJAVScreenCaptureCallback();

    void SendErrorCallback(int32_t errCode, const std::string &msg);
    void SendStateCallback(AVScreenCaptureStateCode stateCode);
    void SaveCallbackReference(const std::string &name, int64_t callbackId);
    void CancelCallbackReference(const std::string &name);
    void ClearCallbackReference();
protected:
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override;
    void OnStateChange(AVScreenCaptureStateCode stateCode) override;
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override
    {
        (void)isReady;
        (void)type;
    }
    void OnVideoBufferAvailable(bool isReady) override
    {
        (void)isReady;
    }
private:
    std::mutex mutex_;
    std::map<std::string, int64_t> refMap_;
};
}
}
#endif