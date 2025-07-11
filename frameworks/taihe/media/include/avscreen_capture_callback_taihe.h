/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef AVSCREEN_CAPTURE_CALLBACK_TAIHE_H
#define AVSCREEN_CAPTURE_CALLBACK_TAIHE_H

#include "screen_capture.h"
#include "avscreen_capture_taihe.h"
#include "event_handler.h"
namespace ANI {
namespace Media {
using namespace OHOS::Media;

class AVScreenCaptureCallback : public ScreenCaptureCallBack {
public:
    explicit AVScreenCaptureCallback();
    virtual ~AVScreenCaptureCallback();

    void SendErrorCallback(int32_t errCode, const std::string &msg);
    void SendStateCallback(OHOS::Media::AVScreenCaptureStateCode stateCode);
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &name);
    void ClearCallbackReference();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
protected:
    void OnError(OHOS::Media::ScreenCaptureErrorType errorType, int32_t errorCode) override;
    void OnStateChange(OHOS::Media::AVScreenCaptureStateCode stateCode) override;
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
    struct AVScreenCaptureTaiheCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        std::string errorMsg = "unknown";
        int32_t errorCode = OHOS::Media::MSERR_EXT_UNKNOWN;
        OHOS::Media::AVScreenCaptureStateCode stateCode;
    };
    void OnTaiheErrorCallBack(AVScreenCaptureTaiheCallback *taiheCb) const;
    void OnTaiheStateChangeCallBack(AVScreenCaptureTaiheCallback *taiheCb) const;
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};
} // namespace Media
} // namespace ANI
#endif // AVSCREEN_CAPTURE_CALLBACK_TAIHE_H