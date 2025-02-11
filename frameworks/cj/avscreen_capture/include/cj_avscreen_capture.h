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

#ifndef CJ_AVSCREEN_CAPTURE_H
#define CJ_AVSCREEN_CAPTURE_H

#include "ffi_remote_data.h"
#include "screen_capture.h"
#include "screen_capture_controller.h"
#include "multimedia_audio_ffi.h"
#include "media_log.h"
#include "cj_avscreen_capture_callback.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "CJAVScreenCapture"};
}

namespace OHOS {
namespace Media {

namespace CJAVScreenCaptureEvent {
const std::string EVENT_STATE_CHANGE = "stateChange";
const std::string EVENT_ERROR = "error";
}
class FFI_EXPORT CJAVScreenCapture : public OHOS::FFI::FFIData {
    DECL_TYPE(CJAVScreenCapture, OHOS::FFI::FFIData)
public:
    static int64_t CreateAVScreenCaptureRecorder(int32_t* errorcode);
    int32_t AVScreenCaptureinit(std::shared_ptr<ScreenCapture> screenCapture, AVScreenCaptureConfig config);
    int32_t StartRecording(std::shared_ptr<ScreenCapture> screenCapture);
    int32_t StopRecording(std::shared_ptr<ScreenCapture> screenCapture);
    int32_t SkipPrivacyMode(std::shared_ptr<ScreenCapture> screenCapture, const std::vector<uint64_t> windowIDsVec);
    int32_t SetMicEnabled(std::shared_ptr<ScreenCapture> screenCapture, const bool enabled);
    int32_t Release(std::shared_ptr<ScreenCapture> screenCapture);

    int32_t OnStateChange(int64_t callbackId);
    int32_t OffStateChange();
    int32_t OnError(int64_t callbackId);
    int32_t OffError();
    
    std::shared_ptr<ScreenCapture> screenCapture_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
};
}
}

#endif // CJ_AVSCREEN_CAPTURE_H