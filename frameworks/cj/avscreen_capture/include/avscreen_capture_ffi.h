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

#ifndef AVSCREEN_CAPTURE_FFI_H
#define AVSCREEN_CAPTURE_FFI_H
#include <vector>
#include "ffi_remote_data.h"
#include "cj_common_ffi.h"
#include "cj_avscreen_capture.h"

namespace OHOS {
namespace Media {
extern "C" {
FFI_EXPORT int64_t FfiAVScreenCaptureCreateAVScreenCaptureRecorder(int32_t* errorcode);
FFI_EXPORT int32_t FfiAVScreenCaptureinit(int64_t id, AVScreenCaptureConfig config);
FFI_EXPORT int32_t FfiAVScreenCaptureStartRecording(int64_t id);
FFI_EXPORT int32_t FfiAVScreenCaptureStopRecording(int64_t id);
FFI_EXPORT int32_t FfiAVScreenCaptureSkipPrivacyMode(int64_t id, CArrUnit windowIDsVec);
FFI_EXPORT int32_t FfiAVScreenCaptureSetMicEnabled(int64_t id, bool enable);
FFI_EXPORT int32_t FfiAVScreenCaptureRelease(int64_t id);
FFI_EXPORT int32_t FfiAVScreenCaptureOnStateChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiAVScreenCaptureOffStateChange(int64_t id);
FFI_EXPORT int32_t FfiAVScreenCaptureOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiAVScreenCaptureOffError(int64_t id);
}
}
}
#endif // AVSCREEN_CAPTURE_FFI_H