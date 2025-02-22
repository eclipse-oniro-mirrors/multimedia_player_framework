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
struct CAudioCaptureInfo {
    int32_t audioSampleRate;
    int32_t audioChannels;
    int32_t audioSource;
    int32_t state;
};

struct CVideoCaptureInfo {
    std::uint64_t displayId;
    CArrI32 taskIDs;
    int32_t videoFrameWidth;
    int32_t videoFrameHeight;
    int32_t videoSource;
    int32_t state;
};

struct CVideoEncInfo {
    int32_t videoCodec;
    int32_t videoBitrate;
    int32_t videoFrameRate;
    int32_t state;
};

struct CVideoInfo {
    CVideoCaptureInfo videoCapInfo;
    CVideoEncInfo videoEncInfo;
};

struct CAudioEncInfo {
    int32_t audioBitrate;
    int32_t audioCodecformat;
    int32_t state;
};

struct CAudioInfo {
    CAudioCaptureInfo micCapInfo;
    CAudioCaptureInfo innerCapInfo;
    CAudioEncInfo audioEncInfo;
};

struct CRecorderInfo {
    char* url;
    char* fileFormat;
};

struct CAVScreenCaptureConfig {
    int32_t captureMode;
    int32_t dataType;
    CAudioInfo audioInfo;
    CVideoInfo videoInfo;
    CRecorderInfo recorderInfo;
};

FFI_EXPORT int64_t FfiAVScreenCaptureCreateAVScreenCaptureRecorder(int32_t* errorcode);
FFI_EXPORT int32_t FfiAVScreenCaptureinit(int64_t id, CAVScreenCaptureConfig config);
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