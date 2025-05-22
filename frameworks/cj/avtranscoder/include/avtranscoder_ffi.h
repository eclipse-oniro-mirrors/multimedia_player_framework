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

#ifndef AVTRANSCODER_FFI_H
#define AVTRANSCODER_FFI_H
#include "ffi_remote_data.h"
#include "cj_common_ffi.h"
#include "cj_avplayer_utils.h"

namespace OHOS {
namespace Media {
extern "C" {

struct CAVTransCoderConfig {
    int32_t audioBitrate;
    char* audioCodecFormat;
    char* fileFormat;
    int32_t videoBitrate;
    char* videoCodecFormat;
    int32_t videoFrameWidth;
    int32_t videoFrameHeight;
};

FFI_EXPORT int64_t FfiAVTranscoderCreateAVTranscoder(int32_t* errCode);

FFI_EXPORT int32_t FfiAVTranscoderPrepare(int64_t id, CAVTransCoderConfig config);
FFI_EXPORT int32_t FfiAVTranscoderStart(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderPause(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderResume(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderCancel(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderRelease(int64_t id);

FFI_EXPORT CAVFileDescriptor FfiAVTranscoderGetFdSrc(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiAVTranscoderSetFdSrc(int64_t id, CAVFileDescriptor fdSrc);

FFI_EXPORT int32_t FfiAVTranscoderGetFdDst(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiAVTranscoderSetFdDst(int64_t id, int32_t fdDst);

FFI_EXPORT int32_t FfiAVTranscoderOnProgressUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiAVTranscoderOffProgressUpdate(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderOnComplete(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiAVTranscoderOffComplete(int64_t id);
FFI_EXPORT int32_t FfiAVTranscoderOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiAVTranscoderOffError(int64_t id);
}
}
}
#endif // AVTRANSCODER_FFI_H