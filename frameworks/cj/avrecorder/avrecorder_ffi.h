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

#ifndef AV_RECORDER_FFI_H
#define AV_RECORDER_FFI_H

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "avrecorder_common.h"

extern "C" {
    FFI_EXPORT int64_t FfiOHOSMediaAVRecorderCreateAVRecorder(int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderPrepare(int64_t id, CAVRecorderConfig config);
    FFI_EXPORT char* FfiOHOSMediaAVRecorderGetInputSurface(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderStart(int64_t id);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderPause(int64_t id);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderResume(int64_t id);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderStop(int64_t id);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderReset(int64_t id);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderRelease(int64_t id);
    FFI_EXPORT CAVRecorderConfig FfiOHOSMediaAVRecorderGetAVRecorderConfig(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderGetAudioCapturerMaxAmplitude(int64_t id, int32_t *errCode);
    FFI_EXPORT void FfiOHOSMediaAVRecorderUpdateRotation(int64_t id, int32_t rotation, int32_t *errCode);

    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderOn(int64_t id, int32_t type, int64_t callback);
    FFI_EXPORT int32_t FfiOHOSMediaAVRecorderOff(int64_t id, int32_t type);
    FFI_EXPORT CAudioCapturerChangeInfo FfiOHOSMediaAVRecorderGetCurrentAudioCapturerInfo(int64_t id, int32_t *errCode);
    FFI_EXPORT CArrEncoderInfo FfiOHOSMediaAVRecorderGetEncoderInfo(int64_t id, int32_t *errCode);
    FFI_EXPORT char* FfiOHOSMediaAVRecorderGetState(int64_t id, int32_t *errCode);
}

#endif /* AV_RECORDER_FFI_H */
