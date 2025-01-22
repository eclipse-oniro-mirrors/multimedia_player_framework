/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_AUDIO_HAPTIC_FFI_H
#define CJ_AUDIO_HAPTIC_FFI_H

#include "cj_lambda.h"

extern "C" {
FFI_EXPORT int64_t FfiOHOSAudioHapticGetManager();
FFI_EXPORT int32_t FfiOHOSAudioHapticMgrRegRes(int64_t id, const char* aUri, const char* hUri, int32_t* resId);
FFI_EXPORT int32_t FfiOHOSAudioHapticMgrUnregRes(int64_t id, int32_t resId);
FFI_EXPORT int32_t FfiOHOSAudioHapticMgrSetLatencyMode(int64_t id, int32_t resId, int32_t mode);
FFI_EXPORT int32_t FfiOHOSAudioHapticMgrSetStreamUsage(int64_t id, int32_t resId, int32_t usage);
FFI_EXPORT int64_t FfiOHOSAudioHapticMgrCreatePlayer(int64_t id, int32_t resId,
    bool muteA, bool muteH, int32_t* errCode);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerisMuted(int64_t id, int32_t type, bool* ret);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerStart(int64_t id);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerStop(int64_t id);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerRelease(int64_t id);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerOn(int64_t id, const char* type, int64_t callbackId);
FFI_EXPORT int32_t FfiOHOSAudioHapticPlayerOff(int64_t id, const char* type);
}

#endif // CJ_AUDIO_HAPTIC_FFI_H
