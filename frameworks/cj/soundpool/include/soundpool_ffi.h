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

#ifndef SOUNDPOOL_FFI_H
#define SOUNDPOOL_FFI_H

#include "cj_common_ffi.h"
#include "cj_soundpool.h"
#include "ffi_remote_data.h"

namespace OHOS {
namespace Media {

const int32_t ERR_INVALID_INSTANCE_CODE = -1;

extern "C"

{
    FFI_EXPORT int64_t FfiSoundPoolCreateSoundPool(int32_t maxStreams, AudioStandard::CAudioRendererInfo info,
        int32_t *errorcode);
    FFI_EXPORT int32_t FfiSoundPoolLoadURI(int64_t id, char *uri, int32_t *errorcode);
    FFI_EXPORT int32_t FfiSoundPoolLoad(int64_t id, int32_t fd, int64_t offset, int64_t length, int32_t *errorcode);
    FFI_EXPORT int32_t FfiSoundPoolPlayParam(int64_t id, int32_t soundID, CPlayParameters params, int32_t *errorcode);
    FFI_EXPORT int32_t FfiSoundPoolPlay(int64_t id, int32_t soundID, int32_t *errorcode);
    FFI_EXPORT int32_t FfiSoundPoolStop(int64_t id, int32_t streamID);
    FFI_EXPORT int32_t FfiSoundPoolSetLoop(int64_t id, int32_t streamID, int32_t loop);
    FFI_EXPORT int32_t FfiSoundPoolSetPriority(int64_t id, int32_t streamID, int32_t priority);
    FFI_EXPORT int32_t FfiSoundPoolSetRate(int64_t id, int32_t streamID, int32_t rate);
    FFI_EXPORT int32_t FfiSoundPoolSetVolume(int64_t id, int32_t streamID, float leftVolume, float rightVolume);
    FFI_EXPORT int32_t FfiSoundPoolUnload(int64_t id, int32_t soundID);
    FFI_EXPORT int32_t FfiSoundPoolRelease(int64_t id);
    FFI_EXPORT void FfiSoundPoolOnLoadCompleted(int64_t id, int64_t callbackId);
    FFI_EXPORT void FfiSoundPoolOnPlayFinished(int64_t id, int64_t callbackId);
    FFI_EXPORT void FfiSoundPoolOnError(int64_t id, int64_t callbackId);
    FFI_EXPORT void FfiSoundPoolOff(int64_t id, int8_t type);
}

} // namespace Media
} // namespace OHOS

#endif // SOUNDPOOL_FFI_H