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

#include "cj_audio_haptic_ffi.h"

#include "cj_audio_haptic_manager.h"
#include "cj_audio_haptic_player.h"

namespace OHOS {
namespace Media {

extern "C" {
int64_t FfiOHOSAudioHapticGetManager()
{
    auto instance = FFI::FFIData::Create<CjAudioHapticManager>();
    return instance == nullptr ? INVALID_OBJ : instance->GetID();
}

int32_t FfiOHOSAudioHapticMgrRegRes(int64_t id, const char* aUri, const char* hUri, int32_t* resId)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticManager>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->RegisterSource(aUri, hUri, *resId);
}

int32_t FfiOHOSAudioHapticMgrUnregRes(int64_t id, int32_t resId)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticManager>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->UnregisterSource(resId);
}

int32_t FfiOHOSAudioHapticMgrSetLatencyMode(int64_t id, int32_t resId, int32_t mode)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticManager>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->SetAudioLatencyMode(resId, mode);
}

int32_t FfiOHOSAudioHapticMgrSetStreamUsage(int64_t id, int32_t resId, int32_t usage)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticManager>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->SetStreamUsage(resId, usage);
}

int64_t FfiOHOSAudioHapticMgrCreatePlayer(int64_t id, int32_t resId, bool muteA, bool muteH, int32_t* errCode)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticManager>(id);
    if (!instance) {
        return INVALID_OBJ;
    }
    return instance->CreatePlayer(resId, muteA, muteH, *errCode);
}

int32_t FfiOHOSAudioHapticPlayerisMuted(int64_t id, int32_t type, bool* ret)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->IsMuted(type, *ret);
}

int32_t FfiOHOSAudioHapticPlayerStart(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->Start();
}

int32_t FfiOHOSAudioHapticPlayerStop(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->Stop();
}

int32_t FfiOHOSAudioHapticPlayerRelease(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->Release();
}

int32_t FfiOHOSAudioHapticPlayerOn(int64_t id, const char* type, int64_t callbackId)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->On(type, callbackId);
}

int32_t FfiOHOSAudioHapticPlayerOff(int64_t id, const char* type)
{
    auto instance = FFI::FFIData::GetData<CjAudioHapticPlayer>(id);
    if (!instance) {
        return INVALID_ID;
    }
    return instance->Off(type);
}
}
} // OHOS
} // Media