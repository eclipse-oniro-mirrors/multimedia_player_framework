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

#include "avrecorder_ffi.h"
#include "cj_avrecorder.h"
#include "cj_avrecorder_callback.h"
#include "media_log.h"
#include "media_core.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderFfi"};
}

namespace OHOS {
namespace Media {
using namespace OHOS::FFI;

extern "C" {
int64_t FfiOHOSMediaAVRecorderCreateAVRecorder(int32_t *errCode)
{
    return CjAVRecorder::CreateAVRecorder(errCode);
}

int32_t FfiOHOSMediaAVRecorderPrepare(int64_t id, CAVRecorderConfig config)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI Prepare - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Prepare(config);
}

char* FfiOHOSMediaAVRecorderGetInputSurface(int64_t id, int32_t *errCode)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI GetInputSurface - cjAVRecorder is nullptr!");
        return nullptr;
    }
    return cjAVRecorder->GetInputSurface(errCode);
}

int32_t FfiOHOSMediaAVRecorderStart(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI start - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Start();
}

int32_t FfiOHOSMediaAVRecorderPause(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI pause - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Pause();
}

int32_t FfiOHOSMediaAVRecorderResume(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI Resume - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Resume();
}

int32_t FfiOHOSMediaAVRecorderStop(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI Stop - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Stop();
}

int32_t FfiOHOSMediaAVRecorderReset(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI Reset - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Reset();
}

int32_t FfiOHOSMediaAVRecorderRelease(int64_t id)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI Release - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->Release();
}

CAVRecorderConfig FfiOHOSMediaAVRecorderGetAVRecorderConfig(int64_t id, int32_t *errCode)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI GetAVRecorderConfig - cjAVRecorder is nullptr!");
        *errCode = -1;
        CAVRecorderConfig retConfig = {};
        return retConfig;
    }
    return cjAVRecorder->GetAVRecorderConfig(errCode);
}

int32_t FfiOHOSMediaAVRecorderGetAudioCapturerMaxAmplitude(int64_t id, int32_t *errCode)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI GetAudioCapturerMaxAmplitude - cjAVRecorder is nullptr!");
        return -1;
    }
    return cjAVRecorder->GetAudioCapturerMaxAmplitude(errCode);
}

void FfiOHOSMediaAVRecorderUpdateRotation(int64_t id, int32_t rotation, int32_t *errCode)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FFI UpdateRotation - cjAVRecorder is nullptr!");
        return;
    }
    cjAVRecorder->UpdateRotation(rotation, errCode);
}

int32_t FfiOHOSMediaAVRecorderOn(int64_t id, int32_t type, int64_t callback)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOn - cjAVRecorder is nullptr!");
        return -1;
    }

    if (!cjAVRecorder->recorderCb_) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOn - recorderCb_ is nullptr!");
        return -1;
    }

    auto Cb_ = std::static_pointer_cast<CJAVRecorderCallback>(cjAVRecorder->recorderCb_);
    if (!Cb_) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOn - Cb_ is nullptr!");
        return -1;
    }
    Cb_->Register(type, callback);
    return 0;
}

int32_t FfiOHOSMediaAVRecorderOff(int64_t id, int32_t type)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOff - cjAVRecorder is nullptr!");
        return -1;
    }

    if (!cjAVRecorder->recorderCb_) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOff - recorderCb_ is nullptr!");
        return -1;
    }

    auto Cb_ = std::static_pointer_cast<CJAVRecorderCallback>(cjAVRecorder->recorderCb_);
    if (!Cb_) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderOff - Cb_ is nullptr!");
        return -1;
    }
    Cb_->UnRegister(type);
    return 0;
}

CAudioCapturerChangeInfo FfiOHOSMediaAVRecorderGetCurrentAudioCapturerInfo(int64_t id, int32_t *errCode)
{
    CAudioCapturerChangeInfo cInfo {};
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderGetCurrentAudioCapturerInfo - cjAVRecorder is nullptr!");
        if (!errCode) {
            *errCode = -1;
        }
        return cInfo;
    }

    AudioRecorderChangeInfo changeInfo {};
    auto ret = cjAVRecorder->GetCurrentAudioCapturerInfo(changeInfo);
    if (ret != MSERR_EXT_API9_OK) {
        if (!errCode) {
            *errCode = static_cast<int32_t>(ret);
        }
        return cInfo;
    }
    ConvertToCAudioCapturerChangeInfo(cInfo, changeInfo);
    if (!errCode) {
        *errCode = 0;
    }
    return cInfo;
}

CArrEncoderInfo FfiOHOSMediaAVRecorderGetEncoderInfo(int64_t id, int32_t *errCode)
{
    CArrEncoderInfo cInfo {};
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderGetEncoderInfo - cjAVRecorder is nullptr!");
        if (!errCode) {
            *errCode = -1;
        }
        return cInfo;
    }
    std::vector<OHOS::Media::EncoderCapabilityData> encoderInfo {};
    auto ret = cjAVRecorder->GetAvailableEncoder(encoderInfo);
    if (ret != MSERR_EXT_API9_OK) {
        if (!errCode) {
            *errCode = static_cast<int32_t>(ret);
        }
        return cInfo;
    }
    ConvertToCArrEncoderInfo(cInfo, encoderInfo);
    if (!errCode) {
        *errCode = 0;
    }
    return cInfo;
}

char* FfiOHOSMediaAVRecorderGetState(int64_t id, int32_t *errCode)
{
    auto cjAVRecorder = FFIData::GetData<CjAVRecorder>(id);
    if (!cjAVRecorder) {
        MEDIA_LOGE("FfiOHOSMediaAVRecorderGetState - cjAVRecorder is nullptr!");
        if (!errCode) {
            *errCode = -1;
        }
        return nullptr;
    }
    std::string state = "";
    auto ret = cjAVRecorder->GetState(state);
    if (ret != MSERR_EXT_API9_OK) {
        if (!errCode) {
            *errCode = static_cast<int32_t>(ret);
        }
        return nullptr;
    }
    if (!errCode) {
        *errCode = 0;
    }
    return MallocCString(state);
}
}
}
}