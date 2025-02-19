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
#include "avscreen_capture_ffi.h"
#include "cj_avscreen_capture.h"
#include "cj_avscreen_capture_callback.h"
#include <string>

namespace OHOS {
namespace Media {
using namespace OHOS::FFI;

extern "C" {
    int64_t FfiAVScreenCaptureCreateAVScreenCaptureRecorder(int32_t* errorcode)
    {
        return CJAVScreenCapture::CreateAVScreenCaptureRecorder(errorcode);
    }

    int32_t FfiAVScreenCaptureinit(int64_t id, AVScreenCaptureConfig config)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
            return -1;
        }
        return cjAVScreenCapture->AVScreenCaptureinit(screenCapture, config);
    }

    int32_t FfiAVScreenCaptureStartRecording(int64_t id)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
            return -1;
        }
        return cjAVScreenCapture->StartRecording(screenCapture);
    }

    int32_t FfiAVScreenCaptureStopRecording(int64_t id)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
        }
        return cjAVScreenCapture->StopRecording(screenCapture);
    }

    int32_t FfiAVScreenCaptureSkipPrivacyMode(int64_t id, CArrUnit windowIDsVec)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
        }
        std::vector<uint64_t> windowIDsVeclist;
        uint64_t *tagptr = static_cast<uint64_t *>(windowIDsVec.head);
        for (int64_t i = 0; i < windowIDsVec.size; i++) {
            windowIDsVeclist.push_back(tagptr[i]);
        }
        
        return cjAVScreenCapture->SkipPrivacyMode(screenCapture, windowIDsVeclist);
    }

    int32_t FfiAVScreenCaptureSetMicEnabled(int64_t id, bool enabled)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
        }
        return cjAVScreenCapture->SetMicEnabled(screenCapture, enabled);
    }

    int32_t FfiAVScreenCaptureRelease(int64_t id)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
        }
        std::shared_ptr<ScreenCapture> screenCapture = cjAVScreenCapture->screenCapture_;
        if (!screenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] screenCapture_ is nullptr!");
        }
        return cjAVScreenCapture->Release(screenCapture);
    }

    int32_t FfiAVScreenCaptureOnStateChange(int64_t id, int64_t callbackId)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return MSERR_EXT_API9_NO_MEMORY;
        }
        return cjAVScreenCapture->OnStateChange(callbackId);
    }

    int32_t FfiAVScreenCaptureOffStateChange(int64_t id)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return MSERR_EXT_API9_NO_MEMORY;
        }
        return cjAVScreenCapture->OffStateChange();
    }

    int32_t FfiAVScreenCaptureOnError(int64_t id, int64_t callbackId)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return MSERR_EXT_API9_NO_MEMORY;
        }
        return cjAVScreenCapture->OnError(callbackId);
    }

    int32_t FfiAVScreenCaptureOffError(int64_t id)
    {
        auto cjAVScreenCapture = FFIData::GetData<CJAVScreenCapture>(id);
        if (!cjAVScreenCapture) {
            MEDIA_LOGE("[CJAVScreenCapture] instance is nullptr!");
            return MSERR_EXT_API9_NO_MEMORY;
        }
        return cjAVScreenCapture->OffError();
    }
}
}
}