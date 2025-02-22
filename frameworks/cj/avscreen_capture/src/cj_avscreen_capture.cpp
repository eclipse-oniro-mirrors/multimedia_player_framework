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

#include "cj_avscreen_capture.h"
#include "media_core.h"

namespace OHOS {
namespace Media {
    int64_t CJAVScreenCapture::CreateAVScreenCaptureRecorder(int32_t* errorcode)
    {
        CJAVScreenCapture *cjAVScreenCapture = FFIData::Create<CJAVScreenCapture>();
        if (cjAVScreenCapture == nullptr) {
            MEDIA_LOGE("No memory!");
        }

        cjAVScreenCapture->screenCapture_ = ScreenCaptureFactory::CreateScreenCapture();
        if (cjAVScreenCapture->screenCapture_ == nullptr) {
            FFIData::Release(cjAVScreenCapture->GetID());
            MEDIA_LOGE("failed to CreateAVScreenCaptureRecorder");
            return -1;
        }

        cjAVScreenCapture->screenCaptureCb_ = std::make_shared<CJAVScreenCaptureCallback>();
        (void)cjAVScreenCapture->screenCapture_->SetScreenCaptureCallback(cjAVScreenCapture->screenCaptureCb_);
        MEDIA_LOGI("Constructor success");
        return cjAVScreenCapture->GetID();
    }

    int32_t CJAVScreenCapture::AVScreenCaptureinit(std::shared_ptr<ScreenCapture> screenCapture,
        AVScreenCaptureConfig config)
    {
        int32_t ret = screenCapture->SetPrivacyAuthorityEnabled();
        if (ret != MSERR_OK) {
            ret = MSERR_EXT_API9_NO_PERMISSION;
            MEDIA_LOGE("failed to SetPrivacyAuthorityEnabled");
        }
        ret = screenCapture->Init(config);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("failed to StartRecording");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::StartRecording(std::shared_ptr<ScreenCapture> screenCapture)
    {
        int32_t ret = screenCapture->SetPrivacyAuthorityEnabled();
        if (ret != MSERR_OK) {
            ret = MSERR_EXT_API9_NO_PERMISSION;
            MEDIA_LOGE("failed to SetPrivacyAuthorityEnabled");
        }
        ret = screenCapture->StartScreenRecording();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("failed to StartRecording");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::StopRecording(std::shared_ptr<ScreenCapture> screenCapture)
    {
        int32_t ret = screenCapture->StopScreenRecording();
        if (ret!= MSERR_OK) {
            MEDIA_LOGE("failed to StopRecording");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::SkipPrivacyMode(std::shared_ptr<ScreenCapture> screenCapture,
        const std::vector<uint64_t> windowIDsVec)
    {
        int32_t ret = screenCapture->SkipPrivacyMode(const_cast<std::vector<uint64_t> &>(windowIDsVec));
        if (ret!= MSERR_OK) {
            MEDIA_LOGE("failed to SkipPrivacyMode");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::SetMicEnabled(std::shared_ptr<ScreenCapture> screenCapture, const bool enabled)
    {
        int32_t ret = screenCapture->SetMicrophoneEnabled(enabled);
        if (ret!= MSERR_OK) {
            MEDIA_LOGE("failed to SetMicEnabled");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::Release(std::shared_ptr<ScreenCapture> screenCapture)
    {
        int32_t ret = screenCapture->Release();
        if (ret!= MSERR_OK) {
            MEDIA_LOGE("failed to Release");
        }
        return ret;
    }

    int32_t CJAVScreenCapture::OnStateChange(int64_t callbackId)
    {
        if (screenCaptureCb_ == nullptr) {
            return MSERR_EXT_API9_NO_MEMORY;
        }

        auto cjCb = std::static_pointer_cast<CJAVScreenCaptureCallback>(screenCaptureCb_);
        cjCb->SaveCallbackReference(CJAVScreenCaptureEvent::EVENT_STATE_CHANGE, callbackId);
        return MSERR_EXT_API9_OK;
    }

    int32_t CJAVScreenCapture::OffStateChange()
    {
        if (screenCaptureCb_ == nullptr) {
            return MSERR_EXT_API9_NO_MEMORY;
        }
        auto cjCb = std::static_pointer_cast<CJAVScreenCaptureCallback>(screenCaptureCb_);
        cjCb->CancelCallbackReference(CJAVScreenCaptureEvent::EVENT_STATE_CHANGE);
        return MSERR_EXT_API9_OK;
    }

    int32_t CJAVScreenCapture::OnError(int64_t callbackId)
    {
        if (screenCaptureCb_ == nullptr) {
            return MSERR_EXT_API9_NO_MEMORY;
        }

        auto cjCb = std::static_pointer_cast<CJAVScreenCaptureCallback>(screenCaptureCb_);
        cjCb->SaveCallbackReference(CJAVScreenCaptureEvent::EVENT_ERROR, callbackId);
        return MSERR_EXT_API9_OK;
    }

    int32_t CJAVScreenCapture::OffError()
    {
        if (screenCaptureCb_ == nullptr) {
            return MSERR_EXT_API9_NO_MEMORY;
        }
        auto cjCb = std::static_pointer_cast<CJAVScreenCaptureCallback>(screenCaptureCb_);
        cjCb->CancelCallbackReference(CJAVScreenCaptureEvent::EVENT_ERROR);
        return MSERR_EXT_API9_OK;
    }

}
}