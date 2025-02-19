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

    int32_t FfiAVScreenCaptureinit(int64_t id, CAVScreenCaptureConfig config)
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
        AVScreenCaptureConfig fconfig;
        fconfig.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
        fconfig.dataType = static_cast<DataType>(config.dataType);
        //audioInfo
        fconfig.audioInfo.micCapInfo.audioSampleRate = config.audioInfo.micCapInfo.audioSampleRate;
        fconfig.audioInfo.innerCapInfo.audioSampleRate = config.audioInfo.innerCapInfo.audioSampleRate;
        fconfig.audioInfo.micCapInfo.audioChannels = config.audioInfo.micCapInfo.audioChannels;
        fconfig.audioInfo.innerCapInfo.audioChannels = config.audioInfo.innerCapInfo.audioChannels;
        fconfig.audioInfo.micCapInfo.audioSource = 
            static_cast<AudioCaptureSourceType>(config.audioInfo.micCapInfo.audioSource);
        fconfig.audioInfo.innerCapInfo.audioSource = 
            static_cast<AudioCaptureSourceType>(config.audioInfo.innerCapInfo.audioSource);
        fconfig.audioInfo.audioEncInfo.audioBitrate = config.audioInfo.audioEncInfo.audioBitrate;
        fconfig.audioInfo.audioEncInfo.audioCodecformat = 
            static_cast<AudioCodecFormat>(config.audioInfo.audioEncInfo.audioCodecformat);

        int32_t displayId = 0;
        fconfig.videoInfo.videoCapInfo.displayId = static_cast<uint64_t>(displayId);
        fconfig.videoInfo.videoCapInfo.videoFrameHeight = config.videoInfo.videoCapInfo.videoFrameHeight;
        fconfig.videoInfo.videoCapInfo.videoFrameWidth = config.videoInfo.videoCapInfo.videoFrameWidth;
        fconfig.videoInfo.videoCapInfo.videoSource = 
            static_cast<VideoSourceType>(config.videoInfo.videoCapInfo.videoSource);

        fconfig.videoInfo.videoEncInfo.videoCodec = 
            static_cast<VideoCodecFormat>(config.videoInfo.videoEncInfo.videoCodec);
        fconfig.videoInfo.videoEncInfo.videoBitrate = config.videoInfo.videoEncInfo.videoBitrate;
        int32_t frame_rate = 60;
        fconfig.videoInfo.videoEncInfo.videoFrameRate = frame_rate;

        std::string file_format = "mp4";
        fconfig.recorderInfo.fileFormat = file_format;
        fconfig.recorderInfo.url = config.recorderInfo.url;
        
        return cjAVScreenCapture->AVScreenCaptureinit(screenCapture, fconfig);
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