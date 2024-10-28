/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "codec/video/encoder/video_encoder.h"
#include <native_avcapability.h>
#include <native_avcodec_videoencoder.h>
#include <native_averrors.h>
#include <native_avformat.h>
#include <external_window.h>

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorEncode"};
}

VideoEncoder::VideoEncoder(uint64_t id, const OnNewOutputDataCallBack& cb) : onNewOutputDataCallBack_(cb)
{
    logTag_ = "video-encoder-" + std::to_string(id);
}

VideoEncoder::~VideoEncoder()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    encoderMutex_.lock();
    if (encoder_) {
        OH_VideoEncoder_Destroy(encoder_);
        encoder_ = nullptr;
    }
    encoderMutex_.unlock();
    if (nativeWindow_) {
        OH_NativeWindow_DestroyNativeWindow(nativeWindow_);
        nativeWindow_ = nullptr;
    }
    MEDIA_LOGD("[%{public}s] destruct finish.", logTag_.c_str());
}

void VideoEncoder::CodecOnError(OH_AVCodec* codec, int32_t errorCode, void* userData)
{
    if (codec == nullptr || userData == nullptr) {
        MEDIA_LOGE("CodecOnError invalid parameter, codec or userData or attr is nullptr.");
        return;
    }
    auto encoder = static_cast<VideoEncoder*>(userData);
    MEDIA_LOGE("[%{public}s] CodecOnError occurred error: %{public}d.", encoder->logTag_.c_str(), errorCode);
}

void VideoEncoder::CodecOnNewOutputData(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data,
    OH_AVCodecBufferAttr* attr, void* userData)
{
    if (codec == nullptr || data == nullptr || attr == nullptr || userData == nullptr) {
        MEDIA_LOGE("CodecOnNewOutputData invalid parameter.");
        return;
    }
    auto encoder = static_cast<VideoEncoder*>(userData);
    MEDIA_LOGD("[%{public}s] CodecOnNewOutputData index: %{public}d.", encoder->logTag_.c_str(), index);
    encoder->WriteFrame(data, attr);
    { // 此处codec其实就是VideoEncoder::encoder_对象，两个是同一个对象，加锁.
        std::lock_guard<ffrt::mutex> lk(encoder->encoderMutex_);
        OH_VideoEncoder_FreeOutputData(codec, index);
    }
}

void VideoEncoder::CodecOnStreamChanged(OH_AVCodec* codec, OH_AVFormat* format, void* userData)
{
    if (codec == nullptr || format == nullptr || userData == nullptr) {
        MEDIA_LOGE("CodecOnStreamChanged invalid parameter.");
        return;
    }
    auto encoder = static_cast<VideoEncoder*>(userData);
    MEDIA_LOGI("[%{public}s] CodecOnStreamChanged.", encoder->logTag_.c_str());
}

void VideoEncoder::CodecOnNeedInputData(OH_AVCodec*, uint32_t, OH_AVMemory*, void*) {}

VEFError VideoEncoder::WriteFrame(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    if (codecState_ == false) {
        MEDIA_LOGI("[%{public}s] encoder has been stopped, drop it pts=%{public}" PRIu64 ".",
            logTag_.c_str(), attr->pts);
        return VEFError::ERR_OK;
    }
    if (onNewOutputDataCallBack_) {
        onNewOutputDataCallBack_(data, attr);
    }
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::CreateEncoder(OH_AVFormat* format)
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    const char* mime = nullptr;
    if (!OH_AVFormat_GetStringValue(format, OH_MD_KEY_CODEC_MIME, &mime)) {
        MEDIA_LOGE("[%{public}s] get [%{public}s] from video format failed.", logTag_.c_str(), OH_MD_KEY_CODEC_MIME);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] create encoder, video mime = %{public}s.", logTag_.c_str(), mime);
    encoder_ = OH_VideoEncoder_CreateByMime(mime);
    if (encoder_ == nullptr) {
        MEDIA_LOGI("[%{public}s] create encoder failed, mime = %{public}s.", logTag_.c_str(), mime);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    OH_AVCodecAsyncCallback callback = { CodecOnError, CodecOnStreamChanged, CodecOnNeedInputData,
        CodecOnNewOutputData };
    auto ret = OH_VideoEncoder_SetCallback(encoder_, callback, this);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGI("[%{public}s] set callback failed, OH_VideoEncoder_SetCallback return: %{public}d.",
            logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    return VEFError::ERR_OK;
}

VEFError VideoEncoder::ConfigureEncoder(OH_AVFormat* format)
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] configure.", logTag_.c_str());
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] configure failed, parameter format is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }

    auto ret = OH_VideoEncoder_Configure(encoder_, format);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s]configure failed, OH_VideoEncoder_Configure return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    ret = OH_VideoEncoder_GetSurface(encoder_, &nativeWindow_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure failed, OH_VideoEncoder_GetSurface return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    int32_t width = 0;
    if (!OH_AVFormat_GetIntValue(format, OH_MD_KEY_WIDTH, &width)) {
        MEDIA_LOGE("[%{public}s] configure failed, OH_AVFormat_GetIntValue get [%{public}s].", logTag_.c_str(),
            OH_MD_KEY_WIDTH);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    int32_t height = 0;
    if (!OH_AVFormat_GetIntValue(format, OH_MD_KEY_HEIGHT, &height)) {
        MEDIA_LOGE("[%{public}s] configure failed, OH_AVFormat_GetIntValue get [%{public}s].", logTag_.c_str(),
            OH_MD_KEY_HEIGHT);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto retCode = OH_NativeWindow_NativeWindowHandleOpt(nativeWindow_, SET_BUFFER_GEOMETRY, width, height);
    if (retCode != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure failed, OH_NativeWindow_NativeWindowHandleOpt return: %{public}d.",
            logTag_.c_str(), retCode);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] configure success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::Start()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] start encoder.", logTag_.c_str());
    codecState_ = true;
    auto ret = OH_VideoEncoder_Prepare(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start encoder failed, OH_VideoEncoder_Prepare return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    ret = OH_VideoEncoder_Start(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s]start encoder failed, OH_VideoEncoder_Start return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] start encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::Stop()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] stop encoder.", logTag_.c_str());
    codecState_ = false;
    OH_AVErrCode ret = OH_VideoEncoder_Stop(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] stop encoder failed, OH_VideoEncoder_Stop return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] stop encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::SendEos()
{
    OH_AVErrCode ret = OH_VideoEncoder_NotifyEndOfStream(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] OH_VideoEncoder_NotifyEndOfStream return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGD("[%{public}s] notify eos encoder finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::Flush()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] finish, flush encoder.", logTag_.c_str());
    OH_AVErrCode ret = OH_VideoEncoder_Flush(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] OH_VideoEncoder_Flush return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGD("[%{public}s] notify eos encoder finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoder::Init(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] init encoder.", logTag_.c_str());
    std::string dumpInfo = OH_AVFormat_DumpInfo(format);
    MEDIA_LOGI("[%{public}s] initializing encoder, format: %{public}s.", logTag_.c_str(), dumpInfo.c_str());
    VEFError error = CreateEncoder(format);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init AVCodec-encoder failed with error: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    error = ConfigureEncoder(format);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure AVCodec-encoder failed with error: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] init encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

OHNativeWindow* VideoEncoder::GetOHNativeWindow() const
{
    return nativeWindow_;
}
} // namespace Media
} // namespace OHOS
