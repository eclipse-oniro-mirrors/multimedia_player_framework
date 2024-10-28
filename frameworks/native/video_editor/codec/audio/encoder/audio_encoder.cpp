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

#include <native_avcodec_audioencoder.h>
#include "media_log.h"
#include "codec/util/codec_util.h"
#include "audio_encoder.h"
#include <string>
#include "securec.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "AEnc"};
}

AudioEncoder::AudioEncoder(uint64_t id, const CodecOnOutData& encodecCallback)
    : CodecEncoder(id, "audio-encoder"), encodeCallback_(encodecCallback)
{
    pcmInputBufferQueue_ = std::make_shared<PcmBufferQueue>(8); //队列长度为8
}

AudioEncoder::~AudioEncoder()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    encoderMutex_.lock();
    if (encoder_) {
        OH_AudioEncoder_Destroy(encoder_);
        encoder_ = nullptr;
    }
    encoderMutex_.unlock();
    MEDIA_LOGD("[%{public}s] destruct finish.", logTag_.c_str());
}

void AudioEncoder::CodecOnErrorInner(OH_AVCodec* codec, int32_t errorCode)
{
    if (codec == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, codec is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGE("[%{public}s] CodecOnError occurred error: %{public}d.", logTag_.c_str(), errorCode);
}

void AudioEncoder::CodecOnNewOutputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data,
    OH_AVCodecBufferAttr* attr)
{
    if (codec == nullptr || data == nullptr || attr == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, codec or data or attr is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGD("[%{public}s] CodecOnNewOutputData index: %{public}d.", logTag_.c_str(), index);
    encodeCallback_(codec, index, data, attr);
}

void AudioEncoder::CodecOnStreamChangedInner(OH_AVFormat* format)
{
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, format is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGI("[%{public}s] CodecOnStreamChanged", logTag_.c_str());
}

void AudioEncoder::CodecOnNeedInputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data)
{
    if (codec == nullptr || data == nullptr) {
        MEDIA_LOGE("[%{public}s] CodecOnNeedInputDataInner, invalid parameter.", logTag_.c_str());
        return;
    }
    
    auto pcmData = pcmInputBufferQueue_->Dequeue();
    if (pcmData == nullptr) {
        MEDIA_LOGE("[%{public}s] CodecOnNeedInputDataInner, pcmData is nullptr.", logTag_.c_str());
        return;
    }

    OH_AVCodecBufferAttr attr {.pts = pcmData->pts, .size = pcmData->dataSize, .offset = 0, .flags = pcmData->flags};
    if ((attr.flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] audio encode input eof.", logTag_.c_str());
    } else {
        if (attr.size <= 0) {
            // callback error;
            MEDIA_LOGE("[%{public}s] attr size abnormal, len=%{public}d.", logTag_.c_str(), attr.size);
        } else if (attr.size > OH_AVMemory_GetSize(data)) {
            // callback error;
            MEDIA_LOGE("[%{public}s] attr size bigger than current get size, len=%{public}d.",
                logTag_.c_str(), OH_AVMemory_GetSize(data));
        } else {
            if (EOK != memcpy_s(OH_AVMemory_GetAddr(data),
                                OH_AVMemory_GetSize(data),
                                pcmData->data.get(),
                                attr.size)) {
                MEDIA_LOGE("[%{public}s] memcpy failed, len=%{public}d.", logTag_.c_str(), attr.size);
                // callback error;
            }
        }
    }

    VEFError error = PushPcmData(index, attr);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] push pcm data failed with error: %{public}d.", logTag_.c_str(), error);
    }
}

VEFError AudioEncoder::PushPcmData(uint32_t index, OH_AVCodecBufferAttr& attr)
{
    auto errCode = OH_AudioEncoder_PushInputData(encoder_, index, attr);
    if (errCode != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] push pcm index %{public}u pts %{public}" PRIu64 " size %{public}d"
            "flags %{public}u ret %{public}s", logTag_.c_str(), index, attr.pts, attr.size, attr.flags,
            CodecUtil::GetCodecErrorStr(errCode));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError AudioEncoder::CreateEncoder()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);

    MEDIA_LOGI("[%{public}s] create encoder, audio mime = %{public}s.", logTag_.c_str(), codecMime_.c_str());
    encoder_ = OH_AudioEncoder_CreateByMime(codecMime_.c_str());
    if (encoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create audio encoder failed, mime = %{public}s!", logTag_.c_str(), codecMime_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }

    auto ret = OH_AudioEncoder_SetCallback(encoder_, GetAVCodecAsyncCallback(), (CodecEncoder*)this);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] set callback failed, OH_AudioEncoder_SetCallback return: %{public}d.",
            logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    return VEFError::ERR_OK;
}

VEFError AudioEncoder::ConfigureEncoder(OH_AVFormat* format)
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] configure.", logTag_.c_str());

    auto ret = OH_AudioEncoder_Configure(encoder_, format);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure failed, OH_AudioEncoder_Configure return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    MEDIA_LOGI("[%{public}s] configure success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioEncoder::Start()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] start encoder.", logTag_.c_str());

    auto ret = OH_AudioEncoder_Prepare(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start encoder failed, OH_AudioEncoder_Prepare return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    ret = OH_AudioEncoder_Start(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start encoder failed, OH_AudioEncoder_Start return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] start encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioEncoder::Stop()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] stop encoder.", logTag_.c_str());

    pcmInputBufferQueue_->CancelDequeue();

    OH_AVErrCode ret = OH_AudioEncoder_Stop(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] stop encoder failed, OH_AudioEncoder_Stop return: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] stop encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioEncoder::Flush()
{
    std::lock_guard<ffrt::mutex> lk(encoderMutex_);
    MEDIA_LOGI("[%{public}s] flush encoder.", logTag_.c_str());
    OH_AVErrCode ret = OH_AudioEncoder_Flush(encoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] flush encoder failed, OH_AudioEncoder_Flush return: %{public}d.", logTag_.c_str(),
            ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] flush encoder finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioEncoder::Init(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] init encoder.", logTag_.c_str());
    std::string dumpInfo = OH_AVFormat_DumpInfo(format);
    MEDIA_LOGI("[%{public}s] initializing encoder, format: %{public}s.", logTag_.c_str(), dumpInfo.c_str());

    const char* mime = nullptr;
    if (!OH_AVFormat_GetStringValue(format, OH_MD_KEY_CODEC_MIME, &mime)) {
        MEDIA_LOGE("[%{public}s] get [%{public}s] from audio format failed.", logTag_.c_str(), OH_MD_KEY_CODEC_MIME);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    codecMime_ = mime;
    VEFError error = CreateEncoder();
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

std::shared_ptr<PcmBufferQueue> AudioEncoder::GetPcmInputBufferQueue() const
{
    return pcmInputBufferQueue_;
}
} // namespace Media
} // namespace OHOS
