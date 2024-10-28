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

#include <native_avcodec_audiodecoder.h>
#include "audio_decoder.h"
#include "media_log.h"
#include "codec/util/codec_util.h"
#include <string>
#include "securec.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "ADec"};
}

AudioDecoder::AudioDecoder(uint64_t id, const CodecOnInData& packetReadFunc,
    const CodecOnDecodeFrame& onDecodeFrameCallback, const CodecOnDecodeResult& onDecodeResultCallback)
    : CodecDecoder(id, "audio-decoder"), packetReadFunc_(packetReadFunc), onDecodeFrameCallback_(onDecodeFrameCallback),
    onDecodeResultCallback_(onDecodeResultCallback)
{
}

AudioDecoder::~AudioDecoder()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    if (decoder_) {
        OH_AudioDecoder_Destroy(decoder_);
    }
}

VEFError AudioDecoder::Init(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, parameter format is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if (!packetReadFunc_ || !onDecodeFrameCallback_ || !onDecodeResultCallback_) {
        MEDIA_LOGE("[%{public}s] init failed, invalid callback.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    std::string dumpInfo = OH_AVFormat_DumpInfo(format);
    MEDIA_LOGI("[%{public}s] initializing decoder, format: %{public}s.", logTag_.c_str(), dumpInfo.c_str());

    const char* mime = nullptr;
    if (!OH_AVFormat_GetStringValue(format, OH_MD_KEY_CODEC_MIME, &mime)) {
        MEDIA_LOGE("[%{public}s] get [%{public}s] from format failed.", logTag_.c_str(), OH_MD_KEY_CODEC_MIME);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    codecMime_ = mime;
    MEDIA_LOGI("[%{public}s] initializing decoder, mime = %{public}s.", logTag_.c_str(), mime);

    VEFError err = CreateDecoder();
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init failed, create decoder failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }

    err = ConfigureDecoder(format);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init failed, configure decoder failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    MEDIA_LOGI("[%{public}s] init success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

void AudioDecoder::SetPcmOutputBufferQueue(std::shared_ptr<PcmBufferQueue>& queue)
{
    pcmInputBufferQueue_ = queue;
}

VEFError AudioDecoder::Start()
{
    MEDIA_LOGI("[%{public}s] start.", logTag_.c_str());
    auto ret = OH_AudioDecoder_Prepare(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start failed, OH_AudioDecoder_Prepare return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    ret = OH_AudioDecoder_Start(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start failed, OH_AudioDecoder_Start return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    state_ = CodecState::RUNNING;
    MEDIA_LOGI("[%{public}s] start success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioDecoder::Stop()
{
    MEDIA_LOGI("[%{public}s] stop.", logTag_.c_str());
    pcmInputBufferQueue_->CancelEnqueue();
    auto ret = OH_AudioDecoder_Stop(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] stop failed, OH_AudioDecoder_Stop return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    state_ = CodecState::CANCEL;
    MEDIA_LOGI("[%{public}s] stop success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError AudioDecoder::CreateDecoder()
{
    decoder_ = OH_AudioDecoder_CreateByMime(codecMime_.c_str());
    if (decoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create decoder failed, OH_AudioDecoder_CreateByMime failed, mime = %{public}s!",
            logTag_.c_str(), codecMime_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }

    auto ret = OH_AudioDecoder_SetCallback(decoder_, GetAVCodecAsyncCallback(), (CodecDecoder*)this);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] set callback for decoder error, return %{public}d(%{public}s).", logTag_.c_str(), ret,
            CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError AudioDecoder::ConfigureDecoder(OH_AVFormat* format)
{
    OH_AVErrCode err = OH_AudioDecoder_Configure(decoder_, format);
    if (err != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure decoder failed, OH_AudioDecoder_Configure return: %{public}d(%{public}s).",
            logTag_.c_str(), err, CodecUtil::GetCodecErrorStr(err));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

void AudioDecoder::CodecOnErrorInner(OH_AVCodec* codec, int32_t errorCode)
{
    if (codec == nullptr) {
        MEDIA_LOGE("[%{public}s] CodecOnErrorInner invalid parameter, codec is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGI("[%{public}s] CodecOnError: %{public}d(%{public}s).", logTag_.c_str(), errorCode,
        CodecUtil::GetCodecErrorStr((OH_AVErrCode)errorCode));
    onDecodeResultCallback_(CodecResult::FAILED);
}

void AudioDecoder::CodecOnStreamChangedInner(OH_AVFormat *format)
{
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, format is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGI("[%{public}s] CodecOnStreamChanged %{public}s.", logTag_.c_str(), OH_AVFormat_DumpInfo(format));
}

void AudioDecoder::CodecOnNeedInputDataInner(OH_AVCodec *codec, uint32_t index, OH_AVMemory* data)
{
    if (codec == nullptr || data == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, codec or data is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGD("[%{public}s] CodecOnNeedInputDataInner index %{public}u.", logTag_.c_str(), index);

    OH_AVCodecBufferAttr attr;
    VEFError error = packetReadFunc_(codec, data, &attr);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] read packet failed with error: %{public}d.", logTag_.c_str(), error);
        return;
    }
    auto errCode = OH_AudioDecoder_PushInputData(decoder_, index, attr);
    if (errCode != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] push inputData index %{public}u pts %{public}" PRIu64 " size %{public}d"
            "flags %{public}u ret %{public}s", logTag_.c_str(), index, attr.pts, attr.size, attr.flags,
            CodecUtil::GetCodecErrorStr(errCode));
        onDecodeResultCallback_(CodecResult::FAILED);
        return;
    }
}

void AudioDecoder::CodecOnNewOutputDataInner(OH_AVCodec *codec, uint32_t index, OH_AVMemory* data,
    OH_AVCodecBufferAttr* attr)
{
    if (codec == nullptr || data == nullptr || attr == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, codec or data or attr is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGD("[%{public}s] CodecOnNewOutputDataInner index %{public}u.", logTag_.c_str(), index);
    
    std::shared_ptr<PcmData> pcmData = std::make_shared<PcmData>();
    pcmData->flags = attr->flags;
    pcmData->pts = attr->pts;
    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        pcmData->dataSize = 0;
        pcmData->data = nullptr;
    } else {
        pcmData->dataSize = attr->size;
        pcmData->data = std::make_shared<uint8_t>(pcmData->dataSize);
        OH_AudioDecoder_FreeOutputData(codec, index);
        onDecodeResultCallback_(CodecResult::FAILED);

        uint8_t* rawData = OH_AVMemory_GetAddr(data) + attr->offset;
        int32_t error = memcpy_s(pcmData->data.get(), pcmData->dataSize, rawData + attr->offset, attr->size);
        if (error != EOK) {
            MEDIA_LOGE("[%{public}s] copy data failed, err = %{public}d.", logTag_.c_str(), error);
            OH_AudioDecoder_FreeOutputData(codec, index);
            onDecodeResultCallback_(CodecResult::FAILED);
            return;
        }
    }

    OH_AudioDecoder_FreeOutputData(codec, index);
    pcmInputBufferQueue_->Enqueue(pcmData);

    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] audio decode output EOS.", logTag_.c_str());
        onDecodeResultCallback_(CodecResult::SUCCESS);
    } else {
        onDecodeFrameCallback_(attr->pts);
    }
}
} // namespace Media
} // namespace OHOS