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
#include "codec/util/codec_util.h"
#include "codec/video/decoder/video_decoder.h"
#include <native_avcodec_videodecoder.h>
#include "codec/video/decoder/video_demuxer.h"
#include <regex>

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorDecode"};
}

VideoDecoder::VideoDecoder(uint64_t id, const CodecOnInData& cb,
    const CodecOnDecodeFrame& onDecodeFrameCallback, const CodecOnDecodeResult& onDecodeResultCallback)
    : packetReadFunc_(cb), onDecodeFrameCallback_(onDecodeFrameCallback),
    onDecodeResultCallback_(onDecodeResultCallback)
{
    logTag_ = "video-decoder-" + std::to_string(id);
}

VideoDecoder::~VideoDecoder()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    if (decoder_ != nullptr) {
        OH_VideoDecoder_Destroy(decoder_);
        decoder_ = nullptr;
    }
}

VEFError VideoDecoder::Init(OH_AVFormat* videoFormat)
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    if (videoFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, parameter videoFormat is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    std::string dumpInfo = OH_AVFormat_DumpInfo(videoFormat);
    MEDIA_LOGI("[%{public}s] initializing decoder, format: %{public}s.", logTag_.c_str(), dumpInfo.c_str());
    const char* mime = nullptr;
    if (!OH_AVFormat_GetStringValue(videoFormat, OH_MD_KEY_CODEC_MIME, &mime)) {
        MEDIA_LOGE("[%{public}s] get [%{public}s] from video format failed.", logTag_.c_str(), OH_MD_KEY_CODEC_MIME);
        return VEFError::ERR_INTERNAL_ERROR;
    }
	std::regex re("codec_profile = (\\d+)");
	std::smatch match;
	if (std::regex_search(dumpInfo, match, re)) {
		std::string bitType = match[1].str();
		if (bitType == "1") {
			MEDIA_LOGE("[%{public}s] 10bit mode is 1, don't match.", logTag_.c_str());
			return VEFError::ERR_INTERNAL_ERROR;
		}
	}

    codecMime_ = mime;
    MEDIA_LOGI("[%{public}s] initializing decoder, video mime = %{public}s.", logTag_.c_str(), mime);
    VEFError err = CreateDecoder();
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init failed, create decoder failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }

    err = ConfigureDecoder(videoFormat);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init failed, configure decoder failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    MEDIA_LOGI("[%{public}s] init success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDecoder::SetNativeWindow(OHNativeWindow* surfaceWindow)
{
    if (surfaceWindow == nullptr) {
        MEDIA_LOGE("[%{public}s] set native window failed, window is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OH_AVErrCode err = OH_VideoDecoder_SetSurface(decoder_, surfaceWindow);
    if (err != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] set decoder surface failed with error, ret %{public}d %{public}s.", logTag_.c_str(),
            err, CodecUtil::GetCodecErrorStr(err));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError VideoDecoder::Start()
{
    MEDIA_LOGI("[%{public}s] start.", logTag_.c_str());
    auto ret = OH_VideoDecoder_Prepare(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start failed, OH_VideoDecoder_Prepare return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    ret = OH_VideoDecoder_Start(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start failed, OH_VideoDecoder_Start return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    state_ = CodecState::RUNNING;
    MEDIA_LOGI("[%{public}s] start success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDecoder::Stop()
{
    MEDIA_LOGI("[%{public}s] stop.", logTag_.c_str());
    auto ret = OH_VideoDecoder_Stop(decoder_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] stop failed, OH_VideoDecoder_Stop return %{public}d(%{public}s).", logTag_.c_str(),
            ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    state_ = CodecState::CANCEL;
    MEDIA_LOGI("[%{public}s] stop success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDecoder::CreateDecoder()
{
    decoder_ = OH_VideoDecoder_CreateByMime(codecMime_.c_str());
    if (decoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create decoder failed, OH_VideoDecoder_CreateByMime failed, mime = %{public}s!",
            logTag_.c_str(), codecMime_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto CodecOnError = [](OH_AVCodec*, int32_t errorCode, void* context) {
        auto error = static_cast<OH_AVErrCode>(errorCode);
        VideoDecoder* decoder = static_cast<VideoDecoder*>(context);
        if (decoder == nullptr) {
            std::string subTag = "video-decoder";
            MEDIA_LOGE("[%{public}s] CodecOnError, context is nullptr, error: %{public}d(%{public}s)", subTag.c_str(),
                error, CodecUtil::GetCodecErrorStr(error));
        } else {
            MEDIA_LOGI("[%{public}s] CodecOnError %{public}d(%{public}s)", decoder->logTag_.c_str(), error,
                CodecUtil::GetCodecErrorStr(error));
        }
    };
    auto CodecOnStreamChanged = [](OH_AVCodec*, OH_AVFormat* format, void* context) {
        VideoDecoder* decoder = static_cast<VideoDecoder*>(context);
        if (decoder) {
            decoder->CodecOnStreamChangedInner(format);
        }
    };
    auto CodecOnNeedInputData = [](OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, void* context) {
        VideoDecoder* decoder = static_cast<VideoDecoder*>(context);
        if (decoder) {
            decoder->CodecOnNeedInputDataInner(codec, index, data);
        }
    };
    auto CodecOnNewOutputData = [](OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr,
        void* context) {
        VideoDecoder* decoder = static_cast<VideoDecoder*>(context);
        if (decoder) {
            decoder->CodecOnNewOutputData(codec, index, data, attr);
        }
    };
    // 设置回调
    OH_AVCodecAsyncCallback callback = { CodecOnError, CodecOnStreamChanged, CodecOnNeedInputData,
        CodecOnNewOutputData };
    auto ret = OH_VideoDecoder_SetCallback(decoder_, callback, this);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] set callback for decoder error, OH_VideoDecoder_SetCallback return"
            " %{public}d(%{public}s)", logTag_.c_str(), ret, CodecUtil::GetCodecErrorStr(ret));
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

void VideoDecoder::CodecOnStreamChangedInner(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] OnStreamChanged %{public}s", logTag_.c_str(), OH_AVFormat_DumpInfo(format));
}

void VideoDecoder::CodecOnNeedInputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data)
{
    MEDIA_LOGD("[%{public}s] CodecOnNeedInputDataInner index %{public}u", logTag_.c_str(), index);

    OH_AVCodecBufferAttr attr;
    VEFError error = packetReadFunc_(codec, data, &attr);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] read packet failed with error: %{public}d.", logTag_.c_str(), error);
        return;
    }
    auto errCode = OH_VideoDecoder_PushInputData(decoder_, index, attr);
    if (errCode != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] push inputData index %{public}u pts %{public}" PRIu64 " size %{public}d "
            "flags %{public}u ret %{public}s", logTag_.c_str(), index, attr.pts, attr.size, attr.flags,
            CodecUtil::GetCodecErrorStr(errCode));
        return;
    }
}

void VideoDecoder::CodecOnNewOutputData(OH_AVCodec* codec, uint32_t index, OH_AVMemory*,
    OH_AVCodecBufferAttr* attr)
{
    bool eosFlag = (attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS;
    if (eosFlag) {
        onDecodeResultCallback_(CodecResult::SUCCESS);
        return;
    }
    auto ret = OH_VideoDecoder_RenderOutputData(codec, index);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGW("[%{public}s] RenderToSurface failed, index %{public}u pts=%{public}" PRIu64 " ret: "
            "%{public}d %{public}s!", logTag_.c_str(), index, attr->pts, ret,
            CodecUtil::GetCodecErrorStr(ret));
        return;
    }
    onDecodeFrameCallback_(attr->pts);
    MEDIA_LOGD("[%{public}s] OnNewOutputData index %{public}u, pts %{public}" PRIu64 ", flags %{public}u",
        logTag_.c_str(), index, attr->pts, attr->flags);
}

VEFError VideoDecoder::ConfigureDecoder(OH_AVFormat* videoFormat)
{
    OH_AVFormat* format = OH_AVFormat_Create();
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] configure decoder, OH_AVFormat_Create failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if (!OH_AVFormat_Copy(format, videoFormat)) {
        MEDIA_LOGE("[%{public}s] configure decoder failed, OH_AVFormat_Copy failed.", logTag_.c_str());
        OH_AVFormat_Destroy(format);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    // 必选参数：像素格式
    if (!OH_AVFormat_SetIntValue(format, OH_MD_KEY_PIXEL_FORMAT, AV_PIXEL_FORMAT_SURFACE_FORMAT)) {
        MEDIA_LOGE("[%{public}s] configure decoder failed, OH_AVFormat_Set [%{public}s] to [%{public}d] failed.",
            logTag_.c_str(), OH_MD_KEY_PIXEL_FORMAT, AV_PIXEL_FORMAT_SURFACE_FORMAT);
        OH_AVFormat_Destroy(format);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OH_AVErrCode err = OH_VideoDecoder_Configure(decoder_, format);
    if (err != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] configure decoder failed, OH_VideoDecoder_Configure return: %{public}d(%{public}s).",
            logTag_.c_str(), err, CodecUtil::GetCodecErrorStr(err));
        OH_AVFormat_Destroy(format);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OH_AVFormat_Destroy(format);
    return VEFError::ERR_OK;
}
} // namespace Media
} // namespace OHOS
