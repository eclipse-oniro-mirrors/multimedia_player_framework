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
#include "codec/video/encoder/video_encoder_engine_impl.h"
#include "codec/common/codec_common.h"
#include <native_avcodec_audioencoder.h>
#include <native_avcodec_videoencoder.h>
#include <native_avcodec_videodecoder.h>
#include "render/graphics/graphics_render_engine.h"
#include "securec.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorEncode"};
}

VideoEncoderEngineImpl::VideoEncoderEngineImpl(uint64_t id, VideoEncodeCallback* cb)
    : id_(id), cb_(cb)
{
    logTag_ = "video-encoder-engine-" + std::to_string(id_);
}

VideoEncoderEngineImpl::~VideoEncoderEngineImpl()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
}

uint64_t VideoEncoderEngineImpl::GetId() const
{
    return id_;
}

VEFError VideoEncoderEngineImpl::InitVideoMuxer(const VideoMuxerParam& muxerParam)
{
    auto muxer = std::make_shared<VideoMuxer>(id_);
    VEFError error = muxer->Init(muxerParam);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init video muxer failed, error: %{public}d.", logTag_.c_str(), error);
        UnInit();
        return error;
    }
    muxer_ = muxer;
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::InitAudioStreamEncoder(OH_AVFormat* audioFormat)
{
    if (audioFormat == nullptr) {
        MEDIA_LOGW("[%{public}s] audio encoder disable.", logTag_.c_str());
        audioEncoderState_ = CodecState::FINISH_SUCCESS;
        OnEncodeResult(CodecResult::SUCCESS);
        return VEFError::ERR_OK;
    }

    std::function onDataOutput = [&](OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
        -> VEFError {
        return OnAudioEncodeOutput(codec, index, data, attr);
    };

    audioEncoder_ = std::make_shared<AudioEncoder>(id_, onDataOutput);
    auto error = muxer_->AddAudioTrack(audioFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] add audio track to muxer failed with error: %{public}d.", logTag_.c_str(), error);
        UnInit();
        return error;
    }
    OH_AVFormat* format = OH_AVFormat_Create();
    if (!format) {
        MEDIA_LOGE("[%{public}s] OH_AVFormat_Create failed.", logTag_.c_str());
        return VEFError::ERR_OOM;
    }

    OH_AVFormat_Copy(format, audioFormat);

    // 由于OHNative支持的采样格式有限，优先采样SAMPLE_S16LE，不同采样格式内部会实现转换
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, SAMPLE_S16LE);

    error = audioEncoder_->Init(format);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init audio encoder failed with error: %{public}d.", logTag_.c_str(), error);
        audioEncoder_ = nullptr;
        OH_AVFormat_Destroy(format);
        return error;
    }
    OH_AVFormat_Destroy(format);
    MEDIA_LOGI("[%{public}s] init audio success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::InitVideoStreamEncoder(OH_AVFormat* videoFormat)
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    if (videoFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, the parameter videoFormat is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    std::function onOutputData = [&](OH_AVMemory* data, OH_AVCodecBufferAttr* attr) {
        OnVideoNewOutputDataCallBack(data, attr);
    };

    encoder_ = std::make_shared<VideoEncoder>(id_, onOutputData);
    if (encoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create video encoder failed.", logTag_.c_str());
        UnInit();
        return VEFError::ERR_INTERNAL_ERROR;
    }
    VEFError error = encoder_->Init(videoFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init video encoder object failed with error: %{public}d.", logTag_.c_str(), error);
        UnInit();
        return error;
    }
    MEDIA_LOGI("[%{public}s] init video stream encoder object success.", logTag_.c_str());

    error = muxer_->AddVideoTrack(videoFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] add video track to muxer failed with error: %{public}d.", logTag_.c_str(), error);
        UnInit();
        return error;
    }

    MEDIA_LOGI("[%{public}s] init video stream encoder success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::Init(const VideoEncodeParam& encodeParam)
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    VEFError error = InitVideoMuxer(encodeParam.muxerParam);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init video file muxer failed, error: %{public}d.", logTag_.c_str(), error);
        return error;
    }

    error = InitVideoStreamEncoder(encodeParam.videoTrunkFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init video stream encoder failed, error: %{public}d.", logTag_.c_str(), error);
        return error;
    }

    return InitAudioStreamEncoder(encodeParam.audioTrunkFormat);
}

void VideoEncoderEngineImpl::UnInit()
{
    MEDIA_LOGI("[%{public}s] uninit.", logTag_.c_str());
    if (encoder_ != nullptr) {
        MEDIA_LOGI("[%{public}s] uninit encoder.", logTag_.c_str());
        encoder_ = nullptr;
    }
    if (audioEncoder_ != nullptr) {
        MEDIA_LOGI("[%{public}s] uninit audio encoder.", logTag_.c_str());
        audioEncoder_ = nullptr;
    }
    if (muxer_ != nullptr) {
        MEDIA_LOGI("[%{public}s] uninit muxer.", logTag_.c_str());
        muxer_ = nullptr;
    }
    MEDIA_LOGI("[%{public}s] uninit finish.", logTag_.c_str());
}

OHNativeWindow* VideoEncoderEngineImpl::GetVideoInputWindow()
{
    return encoder_->GetOHNativeWindow();
}

std::shared_ptr<PcmBufferQueue> VideoEncoderEngineImpl::GetAudioInputBufferQueue() const
{
    return audioEncoder_ == nullptr ? nullptr : audioEncoder_->GetPcmInputBufferQueue();
}

VEFError VideoEncoderEngineImpl::StartEncode()
{
    MEDIA_LOGI("[%{public}s] start encode.", logTag_.c_str());
    VEFError error = muxer_->Start();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start muxer failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    error = encoder_->Start();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start encoder failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    videoEncoderState_ = CodecState::RUNNING;
    if (audioEncoder_ == nullptr) {
        videoEncoderState_ = CodecState::FINISH_SUCCESS;
        MEDIA_LOGE("[%{public}s] startEncode audioEncoder_ is null.", logTag_.c_str());
    } else {
        VEFError error = audioEncoder_->Start();
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("[%{public}s] start audio encoder failed with error: %{public}d.", logTag_.c_str(), error);
            return error;
        }
        audioEncoderState_ = CodecState::RUNNING;
    }
    MEDIA_LOGI("[%{public}s] start encoder engine success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::StopEncode()
{
    MEDIA_LOGI("[%{public}s] stop encode.", logTag_.c_str());
    if (audioEncoder_ != nullptr) {
        VEFError error = audioEncoder_->Stop();
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("[%{public}s] stop audio encoder failed with error: %{public}d.", logTag_.c_str(), error);
            return error;
        }
        audioEncoderState_ = CodecState::CANCEL;
    }

    VEFError error = encoder_->Stop();
    if (error != VEFError::ERR_OK) {
        audioEncoderState_ = CodecState::FINISH_FAILED;
        MEDIA_LOGE("[%{public}s] stop encoder failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    videoEncoderState_ = CodecState::CANCEL;
    error = muxer_->Stop();
    if (error != VEFError::ERR_OK) {
        audioEncoderState_ = CodecState::FINISH_FAILED;
        MEDIA_LOGE("[%{public}s] stop muxer failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    MEDIA_LOGI("[%{public}s] stop encode finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

void VideoEncoderEngineImpl::OnEncodeResult(CodecResult result)
{
    if (videoEncoderState_ == CodecState::FINISH_SUCCESS && audioEncoderState_ == CodecState::FINISH_SUCCESS) {
        cb_->OnEncodeResult(result);
    }
}

void VideoEncoderEngineImpl::OnVideoNewOutputDataCallBack(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    if (data == nullptr || attr == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, data or attr is nullptr.", logTag_.c_str());
        return;
    }
    MEDIA_LOGD("[%{public}s] OnVideoNewOutputDataCallBack packet pts: %{public}" PRIu64 " flag: %{public}u",
        logTag_.c_str(), attr->pts, attr->flags);
    if (muxer_ == nullptr) {
        MEDIA_LOGE("[%{public}s] muxer_ is nullptr.", logTag_.c_str());
        return;
    }
    VEFError error = muxer_->WriteVideoData(data, attr);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] WriteVideoData with error: %{public}d.", logTag_.c_str(), error);
        return;
    }
    if (cb_ == nullptr) {
        audioEncoderState_ = CodecState::FINISH_FAILED;
        MEDIA_LOGE("[%{public}s] OnVideoNewOutputDataCallBack, but cb is expired.", logTag_.c_str());
        return;
    }
    cb_->OnEncodeFrame(attr->pts);
    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] encode video output eos.", logTag_.c_str());
        videoEncoderState_ = CodecState::FINISH_SUCCESS;
        OnEncodeResult(CodecResult::SUCCESS);
    }
}

VEFError VideoEncoderEngineImpl::SendEos()
{
    MEDIA_LOGD("[%{public}s] send eos to encoder.", logTag_.c_str());
    if (encoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] encoder_ is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    VEFError error = encoder_ ->SendEos();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGI("[%{public}s] send eos to video encoder failed, error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::Flush()
{
    MEDIA_LOGI("[%{public}s] finish encode.", logTag_.c_str());
    if (audioEncoder_ != nullptr) {
        VEFError error = audioEncoder_->Flush();
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("[%{public}s] finish audio encoder failed with error: %{public}d.", logTag_.c_str(), error);
            return error;
        }
    }
    if (encoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] encoder_ is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    VEFError error = encoder_->Flush();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] finish video encoder failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::OnAudioEncodeOutput(OH_AVCodec *codec, uint32_t index, OH_AVMemory* data,
    OH_AVCodecBufferAttr* attr)
{
    if (codec == nullptr || data == nullptr || attr == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, codec or data or attr is nullptr.", logTag_.c_str());
        audioEncoderState_ = CodecState::FINISH_FAILED;
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if (encoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] encoder_ is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    VEFError error = muxer_->WriteAudioData(data, attr);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] WriteAudioData with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    OH_AVErrCode err = OH_AudioEncoder_FreeOutputData(codec, index);
    if (err != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] OH_AudioEncoder_FreeOutputData with error: %{public}d.", logTag_.c_str(), err);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] audio encode output eos.", logTag_.c_str());
        audioEncoderState_ = CodecState::FINISH_SUCCESS;
        OnEncodeResult(CodecResult::SUCCESS);
    }
    return VEFError::ERR_OK;
}

} // namespace Media
} // namespace OHOS
