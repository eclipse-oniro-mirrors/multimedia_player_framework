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
#include <cstdint>
#include <native_avcodec_audiodecoder.h>
#include "media_log.h"
#include "video_decoder_engine_impl.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorDecode"};
}

VideoDecoderEngineImpl::VideoDecoderEngineImpl(uint64_t id, int fd, VideoDecodeCallback* cb)
    : id_(id), fd_(fd), cb_(cb)
{
    logTag_ = "video-decoder-engine-" + std::to_string(id);
}

VideoDecoderEngineImpl::~VideoDecoderEngineImpl()
{
    MEDIA_LOGD("[%{public}s] destruct, file fd: %{public}d.", logTag_.c_str(), fd_);
}

uint64_t VideoDecoderEngineImpl::GetId() const
{
    return id_;
}

VEFError VideoDecoderEngineImpl::Init()
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    VEFError error = InitDeMuxer();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init demuxer failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    error = InitDecoder();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init decoder failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    MEDIA_LOGI("[%{public}s] init success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::SetVideoOutputWindow(OHNativeWindow* surfaceWindow)
{
    return videoDecoder_->SetNativeWindow(surfaceWindow);
}

void VideoDecoderEngineImpl::SetAudioOutputBufferQueue(std::shared_ptr<PcmBufferQueue>& queue)
{
    if (audioDecoder_ != nullptr) {
        audioDecoder_->SetPcmOutputBufferQueue(queue);
    }
}

OH_AVFormat* VideoDecoderEngineImpl::GetVideoFormat()
{
    return deMuxer_->GetVideoFormat();
}

OH_AVFormat* VideoDecoderEngineImpl::GetAudioFormat()
{
    return deMuxer_->GetAudioFormat();
}

int32_t VideoDecoderEngineImpl::GetRotation() const
{
    int32_t rotation = 0;
    auto videoFormat = deMuxer_->GetVideoFormat();
    if (videoFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] get video format failed.", logTag_.c_str());
        return rotation;
    }
    if (OH_AVFormat_GetIntValue(videoFormat, OH_MD_KEY_ROTATION, &rotation)) {
        MEDIA_LOGD("[%{public}s] get rotation [%{public}d].", logTag_.c_str(), rotation);
    } else {
        MEDIA_LOGD("[%{public}s] not find rotation.", logTag_.c_str());
    }
    return rotation;
}

int64_t VideoDecoderEngineImpl::GetVideoDuration() const
{
    int64_t duration = -1;
    auto sourceFormat = deMuxer_->GetSourceFormat();
    if (sourceFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] get source format failed.", logTag_.c_str());
        return duration;
    }
    if (!OH_AVFormat_GetLongValue(sourceFormat, OH_MD_KEY_DURATION, &duration)) {
        MEDIA_LOGE("[%{public}s] get duration failed.", logTag_.c_str());
    }
    return duration;
}

VEFError VideoDecoderEngineImpl::StartDecode()
{
    if (audioDecoder_ == nullptr) {
        MEDIA_LOGI("[%{public}s] StartDecode audioDecoder_ is null.", logTag_.c_str());
    } else {
        audioDecoderState_ = CodecState::RUNNING;
        VEFError error = audioDecoder_->Start();
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("[%{public}s] audio decoder start failed, err: %{public}d.", logTag_.c_str(), error);
            audioDecoderState_ = CodecState::FINISH_FAILED;
            return error;
        }
    }
    videoDecoderState_ = CodecState::RUNNING;
    VEFError error = videoDecoder_->Start();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] video decoder start failed, err: %{public}d.", logTag_.c_str(), error);
        videoDecoderState_ = CodecState::FINISH_FAILED;
        return error;
    }
    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::StopDecode()
{
    if (audioDecoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] StopDecode audio Decoder_ is null.", logTag_.c_str());
    } else {
        VEFError error = audioDecoder_->Stop();
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("[%{public}s] audio decoder stop failed, err: %{public}d.", logTag_.c_str(), error);
            return error;
        }
    }
    return videoDecoder_->Stop();
}

VEFError VideoDecoderEngineImpl::InitDeMuxer()
{
    MEDIA_LOGI("[%{public}s] init deMuxer.", logTag_.c_str());
    deMuxer_ = std::make_shared<VideoDeMuxer>(id_, fd_);

    VEFError error = deMuxer_->Init();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init video deMuxer object failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }

    auto videoFormat = deMuxer_->GetVideoFormat();

    MEDIA_LOGI("[%{public}s] init deMuxer success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::InitDecoder()
{
    std::function packetReader = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return ReadVideoPacket(data, attr);
    };

    std::function onDecodeFrame = [&](uint64_t pts) -> void {
        OnVideoDecoderFrame(pts);
    };

    std::function onDecodeResult = [&](CodecResult result) -> void {
        OnVideoDecodeResult(result);
    };

    videoDecoder_ = std::make_shared<VideoDecoder>(id_, packetReader, onDecodeFrame, onDecodeResult);
    if (videoDecoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create decoder object failed.", logTag_.c_str());
        return VEFError::ERR_OOM;
    }
    auto videoFormat = deMuxer_->GetVideoFormat();
    if (videoFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] init decoder failed, get video format from deMuxer failed.", logTag_.c_str());
        videoDecoder_ = nullptr;
    }
    VEFError error = videoDecoder_->Init(videoFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init decoder failed with error: %{public}d.", logTag_.c_str(), error);
        videoDecoder_ = nullptr;
        return error;
    }
    return InitAudioDecoder();
}

VEFError VideoDecoderEngineImpl::InitAudioDecoder()
{
    auto audioFormat = deMuxer_->GetAudioFormat();
    if (audioFormat == nullptr) {
        OnAudioDecodeResult(CodecResult::SUCCESS);
        return VEFError::ERR_OK;
    }

    std::function packetReader = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return ReadAudioPacket(data, attr);
    };

    std::function onDecodeFrame = [&](uint64_t pts) -> void {
        OnAudioDecodeFrame(pts);
    };

    std::function onDecodeResult = [&](CodecResult result) -> void {
        OnAudioDecodeResult(result);
    };

    audioDecoder_ = std::make_shared<AudioDecoder>(id_, packetReader, onDecodeFrame, onDecodeResult);
    if (audioDecoder_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create audio decoder object failed.", logTag_.c_str());
        return VEFError::ERR_OOM;
    }

    OH_AVFormat* format = OH_AVFormat_Create();
    if (!format) {
        MEDIA_LOGE("[%{public}s] OH_AVFormat_Create failed.", logTag_.c_str());
        return VEFError::ERR_OOM;
    }

    OH_AVFormat_Copy(format, audioFormat);

    // 由于OHNative支持的采样格式有限，优先采样SAMPLE_S16LE，不同采样格式内部会实现转换
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, SAMPLE_S16LE);

    VEFError error = audioDecoder_->Init(format);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init audio decoder failed with error: %{public}d.", logTag_.c_str(), error);
        audioDecoder_ = nullptr;
        OH_AVFormat_Destroy(format);
        return error;
    }

    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::ReadVideoPacket(OH_AVMemory* packet, OH_AVCodecBufferAttr* attr)
{
    auto ret = deMuxer_->ReadVideoData(packet, attr);
    if (ret != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] video packets read failed, ret=%{public}d, flags=%{public}d.", logTag_.c_str(), ret,
            attr->flags);
        return ret;
    }
    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] decode video input eof, flags=%{public}d", logTag_.c_str(), attr->flags);
    }
    MEDIA_LOGD("[%{public}s] video packets read pts %{public}" PRIu64, logTag_.c_str(), attr->pts);
    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::ReadAudioPacket(OH_AVMemory* packet, OH_AVCodecBufferAttr* attr)
{
    auto ret = deMuxer_->ReadAudioData(packet, attr);
    if (ret != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] audio packets read failed, ret=%{public}d, flags=%{public}d.", logTag_.c_str(), ret,
            attr->flags);
        return ret;
    }
    if ((attr->flags & AVCODEC_BUFFER_FLAGS_EOS) == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] decode audio input eof, flags=%{public}d", logTag_.c_str(), attr->flags);
    }
    MEDIA_LOGD("[%{public}s] audio packets read pts %{public}" PRIu64, logTag_.c_str(), attr->pts);
    return VEFError::ERR_OK;
}

void VideoDecoderEngineImpl::OnAudioDecodeFrame(uint64_t)
{
}

void VideoDecoderEngineImpl::OnAudioDecodeResult(CodecResult result)
{
    MEDIA_LOGD("[%{public}s] audio trunk decode result %{public}d.", logTag_.c_str(), result);
    if (result == CodecResult::SUCCESS) {
        audioDecoderState_ = CodecState::FINISH_SUCCESS;
    } else if (result == CodecResult::FAILED) {
        audioDecoderState_ = CodecState::FINISH_FAILED;
    } else {
        audioDecoderState_ = CodecState::CANCEL;
    }
    NotifyDecodeResult();
}

void VideoDecoderEngineImpl::OnVideoDecoderFrame(uint64_t pts)
{
    if (cb_ == nullptr) {
        MEDIA_LOGE("[%{public}s] OnDecodeFrame[pts= %{public}" PRIu64 "], but callback is expired.",
            logTag_.c_str(), pts);
        return;
    }
    cb_->OnDecodeFrame(pts);
}

void VideoDecoderEngineImpl::OnVideoDecodeResult(CodecResult result)
{
    MEDIA_LOGD("[%{public}s] video trunk decode result %{public}d.", logTag_.c_str(), result);
    if (result == CodecResult::SUCCESS) {
        videoDecoderState_ = CodecState::FINISH_SUCCESS;
    } else if (result == CodecResult::FAILED) {
        videoDecoderState_ = CodecState::FINISH_FAILED;
    } else {
        videoDecoderState_ = CodecState::CANCEL;
    }
    NotifyDecodeResult();
}

void VideoDecoderEngineImpl::NotifyDecodeResult()
{
    if (audioDecoderState_ == CodecState::FINISH_SUCCESS && videoDecoderState_ == CodecState::FINISH_SUCCESS) {
        cb_->OnDecodeResult(CodecResult::SUCCESS);
    } else if (audioDecoderState_ == CodecState::FINISH_FAILED || videoDecoderState_ == CodecState::FINISH_FAILED) {
        cb_->OnDecodeResult(CodecResult::FAILED);
    } else if (audioDecoderState_ == CodecState::CANCEL || videoDecoderState_ == CodecState::CANCEL) {
        cb_->OnDecodeResult(CodecResult::CANCELED);
    } else {
        MEDIA_LOGD("[%{public}s] codec result id not finish, v= %{public}d, a=  %{public}d.",
            logTag_.c_str(), videoDecoderState_, audioDecoderState_);
    }
}

} // namespace Media
} // namespace OHOS
