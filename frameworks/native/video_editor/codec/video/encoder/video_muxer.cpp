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
#include <native_avcapability.h>
#include <native_avcodec_videoencoder.h>
#include <native_averrors.h>
#include <native_avformat.h>
#include "codec/video/encoder/video_muxer.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorMuxer"};
}

VideoMuxer::VideoMuxer(uint64_t id)
{
    logTag_ = "video-muxer-" + std::to_string(id);
}

VideoMuxer::~VideoMuxer()
{
    MEDIA_LOGD("[%{public}s] video muxer destruct begin.", logTag_.c_str());
    if (muxer_) {
        OH_AVMuxer_Destroy(muxer_);
        muxer_ = nullptr;
    }
    MEDIA_LOGD("[%{public}s] video muxer destruct finish.", logTag_.c_str());
}

VEFError VideoMuxer::Start()
{
    MEDIA_LOGI("[%{public}s] start muxer.", logTag_.c_str());
    OH_AVErrCode error = OH_AVMuxer_Start(muxer_);
    if (error != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] start muxer failed, OH_AVMuxer_Start return: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] start muxer success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::Stop()
{
    MEDIA_LOGI("[%{public}s] stop muxer.", logTag_.c_str());
    OH_AVErrCode error = OH_AVMuxer_Stop(muxer_);
    if (error != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] stop muxer failed, OH_AVMuxer_Stop return: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] stop muxer success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::Init(const VideoMuxerParam& muxerParam)
{
    MEDIA_LOGD("[%{public}s] init video muxer, format = %{public}d, rotation = %{public}d.", logTag_.c_str(),
        muxerParam.avOutputFormat, muxerParam.rotation);
    muxer_ = OH_AVMuxer_Create(muxerParam.targetFileFd, muxerParam.avOutputFormat);
    if (muxer_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create muxer by OH_AVMuxer_Create failed, fd = %{public}d, format = %{public}d.",
            logTag_.c_str(), muxerParam.targetFileFd, muxerParam.avOutputFormat);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    OH_AVErrCode error = OH_AVMuxer_SetRotation(muxer_, muxerParam.rotation);
    if (error != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] set rotation to %{public}d failed, err = %{public}d.",
            logTag_.c_str(), muxerParam.rotation, error);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    MEDIA_LOGI("[%{public}s] init video muxer success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::AddVideoTrack(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] add video track.", logTag_.c_str());
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] add video track failed, parameter format is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OH_AVErrCode error = OH_AVMuxer_AddTrack(muxer_, &videoTrackId_, format);
    if (error != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] add video track failed, OH_AVMuxer_AddTrack return: %{public}d.", logTag_.c_str(),
            error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::AddAudioTrack(OH_AVFormat* format)
{
    MEDIA_LOGI("[%{public}s] add audio track.", logTag_.c_str());
    if (format == nullptr) {
        MEDIA_LOGE("[%{public}s] add audio track failed, parameter format is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OH_AVErrCode error = OH_AVMuxer_AddTrack(muxer_, &audioTrackId_, format);
    if (error != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] add audio track failed, OH_AVMuxer_AddTrack return: %{public}d.", logTag_.c_str(),
            error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::WriteVideoData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    MEDIA_LOGD("[%{public}s] OH_AVMuxer_WriteSample video flags=%{public}u, pts=%{public}" PRIu64 ","
        "size:%{public}d.", logTag_.c_str(), attr->flags, attr->pts, attr->size);
    std::lock_guard<ffrt::mutex> lk(writeFrameMutex_);
    auto ret = OH_AVMuxer_WriteSample(muxer_, videoTrackId_, data, *attr);
    if (attr->flags == AVCODEC_BUFFER_FLAGS_EOS) {
        MEDIA_LOGI("[%{public}s] write video finish(EOS).", logTag_.c_str());
        return VEFError::ERR_OK;
    }
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] OH_AVMuxer_WriteSample video failed, pts=%{public}" PRIu64 ".",
            logTag_.c_str(), attr->pts);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError VideoMuxer::WriteAudioData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    if (data == nullptr || attr == nullptr) {
        MEDIA_LOGE("[%{public}s] invalid parameter, data or attr is nullptr.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGD("[%{public}s] OH_AVMuxer_WriteSample audio flags=%{public}u, pts=%{public}" PRIu64
        ", size:%{public}d.", logTag_.c_str(), attr->flags, attr->pts, attr->size);
    std::lock_guard<ffrt::mutex> lk(writeFrameMutex_);
    auto ret = OH_AVMuxer_WriteSample(muxer_, audioTrackId_, data, *attr);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] OH_AVMuxer_WriteSample audio failed, pts=%{public}" PRIu64 ".",
            logTag_.c_str(), attr->pts);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}
} // namespace Media
} // namespace OHOS
