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

#include <sys/stat.h>
#include "media_log.h"
#include <native_avcapability.h>
#include <native_avcodec_videoencoder.h>
#include <native_averrors.h>
#include <native_avformat.h>
#include "codec/video/decoder/video_demuxer.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorDemuxer"};
}

VideoDeMuxer::VideoDeMuxer(uint64_t id, int fd) : fd_(fd)
{
    logTag_ = "video-demuxer-" + std::to_string(id);
}

VideoDeMuxer::~VideoDeMuxer()
{
    MEDIA_LOGI("[%{public}s] video deMuxer destruct begin.", logTag_.c_str());
    if (sourceFormat_) {
        OH_AVFormat_Destroy(sourceFormat_);
        sourceFormat_ = nullptr;
    }
    if (videoFormat_) {
        OH_AVFormat_Destroy(videoFormat_);
        videoFormat_ = nullptr;
    }
    if (audioFormat_) {
        OH_AVFormat_Destroy(audioFormat_);
        audioFormat_ = nullptr;
    }
    if (deMuxer_) {
        OH_AVDemuxer_Destroy(deMuxer_);
        deMuxer_ = nullptr;
    }
    if (source_) {
        OH_AVSource_Destroy(source_);
        source_ = nullptr;
    }
    MEDIA_LOGI("[%{public}s] video deMuxer destruct finish.", logTag_.c_str());
}

VEFError VideoDeMuxer::Init()
{
    MEDIA_LOGI("[%{public}s] init, source file fd: %{public}d.", logTag_.c_str(), fd_);
    struct stat st;
    if (fstat(fd_, &st) != 0) {
        MEDIA_LOGE("[%{public}s] init failed, fstat file failed with error: %{public}d.", logTag_.c_str(), errno);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] init, source file size: %{public}" PRIu64 ".", logTag_.c_str(), st.st_size);
    source_ = OH_AVSource_CreateWithFD(fd_, 0, st.st_size);
    if (source_ == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, OH_AVSource_CreateWithFD failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    deMuxer_ = OH_AVDemuxer_CreateWithSource(source_);
    if (deMuxer_ == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, OH_AVDemuxer_CreateWithSource failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    sourceFormat_ = OH_AVSource_GetSourceFormat(source_);
    if (sourceFormat_ == nullptr) {
        MEDIA_LOGE("[%{public}s] init failed, OH_AVSource_GetSourceFormat failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }

    VEFError error = ParseTrackInfo();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] init failed, parse track info with error: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    MEDIA_LOGI("[%{public}s] init success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoDeMuxer::ParseTrackInfo()
{
    int32_t trackCount = 0;
    if (!OH_AVFormat_GetIntValue(sourceFormat_, OH_MD_KEY_TRACK_COUNT, &trackCount)) {
        MEDIA_LOGE("[%{public}s] get [%{public}s] from source format failed.", logTag_.c_str(), OH_MD_KEY_TRACK_COUNT);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("[%{public}s] get track count = %{public}d.", logTag_.c_str(), trackCount);

    for (int32_t trackIndex = 0; trackIndex < trackCount; trackIndex++) {
        OH_AVFormat* trackFormat = OH_AVSource_GetTrackFormat(source_, trackIndex);
        if (trackFormat == nullptr) {
            MEDIA_LOGE("[%{public}s] get track format of track[%{public}d] failed.", logTag_.c_str(), trackIndex);
            continue;
        }
        int32_t trackType;
        if (!OH_AVFormat_GetIntValue(trackFormat, OH_MD_KEY_TRACK_TYPE, &trackType)) {
            MEDIA_LOGE("[%{public}s] get track type of track[%{public}d] failed.", logTag_.c_str(), trackIndex);
            continue;
        }
        if (trackType == OH_MediaType::MEDIA_TYPE_VID) {
            videoFormat_ = trackFormat;
            videoTrackId_ = trackIndex;
            MEDIA_LOGI("[%{public}s] get video track success, track id = %{public}d.", logTag_.c_str(), trackIndex);
        } else if (trackType == OH_MediaType::MEDIA_TYPE_AUD) {
            audioFormat_ = trackFormat;
            audioTrackId_ = trackIndex;
            MEDIA_LOGI("[%{public}s] get audio track success, track id = %{public}d.", logTag_.c_str(), trackIndex);
        }
    }

    if (videoTrackId_ == -1 || videoFormat_ == nullptr) {
        MEDIA_LOGE("[%{public}s] get video track failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }

    if (audioTrackId_ == -1 || audioFormat_ == nullptr) {
        audioTrackId_ = -1;
        audioFormat_ = nullptr;
        MEDIA_LOGW("[%{public}s] no invalid audio track.", logTag_.c_str());
    } else {
        auto ret = OH_AVDemuxer_SelectTrackByID(deMuxer_, audioTrackId_);
        if (ret != AV_ERR_OK) {
            MEDIA_LOGE("[%{public}s] select audio track failed with error: %{public}d.", logTag_.c_str(), ret);
            return VEFError::ERR_INTERNAL_ERROR;
        }
    }

    auto ret = OH_AVDemuxer_SelectTrackByID(deMuxer_, videoTrackId_);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] select video track failed with error: %{public}d.", logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

OH_AVFormat* VideoDeMuxer::GetVideoFormat() const
{
    return videoFormat_;
}

OH_AVFormat* VideoDeMuxer::GetAudioFormat() const
{
    return audioFormat_;
}

OH_AVFormat* VideoDeMuxer::GetSourceFormat() const
{
    return sourceFormat_;
}

VEFError VideoDeMuxer::ReadVideoData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    auto ret = OH_AVDemuxer_ReadSample(deMuxer_, videoTrackId_, data, attr);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] read video packet failed, OH_AVDemuxer_ReadSample return: %{public}d.",
            logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}

VEFError VideoDeMuxer::ReadAudioData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)
{
    auto ret = OH_AVDemuxer_ReadSample(deMuxer_, audioTrackId_, data, attr);
    if (ret != AV_ERR_OK) {
        MEDIA_LOGE("[%{public}s] read audio packet failed, OH_AVDemuxer_ReadSample return: %{public}d.",
            logTag_.c_str(), ret);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    return VEFError::ERR_OK;
}
} // namespace Media
} // namespace OHOS
