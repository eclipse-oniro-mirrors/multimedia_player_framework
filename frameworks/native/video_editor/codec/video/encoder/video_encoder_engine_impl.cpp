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
#include "native_avsource.h"
#include "codec/video/encoder/video_encoder_engine_impl.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorEncode"};
}

VideoEncoderEngineImpl::VideoEncoderEngineImpl(uint64_t id, int fd, std::weak_ptr<VideoEncodeCallback> cb)
    : id_(id), fd_(fd), cb_(cb)
{
    logTag_ = "video-encoder-engine-" + std::to_string(id_);
    MEDIA_LOGI("[%{public}s] construct, file fd: %{public}d.", logTag_.c_str(), fd_);
}

VideoEncoderEngineImpl::~VideoEncoderEngineImpl()
{
    MEDIA_LOGI("[%{public}s] destruct, file fd: %{public}d.", logTag_.c_str(), fd_);
}

uint64_t VideoEncoderEngineImpl::GetId() const
{
    return id_;
}

VEFError VideoEncoderEngineImpl::Init(OH_AVFormat* videoFormat)
{
    MEDIA_LOGI("[%{public}s] init.", logTag_.c_str());
    MEDIA_LOGI("[%{public}s] init finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

OHNativeWindow* VideoEncoderEngineImpl::GetEncoderNativeWindow()
{
    return nullptr;
}

VEFError VideoEncoderEngineImpl::StartEncode()
{
    MEDIA_LOGI("[%{public}s] start encode.", logTag_.c_str());
    MEDIA_LOGI("[%{public}s] start encode finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEncoderEngineImpl::StopEncode()
{
    MEDIA_LOGI("[%{public}s] stop encode.", logTag_.c_str());
    MEDIA_LOGI("[%{public}s] stop encode finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

void VideoEncoderEngineImpl::FinishEncode()
{
    MEDIA_LOGI("[%{public}s] finish encode.", logTag_.c_str());
    auto cbPtr = cb_.lock();
    if (cbPtr == nullptr) {
        MEDIA_LOGE("[%{public}s] finish encode, but cb is expired.", logTag_.c_str());
        return;
    }
    cbPtr->OnEncodeResult(VideoEncodeResult::SUCCESS);
}

} // namespace Media
} // namespace OHOS
