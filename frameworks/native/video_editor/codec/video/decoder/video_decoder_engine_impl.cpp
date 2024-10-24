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
#include "video_decoder_engine_impl.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorDecode"};
}

VideoDecoderEngineImpl::VideoDecoderEngineImpl(uint64_t id, int fd, std::weak_ptr<VideoDecodeCallback> cb)
    : id_(id), fd_(fd), cb_(cb)
{
    logTag_ = "video-decoder-engine-" + std::to_string(id);
    MEDIA_LOGI("[%{public}s] construct, file fd: %{public}d.", logTag_.c_str(), fd_);
}

VideoDecoderEngineImpl::~VideoDecoderEngineImpl()
{
    MEDIA_LOGI("[%{public}s] destruct, file fd: %{public}d.", logTag_.c_str(), fd_);
}

uint64_t VideoDecoderEngineImpl::GetId() const
{
    return id_;
}

VEFError VideoDecoderEngineImpl::Init()
{
    return VEFError::ERR_OK;
}

VEFError VideoDecoderEngineImpl::SetNativeWindow(OHNativeWindow* surfaceWindow)
{
    return VEFError::ERR_OK;
}

OH_AVFormat* VideoDecoderEngineImpl::GetVideoFormat()
{
    return nullptr;
}

VEFError VideoDecoderEngineImpl::StartDecode()
{
    return VEFError::ERR_OK;
}

int32_t VideoDecoderEngineImpl::GetColorRange()
{
    return 1;
}

VEFError VideoDecoderEngineImpl::StopDecode()
{
    return VEFError::ERR_OK;
}

void VideoDecoderEngineImpl::OnDecodeFrame(uint64_t pts)
{
    auto cbPtr = cb_.lock();
    if (cbPtr == nullptr) {
        MEDIA_LOGE("[%{public}s] OnDecodeFrame[pts= %{public}" PRIu64 "], but callback is expired.",
            logTag_.c_str(), pts);
        return;
    }
    cbPtr->OnDecodeFrame(pts);
}

void VideoDecoderEngineImpl::OnDecodeResult(VideoDecodeResult result)
{
    auto cbPtr = cb_.lock();
    if (cbPtr == nullptr) {
        MEDIA_LOGE("[%{public}s] finish decode, but cb is expired.", logTag_.c_str());
        return;
    }
    cbPtr->OnDecodeResult(result);
}

} // namespace Media
} // namespace OHOS
