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
#include "composite_engine/impl/video_composite_engine.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoComposite"};
}

VideoCompositeEngine::VideoCompositeEngine(uint64_t id) : id_(id)
{
    logTag_ = "eng-id:" + std::to_string(id);
    MEDIA_LOGI("[%{public}s] construct.", logTag_.c_str());
}

VideoCompositeEngine::~VideoCompositeEngine()
{
    MEDIA_LOGI("[%{public}s] destruct.", logTag_.c_str());
}

uint64_t VideoCompositeEngine::GetId() const
{
    return id_;
}

VEFError VideoCompositeEngine::StartComposite(const std::shared_ptr<CompositionOptions>& options,
                                              const OnCompositeResultFunc& func)
{
    MEDIA_LOGI("[%{public}s] start composite.", logTag_.c_str());
    auto err = CheckCompositeOptions(options);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] check composite options failed, err: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    callback_ = options->callback_;
    targetFileFd_ = options->targetFileFd_;
    err = OrchestratePipelines();
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] orchestrate piplines failed, error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    err = StartComposite();
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start composite engine failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    MEDIA_LOGI("[%{public}s] start composite success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::StopComposite()
{
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::Init(const std::shared_ptr<IDataCenter>& dataCenter)
{
    MEDIA_LOGI("[%{public}s] init composite engine.", logTag_.c_str());
    if (dataCenter == nullptr) {
        MEDIA_LOGE("[%{public}s] data center is null.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    dataCenter_ = dataCenter;
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::OrchestratePipelines()
{
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::StartComposite()
{
    return VEFError::ERR_OK;
}

void VideoCompositeEngine::OnDecodeFrame(uint64_t pts)
{
    MEDIA_LOGD("[%{public}s] OnDecodeFrame[pts = %{public}" PRIu64 "].", logTag_.c_str(), pts);
}

void VideoCompositeEngine::OnDecodeResult(VideoDecodeResult result)
{
    MEDIA_LOGI("[%{public}s] OnDecodeResult[result = %{public}u].", logTag_.c_str(), result);
}

void VideoCompositeEngine::OnEncodeFrame(uint64_t pts)
{
    MEDIA_LOGD("[%{public}s] OnEncodeFrame[pts = %{public}" PRIu64 "].", logTag_.c_str(), pts);
}

void VideoCompositeEngine::OnEncodeResult(VideoEncodeResult result)
{
    MEDIA_LOGI("[%{public}s] OnEncodeResult[result = %{public}u].", logTag_.c_str(), result);
}

void VideoCompositeEngine::OnRenderFinish(uint64_t pts, GraphicsRenderResult result)
{
    MEDIA_LOGD("[%{public}s] OnRenderFinish, pts: %{public}" PRIu64 ", result = %{public}u.",
        logTag_.c_str(), pts, result);
}

VEFError VideoCompositeEngine::CheckCompositeOptions(const std::shared_ptr<CompositionOptions>& options)
{
    if (options == nullptr) {
        MEDIA_LOGE("options for composition is nullptr.");
        return VEFError::ERR_INVALID_PARAM;
    }
    if (options->callback_ == nullptr) {
        MEDIA_LOGE("callback for composition is nullptr.");
        return VEFError::ERR_INVALID_PARAM;
    }
    if (options->targetFileFd_ <= 0) {
        MEDIA_LOGE("target fd[%{public}d] for composition is invalid(<=0).", options->targetFileFd_);
        return VEFError::ERR_INVALID_PARAM;
    }
    return VEFError::ERR_OK;
}

} // namespace Media
} // namespace OHOS
