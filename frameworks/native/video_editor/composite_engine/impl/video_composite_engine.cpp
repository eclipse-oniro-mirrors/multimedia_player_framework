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
const int WAIT_TIMEOUT_DEC = 30000;

VideoCompositeEngine::VideoCompositeEngine(uint64_t id) : id_(id)
{
    logTag_ = "eng-id:" + std::to_string(id);
}

VideoCompositeEngine::~VideoCompositeEngine()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    if (taskMgr_ != nullptr) {
        taskMgr_->Wait();
    }
}

uint64_t VideoCompositeEngine::GetId() const
{
    return id_;
}

VEFError VideoCompositeEngine::StartComposite(const std::shared_ptr<CompositionOptions>& options)
{
    MEDIA_LOGI("[%{public}s] start composite.", logTag_.c_str());
    std::lock_guard<ffrt::mutex> lk(selfLock_);
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
    auto duration = decoderEngine_->GetVideoDuration();
    if (duration == -1) {
        MEDIA_LOGW("[%{public}s] get video duration failed .", logTag_.c_str());
    } else {
        duration_ = static_cast<uint64_t>(duration);
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
    MEDIA_LOGI("[%{public}s] stop composite.", logTag_.c_str());
    std::lock_guard<ffrt::mutex> lk(selfLock_);
    if (this->state_ == CompositeState::COMPOSITING) {
        decoderEngine_->StopDecode();
        graphicsRenderEngine_->StopRender();
        encoderEngine_->StopEncode();
        this->state_ = CompositeState::CANCLED; // confirm state
    }

    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::Init(const std::shared_ptr<IDataCenter>& dataCenter)
{
    MEDIA_LOGI("[%{public}s] init composite engine.", logTag_.c_str());
    std::lock_guard<ffrt::mutex> lk(selfLock_);
    taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::SEQUENTIAL);
    if (dataCenter == nullptr) {
        MEDIA_LOGE("[%{public}s] data center is null.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    dataCenter_ = dataCenter;
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::OrchestratePipelines()
{
    auto videoList = dataCenter_->GetAssetList();
    if (videoList.empty()) {
        MEDIA_LOGE("[%{public}s] can not find any video from data center.", logTag_.c_str());
        return VEFError::ERR_NOT_SET_INPUT_VIDEO;
    }
    std::shared_ptr<VideoAsset> mainAsset = std::static_pointer_cast<VideoAsset>(videoList[0]);
    std::vector<const std::shared_ptr<Effect>> effectList = mainAsset->GetEffectList();
    renderInfo_ = std::make_shared<GraphicsRenderInfo>();
    for (auto effect : effectList) {
        renderInfo_->effectInfoList_.emplace_back(effect->GetRenderInfo());
    }
    auto fd = mainAsset->GetFd();
    decoderEngine_ = IVideoDecoderEngine::Create(fd, this);
    if (decoderEngine_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create video decoder failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    VideoEncodeParam encodeParam;
    VEFError error = BuildEncoderParameter(encodeParam);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] build encoder parameter failed, error: %{public}d.", logTag_.c_str(), error);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    encoderEngine_ = IVideoEncoderEngine::Create(encodeParam, this);
    if (encoderEngine_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create encoder engine failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OHNativeWindow* nativeWindowEncoder = encoderEngine_->GetVideoInputWindow();
    if (nativeWindowEncoder == nullptr) {
        MEDIA_LOGE("[%{public}s] get native window from encoder engine failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    graphicsRenderEngine_ = IGraphicsRenderEngine::Create(nativeWindowEncoder);
    if (graphicsRenderEngine_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create graphics render engine failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    OHNativeWindow* inputWindowOfRender = graphicsRenderEngine_->GetInputWindow();
    if (inputWindowOfRender == nullptr) {
        MEDIA_LOGE("[%{public}s] get input window.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto inputPcmBufferQueue = encoderEngine_->GetAudioInputBufferQueue();
    decoderEngine_->SetVideoOutputWindow(inputWindowOfRender);
    decoderEngine_->SetAudioOutputBufferQueue(inputPcmBufferQueue);
    MEDIA_LOGI("[%{public}s] Orchestrate pipelines success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::StartComposite()
{
    MEDIA_LOGI("[%{public}s] start composite.", logTag_.c_str());
    VEFError error = encoderEngine_->StartEncode();
    if (error != VEFError::ERR_OK) {
        this->state_ = CompositeState::FAILED;
        MEDIA_LOGE("[%{public}s] start encode engine failed with error: %{public}d.", logTag_.c_str(), error);
        return error;
    }
    error = graphicsRenderEngine_->StartRender();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start render engine failed with error: %{public}d.", logTag_.c_str(), error);
        this->state_ = CompositeState::FAILED;
        return error;
    }
    error = decoderEngine_->StartDecode();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start decoder engine failed with error: %{public}d.", logTag_.c_str(), error);
        this->state_ = CompositeState::FAILED;
        return error;
    }
    this->state_ = CompositeState::COMPOSITING;
    MEDIA_LOGI("[%{public}s] start composite success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoCompositeEngine::BuildEncoderParameter(VideoEncodeParam& param)
{
    OH_AVFormat* videoFormat = decoderEngine_->GetVideoFormat();
    if (videoFormat == nullptr) {
        MEDIA_LOGE("[%{public}s] get video format from decode engine failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    param.videoTrunkFormat = videoFormat;
    param.audioTrunkFormat = decoderEngine_->GetAudioFormat();

    param.muxerParam.targetFileFd = targetFileFd_;
    param.muxerParam.avOutputFormat = AV_OUTPUT_FORMAT_MPEG_4;
    param.muxerParam.rotation = decoderEngine_->GetRotation();

    return VEFError::ERR_OK;
}

void VideoCompositeEngine::OnDecodeFrame(uint64_t pts)
{
    MEDIA_LOGD("[%{public}s] OnDecodeFrame[pts = %{public}" PRIu64 "].", logTag_.c_str(), pts);
    {
        std::unique_lock lk(renderingCntLock_);
        renderingCnt_++;
    }
    renderInfo_->rotation_ = decoderEngine_->GetRotation();
    taskMgr_->Submit([this, pts]() {
        RenderResultCallback onRenderFinishCb = [this, pts](GraphicsRenderResult result) {
            this->OnRenderFinish(pts, result);
        };
        graphicsRenderEngine_->Render(pts, renderInfo_, onRenderFinishCb);
    });
}

void VideoCompositeEngine::OnDecodeResult(CodecResult result)
{
    MEDIA_LOGI("[%{public}s] OnDecodeResult[result = %{public}u].", logTag_.c_str(), result);
    if (result != CodecResult::SUCCESS) {
        MEDIA_LOGE("[%{public}s] decode with error: %{public}u.", logTag_.c_str(), result);
        return;
    }
    {
        std::unique_lock lk(renderingCntLock_);
        if (renderingCnt_ > 0) {
            bool res = renderingCntCv_.wait_for(lk, std::chrono::milliseconds(WAIT_TIMEOUT_DEC),
                [this]() {
                return renderingCnt_ == 0;
            });
            if (!res) {
                MEDIA_LOGE("[%{public}s] OnDecodeResult time out.", logTag_.c_str());
            }
        }
    }

    taskMgr_->Submit([this]() {
        std::lock_guard<ffrt::mutex> lk(selfLock_);
        decoderEngine_->StopDecode();
        encoderEngine_->SendEos();
    });
}

void VideoCompositeEngine::OnEncodeFrame(uint64_t pts)
{
    MEDIA_LOGD("[%{public}s] OnEncodeFrame[pts = %{public}" PRIu64 "].", logTag_.c_str(), pts);
    std::lock_guard<ffrt::mutex> lk(selfLock_);
    if (this->state_ != CompositeState::COMPOSITING) {
        return;
    }
    auto callback = callback_;
    auto duration = duration_;
    ffrt::submit([callback, pts, duration]() {
        if (duration <= 0) {
            callback->onProgress(0);
        } else if (pts < 0) {
            callback->onProgress(0);
        } else if (pts > duration) {
            callback->onProgress(100); // 100表示完整进度
        } else if (duration != 0) {
            callback->onProgress(static_cast<int>((pts * 100) / duration)); // 100表示完整进度
        }
    });
}

void VideoCompositeEngine::OnEncodeResult(CodecResult result)
{
    MEDIA_LOGI("[%{public}s] OnEncodeResult[result = %{public}u].", logTag_.c_str(), result);
    VEFResult res = result == CodecResult::SUCCESS ? VEFResult::SUCCESS : VEFResult::FAILED;
    VEFError errCode = result == CodecResult::SUCCESS ? VEFError::ERR_OK : VEFError::ERR_INTERNAL_ERROR;
    std::lock_guard<ffrt::mutex> lk(selfLock_);
    this->state_ = CompositeState::FINISHING;
    taskMgr_->Submit([this, res, errCode]() {
        std::lock_guard<ffrt::mutex> lk(selfLock_);
        encoderEngine_->Flush();
        graphicsRenderEngine_->StopRender();
        encoderEngine_->StopEncode();
        auto callback = callback_;
        ffrt::submit([callback, res, errCode]() {
            callback->onResult(res, errCode);
        });
    this->state_ = (res == VEFResult::SUCCESS) ? CompositeState::FINISHED : CompositeState::FAILED;
    });
}

void VideoCompositeEngine::OnRenderFinish(uint64_t pts, GraphicsRenderResult result)
{
    MEDIA_LOGD("[%{public}s] OnRenderFinish, pts: %{public}" PRIu64 ", result = %{public}u.",
        logTag_.c_str(), pts, result);
    {
        std::unique_lock lk(renderingCntLock_);
        renderingCnt_--;
        renderingCntCv_.notify_all();
    }
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
