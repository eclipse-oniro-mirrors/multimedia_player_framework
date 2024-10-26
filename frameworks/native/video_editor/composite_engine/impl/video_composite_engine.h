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

#ifndef OH_VEF_VIDEO_COMPOSITE_ENGINE_H
#define OH_VEF_VIDEO_COMPOSITE_ENGINE_H

#include "util/task/task_manager.h"
#include "codec/common/codec_common.h"
#include "data_center/asset/video_asset.h"
#include "composite_engine/composite_engine.h"
#include "codec/video_decoder_engine.h"
#include "codec/video_encoder_engine.h"
#include "render/graphics/graphics_render_engine.h"

namespace OHOS {
namespace Media {

class VideoCompositeEngine : public ICompositeEngine, VideoDecodeCallback, VideoEncodeCallback {
public:
    explicit VideoCompositeEngine(uint64_t id);
    virtual ~VideoCompositeEngine();

    uint64_t GetId() const override;
    VEFError StartComposite(const std::shared_ptr<CompositionOptions>& options) override;
    VEFError StopComposite() override;

    void OnDecodeFrame(uint64_t pts) override;
    void OnDecodeResult(CodecResult result) override;

    void OnEncodeFrame(uint64_t pts) override;
    void OnEncodeResult(CodecResult result) override;

    void OnRenderFinish(uint64_t pts, GraphicsRenderResult result);

    VEFError Init(const std::shared_ptr<IDataCenter>& dataCenter);

private:
    VEFError StartComposite();
    VEFError CheckCompositeOptions(const std::shared_ptr<CompositionOptions>& options);
    VEFError OrchestratePipelines();
    VEFError BuildEncoderParameter(VideoEncodeParam& param);

private:
    uint64_t id_{ 0 };
    std::string logTag_;
    int targetFileFd_ = -1;
    std::shared_ptr<CompositionCallback> callback_{ nullptr };
    std::shared_ptr<IDataCenter> dataCenter_{ nullptr };
    std::shared_ptr<TaskManager> taskMgr_{ nullptr };
    std::shared_ptr<IVideoDecoderEngine> decoderEngine_{ nullptr };
    std::shared_ptr<IVideoEncoderEngine> encoderEngine_{ nullptr };
    std::shared_ptr<IGraphicsRenderEngine> graphicsRenderEngine_{ nullptr };
    std::shared_ptr<GraphicsRenderInfo> renderInfo_{ nullptr };
    uint64_t duration_{ UINT64_MAX };
    std::mutex renderingCntLock_;
    std::condition_variable renderingCntCv_;
    uint64_t renderingCnt_ = 0;
    ffrt::mutex selfLock_;
    enum class CompositeState : uint32_t { INIT = 0, COMPOSITING, FINISHING, FINISHED, CANCELING, CANCLED, FAILED };
    CompositeState state_{ CompositeState::INIT };
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_COMPOSITE_ENGINE_H
