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

#include "gtest/gtest.h"
#include "render/graphics/render_engine/graphics_render_engine_impl.h"
#include "render/graphics/graphics_render_engine.h"
#include "data_center/effect/effect_factory.h"
#include "ut_common_data.h"
#include <fcntl.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class GraphicsRenderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test GraphicsRenderEngineImplTest Init method
HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_Init, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    EXPECT_EQ(graphicsRenderEngineImpl.Init(nullptr), VEFError::ERR_INVALID_PARAM);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_Init_ok, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    graphicsRenderEngineImpl.ready_ = true;
    EXPECT_EQ(graphicsRenderEngineImpl.Init(nullptr), VEFError::ERR_OK);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_Destroy_ok, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    graphicsRenderEngineImpl.ready_ = true;
    graphicsRenderEngineImpl.renderThread_ = nullptr;
    graphicsRenderEngineImpl.Destroy();
    EXPECT_EQ(graphicsRenderEngineImpl.ready_, false);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_StopRender, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    EXPECT_EQ(graphicsRenderEngineImpl.StopRender(), VEFError::ERR_OK);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_GetInputWindow_nullptr, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    graphicsRenderEngineImpl.surfaceTexture_ = nullptr;
    EXPECT_EQ(graphicsRenderEngineImpl.GetInputWindow(), nullptr);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_GetInputWindow, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, cb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* nativeWindowEncoder = encoderEngine->GetVideoInputWindow();
    ASSERT_NE(nativeWindowEncoder, nullptr);
    auto graphicsRenderEngine = IGraphicsRenderEngine::Create(nativeWindowEncoder);
    ASSERT_NE(graphicsRenderEngine, nullptr);
    OHNativeWindow* inputWindowRender = graphicsRenderEngine->GetInputWindow();
    ASSERT_NE(inputWindowRender, nullptr);
    (void)close(srcFd);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_StartRender, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, cb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* nativeWindowEncoder = encoderEngine->GetVideoInputWindow();
    ASSERT_NE(nativeWindowEncoder, nullptr);
    auto graphicsRenderEngine = IGraphicsRenderEngine::Create(nativeWindowEncoder);
    ASSERT_NE(graphicsRenderEngine, nullptr);
    EXPECT_EQ(graphicsRenderEngine->StartRender(), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_Render, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, cb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* nativeWindowEncoder = encoderEngine->GetVideoInputWindow();
    ASSERT_NE(nativeWindowEncoder, nullptr);
    auto graphicsRenderEngine = IGraphicsRenderEngine::Create(nativeWindowEncoder);
    ASSERT_NE(graphicsRenderEngine, nullptr);
    auto renderInfo = std::make_shared<GraphicsRenderInfo>();
    renderInfo->rotation_ = decoderEngine->GetRotation();
    uint64_t pts = 99;
    RenderResultCallback onRenderFinishCb = [pts](GraphicsRenderResult result) {
        std::cout << "pts=" << pts << "; result=" << static_cast<int>(result) << std::endl;
    };
    EXPECT_EQ(graphicsRenderEngine->Render(99, renderInfo, onRenderFinishCb), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_Render_error, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    graphicsRenderEngineImpl.ready_ = false;
    uint64_t pts = 99;
    RenderResultCallback onRenderFinishCb = [pts](GraphicsRenderResult result) {
        std::cout << "pts=" << pts << "; result=" << static_cast<int>(result) << std::endl;
    };
    EXPECT_EQ(graphicsRenderEngineImpl.Render(99, nullptr, onRenderFinishCb), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_UnInit, TestSize.Level0)
{
    auto renderEngine = GraphicsRenderEngineImpl(1);
    renderEngine.renderThread_ = nullptr;
    EXPECT_EQ(renderEngine.UnInit(), VEFError::ERR_OK);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_UnInit_1, TestSize.Level0)
{
    auto renderEngine = GraphicsRenderEngineImpl(1);
    auto func = []() {};
    renderEngine.renderThread_ = new (std::nothrow) RenderThread<>(RENDER_QUEUE_SIZE, func);
    ASSERT_NE(renderEngine.renderThread_, nullptr);
    EXPECT_EQ(renderEngine.UnInit(), VEFError::ERR_OK);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_RenderEffects, TestSize.Level0)
{
    auto renderEngine = GraphicsRenderEngineImpl(1);
    EXPECT_EQ(renderEngine.RenderEffects(nullptr, nullptr), nullptr);
    auto renderInfo = std::make_shared<GraphicsRenderInfo>();
    EXPECT_EQ(renderEngine.RenderEffects(nullptr, renderInfo), nullptr);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_CreateEffect_nullptr, TestSize.Level0)
{
    std::string description = "";
    EXPECT_EQ(EffectFactory::CreateEffect(description), nullptr);
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_DrawFrame, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);

    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, cb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* window = encoderEngine->GetVideoInputWindow();
    auto renderEngine = GraphicsRenderEngineImpl(1);
    EXPECT_EQ(renderEngine.InitExportEngine(window), VEFError::ERR_OK);
    renderEngine.context_ = std::make_shared<RenderContext>();
    renderEngine.shaderPassOnScreen_ = std::make_shared<ShaderPassOnScreen>(renderEngine.context_.get());
    auto renderTexture = std::make_shared<RenderTexture>(renderEngine.context_.get(), 320, 480, GL_RGBA8);
    renderEngine.DrawFrame(100, renderTexture);
    renderEngine.DrawFrame(100, nullptr);
    auto renderEngine1 = GraphicsRenderEngineImpl(1);
    renderEngine1.context_ = std::make_shared<RenderContext>();
    renderEngine1.shaderPassOnScreen_ = std::make_shared<ShaderPassOnScreen>(renderEngine1.context_.get());
    auto renderTexture1 = std::make_shared<RenderTexture>(renderEngine1.context_.get(), 320, 480, GL_RGBA8);
    EXPECT_EQ(renderEngine1.InitExportEngine(nullptr), VEFError::ERR_INVALID_PARAM);
    renderEngine1.DrawFrame(100, renderTexture1);
    (void)close(srcFd);
}
} // namespace Media
} // namespace OHOS
