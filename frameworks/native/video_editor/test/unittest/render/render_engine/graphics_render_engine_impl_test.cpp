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
    EXPECT_EQ(graphicsRenderEngineImpl.Init(nullptr), VEFError::ERR_INVALID_PARAM);  // 2 is rotation
}

HWTEST_F(GraphicsRenderEngineImplTest, GraphicsRenderEngineImplTest_StopRender, TestSize.Level0)
{
    GraphicsRenderEngineImpl graphicsRenderEngineImpl(1);
    EXPECT_EQ(graphicsRenderEngineImpl.StopRender(), VEFError::ERR_OK);
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
        std::cout << "pts=" << pts << "result=" << static_cast<int>(result) << std::endl;
    };
    EXPECT_EQ(graphicsRenderEngine->Render(99, renderInfo, onRenderFinishCb), VEFError::ERR_OK);
    (void)close(srcFd);
}
} // namespace Media
} // namespace OHOS
