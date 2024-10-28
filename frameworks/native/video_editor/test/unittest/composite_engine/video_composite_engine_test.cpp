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
#include "gmock/gmock.h"
#include "ohos_media_videoeditor_engine_video_composite_engine.h"
#include "ohos_media_videoeditor_engine_video_decoder_engine.h"
#include "ohos_media_videoeditor_engine_video_encoder_engine.h"
#include "ohos_media_videoeditor_engine_graphics_render_engine.h"
#include "ohos_media_videoeditor_engine_data_center.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media;

class MockVideoDecoderEngine : public IVideoDecoderEngine {
public:
    MOCK_METHOD(VEFError, Init, (), (override));
    MOCK_METHOD(VEFError, StartDecode, (), (override));
    MOCK_METHOD(VEFError, StopDecode, (), (override));
};

class MockVideoEncoderEngine : public IVideoEncoderEngine {
public:
    MOCK_METHOD(VEFError, Init, (const OH_AVDormat *, const OH_AVDormat *), (override));
    MOCK_METHOD(VEFError, StartEncode, (), (override));
    MOCK_METHOD(VEFError, StopEncode, (), (override));
};

class MockGraphicsRenderEngine : public IGraphicsRenderEngine {
public:
    MOCK_METHOD(VEFError, Init, (OHNativeWindow *), (override));
    MOCK_METHOD(VEFError, StartRender, (), (override));
    MOCK_METHOD(VEFError, StopRender, (), (override));
};

class MockIDataCenter : public IDataCenter {
public:
    MOCK_METHOD(std::vector<std::shared_ptr<Asset>>, GetAssetList, (), (override));
};

class VideoCompositeEngineTest : public testing::Test {
public:
    void SetUp() override
    {
        dataCenter = std::make_shared<MockIDataCenter>();
        decoderEngine = std::make_shared<MockVideoDecoderEngine>();
        encoderEngine = std::make_shared<MockVideoEncoderEngine>();
        graphicsRenderEngine = std::make_shared<MockGraphicsRenderEngine>();
        videoCompositeEngine = std::make_shared<VideoCompositeEngine>();
    }

    void TearDown() override
    {
        videoCompositeEngine.reset();
        graphicsRenderEngine.reset();
        encoderEngine.reset();
        decoderEngine.reset();
        dataCenter.reset();
    }

    std::shared_ptr<VideoCompositeEngine> videoCompositeEngine;
    std::shared_ptr<MockVideoDecoderEngine> decoderEngine;
    std::shared_ptr<MockVideoEncoderEngine> encoderEngine;
    std::shared_ptr<MockGraphicsRenderEngine> graphicsRenderEngine;
    std::shared_ptr<MockIDataCenter> dataCenter;
};

HWTEST_F(VideoCompositeEngineTest, StartComposite_Success, TestSize.Level0)
{
    std::shared_ptr<CompositionOptions> options = std::make_shared<CompositionOptions>();
    options->targetFileFd_ = 1;

    EXPECT_CALL(*decoderEngine, Init()).WillOnce(Return(VEFError::ERR_OK));
    EXPECT_CALL(*encoderEngine, Init(_, _)).WillOnce(Return(VEFError::ERR_OK));
    EXPECT_CALL(*graphicsRenderEngine, Init(_)).WillOnce(Return(VEFError::ERR_OK));

    VEFError error = VideoCompositeEngine->StartComposite(options);
    EXPECT_EQ(error, VEFError::ERR_OK);
}

HWTEST_F(VideoCompositeEngineTest, StartComposite_DecoderInitFailed, TestSize.Level0)
{
    std::shared_ptr<CompositionOptions> options = std::make_shared<CompositionOptions>();
    options->targetFileFd_ = 1;

    EXPECT_CALL(*decoderEngine, Init()).WillOnce(Return(VEFError::ERR_INTERNAL_ERROR));

    VEFError error = VideoCompositeEngine->StartComposite(options);
    EXPECT_EQ(error, VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoCompositeEngineTest, StartComposite_EncoderInitFailed, TestSize.Level0)
{
    std::shared_ptr<CompositionOptions> options = std::make_shared<CompositionOptions>();
    options->targetFileFd_ = 1;

    EXPECT_CALL(*decoderEngine, Init()).WillOnce(Return(VEFError::ERR_OK));
    EXPECT_CALL(*encoderEngine, Init(_, _)).WillOnce(Return(VEFError::ERR_INTERNAL_ERROR));

    VEFError error = VideoCompositeEngine->StartComposite(options);
    EXPECT_EQ(error, VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoCompositeEngineTest, StartComposite_GraphicsRenderInitFailed, TestSize.Level0)
{
    std::shared_ptr<CompositionOptions> options = std::make_shared<CompositionOptions>();
    options->targetFileFd_ = 1;

    EXPECT_CALL(*decoderEngine, Init()).WillOnce(Return(VEFError::ERR_OK));
    EXPECT_CALL(*encoderEngine, Init(_, _)).WillOnce(Return(VEFError::ERR_OK));
    EXPECT_CALL(*graphicsRenderEngine, Init(_)).WillOnce(Return(VEFError::ERR_INTERNAL_ERROR));

    VEFError error = VideoCompositeEngine->StartComposite(options);
    EXPECT_EQ(error, VEFError::ERR_INTERNAL_ERROR);
}