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
#include "codec/video/decoder/video_decoder.h"
#include "ut_common_data.h"
#include "render/graphics/graphics_render_engine.h"
#include <fcntl.h>
#include <native_avcodec_videodecoder.h>
#include <native_avcodec_base.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDecoderTest : public testing::Test {
protected:
    void SetUp() override
    {
        std::function cb = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
            return VEFError::ERR_OK;
        };
        id_ = 1;
        decoder_ = std::make_shared<VideoDecoder>(id_, cb, onDecodeFrameCallback_, onDecodeResultCallback_);
        codec_ = OH_VideoDecoder_CreateByMime(OH_AVCODEC_MIMETYPE_VIDEO_AVC);
        uint32_t buffersize = 1024 * 1024;
        sampleMem_ = OH_AVMemory_Create(buffersize);
        format_ = OH_AVFormat_Create();
    }

    void TearDown() override
    {
        if (codec_ != nullptr) {
            OH_VideoDecoder_Destroy(codec_);
            codec_ = nullptr;
        }
        if (sampleMem_ != nullptr) {
            OH_AVMemory_Destroy(sampleMem_);
            sampleMem_ = nullptr;
        }
        if (format_ != nullptr) {
            OH_AVFormat_Destroy(format_);
            format_ = nullptr;
        }
    }

private:
    uint64_t id_;
    std::shared_ptr<VideoDecoder> decoder_ = nullptr;
    CodecOnDecodeFrame onDecodeFrameCallback_;
    CodecOnDecodeResult onDecodeResultCallback_;
    OH_AVCodec* codec_ = nullptr;
    OH_AVMemory* sampleMem_ = nullptr;
    OH_AVFormat* format_ = nullptr;
};

// test VideoDecoder Start method
HWTEST_F(VideoDecoderTest, VideoDecoder_Start, TestSize.Level0)
{
    EXPECT_EQ(decoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoDecoder Stop method
HWTEST_F(VideoDecoderTest, VideoDecoder_Stop, TestSize.Level0)
{
    EXPECT_EQ(decoder_->Stop(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_Init, TestSize.Level0)
{
    EXPECT_EQ(decoder_->Init(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_SetVideoOutputWindow, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);

    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    ASSERT_NE(decoderEngine, nullptr);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* enCb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, enCb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* nativeWindowEncoder = encoderEngine->GetVideoInputWindow();
    ASSERT_NE(nativeWindowEncoder, nullptr);
    auto graphicsRenderEngine = IGraphicsRenderEngine::Create(nativeWindowEncoder);
    ASSERT_NE(graphicsRenderEngine, nullptr);
    OHNativeWindow* inputWindowRender = graphicsRenderEngine->GetInputWindow();
    ASSERT_NE(inputWindowRender, nullptr);
    EXPECT_EQ(decoderEngine->SetVideoOutputWindow(inputWindowRender), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_CodecOnNeedInputDataInner, TestSize.Level0)
{
    decoder_->CodecOnNeedInputDataInner(nullptr, 1, nullptr);
    decoder_->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(decoder_->Init(nullptr), VEFError::ERR_INTERNAL_ERROR);

    std::function decodeCb =[&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_INTERNAL_ERROR;
    };
    auto decoder = std::make_shared<VideoDecoder>(2, decodeCb, onDecodeFrameCallback_, onDecodeResultCallback_);
    decoder->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(decoder->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_CodecOnNewOutputData, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 0;
    decoder_->CodecOnNewOutputData(codec_, 1, sampleMem_, &attr);

    std::function codecOnDecodeResult = [&](CodecResult codecResult) -> VEFError {
        return VEFError::ERR_OK;
    };
    attr.flags = 1;
    std::function cb = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_OK;
    };
    auto decoder = std::make_shared<VideoDecoder>(1, cb, onDecodeFrameCallback_, codecOnDecodeResult);
    decoder->CodecOnNewOutputData(codec_, 1, sampleMem_, &attr);
    EXPECT_EQ(decoder_->Init(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_ConfigureDecoder, TestSize.Level0)
{
    decoder_->ConfigureDecoder(nullptr);
    decoder_->ConfigureDecoder(format_);
    EXPECT_EQ(decoder_->Init(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_SetNativeWindow_with_nullptr, TestSize.Level0)
{
    EXPECT_EQ(decoder_->SetNativeWindow(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderTest, VideoDecoder_SetNativeWindow, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    ASSERT_NE(decoderEngine, nullptr);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* enCb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, enCb);
    ASSERT_NE(encoderEngine, nullptr);
    OHNativeWindow* nativeWindowEncoder = encoderEngine->GetVideoInputWindow();
    ASSERT_NE(nativeWindowEncoder, nullptr);
    std::function cb = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_OK;
    };
    auto decoder = std::make_shared<VideoDecoder>(1, cb, onDecodeFrameCallback_, onDecodeResultCallback_);
    decoder->decoder_ = nullptr;
    EXPECT_EQ(decoder->SetNativeWindow(nativeWindowEncoder), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}
} // namespace Media
} // namespace OHOS