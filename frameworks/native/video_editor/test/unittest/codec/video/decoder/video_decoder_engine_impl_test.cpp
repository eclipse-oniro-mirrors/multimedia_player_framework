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
#include "codec/video/decoder/video_decoder_engine_impl.h"
#include "render/graphics/graphics_render_engine.h"
#include <fcntl.h>
#include "ut_common_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDecoderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// Test the constructor of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, construct, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->GetId(), 12345);
    EXPECT_EQ(engine->fd_, 50);
    EXPECT_EQ(engine->cb_, cb);
}

// Test the Init method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, init_error, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderEngineImplTest, init_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    (void)close(srcFd);
}

/**
 * @tc.name  : VideoDecoderEngineImpl_001
 * @tc.number: VideoDecoderEngineImpl_001
 * @tc.desc  : Test when InitDeMuxer failed with error then return error
 */
HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_001, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_initDeMuxer_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StopDecode_error, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, 1, cb);
    EXPECT_EQ(engine->StopDecode(), VEFError::ERR_INTERNAL_ERROR);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_ok, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 0;
    EXPECT_EQ(cb->pts_, pts);
}

HWTEST_F(VideoDecoderEngineImplTest, OnAudioDecodeResult_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    CodecResult failResult = CodecResult::FAILED;
    CodecResult cancelResult = CodecResult::CANCELED;
    engine->OnAudioDecodeResult(sucResult);
    engine->OnAudioDecodeResult(failResult);
    engine->OnAudioDecodeResult(cancelResult);
    EXPECT_EQ(cb->result_, cancelResult);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, OnVideoDecodeResult_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    CodecResult failResult = CodecResult::FAILED;
    CodecResult cancelResult = CodecResult::CANCELED;
    engine->OnVideoDecodeResult(sucResult);
    engine->OnVideoDecodeResult(failResult);
    engine->OnVideoDecodeResult(cancelResult);
    EXPECT_EQ(cb->result_, cancelResult);
    engine->OnVideoDecoderFrame(80);
    EXPECT_EQ(cb->pts_, 80);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, OnVideoDecodeResult_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, nullptr);
    engine->OnVideoDecoderFrame(80);
    ASSERT_EQ(engine->cb_, nullptr);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, OnVideoDecodeResult_success, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    engine->OnVideoDecodeResult(sucResult);
    engine->OnAudioDecodeResult(sucResult);
    EXPECT_EQ(cb->result_, sucResult);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, GetVideoDuration_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    EXPECT_EQ(engine->GetVideoDuration(), 10034000);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_GetVideoDuration_error, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, 1, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->GetVideoDuration(), -1);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_GetRotation_zero, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, 1, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->GetRotation(), 0);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StartDecode, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);

    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, deCb);
    EXPECT_EQ(decoderEngine->StartDecode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StartDecode_audioDecoder_not_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    engine->videoDecoder_->decoder_ = nullptr;
    EXPECT_EQ(engine->StartDecode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StartDecode_audioDecoder_decoder_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    engine->audioDecoder_->decoder_ = nullptr;
    EXPECT_EQ(engine->StartDecode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StopDecode, TestSize.Level0)
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
    OHNativeWindow* inputWindowOfRender = graphicsRenderEngine->GetInputWindow();
    ASSERT_NE(inputWindowOfRender, nullptr);
    auto inputPcmBufferQueue = encoderEngine->GetAudioInputBufferQueue();
    decoderEngine->SetVideoOutputWindow(inputWindowOfRender);
    decoderEngine->SetAudioOutputBufferQueue(inputPcmBufferQueue);
    EXPECT_EQ(decoderEngine->StopDecode(), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_Enqueue, TestSize.Level0)
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
    auto inputPcmBufferQueue = encoderEngine->GetAudioInputBufferQueue();
    ASSERT_NE(inputPcmBufferQueue, nullptr);
    std::shared_ptr<PcmData> pcmData = std::make_shared<PcmData>();
    pcmData->flags = 12;
    pcmData->pts = 100;
    pcmData->dataSize = 0;
    pcmData->data = nullptr;
    inputPcmBufferQueue->Enqueue(pcmData);
    inputPcmBufferQueue->Dequeue();
    ASSERT_FALSE(inputPcmBufferQueue->cancelEnqueueFlag_);
    inputPcmBufferQueue->cancelEnqueueFlag_ = true;
    inputPcmBufferQueue->Enqueue(pcmData);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_ReadVideoPacket, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, deCb);
    EXPECT_EQ(decoderEngine->InitDeMuxer(), VEFError::ERR_OK);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(decoderEngine->ReadVideoPacket(sampleMem, &attr), VEFError::ERR_OK);
    OH_AVCodecBufferAttr attr1;
    attr1.size = 1024 * 1024;
    attr1.pts = 100;
    attr1.flags = 0;
    EXPECT_EQ(decoderEngine->ReadVideoPacket(sampleMem, &attr1), VEFError::ERR_OK);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_ReadAudioPacket, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, deCb);
    EXPECT_EQ(decoderEngine->InitDeMuxer(), VEFError::ERR_OK);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(decoderEngine->ReadAudioPacket(sampleMem, &attr), VEFError::ERR_OK);
    OH_AVCodecBufferAttr attr1;
    attr1.size = 1024 * 1024;
    attr1.pts = 100;
    attr1.flags = 0;
    EXPECT_EQ(decoderEngine->ReadAudioPacket(sampleMem, &attr1), VEFError::ERR_OK);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_ReadAudioPacket_err, TestSize.Level0)
{
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = std::make_shared<VideoDecoderEngineImpl>(1, 1, deCb);
    EXPECT_EQ(decoderEngine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(decoderEngine->ReadAudioPacket(sampleMem, &attr), VEFError::ERR_INTERNAL_ERROR);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_ReadVideoPacket_err, TestSize.Level0)
{
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = std::make_shared<VideoDecoderEngineImpl>(1, 1, deCb);
    EXPECT_EQ(decoderEngine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(decoderEngine->ReadVideoPacket(sampleMem, &attr), VEFError::ERR_INTERNAL_ERROR);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_SetAudioOutputBufferQueue, TestSize.Level0)
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
    auto inputPcmBufferQueue = encoderEngine->GetAudioInputBufferQueue();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, deCb);
    engine->audioDecoder_ = nullptr;
    engine->SetAudioOutputBufferQueue(inputPcmBufferQueue);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_InitAudioDecoder, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, deCb);
    engine->deMuxer_ = std::make_shared<VideoDeMuxer>(9, srcFd);
    EXPECT_EQ(engine->InitAudioDecoder(), VEFError::ERR_OK);
    (void)close(srcFd);
}
} // namespace Media
} // namespace OHOS