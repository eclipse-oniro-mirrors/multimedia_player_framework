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
#include "codec/video/encoder/video_encoder_engine_impl.h"
#include "composite_engine/impl/video_composite_engine.h"
#include <native_avcodec_videoencoder.h>
#include <native_avcodec_base.h>
#include "ut_common_data.h"
#include <fcntl.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEncoderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// Test VideoEncoderEngineImpl constructor
HWTEST_F(VideoEncoderEngineImplTest, construct, TestSize.Level0)
{
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb);
    EXPECT_EQ(engine->GetId(), 20);
}

// Test VideoEncoderEngineImpl Init method
HWTEST_F(VideoEncoderEngineImplTest, init_error, TestSize.Level0)
{
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb);
    VideoEncodeParam enCoderParam;
    EXPECT_EQ(engine->Init(enCoderParam), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoEncoderEngineImplTest, init_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    VideoEncodeParam enCoderParam;
    EXPECT_EQ(videoCompositeEngine->BuildEncoderParameter(enCoderParam), VEFError::ERR_OK);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    EXPECT_EQ(engine->Init(enCoderParam), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, StartEncode_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    EXPECT_EQ(engine->StartEncode(), VEFError::ERR_OK);
    EXPECT_EQ(engine->StopEncode(), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, UnInit_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(24);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    VideoDecodeCallbackTester* decodeCallback = new VideoDecodeCallbackTester();
    auto decoderEng = IVideoDecoderEngine::Create(srcFd, decodeCallback);
    VideoEncodeParam params = VideoResource::instance().getEncodeParam(srcFd, decoderEng);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    EXPECT_EQ(engine->Init(params), VEFError::ERR_OK);
    engine->UnInit();
    EXPECT_EQ(engine->encoder_, nullptr);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, Flush_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(36);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    VideoDecodeCallbackTester* decoderCb = new VideoDecodeCallbackTester();
    auto deEngine = IVideoDecoderEngine::Create(srcFd, decoderCb);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, deEngine);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    EXPECT_EQ(engine->Flush(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, SendEos_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(48);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    VideoDecodeCallbackTester* deCallback = new VideoDecodeCallbackTester();
    auto decoEng = IVideoDecoderEngine::Create(srcFd, deCallback);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoEng);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    EXPECT_EQ(engine->SendEos(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImplTest_OnEncodeResult, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    CodecResult result = CodecResult::SUCCESS;
    engine->OnEncodeResult(result);
    engine->videoEncoderState_ = CodecState::FINISH_SUCCESS;
    engine->OnEncodeResult(result);
    engine->audioEncoderState_ = CodecState::FINISH_SUCCESS;
    engine->OnEncodeResult(result);
    engine->videoEncoderState_ = CodecState::RUNNING;
    engine->audioEncoderState_ = CodecState::FINISH_SUCCESS;
    engine->OnEncodeResult(result);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::RUNNING);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImplTest_OnVideoNewOutputDataCallBack, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 0;
    VideoMuxerParam muxerParam;
    muxerParam.targetFileFd = srcFd;
    EXPECT_EQ(engine->InitVideoMuxer(muxerParam), VEFError::ERR_OK);
    engine->OnVideoNewOutputDataCallBack(nullptr, nullptr);
    engine->OnVideoNewOutputDataCallBack(sampleMem, nullptr);
    engine->OnVideoNewOutputDataCallBack(nullptr, &attr);
    engine->OnVideoNewOutputDataCallBack(sampleMem, &attr);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::INIT);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImplTest_OnAudioEncodeOutput, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 0;
    VideoMuxerParam muxerParam;
    muxerParam.targetFileFd = srcFd;
    EXPECT_EQ(engine->InitVideoMuxer(muxerParam), VEFError::ERR_OK);
    OH_AVCodec* codec = OH_VideoEncoder_CreateByMime(OH_AVCODEC_MIMETYPE_VIDEO_AVC);
    EXPECT_EQ(engine->OnAudioEncodeOutput(nullptr, 1, nullptr, nullptr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->OnAudioEncodeOutput(codec, 1, nullptr, nullptr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->OnAudioEncodeOutput(codec, 1, sampleMem, nullptr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->OnAudioEncodeOutput(nullptr, 1, sampleMem, &attr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->OnAudioEncodeOutput(codec, 1, nullptr, &attr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->OnAudioEncodeOutput(codec, 1, sampleMem, &attr), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
    OH_VideoEncoder_Destroy(codec);
}
} // namespace Media
} // namespace OHOS