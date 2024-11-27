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
#include "codec/video/decoder/video_decoder_engine_impl.h"
#include "render/graphics/render_engine/graphics_render_engine_impl.h"
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
        cb_ = new VideoEncodeCallbackTester();
        deCb_ = new VideoDecodeCallbackTester();
    }

    void TearDown() override
    {
        if (cb_ != nullptr) {
            delete cb_;
            cb_ = nullptr;
        }
        if (deCb_ != nullptr) {
            delete deCb_;
            deCb_ = nullptr;
        }
    }

private:
    VideoEncodeCallbackTester* cb_ = nullptr;
    VideoDecodeCallbackTester* deCb_ = nullptr;
};

// Test VideoEncoderEngineImpl constructor
HWTEST_F(VideoEncoderEngineImplTest, construct, TestSize.Level0)
{
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb_);
    EXPECT_EQ(engine->GetId(), 20);
}

// Test VideoEncoderEngineImpl Init method
HWTEST_F(VideoEncoderEngineImplTest, init_error, TestSize.Level0)
{
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb_);
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
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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
    auto decoderEng = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam params = VideoResource::instance().getEncodeParam(srcFd, decoderEng);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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
    auto deEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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
    auto decoEng = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, decoEng);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    EXPECT_EQ(engine->SendEos(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImplTest_OnEncodeResult, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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

    OH_AVCodecBufferAttr attr1;
    attr1.size = 1024 * 1024;
    attr1.pts = 100;
    attr1.flags = 1;
    engine->OnVideoNewOutputDataCallBack(sampleMem, &attr1);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::FINISH_SUCCESS);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoEncoderEngineImplTest, OnVideoNewOutputDataCallBack_with_muxer_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 0;
    engine->OnVideoNewOutputDataCallBack(sampleMem, &attr);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::INIT);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoEncoderEngineImplTest, OnVideoNewOutputDataCallBack_with_cb_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, nullptr);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    VideoMuxerParam muxerParam;
    muxerParam.targetFileFd = srcFd;
    EXPECT_EQ(engine->InitVideoMuxer(muxerParam), VEFError::ERR_OK);
    engine->OnVideoNewOutputDataCallBack(sampleMem, &attr);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::INIT);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoEncoderEngineImplTest, OnVideoNewOutputDataCallBack_with_cb_not_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* sampleMem = OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    VideoMuxerParam muxerParam;
    muxerParam.targetFileFd = srcFd;
    EXPECT_EQ(engine->InitVideoMuxer(muxerParam), VEFError::ERR_OK);
    engine->OnVideoNewOutputDataCallBack(sampleMem, &attr);
    EXPECT_EQ(engine->videoEncoderState_, CodecState::FINISH_SUCCESS);

    OH_AVCodecBufferAttr attr1;
    attr1.size = 1024 * 1024;
    attr1.pts = 100;
    attr1.flags = 0;
    auto engine1 = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine1->InitVideoMuxer(muxerParam), VEFError::ERR_OK);
    engine1->OnVideoNewOutputDataCallBack(sampleMem, &attr1);
    EXPECT_EQ(engine1->videoEncoderState_, CodecState::INIT);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImplTest_OnAudioEncodeOutput, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
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

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_InitAudioStreamEncoder, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine->InitAudioStreamEncoder(nullptr), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_Init_with_format_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    VideoEncodeParam enCodeParam;
    enCodeParam.videoTrunkFormat = nullptr;
    enCodeParam.audioTrunkFormat = nullptr;
    enCodeParam.muxerParam.targetFileFd = srcFd;
    enCodeParam.muxerParam.avOutputFormat = AV_OUTPUT_FORMAT_MPEG_4;
    enCodeParam.muxerParam.rotation = 90;
    EXPECT_EQ(engine->Init(enCodeParam), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_StartEncode_muxer_error, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t fileFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(fileFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(fileFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(fileFd, deEngine);
    auto enEngine = std::make_shared<VideoEncoderEngineImpl>(fileFd, cb_);
    EXPECT_EQ(enEngine->Init(param), VEFError::ERR_OK);
    enEngine->muxer_->muxer_ = nullptr;
    EXPECT_EQ(enEngine->StartEncode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(fileFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_StartEncode_encoder_error, TestSize.Level0)
{
    std::string fileName = "H264_AAC_320x240.mp4";
    int32_t aacFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(aacFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(aacFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(aacFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(aacFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    engine->encoder_->encoder_ = nullptr;
    EXPECT_EQ(engine->StartEncode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(aacFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_StartEncode_audioEncoder_error, TestSize.Level0)
{
    std::string fileName = "ChineseColor_H264_AAC_480p_15fps.mp4";
    int32_t aacFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(aacFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(aacFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(aacFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(aacFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    engine->audioEncoder_ = nullptr;
    EXPECT_EQ(engine->StartEncode(), VEFError::ERR_OK);
    (void)close(aacFd);
}

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_SendEos_error, TestSize.Level0)
{
    std::string fileName = "ChineseColor_H264_AAC_480p_15fps.mp4";
    int32_t aacFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(aacFd, cb_);
    EXPECT_EQ(engine->SendEos(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(aacFd);
}

HWTEST_F(VideoEncoderEngineImplTest, Flush_audioEncoder_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(36);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    engine->audioEncoder_->encoder_ = nullptr;
    EXPECT_EQ(engine->StopEncode(), VEFError::ERR_INTERNAL_ERROR);
    engine->audioEncoder_ = nullptr;
    EXPECT_EQ(engine->Flush(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(engine->StopEncode(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, Flush_encoder_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(36);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);
    engine->muxer_->muxer_ = nullptr;
    EXPECT_EQ(engine->StopEncode(), VEFError::ERR_INTERNAL_ERROR);
    engine->audioEncoder_ = nullptr;
    engine->encoder_ = nullptr;
    EXPECT_EQ(engine->Flush(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, OnAudioEncodeOutput_encoder_not_nullptr, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(36);
    auto dataCenter = IDataCenter::Create();
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->Init(dataCenter), VEFError::ERR_OK);
    EXPECT_EQ(videoCompositeEngine->OrchestratePipelines(), VEFError::ERR_INTERNAL_ERROR);
    auto deEngine = IVideoDecoderEngine::Create(srcFd, deCb_);
    VideoEncodeParam param = VideoResource::instance().getEncodeParam(srcFd, deEngine);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    EXPECT_EQ(engine->Init(param), VEFError::ERR_OK);

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
    EXPECT_EQ(engine->OnAudioEncodeOutput(codec, 1, sampleMem, &attr), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
    OH_AVMemory_Destroy(sampleMem);
    OH_VideoEncoder_Destroy(codec);
}

HWTEST_F(VideoEncoderEngineImplTest, StopComposite_init, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->state_ = VideoCompositeEngine::CompositeState::INIT;
    ASSERT_EQ(videoCompositeEngine->StopComposite(), VEFError::ERR_OK);
}

HWTEST_F(VideoEncoderEngineImplTest, OnDecodeResult_canceled, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    CodecResult result = CodecResult::CANCELED;
    videoCompositeEngine->OnDecodeResult(result);
}

HWTEST_F(VideoEncoderEngineImplTest, OnDecodeResult_success, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    static std::atomic<uint64_t> codecId { 1 };
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::SEQUENTIAL);
    videoCompositeEngine->decoderEngine_ = std::make_shared<VideoDecoderEngineImpl>(codecId.fetch_add(1), srcFd, deCb_);
    videoCompositeEngine->encoderEngine_ = std::make_shared<VideoEncoderEngineImpl>(codecId.fetch_add(1), cb_);
    CodecResult result = CodecResult::SUCCESS;
    videoCompositeEngine->OnDecodeResult(result);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, OnDecodeResult_success_1, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    static std::atomic<uint64_t> codecId { 1 };
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::SEQUENTIAL);
    videoCompositeEngine->decoderEngine_ = std::make_shared<VideoDecoderEngineImpl>(codecId.fetch_add(1), srcFd, deCb_);
    videoCompositeEngine->encoderEngine_ = std::make_shared<VideoEncoderEngineImpl>(codecId.fetch_add(1), cb_);
    CodecResult result = CodecResult::SUCCESS;
    videoCompositeEngine->renderingCnt_ = 2;
    videoCompositeEngine->OnDecodeResult(result);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, OnEncodeFrame_state_init, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->state_ = VideoCompositeEngine::CompositeState::INIT;
    videoCompositeEngine->OnEncodeFrame(66);
}

HWTEST_F(VideoEncoderEngineImplTest, OnEncodeFrame_state_compositing, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->state_ = VideoCompositeEngine::CompositeState::COMPOSITING;
    videoCompositeEngine->callback_ = std::make_shared<CompositionCallbackTesterImpl>();
    videoCompositeEngine->duration_ = 0;
    videoCompositeEngine->OnEncodeFrame(99);
}

HWTEST_F(VideoEncoderEngineImplTest, OnEncodeFrame_state_compositing_1, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->state_ = VideoCompositeEngine::CompositeState::COMPOSITING;
    videoCompositeEngine->callback_ = std::make_shared<CompositionCallbackTesterImpl>();
    videoCompositeEngine->duration_ = 33;
    videoCompositeEngine->OnEncodeFrame(99);
}
} // namespace Media
} // namespace OHOS