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
#include "render/graphics/graphics_render_engine.h"
#include "data_center/asset/asset_factory.h"
#include "data_center/impl/data_center_impl.h"
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

HWTEST_F(VideoEncoderEngineImplTest, VideoEncoderEngineImpl_SendEos_error, TestSize.Level0)
{
    std::string fileName = "ChineseColor_H264_AAC_480p_15fps.mp4";
    int32_t aacFd = VideoResource::instance().getFileResource(fileName);
    auto engine = std::make_shared<VideoEncoderEngineImpl>(aacFd, cb_);
    EXPECT_EQ(engine->SendEos(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(aacFd);
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

HWTEST_F(VideoEncoderEngineImplTest, CheckCompositeOptions_cb_nullptr, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    auto options = std::make_shared<CompositionOptions>(8, nullptr);
    EXPECT_EQ(videoCompositeEngine->CheckCompositeOptions(options), VEFError::ERR_INVALID_PARAM);
}

HWTEST_F(VideoEncoderEngineImplTest, StartComposite_error, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    auto enEngine = std::make_shared<VideoEncoderEngineImpl>(srcFd, cb_);
    enEngine->muxer_ = std::make_shared<VideoMuxer>(9);
    videoCompositeEngine->encoderEngine_ = enEngine;
    EXPECT_EQ(videoCompositeEngine->StartComposite(), VEFError::ERR_INTERNAL_ERROR);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, StartEncode_AppendVideo, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(12);
    auto dataCenter = std::make_shared<DataCenterImpl>();
    auto asset = AssetFactory::CreateAsset(AssetType::VIDEO, srcFd);
    dataCenter->assetList_.emplace_back(asset);
    ASSERT_EQ(dataCenter->AppendVideo(srcFd, WATER_MARK_DESC), VEFError::ERR_INPUT_VIDEO_COUNT_LIMITED);
    (void)close(srcFd);
}

HWTEST_F(VideoEncoderEngineImplTest, TaskManager_wait_no_param, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::CONCURRENT);
    videoCompositeEngine->taskMgr_->Wait();
    EXPECT_EQ(videoCompositeEngine->taskMgr_->GetTaskCount(), 0);
}

HWTEST_F(VideoEncoderEngineImplTest, TaskManager_wait_param_if, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::SEQUENTIAL);
    std::vector<TaskHandle> taskHandles;
    videoCompositeEngine->taskMgr_->Wait(taskHandles);
    EXPECT_EQ(videoCompositeEngine->taskMgr_->GetTaskCount(), 0);
}

HWTEST_F(VideoEncoderEngineImplTest, TaskManager_wait_param, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::CONCURRENT);
    std::vector<TaskHandle> taskHandles;
    videoCompositeEngine->taskMgr_->Wait(taskHandles);
    EXPECT_EQ(videoCompositeEngine->taskMgr_->GetTaskCount(), 0);
}

HWTEST_F(VideoEncoderEngineImplTest, TaskManager_submit, TestSize.Level0)
{
    auto videoCompositeEngine = std::make_shared<VideoCompositeEngine>(9);
    ASSERT_NE(videoCompositeEngine, nullptr);
    videoCompositeEngine->taskMgr_ = std::make_shared<TaskManager>("compositeEngine", TaskManagerTimeOpt::CONCURRENT);
    std::function<void()> func = []() {
        std::cout << "TaskManager Submit testFunc" << std::endl;
    };
    EXPECT_NE(videoCompositeEngine->taskMgr_, nullptr);
    videoCompositeEngine->taskMgr_->Submit(func, "testFunction");
}
} // namespace Media
} // namespace OHOS