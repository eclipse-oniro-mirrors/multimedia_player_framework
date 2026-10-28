/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hitranscode_impl_unittest.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

const static int32_t TIMES_ONE = 1;
const static int32_t TIMES_TWO = 2;
const std::string MEDIA_ROOT = "files:///data/test/media/";

void HitranscodeImplUnitTest::SetUpTestCase(void)
{
}

void HitranscodeImplUnitTest::TearDownTestCase(void)
{
}

void HitranscodeImplUnitTest::SetUp(void)
{
    int32_t appUid = 0;
    int32_t appPid = 0;
    uint32_t appTokenId = 0;
    uint64_t appFullTokenId = 0;

    demuxerFilter_ = std::make_shared<Pipeline::DemuxerFilter>("mockDemuxerFilter",
        Pipeline::FilterType::FILTERTYPE_DEMUXER);
    mockCallbackLooper_ = std::make_shared<MockHiTransCoderCallbackLooper>();
    transcoder_ = std::make_unique<HiTransCoderImpl>(appUid, appPid, appTokenId, appFullTokenId);
}

void HitranscodeImplUnitTest::TearDown(void)
{
    demuxerFilter_.reset();
    mockCallbackLooper_.reset();
    transcoder_.reset();
}

/**
 * @tc.name  : Test SetInputFile
 * @tc.number: SetInputFile_001
 * @tc.desc  : Test SetInputFile demuxerFilter_ == nullptr
 *             Test ~HiTransCoderImpl transCoderEventReceiver_ == nullptr
 *             Test ~HiTransCoderImpl transCoderFilterCallback_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, SetInputFile_001, TestSize.Level1)
{
    // Test SetInputFile demuxerFilter_ == nullptr
    Pipeline::FilterFactory::Instance().generators.clear();

    // Test ~HiTransCoderImpl transCoderEventReceiver_ == nullptr
    transcoder_->transCoderEventReceiver_ = nullptr;

    // Test ~HiTransCoderImpl transCoderFilterCallback_ == nullptr
    transcoder_->transCoderFilterCallback_ = nullptr;

    int32_t ret = transcoder_->SetInputFile(MEDIA_ROOT);
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/**
 * @tc.name  : Test SetInputFile
 * @tc.number: SetInputFile_002
 * @tc.desc  : Test SetInputFile TransTranscoderStatus != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, SetInputFile_002, TestSize.Level1)
{
    Pipeline::FilterFactory::Instance().RegisterFilter<Pipeline::DemuxerFilter>(
        "builtin.player.demuxer", Pipeline::FilterType::FILTERTYPE_DEMUXER,
        [](const std::string& name, const Pipeline::FilterType type) {
            return std::make_shared<Pipeline::DemuxerFilter>(name, Pipeline::FilterType::FILTERTYPE_DEMUXER);
        }
    );
    int32_t ret = transcoder_->SetInputFile(MEDIA_ROOT);
    EXPECT_EQ(ret, MSERR_UNSUPPORT_CONTAINER_TYPE);
}

/**
 * @tc.name  : Test ConfigureVideoAudioMetaData
 * @tc.number: ConfigureVideoAudioMetaData_001
 * @tc.desc  : Test ConfigureVideoAudioMetaData trackCount == 0
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoAudioMetaData_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    Status ret = transcoder_->ConfigureVideoAudioMetaData();
    EXPECT_EQ(ret, Status::ERROR_NO_VALID_TRACK_FOUND);
}

/**
 * @tc.name  : Test Start
 * @tc.number: Start_001
 * @tc.desc  : Test Start TransTranscoderStatus(pipeline_->Start()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Start_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Start();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test Resume
 * @tc.number: Resume_001
 * @tc.desc  : Test Resume TransTranscoderStatus(pipeline_->Resume()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Resume_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Resume();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test Cancel
 * @tc.number: Cancel_001
 * @tc.desc  : Test Cancel TransTranscoderStatus(pipeline_->Stop()) != MSERR_OK
 */
HWTEST_F(HitranscodeImplUnitTest, Cancel_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCallbackLooper_, OnError(_, _)).Times(TIMES_ONE);
    transcoder_->callbackLooper_ = mockCallbackLooper_;

    transcoder_->demuxerFilter_ = demuxerFilter_;
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    transcoder_->demuxerFilter_->demuxer_.reset();
    int32_t ret = transcoder_->Cancel();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test HandleErrorEvent
 * @tc.number: HandleErrorEvent_001
 * @tc.desc  : Test HandleErrorEvent pipeline_ == nullptr
 *             Test OnEvent event.type == EventType::EVENT_COMPLETE
 *             Test OnEvent event.type == default
 */
HWTEST_F(HitranscodeImplUnitTest, HandleErrorEvent_001, TestSize.Level1)
{
    // Test OnEvent event.type == EventType::EVENT_COMPLETE
    Event event { .type = EventType::EVENT_COMPLETE };
    transcoder_->OnEvent(event);

    // Test OnEvent event.type == default
    event.type = EventType::EVENT_READY;
    transcoder_->OnEvent(event);

    // Test HandleErrorEvent pipeline_ == nullptr
    EXPECT_CALL(*mockCallbackLooper_, OnError(_, _)).Times(TIMES_ONE);
    transcoder_->ignoreError_ = false;
    transcoder_->callbackLooper_ = mockCallbackLooper_;
    transcoder_->pipeline_.reset();
    int32_t errorCode = MSERR_OK;
    transcoder_->HandleErrorEvent(errorCode);
}

/**
 * @tc.name  : Test HandleCompleteEvent
 * @tc.number: HandleCompleteEvent_001
 * @tc.desc  : Test HandleCompleteEvent obs_.lock() == nullptr
 *             Test HandleCompleteEvent pipeline_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, HandleCompleteEvent_001, TestSize.Level1)
{
    // Test HandleCompleteEvent obs_.lock() == nullptr
    transcoder_->obs_.reset();

    // Test HandleCompleteEvent pipeline_ == nullptr
    transcoder_->pipeline_.reset();

    transcoder_->callbackLooper_ = mockCallbackLooper_;
    transcoder_->HandleCompleteEvent();
    EXPECT_EQ(transcoder_->callbackLooper_->taskStarted_, false);
}

/**
 * @tc.name  : Test HandleCompleteEvent
 * @tc.number: HandleCompleteEvent_002
 * @tc.desc  : Test HandleCompleteEvent obs_.lock() != nullptr
 *             Test HandleCompleteEvent pipeline_ != nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, HandleCompleteEvent_002, TestSize.Level1)
{
    transcoder_->callbackLooper_ = mockCallbackLooper_;
    auto mockEngineObs = std::make_shared<MockITransCoderEngineObs>();
    EXPECT_CALL(*mockEngineObs, OnInfo(_, _)).Times(TIMES_TWO);
    transcoder_->obs_ = mockEngineObs;
    transcoder_->HandleCompleteEvent();
}

/**
 * @tc.name  : Test ConfigureAudioParam
 * @tc.number: ConfigureAudioParam_001
 * @tc.desc  : Test ConfigureAudioParam with AUDIO_BITRATE and invalid bitrate <= 0
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureAudioParam_001, TestSize.Level1)
{
    AudioBitRate audioBitrate(-1);
    int32_t ret = transcoder_->Configure(audioBitrate);
    EXPECT_EQ(ret, MSERR_INVALID_AUDIO_BITRATE);
}

/**
 * @tc.name  : Test ConfigureAudioParam
 * @tc.number: ConfigureAudioParam_002
 * @tc.desc  : Test ConfigureAudioParam with AUDIO_ENC_FMT
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureAudioParam_002, TestSize.Level1)
{
    AudioEnc audioEnc(AudioCodecFormat::AAC_LC);
    int32_t ret = transcoder_->Configure(audioEnc);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ConfigureVideoParam
 * @tc.number: ConfigureVideoParam_001
 * @tc.desc  : Test ConfigureVideoParam with VIDEO_ENABLE_B_FRAME_ENCODING
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoParam_001, TestSize.Level1)
{
    VideoEnableBFrameEncoding enableBFrame(true);
    Status ret = transcoder_->ConfigureVideoParam(enableBFrame);
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoParam
 * @tc.number: ConfigureVideoParam_002
 * @tc.desc  : Test ConfigureVideoParam with COLOR_SPACE_FMT and invalid colorSpaceFmt <= 0
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoParam_002, TestSize.Level1)
{
    VideoColorSpace colSpa(TranscoderColorSpace::TRANSCODER_COLORSPACE_NONE);
    Status ret = transcoder_->ConfigureVideoParam(colSpa);
    EXPECT_EQ(Status::ERROR_INVALID_PARAMETER, ret);
}

/**
 * @tc.name  : Test ConfigureVideoParam
 * @tc.number: ConfigureVideoParam_003
 * @tc.desc  : Test ConfigureVideoParam with default case
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoParam_003, TestSize.Level1)
{
    VideoBitRate videoBitRate(1000);
    Status ret = transcoder_->ConfigureVideoParam(videoBitRate);
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoBitrateMode
 * @tc.number: ConfigureVideoBitrateMode_001
 * @tc.desc  : Test ConfigureVideoBitrateMode with SQR mode (supported)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrateMode_001, TestSize.Level1)
{
    int32_t sqrMode = static_cast<int32_t>(Plugins::VideoEncodeBitrateMode::SQR);
    VideoBitrateMode bitrateModeParam(sqrMode);
    Status ret = transcoder_->ConfigureVideoParam(bitrateModeParam);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->videoBitrateMode_, sqrMode);
}

/**
 * @tc.name  : Test ConfigureVideoBitrateMode
 * @tc.number: ConfigureVideoBitrateMode_002
 * @tc.desc  : Test ConfigureVideoBitrateMode with VBR mode (supported)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrateMode_002, TestSize.Level1)
{
    int32_t vbrMode = static_cast<int32_t>(Plugins::VideoEncodeBitrateMode::VBR);
    VideoBitrateMode bitrateModeParam(vbrMode);
    Status ret = transcoder_->ConfigureVideoParam(bitrateModeParam);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->videoBitrateMode_, vbrMode);
}

/**
 * @tc.name  : Test ConfigureVideoBitrateMode
 * @tc.number: ConfigureVideoBitrateMode_003
 * @tc.desc  : Test ConfigureVideoBitrateMode with CBR mode (not supported by transcoder)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrateMode_003, TestSize.Level1)
{
    int32_t cbrMode = static_cast<int32_t>(Plugins::VideoEncodeBitrateMode::CBR);
    VideoBitrateMode bitrateModeParam(cbrMode);
    Status ret = transcoder_->ConfigureVideoParam(bitrateModeParam);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name  : Test ConfigureVideoBitrateMode
 * @tc.number: ConfigureVideoBitrateMode_004
 * @tc.desc  : Test ConfigureVideoBitrateMode with invalid mode (-1)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrateMode_004, TestSize.Level1)
{
    VideoBitrateMode bitrateModeParam(-1);
    Status ret = transcoder_->ConfigureVideoParam(bitrateModeParam);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name  : Test ConfigureSQRFactor
 * @tc.number: ConfigureSQRFactor_001
 * @tc.desc  : Test ConfigureSQRFactor with valid factor 30
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureSQRFactor_001, TestSize.Level1)
{
    VideoSqrFactor sqrFactorParam(30);
    Status ret = transcoder_->ConfigureVideoParam(sqrFactorParam);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->videoSqrFactor_, 30);
}

/**
 * @tc.name  : Test ConfigureSQRFactor
 * @tc.number: ConfigureSQRFactor_002
 * @tc.desc  : Test ConfigureSQRFactor with boundary values 0 and 51
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureSQRFactor_002, TestSize.Level1)
{
    VideoSqrFactor sqrFactorParamMin(0);
    Status ret = transcoder_->ConfigureVideoParam(sqrFactorParamMin);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->videoSqrFactor_, 0);
 
    VideoSqrFactor sqrFactorParamMax(51);
    ret = transcoder_->ConfigureVideoParam(sqrFactorParamMax);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->videoSqrFactor_, 51);
}

/**
 * @tc.name  : Test ConfigureSQRFactor
 * @tc.number: ConfigureSQRFactor_003
 * @tc.desc  : Test ConfigureSQRFactor with invalid factor < 0
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureSQRFactor_003, TestSize.Level1)
{
    VideoSqrFactor sqrFactorParam(-1);
    Status ret = transcoder_->ConfigureVideoParam(sqrFactorParam);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name  : Test ConfigureSQRFactor
 * @tc.number: ConfigureSQRFactor_004
 * @tc.desc  : Test ConfigureSQRFactor with invalid factor > 51
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureSQRFactor_004, TestSize.Level1)
{
    VideoSqrFactor sqrFactorParam(52);
    Status ret = transcoder_->ConfigureVideoParam(sqrFactorParam);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name  : Test LinkAudioDecoderFilter
 * @tc.number: LinkAudioDecoderFilter_001
 * @tc.desc  : Test LinkAudioDecoderFilter with nullptr audioDecoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkAudioDecoderFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->audioDecoderFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->LinkAudioDecoderFilter(preFilter, Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkAudioEncoderFilter
 * @tc.number: LinkAudioEncoderFilter_001
 * @tc.desc  : Test LinkAudioEncoderFilter with nullptr audioEncoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkAudioEncoderFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->audioEncoderFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->LinkAudioEncoderFilter(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkVideoDecoderFilter
 * @tc.number: LinkVideoDecoderFilter_001
 * @tc.desc  : Test LinkVideoDecoderFilter with nullptr videoDecoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkVideoDecoderFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->videoDecoderFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->LinkVideoDecoderFilter(preFilter, Pipeline::StreamType::STREAMTYPE_ENCODED_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkVideoEncoderFilter
 * @tc.number: LinkVideoEncoderFilter_001
 * @tc.desc  : Test LinkVideoEncoderFilter with nullptr videoEncoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkVideoEncoderFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->videoEncoderFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->LinkVideoEncoderFilter(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkVideoEncoderFilter
 * @tc.number: LinkVideoEncoderFilter_002
 * @tc.desc  : Test LinkVideoEncoderFilter with nullptr videoEncFormat_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkVideoEncoderFilter_002, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->videoEncFormat_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->LinkVideoEncoderFilter(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkVideoResizeFilter
 * @tc.number: LinkVideoResizeFilter_001
 * @tc.desc  : Test LinkVideoResizeFilter with nullptr videoResizeFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkVideoResizeFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->videoResizeFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->LinkVideoResizeFilter(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkMuxerFilter
 * @tc.number: LinkMuxerFilter_001
 * @tc.desc  : Test LinkMuxerFilter with nullptr muxerFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkMuxerFilter_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->muxerFilter_ = nullptr;
    transcoder_->fd_.Reset();
    transcoder_->outputFormatType_ = OutputFormatType::FORMAT_MPEG_4;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_AENC);
    Status ret = transcoder_->LinkMuxerFilter(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test SetOutputFormat
 * @tc.number: SetOutputFormat_001
 * @tc.desc  : Test SetOutputFormat
 */
HWTEST_F(HitranscodeImplUnitTest, SetOutputFormat_001, TestSize.Level1)
{
    OutputFormatType format = OutputFormatType::FORMAT_MPEG_4;
    int32_t ret = transcoder_->SetOutputFormat(format);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(transcoder_->outputFormatType_, format);
}

/**
 * @tc.name  : Test SetObs
 * @tc.number: SetObs_001
 * @tc.desc  : Test SetObs
 */
HWTEST_F(HitranscodeImplUnitTest, SetObs_001, TestSize.Level1)
{
    transcoder_->Init();
    auto mockObs = std::make_shared<MockITransCoderEngineObs>();
    std::weak_ptr<ITransCoderEngineObs> obs = mockObs;
    int32_t ret = transcoder_->SetObs(obs);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetRealPath
 * @tc.number: GetRealPath_001
 * @tc.desc  : Test GetRealPath with file:// prefix
 */
HWTEST_F(HitranscodeImplUnitTest, GetRealPath_001, TestSize.Level1)
{
    std::string url = "file:///data/test/media/test.mp4";
    std::string realPath;
    int32_t ret = transcoder_->GetRealPath(url, realPath);
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
 * @tc.name  : Test GetRealPath
 * @tc.number: GetRealPath_002
 * @tc.desc  : Test GetRealPath with invalid path containing ".."
 */
HWTEST_F(HitranscodeImplUnitTest, GetRealPath_002, TestSize.Level1)
{
    std::string url = "file:///data/../etc/passwd";
    std::string realPath;
    int32_t ret = transcoder_->GetRealPath(url, realPath);
    EXPECT_EQ(ret, MSERR_FILE_ACCESS_FAILED);
}

/**
 * @tc.name  : Test BuildPipeline
 * @tc.number: BuildPipeline_001
 * @tc.desc  : Test BuildPipeline with DECODER_RESIZE_ENCODER mode
 */
HWTEST_F(HitranscodeImplUnitTest, BuildPipeline_001, TestSize.Level1)
{
    transcoder_->videoResizeFilter_ = std::make_shared<Pipeline::VideoResizeFilter>("resize", 
        Pipeline::FilterType::FILTERTYPE_VIDRESIZE);
    Status ret = transcoder_->BuildPipeline(VideoProcessMode::DECODER_RESIZE_ENCODER, 640, 480);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test BuildPipeline
 * @tc.number: BuildPipeline_002
 * @tc.desc  : Test BuildPipeline with default mode
 */
HWTEST_F(HitranscodeImplUnitTest, BuildPipeline_002, TestSize.Level1)
{
    transcoder_->videoEncoderFilter_ = std::make_shared<Pipeline::SurfaceEncoderFilter>("enc", 
        Pipeline::FilterType::FILTERTYPE_VENC);
    transcoder_->videoDecoderFilter_ = std::make_shared<Pipeline::SurfaceDecoderFilter>("dec", 
        Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->BuildPipeline(VideoProcessMode::DECODER_TO_ENCODER, 640, 480);
    EXPECT_EQ(ret, Status::ERROR_GET_INPUT_SURFACE_FAILED);
}

/**
 * @tc.name  : Test DetermineProcessMode
 * @tc.number: DetermineProcessMode_001
 * @tc.desc  : Test DetermineProcessMode with hasResize && hasWatermark
 */
HWTEST_F(HitranscodeImplUnitTest, DetermineProcessMode_001, TestSize.Level1)
{
    transcoder_->videoResizeFilter_ = std::make_shared<Pipeline::VideoResizeFilter>("resize", 
        Pipeline::FilterType::FILTERTYPE_VIDRESIZE);
    transcoder_->waterMarkFilter_ = std::make_shared<Pipeline::Filter>("watermark", 
        Pipeline::FilterType::WATERMARK);
    transcoder_->skipProcessFilterFlag_.isSameVideoResolution = false;
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = true;
    VideoProcessMode mode = transcoder_->DetermineProcessMode();
    EXPECT_EQ(mode, VideoProcessMode::DECODER_RESIZE_WATERMARK_ENCODER);
}

/**
 * @tc.name  : Test DetermineProcessMode
 * @tc.number: DetermineProcessMode_002
 * @tc.desc  : Test DetermineProcessMode with only hasResize
 */
HWTEST_F(HitranscodeImplUnitTest, DetermineProcessMode_002, TestSize.Level1)
{
    transcoder_->videoResizeFilter_ = std::make_shared<Pipeline::VideoResizeFilter>("resize", 
        Pipeline::FilterType::FILTERTYPE_VIDRESIZE);
    transcoder_->waterMarkFilter_ = nullptr;
    transcoder_->skipProcessFilterFlag_.isSameVideoResolution = false;
    VideoProcessMode mode = transcoder_->DetermineProcessMode();
    EXPECT_EQ(mode, VideoProcessMode::DECODER_RESIZE_ENCODER);
}

/**
 * @tc.name  : Test GetModeString
 * @tc.number: GetModeString_001
 * @tc.desc  : Test GetModeString with DECODER_RESIZE_ENCODER
 */
HWTEST_F(HitranscodeImplUnitTest, GetModeString_001, TestSize.Level1)
{
    std::string modeStr = transcoder_->GetModeString(VideoProcessMode::DECODER_RESIZE_ENCODER);
    EXPECT_EQ(modeStr, "Decoder -> Resize -> Encoder");
}

/**
 * @tc.name  : Test GetModeString
 * @tc.number: GetModeString_002
 * @tc.desc  : Test GetModeString with default mode
 */
HWTEST_F(HitranscodeImplUnitTest, GetModeString_002, TestSize.Level1)
{
    std::string modeStr = transcoder_->GetModeString(VideoProcessMode::DECODER_TO_ENCODER);
    EXPECT_EQ(modeStr, "Decoder -> Encoder");
}

/**
 * @tc.name  : Test AddWatermark
 * @tc.number: AddWatermark_001
 * @tc.desc  : Test AddWatermark with nullptr waterMarkBuffer
 */
HWTEST_F(HitranscodeImplUnitTest, AddWatermark_001, TestSize.Level1)
{
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = false;
    transcoder_->waterMarkFilter_ = std::make_shared<Pipeline::Filter>("watermark",
        Pipeline::FilterType::WATERMARK);
    std::shared_ptr<AVBuffer> waterMarkBuffer = nullptr;
    int32_t ret = transcoder_->AddWatermark(waterMarkBuffer, 100, 100);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test AddWatermark
 * @tc.number: AddWatermark_002
 * @tc.desc  : Test AddWatermark with nullptr waterMarkBuffer
 */
HWTEST_F(HitranscodeImplUnitTest, AddWatermark_002, TestSize.Level1)
{
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = false;
    transcoder_->waterMarkFilter_ = std::make_shared<Pipeline::Filter>("watermark",
        Pipeline::FilterType::WATERMARK);
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer();
    int32_t ret = transcoder_->AddWatermark(waterMarkBuffer, 100, 100);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test OnCallback
 * @tc.number: OnCallback_001
 * @tc.desc  : Test OnCallback with NEXT_FILTER_NEEDED and STREAMTYPE_RAW_AUDIO from DEMUXER
 */
HWTEST_F(HitranscodeImplUnitTest, OnCallback_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->audioEncFormat_ = std::make_shared<Meta>();
    transcoder_->audioEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::AUDIO_AAC));
    transcoder_->isAudioTrackLinked_ = false;
    
    auto filter = std::make_shared<Pipeline::Filter>("demuxer", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->OnCallback(filter, Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED,
        Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test OnCallback
 * @tc.number: OnCallback_002
 * @tc.desc  : Test OnCallback with NEXT_FILTER_NEEDED and STREAMTYPE_ENCODED_AUDIO from DEMUXER
 */
HWTEST_F(HitranscodeImplUnitTest, OnCallback_002, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->isAudioTrackLinked_ = false;
    
    auto filter = std::make_shared<Pipeline::Filter>("demuxer", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->OnCallback(filter, Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED,
        Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test OnCallback
 * @tc.number: OnCallback_003
 * @tc.desc  : Test OnCallback with NEXT_FILTER_NEEDED and STREAMTYPE_ENCODED_VIDEO from DEMUXER
 */
HWTEST_F(HitranscodeImplUnitTest, OnCallback_003, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->isVideoTrackLinked_ = false;
    
    auto filter = std::make_shared<Pipeline::Filter>("demuxer", Pipeline::FilterType::FILTERTYPE_DEMUXER);
    Status ret = transcoder_->OnCallback(filter, Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED,
        Pipeline::StreamType::STREAMTYPE_ENCODED_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test OnCallback
 * @tc.number: OnCallback_004
 * @tc.desc  : Test OnCallback with nullptr filter
 */
HWTEST_F(HitranscodeImplUnitTest, OnCallback_004, TestSize.Level1)
{
    std::shared_ptr<Pipeline::Filter> filter = nullptr;
    Status ret = transcoder_->OnCallback(filter, Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED,
        Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test ConfigureVideoWidthHeight
 * @tc.number: ConfigureVideoWidthHeight_001
 * @tc.desc  : Test ConfigureVideoWidthHeight with width = -1 and height = -1
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoWidthHeight_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoRectangle videoRectangle(-1, -1);
    transcoder_->ConfigureVideoWidthHeight(videoRectangle);
    int32_t width = 0;
    int32_t height = 0;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_WIDTH, width));
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, height));
}

/**
 * @tc.name  : Test ConfigureColorSpace
 * @tc.number: ConfigureColorSpace_001
 * @tc.desc  : Test ConfigureColorSpace with valid colorSpaceFmt
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureColorSpace_001, TestSize.Level1)
{
    VideoColorSpace colSpa(TranscoderColorSpace::TRANSCODER_COLORSPACE_BT709_LIMIT);
    Status ret = transcoder_->ConfigureColorSpace(colSpa);
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoBitrate
 * @tc.number: ConfigureVideoBitrate_001
 * @tc.desc  : Test ConfigureVideoBitrate with minNum > HEIGHT_1080
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrate_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1920);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(1088);
    transcoder_->videoEncFormat_->Set<Tag::MEDIA_BITRATE>(static_cast<int64_t>(0));
    Status ret = transcoder_->ConfigureVideoBitrate();
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoBitrate
 * @tc.number: ConfigureVideoBitrate_002
 * @tc.desc  : Test ConfigureVideoBitrate with HEIGHT_480 < minNum <= HEIGHT_720
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrate_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(540);
    transcoder_->videoEncFormat_->Set<Tag::MEDIA_BITRATE>(static_cast<int64_t>(0));
    Status ret = transcoder_->ConfigureVideoBitrate();
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoBitrate
 * @tc.number: ConfigureVideoBitrate_003
 * @tc.desc  : Test ConfigureVideoBitrate with minNum <= HEIGHT_480
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoBitrate_003, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(320);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(240);
    transcoder_->videoEncFormat_->Set<Tag::MEDIA_BITRATE>(static_cast<int64_t>(0));
    Status ret = transcoder_->ConfigureVideoBitrate();
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name  : Test ConfigureVideoDefaultEncFormat
 * @tc.number: ConfigureVideoDefaultEncFormat_001
 * @tc.desc  : Test ConfigureVideoDefaultEncFormat with non-HEVC/AVC mime
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoDefaultEncFormat_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_MPEG4));
    transcoder_->ConfigureVideoDefaultEncFormat();
    std::string mime;
    transcoder_->videoEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::VIDEO_AVC);
}

/**
 * @tc.name  : Test ConfigureAudioDefaultEncFormat
 * @tc.number: ConfigureAudioDefaultEncFormat_001
 * @tc.desc  : Test ConfigureAudioDefaultEncFormat with non-AAC mime
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureAudioDefaultEncFormat_001, TestSize.Level1)
{
    transcoder_->audioEncFormat_ = std::make_shared<Meta>();
    transcoder_->audioEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::AUDIO_MPEG));
    transcoder_->ConfigureAudioDefaultEncFormat();
    std::string mime;
    transcoder_->audioEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::AUDIO_AAC);
}

/**
 * @tc.name  : Test SkipAudioDecAndEnc
 * @tc.number: SkipAudioDecAndEnc_001
 * @tc.desc  : Test SkipAudioDecAndEnc with demuxerFilter_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, SkipAudioDecAndEnc_001, TestSize.Level1)
{
    transcoder_->demuxerFilter_ = nullptr;
    transcoder_->SkipAudioDecAndEnc();
    EXPECT_FALSE(transcoder_->skipProcessFilterFlag_.CanSkipAudioDecAndEncFilter());
}

/**
 * @tc.name  : Test LinkWaterMark
 * @tc.number: LinkWaterMark_001
 * @tc.desc  : Test LinkWaterMark with nullptr waterMarkFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkWaterMark_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->waterMarkFilter_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->LinkWaterMark(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test LinkWaterMark
 * @tc.number: LinkWaterMark_002
 * @tc.desc  : Test LinkWaterMark with nullptr pipeline_
 */
HWTEST_F(HitranscodeImplUnitTest, LinkWaterMark_002, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = std::make_shared<MockTransCoderEventReceiver>(
        transcoder_.get(), "testTranscoderId");
    transcoder_->transCoderFilterCallback_ = std::make_shared<MockTransCoderFilterCallback>(
        transcoder_.get());
    transcoder_->pipeline_ = nullptr;
    auto preFilter = std::make_shared<Pipeline::Filter>("preFilter", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->LinkWaterMark(preFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test ConnectDecoderToEncoder
 * @tc.number: ConnectDecoderToEncoder_001
 * @tc.desc  : Test ConnectDecoderToEncoder with nullptr videoEncoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, ConnectDecoderToEncoder_001, TestSize.Level1)
{
    transcoder_->videoEncoderFilter_ = nullptr;
    transcoder_->videoDecoderFilter_ = std::make_shared<Pipeline::SurfaceDecoderFilter>("dec", 
        Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    Status ret = transcoder_->ConnectDecoderToEncoder();
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test ConnectDecoderToEncoder
 * @tc.number: ConnectDecoderToEncoder_002
 * @tc.desc  : Test ConnectDecoderToEncoder with nullptr videoDecoderFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, ConnectDecoderToEncoder_002, TestSize.Level1)
{
    transcoder_->videoEncoderFilter_ = std::make_shared<Pipeline::SurfaceEncoderFilter>("enc", 
        Pipeline::FilterType::FILTERTYPE_VENC);
    transcoder_->videoDecoderFilter_ = nullptr;
    Status ret = transcoder_->ConnectDecoderToEncoder();
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test ConnectDecoderResizeEncoder
 * @tc.number: ConnectDecoderResizeEncoder_001
 * @tc.desc  : Test ConnectDecoderResizeEncoder with nullptr videoResizeFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, ConnectDecoderResizeEncoder_001, TestSize.Level1)
{
    transcoder_->videoEncoderFilter_ = std::make_shared<Pipeline::SurfaceEncoderFilter>("enc", 
        Pipeline::FilterType::FILTERTYPE_VENC);
    transcoder_->videoDecoderFilter_ = std::make_shared<Pipeline::SurfaceDecoderFilter>("dec", 
        Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    transcoder_->videoResizeFilter_ = nullptr;
    Status ret = transcoder_->ConnectDecoderResizeEncoder(640, 480);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test ConnectDecoderWatermarkEncoder
 * @tc.number: ConnectDecoderWatermarkEncoder_001
 * @tc.desc  : Test ConnectDecoderWatermarkEncoder with nullptr waterMarkFilter_
 */
HWTEST_F(HitranscodeImplUnitTest, ConnectDecoderWatermarkEncoder_001, TestSize.Level1)
{
    transcoder_->videoEncoderFilter_ = std::make_shared<Pipeline::SurfaceEncoderFilter>("enc", 
        Pipeline::FilterType::FILTERTYPE_VENC);
    transcoder_->videoDecoderFilter_ = std::make_shared<Pipeline::SurfaceDecoderFilter>("dec", 
        Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    transcoder_->waterMarkFilter_ = nullptr;
    Status ret = transcoder_->ConnectDecoderWatermarkEncoder(640, 480);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name  : Test SetSurfacePipeline
 * @tc.number: SetSurfacePipeline_001
 * @tc.desc  : Test SetSurfacePipeline
 */
HWTEST_F(HitranscodeImplUnitTest, SetSurfacePipeline_001, TestSize.Level1)
{
    transcoder_->isExistVideoTrack_ = true;
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(640);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(480);
    Status ret = transcoder_->SetSurfacePipeline(640, 480);
    EXPECT_NE(ret, Status::OK);
}

/**
 * @tc.name  : Test Prepare
 * @tc.number: Prepare_001
 * @tc.desc  : Test Prepare with invalid output resolution
 */
HWTEST_F(HitranscodeImplUnitTest, Prepare_001, TestSize.Level1)
{
    transcoder_->isExistVideoTrack_ = true;
    transcoder_->inputVideoWidth_ = 640;
    transcoder_->inputVideoHeight_ = 480;
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1920);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(1080);
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, MSERR_INVALID_OUTPUT_RESOLUTION);
}

/**
 * @tc.name  : Test Prepare
 * @tc.number: Prepare_002
 * @tc.desc  : Test Prepare with width < MINIMUM_WIDTH_HEIGHT
 */
HWTEST_F(HitranscodeImplUnitTest, Prepare_002, TestSize.Level1)
{
    transcoder_->isExistVideoTrack_ = true;
    transcoder_->inputVideoWidth_ = 640;
    transcoder_->inputVideoHeight_ = 480;
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(100);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(200);
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, MSERR_INVALID_OUTPUT_RESOLUTION);
}

/**
 * @tc.name  : Test Prepare
 * @tc.number: Prepare_003
 * @tc.desc  : Test Prepare with pipeline Prepare failed
 */
HWTEST_F(HitranscodeImplUnitTest, Prepare_003, TestSize.Level1)
{
    transcoder_->isExistVideoTrack_ = true;
    transcoder_->inputVideoWidth_ = 640;
    transcoder_->inputVideoHeight_ = 480;
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(640);
    transcoder_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(480);
    transcoder_->pipeline_->filters_.push_back(demuxerFilter_);
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(MSERR_INVALID_VAL, ret);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderFormat
 * @tc.number: ConfigureVideoEncoderFormat_001
 * @tc.desc  : Test ConfigureVideoEncoderFormat with MPEG4
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderFormat_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoEnc videoEnc(VideoCodecFormat::MPEG4);
    transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    std::string mime;
    transcoder_->videoEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::VIDEO_MPEG4);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderFormat
 * @tc.number: ConfigureVideoEncoderFormat_002
 * @tc.desc  : Test ConfigureVideoEncoderFormat with H265
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderFormat_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoEnc videoEnc(VideoCodecFormat::H265);
    transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    std::string mime;
    transcoder_->videoEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::VIDEO_HEVC);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderFormat
 * @tc.number: ConfigureVideoEncoderFormat_003
 * @tc.desc  : Test ConfigureVideoEncoderFormat with default case
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderFormat_003, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoEnc videoEnc(VideoCodecFormat::H264);
    transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    std::string mime;
    transcoder_->videoEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::VIDEO_AVC);
}

/**
 * @tc.name  : Test Pause
 * @tc.number: Pause_002
 * @tc.desc  : Test Pause with startTime_ == -1
 */
HWTEST_F(HitranscodeImplUnitTest, Pause_002, TestSize.Level1)
{
    transcoder_->callbackLooper_ = std::make_shared<HiTransCoderCallbackLooper>();
    transcoder_->pipeline_ = std::make_shared<Pipeline::Pipeline>();
    transcoder_->startTime_ = -1;
    int32_t ret = transcoder_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetAudioEncFormat
 * @tc.number: GetAudioEncFormat_001
 * @tc.desc  : Test GetAudioEncFormat with AUDIO_MPEG
 */
HWTEST_F(HitranscodeImplUnitTest, GetAudioEncFormat_001, TestSize.Level1)
{
    const char* mime = transcoder_->GetAudioEncFormat(AudioCodecFormat::AUDIO_MPEG);
    EXPECT_STREQ(mime, Plugins::MimeType::AUDIO_MPEG);
}

/**
 * @tc.name  : Test GetAudioEncFormat
 * @tc.number: GetAudioEncFormat_002
 * @tc.desc  : Test GetAudioEncFormat with AUDIO_RAW
 */
HWTEST_F(HitranscodeImplUnitTest, GetAudioEncFormat_002, TestSize.Level1)
{
    const char* mime = transcoder_->GetAudioEncFormat(AudioCodecFormat::AUDIO_RAW);
    EXPECT_STREQ(mime, Plugins::MimeType::AUDIO_RAW);
}

/**
 * @tc.name  : Test GetAudioEncFormat
 * @tc.number: GetAudioEncFormat_003
 * @tc.desc  : Test GetAudioEncFormat with default case
 */
HWTEST_F(HitranscodeImplUnitTest, GetAudioEncFormat_003, TestSize.Level1)
{
    const char* mime = transcoder_->GetAudioEncFormat(AudioCodecFormat::AUDIO_AMR_WB);
    EXPECT_STREQ(mime, Plugins::MimeType::AUDIO_AMR_WB);
}

/**
 * @tc.name  : Test Configure
 * @tc.number: Configure_001
 * @tc.desc  : Test Configure with VIDEO_BITRATE bitRate <= 0
 */
HWTEST_F(HitranscodeImplUnitTest, Configure_001, TestSize.Level1)
{
    VideoBitRate videoBitrate(0);
    int32_t ret = transcoder_->Configure(videoBitrate);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test Configure
 * @tc.number: Configure_002
 * @tc.desc  : Test Configure with VIDEO_BITRATE valid bitRate
 */
HWTEST_F(HitranscodeImplUnitTest, Configure_002, TestSize.Level1)
{
    VideoBitRate videoBitrate(2000000);
    int32_t ret = transcoder_->Configure(videoBitrate);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(transcoder_->isConfiguredVideoBitrate_);
}

/**
 * @tc.name  : Test Init
 * @tc.number: Init_001
 * @tc.desc  : Test Init
 */
HWTEST_F(HitranscodeImplUnitTest, Init_001, TestSize.Level1)
{
    transcoder_->transCoderEventReceiver_ = nullptr;
    transcoder_->transCoderFilterCallback_ = nullptr;
    int32_t ret = transcoder_->Init();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetInstanceId
 * @tc.number: SetInstanceId_001
 * @tc.desc  : Test SetInstanceId
 */
HWTEST_F(HitranscodeImplUnitTest, SetInstanceId_001, TestSize.Level1)
{
    uint64_t instanceId = 12345;
    transcoder_->SetInstanceId(instanceId);
    EXPECT_EQ(transcoder_->instanceId_, instanceId);
}

/**
 * @tc.name  : Test GetCurrentTime
 * @tc.number: GetCurrentTime_001
 * @tc.desc  : Test GetCurrentTime with muxerFilter_ == nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, GetCurrentTime_001, TestSize.Level1)
{
    transcoder_->muxerFilter_ = nullptr;
    int32_t currentPositionMs = 0;
    int32_t ret = transcoder_->GetCurrentTime(currentPositionMs);
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name  : Test GetDuration
 * @tc.number: GetDuration_001
 * @tc.desc  : Test GetDuration
 */
HWTEST_F(HitranscodeImplUnitTest, GetDuration_001, TestSize.Level1)
{
    transcoder_->durationMs_ = 5000;
    int32_t durationMs = 0;
    int32_t ret = transcoder_->GetDuration(durationMs);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(durationMs, 5000);
}

/**
 * @tc.name  : Test CollectionErrorInfo
 * @tc.number: CollectionErrorInfo_001
 * @tc.desc  : Test CollectionErrorInfo
 */
HWTEST_F(HitranscodeImplUnitTest, CollectionErrorInfo_001, TestSize.Level1)
{
    int32_t errCode = MSERR_INVALID_VAL;
    std::string errMsg = "Test error";
    transcoder_->CollectionErrorInfo(errCode, errMsg);
    EXPECT_EQ(transcoder_->errCode_, errCode);
    EXPECT_EQ(transcoder_->errMsg_, errMsg);
}

/**
 * @tc.name  : Test SetTimeRange
 * @tc.number: SetTimeRange_001
 * @tc.desc  : Test SetTimeRange sets startTime and endTime
 */
HWTEST_F(HitranscodeImplUnitTest, SetTimeRange_001, TestSize.Level1)
{
    int64_t start = 1000;
    int64_t end = 5000;
    transcoder_->SetTimeRange(start, end);
    EXPECT_EQ(transcoder_->startTimeMs_, start);
    EXPECT_EQ(transcoder_->endTimeMs_, end);
}

/**
 * @tc.name: Test ValidateTimeRange_0100
 * @tc.desc: ValidateTimeRange returns OK when both startTime and endTime are -1 (no range set)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRange_0100, TestSize.Level1)
{
    transcoder_->startTimeMs_ = -1;
    transcoder_->endTimeMs_ = -1;
    int32_t ret = transcoder_->ValidateTimeRange();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: Test ValidateTimeRange_0200
 * @tc.desc: ValidateTimeRange returns START_ERROR when startTime >= source duration
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRange_0200, TestSize.Level1)
{
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    transcoder_->durationMs_ = 3000;
    transcoder_->startTimeMs_ = 3000;
    int32_t ret = transcoder_->ValidateTimeRange();
    EXPECT_EQ(ret, MSERR_TIME_RANGE_START_ERROR_401);
}

/**
 * @tc.name: Test ValidateTimeRange_0300
 * @tc.desc: ValidateTimeRange returns END_ERROR when endTime > source duration
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRange_0300, TestSize.Level1)
{
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    transcoder_->durationMs_ = 3000;
    transcoder_->endTimeMs_ = 4000;
    int32_t ret = transcoder_->ValidateTimeRange();
    EXPECT_EQ(ret, MSERR_TIME_RANGE_END_ERROR_401);
}

/**
 * @tc.name: Test ValidateTimeRangeStartEnd_0100
 * @tc.desc: ValidateTimeRangeStartEnd returns INVALID when startTime >= endTime
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRangeStartEnd_0100, TestSize.Level1)
{
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    transcoder_->startTimeMs_ = 5000;
    transcoder_->endTimeMs_ = 5000;
    int32_t ret = transcoder_->ValidateTimeRangeStartEnd();
    EXPECT_EQ(ret, MSERR_TIME_RANGE_INVALID_ERROR_401);
}

/**
 * @tc.name: Test ValidateTimeRangeStartEnd_0200
 * @tc.desc: ValidateTimeRangeStartEnd returns INVALID when time slice < 100ms (strictly below boundary)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRangeStartEnd_0200, TestSize.Level1)
{
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    transcoder_->startTimeMs_ = 1000;
    transcoder_->endTimeMs_ = 1050;  // 50ms < 100ms
    int32_t ret = transcoder_->ValidateTimeRangeStartEnd();
    EXPECT_EQ(ret, MSERR_TIME_RANGE_INVALID_ERROR_401);
}

/**
 * @tc.name: Test ValidateTimeRangeStartEnd_0250
 * @tc.desc: ValidateTimeRangeStartEnd returns OK at the 100ms boundary (inclusive)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRangeStartEnd_0250, TestSize.Level1)
{
    transcoder_->startTimeMs_ = 1000;
    transcoder_->endTimeMs_ = 1100;  // exactly 100ms, allowed
    int32_t ret = transcoder_->ValidateTimeRangeStartEnd();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: Test ValidateTimeRangeStartEnd_0300
 * @tc.desc: ValidateTimeRangeStartEnd returns OK when start < 0 (only end set, not reaching the
 *         start>=end branch because of the early-return on startTimeMs_ < 0)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRangeStartEnd_0300, TestSize.Level1)
{
    transcoder_->startTimeMs_ = -1;
    transcoder_->endTimeMs_ = 5000;
    int32_t ret = transcoder_->ValidateTimeRangeStartEnd();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: Test ValidateTimeRange_0400
 * @tc.desc: ValidateTimeRange returns OK when both start and end are positive, valid
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateTimeRange_0400, TestSize.Level1)
{
    transcoder_->durationMs_ = 10000;
    transcoder_->startTimeMs_ = 1000;
    transcoder_->endTimeMs_ = 5000;
    int32_t ret = transcoder_->ValidateTimeRange();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: Test PropagateTimeRangeToFilters_0100
 * @tc.desc: PropagateTimeRangeToFilters does nothing when startTime and endTime are both -1
 */
HWTEST_F(HitranscodeImplUnitTest, PropagateTimeRangeToFilters_0100, TestSize.Level1)
{
    transcoder_->startTimeMs_ = -1;
    transcoder_->endTimeMs_ = -1;
    EXPECT_NO_THROW(transcoder_->PropagateTimeRangeToFilters());
    // Both -1 means no time range set, the function should early-return without
    // touching state. Verify the inputs remain unchanged after the call.
    EXPECT_EQ(transcoder_->startTimeMs_, -1);
    EXPECT_EQ(transcoder_->endTimeMs_, -1);
}

// ===================== HDR 相关测试 =====================

/**
 * @tc.name  : Test ConfigureDestHdrMode
 * @tc.number: ConfigureDestHdrMode_001
 * @tc.desc  : Test ConfigureDestHdrMode with SDR mode
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureDestHdrMode_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoDestHdrMode destHdrMode(DestHDRMode::SDR);
    Status ret = transcoder_->ConfigureDestHdrMode(destHdrMode);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->destHdrMode_, static_cast<int32_t>(DestHDRMode::SDR));
    int32_t mode = -1;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::AV_TRANSCODER_DEST_HDR_MODE, mode));
    EXPECT_EQ(mode, static_cast<int32_t>(DestHDRMode::SDR));
}

/**
 * @tc.name  : Test ConfigureDestHdrMode
 * @tc.number: ConfigureDestHdrMode_002
 * @tc.desc  : Test ConfigureDestHdrMode with AUTO_HDR_VIVID mode
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureDestHdrMode_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoDestHdrMode destHdrMode(DestHDRMode::AUTO_HDR_VIVID);
    Status ret = transcoder_->ConfigureDestHdrMode(destHdrMode);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(transcoder_->destHdrMode_, static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID));
    int32_t mode = -1;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::AV_TRANSCODER_DEST_HDR_MODE, mode));
    EXPECT_EQ(mode, static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID));
}

/**
 * @tc.name  : Test QuerySrcIsHdrVivid
 * @tc.number: QuerySrcIsHdrVivid_001
 * @tc.desc  : Test QuerySrcIsHdrVivid with nullptr srcVideoFormat_
 */
HWTEST_F(HitranscodeImplUnitTest, QuerySrcIsHdrVivid_001, TestSize.Level1)
{
    transcoder_->srcVideoFormat_ = nullptr;
    EXPECT_FALSE(transcoder_->QuerySrcIsHdrVivid());
}

/**
 * @tc.name  : Test QuerySrcIsHdrVivid
 * @tc.number: QuerySrcIsHdrVivid_002
 * @tc.desc  : Test QuerySrcIsHdrVivid with srcVideoFormat_ not containing HDR Vivid flag
 */
HWTEST_F(HitranscodeImplUnitTest, QuerySrcIsHdrVivid_002, TestSize.Level1)
{
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    EXPECT_FALSE(transcoder_->QuerySrcIsHdrVivid());
}

/**
 * @tc.name  : Test QuerySrcIsHdrVivid
 * @tc.number: QuerySrcIsHdrVivid_003
 * @tc.desc  : Test QuerySrcIsHdrVivid with srcVideoFormat_ containing HDR Vivid flag = true
 */
HWTEST_F(HitranscodeImplUnitTest, QuerySrcIsHdrVivid_003, TestSize.Level1)
{
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    EXPECT_TRUE(transcoder_->QuerySrcIsHdrVivid());
}

/**
 * @tc.name  : Test QuerySrcIsHdrVivid
 * @tc.number: QuerySrcIsHdrVivid_004
 * @tc.desc  : Test QuerySrcIsHdrVivid with srcVideoFormat_ containing HDR Vivid flag = false
 */
HWTEST_F(HitranscodeImplUnitTest, QuerySrcIsHdrVivid_004, TestSize.Level1)
{
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(false);
    EXPECT_FALSE(transcoder_->QuerySrcIsHdrVivid());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_001
 * @tc.desc  : Test IsHdrOutput with nullptr videoEncFormat_
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = nullptr;
    EXPECT_FALSE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_002
 * @tc.desc  : Test IsHdrOutput with explicit HDR color space set
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT));
    EXPECT_TRUE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_003
 * @tc.desc  : Test IsHdrOutput with explicit SDR color space set
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_003, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT));
    EXPECT_FALSE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_004
 * @tc.desc  : Test IsHdrOutput with AUTO_HDR_VIVID and source is HDRVivid
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_004, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    EXPECT_TRUE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_005
 * @tc.desc  : Test IsHdrOutput with AUTO_HDR_VIVID but source is not HDRVivid
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_005, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    EXPECT_FALSE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test IsHdrOutput
 * @tc.number: IsHdrOutput_006
 * @tc.desc  : Test IsHdrOutput with SDR mode and no explicit color space
 */
HWTEST_F(HitranscodeImplUnitTest, IsHdrOutput_006, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::SDR);
    EXPECT_FALSE(transcoder_->IsHdrOutput());
}

/**
 * @tc.name  : Test ValidateHdrCodecCompatibility
 * @tc.number: ValidateHdrCodecCompatibility_001
 * @tc.desc  : Test ValidateHdrCodecCompatibility with SDR mode (skip check)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrCodecCompatibility_001, TestSize.Level1)
{
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::SDR);
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_AVC));
    EXPECT_EQ(transcoder_->ValidateHdrCodecCompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrCodecCompatibility
 * @tc.number: ValidateHdrCodecCompatibility_002
 * @tc.desc  : Test ValidateHdrCodecCompatibility with AUTO_HDR_VIVID but source not HDRVivid (skip check)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrCodecCompatibility_002, TestSize.Level1)
{
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_AVC));
    EXPECT_EQ(transcoder_->ValidateHdrCodecCompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrCodecCompatibility
 * @tc.number: ValidateHdrCodecCompatibility_003
 * @tc.desc  : Test ValidateHdrCodecCompatibility with AUTO_HDR_VIVID, source HDRVivid, HEVC codec (OK)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrCodecCompatibility_003, TestSize.Level1)
{
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    EXPECT_EQ(transcoder_->ValidateHdrCodecCompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrCodecCompatibility
 * @tc.number: ValidateHdrCodecCompatibility_004
 * @tc.desc  : Test ValidateHdrCodecCompatibility with AUTO_HDR_VIVID, source HDRVivid, AVC codec (mismatch)
 *             Should return MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrCodecCompatibility_004, TestSize.Level1)
{
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_AVC));
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    int32_t ret = transcoder_->ValidateHdrCodecCompatibility();
    EXPECT_EQ(ret, MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401);
    EXPECT_EQ(transcoder_->errCode_, MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401);
}

/**
 * @tc.name  : Test ValidateHdrCodecCompatibility
 * @tc.number: ValidateHdrCodecCompatibility_005
 * @tc.desc  : Test ValidateHdrCodecCompatibility with AUTO_HDR_VIVID, source HDRVivid, nullptr videoEncFormat_
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrCodecCompatibility_005, TestSize.Level1)
{
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    transcoder_->videoEncFormat_ = nullptr;
    EXPECT_EQ(transcoder_->ValidateHdrCodecCompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrWatermarkIncompatibility
 * @tc.number: ValidateHdrWatermarkIncompatibility_001
 * @tc.desc  : Test ValidateHdrWatermarkIncompatibility with SDR output and watermark (OK)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrWatermarkIncompatibility_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::SDR);
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = true;
    EXPECT_EQ(transcoder_->ValidateHdrWatermarkIncompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrWatermarkIncompatibility
 * @tc.number: ValidateHdrWatermarkIncompatibility_002
 * @tc.desc  : Test ValidateHdrWatermarkIncompatibility with HDR output but no watermark (OK)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrWatermarkIncompatibility_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = false;
    EXPECT_EQ(transcoder_->ValidateHdrWatermarkIncompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ValidateHdrWatermarkIncompatibility
 * @tc.number: ValidateHdrWatermarkIncompatibility_003
 * @tc.desc  : Test ValidateHdrWatermarkIncompatibility with HDR output and watermark (incompatible)
 *             Should return MSERR_HDR_VIVID_WATERMARK_ERROR_5400106
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrWatermarkIncompatibility_003, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = true;
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    int32_t ret = transcoder_->ValidateHdrWatermarkIncompatibility();
    EXPECT_EQ(ret, MSERR_HDR_VIVID_WATERMARK_ERROR_5400106);
    EXPECT_EQ(transcoder_->errCode_, MSERR_HDR_VIVID_WATERMARK_ERROR_5400106);
}

/**
 * @tc.name  : Test ValidateHdrWatermarkIncompatibility
 * @tc.number: ValidateHdrWatermarkIncompatibility_004
 * @tc.desc  : Test ValidateHdrWatermarkIncompatibility with explicit HDR color space and watermark (incompatible)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrWatermarkIncompatibility_004, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT));
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = true;
    transcoder_->ignoreError_ = true;  // Suppress OnEvent side effects
    int32_t ret = transcoder_->ValidateHdrWatermarkIncompatibility();
    EXPECT_EQ(ret, MSERR_HDR_VIVID_WATERMARK_ERROR_5400106);
}

/**
 * @tc.name  : Test ValidateHdrWatermarkIncompatibility
 * @tc.number: ValidateHdrWatermarkIncompatibility_005
 * @tc.desc  : Test ValidateHdrWatermarkIncompatibility with explicit SDR color space and watermark (OK)
 */
HWTEST_F(HitranscodeImplUnitTest, ValidateHdrWatermarkIncompatibility_005, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT));
    transcoder_->skipProcessFilterFlag_.isAddWaterMark = true;
    EXPECT_EQ(transcoder_->ValidateHdrWatermarkIncompatibility(), MSERR_OK);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_001
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with nullptr videoEncFormat_ (skip)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = nullptr;
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_002
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with explicit SDR color space (skip HDR config)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT));
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    // Should not set HDR Vivid flag
    bool isHdrVivid = false;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_003
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with SDR mode (skip HDR config)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_003, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::SDR);
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    bool isHdrVivid = false;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_004
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with AUTO_HDR_VIVID but source not HDRVivid (skip)
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_004, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    bool isHdrVivid = false;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_005
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with AUTO_HDR_VIVID and source HDRVivid
 *             Should configure HDR output with VIDEO_IS_HDR_VIVID=true
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_005, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    bool isHdrVivid = false;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
    EXPECT_TRUE(isHdrVivid);
    // Should set HEVC Main10 profile
    Plugins::HEVCProfile profile = Plugins::HEVCProfile::HEVC_PROFILE_MAIN;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_H265_PROFILE, profile));
    EXPECT_EQ(profile, Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    // Should set AV_TRANSCODER_DST_COLOR_SPACE
    int32_t colorSpace = 0;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::AV_TRANSCODER_DST_COLOR_SPACE, colorSpace));
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_006
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with explicit HDR color space (BT2020_HLG_LIMIT)
 *             Should configure HDR color aspects via explicit path
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_006, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT));
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    bool isHdrVivid = false;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
    EXPECT_TRUE(isHdrVivid);
    // Should set color primaries to BT2020
    Plugins::ColorPrimary primaries = Plugins::ColorPrimary::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_PRIMARIES, primaries));
    EXPECT_EQ(primaries, Plugins::ColorPrimary::BT2020);
    // Should set transfer to HLG
    Plugins::TransferCharacteristic transfer = Plugins::TransferCharacteristic::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_TRC, transfer));
    EXPECT_EQ(transfer, Plugins::TransferCharacteristic::HLG);
    // Should set matrix to BT2020_NCL
    Plugins::MatrixCoefficient matrix = Plugins::MatrixCoefficient::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_MATRIX_COEFF, matrix));
    EXPECT_EQ(matrix, Plugins::MatrixCoefficient::BT2020_NCL);
    // Should set range to limited (false)
    bool colorRange = true;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_RANGE, colorRange));
    EXPECT_FALSE(colorRange);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderHdrFormat
 * @tc.number: ConfigureVideoEncoderHdrFormat_007
 * @tc.desc  : Test ConfigureVideoEncoderHdrFormat with explicit HDR color space but source not HDRVivid
 *             Should still configure HDR color aspects but not set VIDEO_IS_HDR_VIVID
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderHdrFormat_007, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    transcoder_->videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT));
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    // Source is not HDRVivid, so VIDEO_IS_HDR_VIVID should not be set
    bool isHdrVivid = false;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
    // But HDR color aspects should still be configured
    Plugins::TransferCharacteristic transfer = Plugins::TransferCharacteristic::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_TRC, transfer));
    EXPECT_EQ(transfer, Plugins::TransferCharacteristic::PQ);
}

/**
 * @tc.name  : Test ConfigureHdrByAutoHdrVivid
 * @tc.number: ConfigureHdrByAutoHdrVivid_001
 * @tc.desc  : Test ConfigureHdrByAutoHdrVivid with source color aspects available
 *             (indirectly tested via ConfigureVideoEncoderHdrFormat_005)
 *             This test verifies default HDR values when srcVideoFormat_ is nullptr
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureHdrByAutoHdrVivid_001, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = nullptr;
    // Source is nullptr so QuerySrcIsHdrVivid returns false, HDR config is skipped
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    bool isHdrVivid = false;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid));
}

/**
 * @tc.name  : Test ConfigureHdrByAutoHdrVivid
 * @tc.number: ConfigureHdrByAutoHdrVivid_002
 * @tc.desc  : Test ConfigureHdrByAutoHdrVivid with source providing custom color aspects
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureHdrByAutoHdrVivid_002, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    transcoder_->videoEncFormat_->Set<Tag::MIME_TYPE>(std::string(Plugins::MimeType::VIDEO_HEVC));
    transcoder_->destHdrMode_ = static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID);
    transcoder_->srcVideoFormat_ = std::make_shared<Meta>();
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    // Set custom source color aspects
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_COLOR_PRIMARIES>(Plugins::ColorPrimary::P3D65);
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_COLOR_TRC>(Plugins::TransferCharacteristic::PQ);
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_COLOR_MATRIX_COEFF>(
        Plugins::MatrixCoefficient::BT2020_NCL);
    transcoder_->srcVideoFormat_->Set<Tag::VIDEO_COLOR_RANGE>(true);
    EXPECT_NO_THROW(transcoder_->ConfigureVideoEncoderHdrFormat());
    // Should copy source color aspects to videoEncFormat_
    Plugins::ColorPrimary primaries = Plugins::ColorPrimary::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_PRIMARIES, primaries));
    EXPECT_EQ(primaries, Plugins::ColorPrimary::P3D65);
    Plugins::TransferCharacteristic transfer = Plugins::TransferCharacteristic::UNSPECIFIED;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_TRC, transfer));
    EXPECT_EQ(transfer, Plugins::TransferCharacteristic::PQ);
    bool colorRange = false;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(Tag::VIDEO_COLOR_RANGE, colorRange));
    EXPECT_TRUE(colorRange);
}

/**
 * @tc.name  : Test ConfigureVideoEncoderFormat with HDR
 * @tc.number: ConfigureVideoEncoderFormat_004
 * @tc.desc  : Test ConfigureVideoEncoderFormat with H265 (HEVC) for HDR readiness
 */
HWTEST_F(HitranscodeImplUnitTest, ConfigureVideoEncoderFormat_004, TestSize.Level1)
{
    transcoder_->videoEncFormat_ = std::make_shared<Meta>();
    VideoEnc videoEnc(VideoCodecFormat::H265);
    transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    std::string mime;
    transcoder_->videoEncFormat_->GetData(Tag::MIME_TYPE, mime);
    EXPECT_EQ(mime, Plugins::MimeType::VIDEO_HEVC);
}

/**
 * @tc.name  : Test CollectionErrorInfo with HDR error codes
 * @tc.number: CollectionErrorInfo_002
 * @tc.desc  : Test CollectionErrorInfo with MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401
 */
HWTEST_F(HitranscodeImplUnitTest, CollectionErrorInfo_002, TestSize.Level1)
{
    transcoder_->CollectionErrorInfo(MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401,
        "HDR Vivid output requires HEVC codec");
    EXPECT_EQ(transcoder_->errCode_, MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401);
}

/**
 * @tc.name  : Test CollectionErrorInfo with HDR error codes
 * @tc.number: CollectionErrorInfo_003
 * @tc.desc  : Test CollectionErrorInfo with MSERR_HDR_VIVID_WATERMARK_ERROR_5400106
 */
HWTEST_F(HitranscodeImplUnitTest, CollectionErrorInfo_003, TestSize.Level1)
{
    transcoder_->CollectionErrorInfo(MSERR_HDR_VIVID_WATERMARK_ERROR_5400106,
        "Watermark is not supported for HDR Vivid output");
    EXPECT_EQ(transcoder_->errCode_, MSERR_HDR_VIVID_WATERMARK_ERROR_5400106);
}
} // namespace Media
} // namespace OHOS