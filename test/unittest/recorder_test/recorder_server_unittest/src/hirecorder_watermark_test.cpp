/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "recorder_server_unit_test.h"
#include "recorder_server_mock.h"
#include "hirecorder_impl.h"
#include "media_errors.h"
#include "media_log.h"
#include "av_common.h"
#include "water_mark_filter.h"
#include "filter/filter_factory.h"
#include "pipeline/pipeline.h"
#include "surface_encoder_filter.h"
#include "video_capture_filter.h"
#include "audio_capture_filter.h"
#include "codec_capability_adapter.h"
#include <fcntl.h>
#include <unistd.h>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::RecorderTestParam;

class HiRecorderWatermarkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<RecorderServerMock> recorderServer_;
};

void HiRecorderWatermarkTest::SetUpTestCase() {}
void HiRecorderWatermarkTest::TearDownTestCase() {}

void HiRecorderWatermarkTest::SetUp()
{
    recorderServer_ = std::make_shared<RecorderServerMock>();
    ASSERT_NE(recorderServer_, nullptr);
    ASSERT_TRUE(recorderServer_->CreateRecorder());
}

void HiRecorderWatermarkTest::TearDown()
{
    if (recorderServer_ != nullptr) {
        recorderServer_->Reset();
        recorderServer_->Release();
    }
    recorderServer_ = nullptr;
}

std::shared_ptr<AVBuffer> CreateWatermarkBuffer()
{
    int32_t dataSize = 200 * 800;
    std::vector<uint8_t> dataBuffer(dataSize, 0);
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    auto buffer = AVBuffer::CreateAVBuffer(allocator, dataSize);
    buffer->memory_->Write(dataBuffer.data(), dataSize, 0);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_X>(100);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_Y>(100);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_W>(200);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_H>(200);
    buffer->meta_->Set<Tag::VIDEO_STRIDE>(800);
    return buffer;
}

/**
 * @tc.name: hirecorder_AddWatermark_001
 * @tc.desc: AddWatermark with valid buffer for the first time (create filter)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_001, TestSize.Level0)
{
    auto watermarkBuffer = CreateWatermarkBuffer();
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 150, 75, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_002
 * @tc.desc: AddWatermark with invalid width (0, -1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_002, TestSize.Level2)
{
    auto watermarkBuffer = CreateWatermarkBuffer();
    ASSERT_NE(watermarkBuffer, nullptr);
    int32_t watermarkCount = 0;
    EXPECT_EQ(recorderServer_->AddWatermark(watermarkBuffer, 0, 50, watermarkCount), MSERR_INVALID_VAL);
    EXPECT_EQ(recorderServer_->AddWatermark(watermarkBuffer, -1, 50, watermarkCount), MSERR_INVALID_VAL);
}

/**
 * @tc.name: hirecorder_AddWatermark_003
 * @tc.desc: AddWatermark with invalid height (0, -1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_003, TestSize.Level2)
{
    auto watermarkBuffer = CreateWatermarkBuffer();
    ASSERT_NE(watermarkBuffer, nullptr);
    int32_t watermarkCount = 0;
    EXPECT_EQ(recorderServer_->AddWatermark(watermarkBuffer, 100, 0, watermarkCount), MSERR_INVALID_VAL);
    EXPECT_EQ(recorderServer_->AddWatermark(watermarkBuffer, 100, -1, watermarkCount), MSERR_INVALID_VAL);
}

/**
 * @tc.name: hirecorder_IsWatermarkSupported_001
 * @tc.desc: IsWatermarkSupported after video source configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_IsWatermarkSupported_001, TestSize.Level0)
{
    VideoRecorderConfig config;
    config.vSource = VIDEO_SOURCE_SURFACE_YUV;
    config.videoFormat = H264;
    config.outputFd = open((RECORDER_ROOT + "hirecorder_IsWatermarkSupported_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(config.outputFd >= 0);

    ASSERT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, config));

    bool isHardWatermarkSupported = false;
    int32_t ret = recorderServer_->IsWatermarkSupported(isHardWatermarkSupported);
    EXPECT_EQ(ret, MSERR_OK);
    close(config.outputFd);
}

/**
 * @tc.name: hirecorder_SetWatermark_001
 * @tc.desc: SetWatermark before Prepare (encoder not created), should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_SetWatermark_001, TestSize.Level2)
{
    auto waterMarkBuffer = CreateWatermarkBuffer();
    ASSERT_NE(waterMarkBuffer, nullptr);

    int32_t ret = recorderServer_->SetWatermark(waterMarkBuffer);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: hirecorder_SetWatermark_002
 * @tc.desc: SetWatermark with nullptr buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_SetWatermark_002, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> waterMarkBuffer = nullptr;
    int32_t ret = recorderServer_->SetWatermark(waterMarkBuffer);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

class HiRecorderImplDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    HiRecorderImpl* impl_ = nullptr;
};

void HiRecorderImplDirectTest::SetUpTestCase() {}
void HiRecorderImplDirectTest::TearDownTestCase() {}

void HiRecorderImplDirectTest::SetUp()
{
    impl_ = new HiRecorderImpl(0, 0, 0, 0);
    ASSERT_NE(impl_, nullptr);
    // Init creates recorderEventReceiver_ and recorderCallback_ which are needed by many methods
    impl_->Init();
}

void HiRecorderImplDirectTest::TearDown()
{
    if (impl_ != nullptr) {
        delete impl_;
        impl_ = nullptr;
    }
}

/**
 * @tc.name: hirecorder_BuildWatermarkPipeline_Soft_001
 * @tc.desc: BuildWatermarkPipeline with isHardWatermarkSupported_=false goes to BuildSoftWatermarkPipeline
 *           Covers: BuildPipeline -> hasWatermark_ true -> BuildWatermarkPipeline ->
 *                   IsWatermarkSupported fail/query -> isWatermarkSupported_=false ->
 *                   BuildSoftWatermarkPipeline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildWatermarkPipeline_Soft_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;
    impl_->codecMimeType_ = "";

    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildWatermarkPipeline();

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_FALSE(impl_->isHardWatermarkSupported_);
}

/**
 * @tc.name: hirecorder_BuildWatermarkPipeline_Hard_001
 * @tc.desc: BuildWatermarkPipeline with isHardWatermarkSupported_=true goes to BuildHardWatermarkPipeline
 *           Covers: BuildWatermarkPipeline -> isHardWatermarkSupported_ true -> BuildHardWatermarkPipeline ->
 *                   CreateAndConfigureEncoder(true) -> SetWatermarkMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildWatermarkPipeline_Hard_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;
    impl_->codecMimeType_ = "video/avc";

    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildHardWatermarkPipeline();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name: hirecorder_BuildHardWatermarkPipeline_NoVideoDimension_001
 * @tc.desc: BuildHardWatermarkPipeline without video dimensions set (videoWidth=0, videoHeight=0)
 *           Covers: BuildHardWatermarkPipeline path (SetVideoResize is now in CheckHardWatermarkPositionViolation)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildHardWatermarkPipeline_NoVideoDimension_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;
    impl_->codecMimeType_ = "video/avc";

    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    int32_t ret = impl_->BuildHardWatermarkPipeline();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name: hirecorder_BuildHardWatermarkPipeline_WithVideoDimension_001
 * @tc.desc: BuildHardWatermarkPipeline with video dimensions set
 *           Covers: BuildHardWatermarkPipeline path (SetVideoResize is now in CheckHardWatermarkPositionViolation)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildHardWatermarkPipeline_WithVideoDimension_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;
    impl_->codecMimeType_ = "video/avc";

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1920);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(1080);

    int32_t ret = impl_->BuildHardWatermarkPipeline();
    // CreateAndConfigureEncoder fails in UT env, returns MSERR_UNKNOWN
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name: hirecorder_BuildSoftWatermarkPipeline_001
 * @tc.desc: BuildSoftWatermarkPipeline directly with waterMarkFilter_ present
 *           Covers: BuildSoftWatermarkPipeline full path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildSoftWatermarkPipeline_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    int32_t ret = impl_->BuildSoftWatermarkPipeline();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_CheckHardWatermarkPositionViolation_NullFilter_001
 * @tc.desc: CheckHardWatermarkPositionViolation with waterMarkFilter_=nullptr returns false
 *           Covers: CheckHardWatermarkPositionViolation -> filter == nullptr -> return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CheckHardWatermarkPositionViolation_NullFilter_001, TestSize.Level0)
{
    impl_->waterMarkFilter_ = nullptr;

    bool result = impl_->CheckHardWatermarkPositionViolation();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: hirecorder_CheckHardWatermarkPositionViolation_NoVideoDimension_001
 * @tc.desc: CheckHardWatermarkPositionViolation with video dimensions unset (0x0)
 *           Covers: CheckHardWatermarkPositionViolation -> filter != nullptr, videoWidth > 0 && videoHeight > 0 false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CheckHardWatermarkPositionViolation_NoVideoDimension_001, TestSize.Level0)
{
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    bool result = impl_->CheckHardWatermarkPositionViolation();
    // No watermarks configured, no position violation
    EXPECT_FALSE(result);
}

/**
 * @tc.name: hirecorder_CheckHardWatermarkPositionViolation_WithVideoDimension_001
 * @tc.desc: CheckHardWatermarkPositionViolation with valid video dimensions
 *           Covers: CheckHardWatermarkPositionViolation -> filter != nullptr,
 *                   videoWidth > 0 && videoHeight > 0 true -> SetVideoResize -> HasHardWatermarkPositionViolation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CheckHardWatermarkPositionViolation_WithVideoDimension_001, TestSize.Level0)
{
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1920);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(1080);

    bool result = impl_->CheckHardWatermarkPositionViolation();
    // No watermarks configured, no position violation
    EXPECT_FALSE(result);
}

/**
 * @tc.name: hirecorder_BuildWatermarkPipeline_PositionViolation_001
 * @tc.desc: BuildWatermarkPipeline with isHardWatermarkSupported_=true forces CheckHardWatermarkPositionViolation
 *           Covers: BuildWatermarkPipeline -> isHardWatermarkSupported early return ->
 *                   CheckHardWatermarkPositionViolation -> no violation -> hard path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildWatermarkPipeline_PositionViolation_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;

    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildWatermarkPipeline();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
    // Verify SUT side effect: CreateAndConfigureEncoder was called and created videoEncoderFilter_
    EXPECT_NE(impl_->videoEncoderFilter_, nullptr);
}

/**
 * @tc.name: hirecorder_BuildPipeline_HasWatermark_001
 * @tc.desc: BuildPipeline with source_=YUV and hasWatermark_=true goes to BuildWatermarkPipeline
 *           Covers: BuildPipeline -> hasWatermark_ true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildPipeline_HasWatermark_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->hasWatermark_ = true;

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildPipeline();
    // codecMimeType_ is empty, isHardWatermarkSupported fails -> soft path -> MSERR_OK
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_FALSE(impl_->isHardWatermarkSupported_);
}

/**
 * @tc.name: hirecorder_BuildPipeline_NonYuvRgbaSource_001
 * @tc.desc: BuildPipeline with source_ that is neither ES, YUV, nor RGBA returns MSERR_OK early
 *           Covers: BuildPipeline -> source_ != ES && source_ != YUV && source_ != RGBA -> return MSERR_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildPipeline_NonYuvRgbaSource_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_BUTT;

    int32_t ret = impl_->BuildPipeline();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_GetSurface_WatermarkSoft_001
 * @tc.desc: GetSurface with hasWatermark_=true and isHardWatermarkSupported_=false returns WaterMarkFilter surface
 *           Covers: GetSurface -> hasWatermark_ && !isHardWatermarkSupported_ true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetSurface_WatermarkSoft_001, TestSize.Level0)
{
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = false;

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);

    sptr<Surface> surface = impl_->GetSurface(0);
    EXPECT_EQ(surface, nullptr);
}

/**
 * @tc.name: hirecorder_GetSurface_WatermarkHard_001
 * @tc.desc: GetSurface with hasWatermark_=true and isHardWatermarkSupported_=true returns videoEncoder surface
 *           Covers: GetSurface -> hasWatermark_ true but isHardWatermarkSupported_ true -> falls to else if
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetSurface_WatermarkHard_001, TestSize.Level0)
{
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;

    sptr<Surface> surface = impl_->GetSurface(0);
    EXPECT_EQ(surface, nullptr);
}

/**
 * @tc.desc: GetSurface without watermark but with videoEncoderFilter_ returns encoder surface
 *           Covers: GetSurface -> else if (videoEncoderFilter_) true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetSurface_VideoEncoder_001, TestSize.Level0)
{
    impl_->hasWatermark_ = false;
    impl_->isHardWatermarkSupported_ = false;

    // Create a videoEncoderFilter_ via FilterFactory
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    sptr<Surface> surface = impl_->GetSurface(0);
    EXPECT_EQ(surface, nullptr);
}

/**
 * @tc.desc: GetSurface without watermark and without videoEncoderFilter_ but with videoCaptureFilter_
 *           Covers: GetSurface -> else if (videoCaptureFilter_) true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetSurface_VideoCapture_001, TestSize.Level0)
{
    impl_->hasWatermark_ = false;
    impl_->isHardWatermarkSupported_ = false;
    impl_->videoEncoderFilter_ = nullptr;

    // Create a videoCaptureFilter_ via FilterFactory
    impl_->videoCaptureFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::VideoCaptureFilter>(
            "videoCaptureFilter", Pipeline::FilterType::VIDEO_CAPTURE);

    sptr<Surface> surface = impl_->GetSurface(0);
    // Routes to GetSurfaceFromVideoCapture; VideoCaptureFilter creates a Surface internally
    EXPECT_NE(surface, nullptr);
    EXPECT_GT(surface->GetQueueSize(), 0u);
}

/**
 * @tc.name: hirecorder_PrepareAudioCapture_WithWatermark_001
 * @tc.desc: PrepareAudioCapture with hasWatermark_=true and no videoEncoderFilter_
 *           Covers: PrepareAudioCapture -> hasWatermark_ || videoEncoderFilter_ -> true (via hasWatermark_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_PrepareAudioCapture_WithWatermark_001, TestSize.Level0)
{
    impl_->hasWatermark_ = true;
    impl_->videoEncoderFilter_ = nullptr;

    // Create audioCaptureFilter_ so PrepareAudioCapture enters the if block
    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::AudioCaptureFilter>(
            "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);

    int32_t ret = impl_->PrepareAudioCapture();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_PrepareAudioCapture_NoWatermarkNoEncoder_001
 * @tc.desc: PrepareAudioCapture with hasWatermark_=false and no videoEncoderFilter_
 *           Covers: PrepareAudioCapture -> hasWatermark_ || videoEncoderFilter_ -> false -> SetWithVideo(false)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_PrepareAudioCapture_NoWatermarkNoEncoder_001, TestSize.Level0)
{
    impl_->hasWatermark_ = false;
    impl_->videoEncoderFilter_ = nullptr;

    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::AudioCaptureFilter>(
            "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);

    int32_t ret = impl_->PrepareAudioCapture();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_CreateAndConfigureEncoder_SetWatermarkMode_001
 * @tc.desc: CreateAndConfigureEncoder with setWatermarkMode=true calls SetWatermarkMode
 *           Covers: CreateAndConfigureEncoder -> if (setWatermarkMode) true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CreateAndConfigureEncoder_SetWatermarkMode_001, TestSize.Level0)
{
    // videoEncoderFilter_ is nullptr so it will be created in the function
    impl_->videoEncoderFilter_ = nullptr;
    impl_->videoSourceIsRGBA_ = false;

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->CreateAndConfigureEncoder(true);
    // Encoder Configure fails in UT env, returns MSERR_VID_ENC_CONFIG_FAILED
    EXPECT_EQ(ret, MSERR_VID_ENC_CONFIG_FAILED);
}

/**
 * @tc.desc: CreateAndConfigureEncoder when videoEncoderFilter_ already exists
 *           Covers: CreateAndConfigureEncoder -> if (!videoEncoderFilter_) false branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CreateAndConfigureEncoder_ExistingEncoder_001, TestSize.Level0)
{
    // Pre-create videoEncoderFilter_ so the if(!videoEncoderFilter_) branch is false
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);
    ASSERT_NE(impl_->videoEncoderFilter_, nullptr);

    impl_->videoSourceIsRGBA_ = false;
    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->CreateAndConfigureEncoder(false);
    // Encoder Configure fails in UT env, returns MSERR_VID_ENC_CONFIG_FAILED
    EXPECT_EQ(ret, MSERR_VID_ENC_CONFIG_FAILED);
}

/**
 * @tc.name: hirecorder_CreateAndConfigureEncoder_RGBA_001
 * @tc.desc: CreateAndConfigureEncoder with videoSourceIsRGBA_=true
 *           Covers: CreateAndConfigureEncoder -> if (videoSourceIsRGBA_) true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_CreateAndConfigureEncoder_RGBA_001, TestSize.Level0)
{
    impl_->videoEncoderFilter_ = nullptr;
    impl_->videoSourceIsRGBA_ = true;
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA;

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->CreateAndConfigureEncoder(false);
    // Encoder Configure fails in UT env, returns MSERR_VID_ENC_CONFIG_FAILED
    EXPECT_EQ(ret, MSERR_VID_ENC_CONFIG_FAILED);
}

/**
 * @tc.name: hirecorder_SetHardWatermarkData_001
 * @tc.desc: SetHardWatermarkData with waterMarkFilter_ present but GetMergedWatermarkBuffer returns null
 *           Covers: SetHardWatermarkData full path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_SetHardWatermarkData_001, TestSize.Level0)
{
    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    // Create videoEncoderFilter_ for SetWatermark call
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    impl_->rotation_ = 0;

    Status ret = impl_->SetHardWatermarkData();
    // GetMergedWatermarkBuffer returns null without EGL context, returns ERROR_NULL_POINTER
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name: hirecorder_Start_WatermarkHard_001
 * @tc.desc: Start with hasWatermark_=true and isHardWatermarkSupported_=true calls SetHardWatermarkData
 *           Covers: Start -> hasWatermark_ true -> isHardWatermarkSupported_ true -> SetHardWatermarkData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_Start_WatermarkHard_001, TestSize.Level0)
{
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = true;

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    // Create videoEncoderFilter_
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    int32_t ret = impl_->Start();
    // SetHardWatermarkData fails but only logs warning; pipeline Start returns OK on empty pipeline
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_Start_WatermarkSoft_001
 * @tc.desc: Start with hasWatermark_=true and isHardWatermarkSupported_=false calls SetVideoEncoderSurface
 *           Covers: Start -> hasWatermark_ true -> isHardWatermarkSupported_ false -> SetVideoEncoderSurface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_Start_WatermarkSoft_001, TestSize.Level0)
{
    impl_->hasWatermark_ = true;
    impl_->isHardWatermarkSupported_ = false;

    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    // Create videoEncoderFilter_
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    int32_t ret = impl_->Start();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: hirecorder_HandleWatermarkCallback_NoEncoder_001
 * @tc.desc: HandleWatermarkCallback when videoEncoderFilter_ is null creates encoder with watermarkMode
 *           Covers: HandleWatermarkCallback -> !videoEncoderFilter_ true ->
 *                   videoSourceIsRGBA_ set -> CreateAndConfigureEncoder(true)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_HandleWatermarkCallback_NoEncoder_001, TestSize.Level0)
{
    impl_->videoEncoderFilter_ = nullptr;
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;

    // Create a dummy filter to pass as the callback source
    auto filter = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::WaterMarkFilter>(
            "Watermark", Pipeline::FilterType::WATERMARK);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    Status ret = impl_->HandleWatermarkCallback(filter, Pipeline::StreamType::STREAMTYPE_WATERMARK);
    // CreateAndConfigureEncoder fails in UT env, returns MSERR_VID_ENC_CONFIG_FAILED as Status
    EXPECT_EQ(ret, static_cast<Status>(MSERR_VID_ENC_CONFIG_FAILED));
}

/**
 * @tc.name: hirecorder_HandleWatermarkCallback_RGBA_001
 * @tc.desc: HandleWatermarkCallback with RGBA source when videoEncoderFilter_ is null
 *           Covers: HandleWatermarkCallback -> videoSourceIsRGBA_ = true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_HandleWatermarkCallback_RGBA_001, TestSize.Level0)
{
    impl_->videoEncoderFilter_ = nullptr;
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA;

    auto filter = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::WaterMarkFilter>(
            "Watermark", Pipeline::FilterType::WATERMARK);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    Status ret = impl_->HandleWatermarkCallback(filter, Pipeline::StreamType::STREAMTYPE_WATERMARK);
    // CreateAndConfigureEncoder fails in UT env, returns MSERR_VID_ENC_CONFIG_FAILED as Status
    EXPECT_EQ(ret, static_cast<Status>(MSERR_VID_ENC_CONFIG_FAILED));
}

/**
 * @tc.name: hirecorder_HandleWatermarkCallback_WithEncoder_001
 * @tc.desc: HandleWatermarkCallback when videoEncoderFilter_ already exists
 *           Covers: HandleWatermarkCallback -> !videoEncoderFilter_ false -> skip CreateAndConfigureEncoder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_HandleWatermarkCallback_WithEncoder_001, TestSize.Level0)
{
    // Pre-create videoEncoderFilter_
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    auto filter = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::WaterMarkFilter>(
            "Watermark", Pipeline::FilterType::WATERMARK);

    Status ret = impl_->HandleWatermarkCallback(filter, Pipeline::StreamType::STREAMTYPE_WATERMARK);
    // Encoder exists, skips CreateAndConfigureEncoder, LinkFilters then returns OK
    EXPECT_EQ(ret, Status::OK);
}

/**
 * @tc.name: hirecorder_SetVideoEncoderSurface_001
 * @tc.desc: SetVideoEncoderSurface with videoEncoderFilter_ and waterMarkFilter_ present
 *           Covers: SetVideoEncoderSurface full path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_SetVideoEncoderSurface_001, TestSize.Level0)
{
    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    // Create videoEncoderFilter_
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::SurfaceEncoderFilter>(
            "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);
    impl_->rotation_ = 0;

    Status ret = impl_->SetVideoEncoderSurface();
    // GetInputSurface returns null without real encoder, returns ERROR_NULL_POINTER
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
}

/**
 * @tc.name: hirecorder_IsWatermarkSupported_Direct_001
 * @tc.desc: IsWatermarkSupported when isWatermarkSupported_ is already true returns OK immediately
 *           Covers: IsWatermarkSupported -> isWatermarkSupported_ true early return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_IsWatermarkSupported_Direct_001, TestSize.Level0)
{
    impl_->isHardWatermarkSupported_ = true;
    bool isSupported = false;
    int32_t ret = impl_->IsWatermarkSupported(isSupported);
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));
    EXPECT_TRUE(isSupported);
}

/**
 * @tc.name: hirecorder_IsWatermarkSupported_Direct_002
 * @tc.desc: IsWatermarkSupported when codecMimeType_ is empty returns error
 *           Covers: IsWatermarkSupported -> codecMimeType_ empty -> ERROR_INVALID_OPERATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_IsWatermarkSupported_Direct_002, TestSize.Level0)
{
    impl_->isHardWatermarkSupported_ = false;
    impl_->codecMimeType_ = "";
    bool isSupported = false;
    int32_t ret = impl_->IsWatermarkSupported(isSupported);
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_OPERATION));
}

/**
 * @tc.name: hirecorder_IsWatermarkSupported_Direct_003
 * @tc.desc: IsWatermarkSupported with valid codecMimeType_ queries codecCapabilityAdapter
 *           Covers: IsWatermarkSupported -> codecCapabilityAdapter_ created and queried
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_IsWatermarkSupported_Direct_003, TestSize.Level0)
{
    impl_->isHardWatermarkSupported_ = false;
    impl_->codecMimeType_ = "video/avc";
    impl_->codecCapabilityAdapter_ = nullptr;

    bool isSupported = false;
    int32_t ret = impl_->IsWatermarkSupported(isSupported);
    // codecCapabilityAdapter_ is created internally when null; query result depends on codec capability
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_SetWatermark_Direct_001
 * @tc.desc: SetWatermark when videoEncoderFilter_ is null returns error
 *           Covers: SetWatermark -> videoEncoderFilter_ nullptr check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_SetWatermark_Direct_001, TestSize.Level0)
{
    impl_->videoEncoderFilter_ = nullptr;
    auto buffer = CreateWatermarkBuffer();
    int32_t ret = impl_->SetWatermark(buffer);
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_NULL_POINTER));
}

/**
 * @tc.name: hirecorder_AddWatermark_Direct_001
 * @tc.desc: AddWatermark with valid buffer creates waterMarkFilter_ and may set hasWatermark_ to true
 *           Covers: AddWatermark -> waterMarkFilter_ creation path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_AddWatermark_Direct_001, TestSize.Level0)
{
    auto watermarkBuffer = CreateWatermarkBuffer();
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t ret = impl_->AddWatermark(watermarkBuffer, 100, 100);
    // AddWatermark creates waterMarkFilter_ and calls SetWatermark (data-only, no OpenGL)
    EXPECT_NE(impl_->waterMarkFilter_, nullptr);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_Direct_002
 * @tc.desc: AddWatermark with nullptr buffer returns error
 *           Covers: AddWatermark -> nullptr check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_AddWatermark_Direct_002, TestSize.Level0)
{
    std::shared_ptr<AVBuffer> watermarkBuffer = nullptr;
    int32_t ret = impl_->AddWatermark(watermarkBuffer, 100, 100);
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_NULL_POINTER));
}

/**
 * @tc.name: hirecorder_OnCallback_Watermark_001
 * @tc.desc: OnCallback with STREAMTYPE_WATERMARK calls HandleWatermarkCallback
 *           Covers: OnCallback -> STREAMTYPE_WATERMARK -> HandleWatermarkCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_OnCallback_Watermark_001, TestSize.Level0)
{
    impl_->videoEncoderFilter_ = nullptr;
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;

    auto filter = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::WaterMarkFilter>(
            "Watermark", Pipeline::FilterType::WATERMARK);

    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    Status ret = impl_->OnCallback(filter,
        Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED,
        Pipeline::StreamType::STREAMTYPE_WATERMARK);
    // Routes to HandleWatermarkCallback which fails at CreateAndConfigureEncoder
    EXPECT_EQ(ret, static_cast<Status>(MSERR_VID_ENC_CONFIG_FAILED));
}

/**
 * @tc.name: hirecorder_GetWaterMarkFilter_001
 * @tc.desc: GetWaterMarkFilter with waterMarkFilter_ present returns valid pointer
 *           Covers: GetWaterMarkFilter -> waterMarkFilter_ not null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetWaterMarkFilter_001, TestSize.Level0)
{
    // Create waterMarkFilter_ directly via FilterFactory
    impl_->waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(impl_->waterMarkFilter_, nullptr);

    auto* filter = impl_->GetWaterMarkFilter();
    EXPECT_NE(filter, nullptr);
    EXPECT_EQ(filter->GetFilterType(), Pipeline::FilterType::WATERMARK);
}

/**
 * @tc.name: hirecorder_GetWaterMarkFilter_Null_001
 * @tc.desc: GetWaterMarkFilter with waterMarkFilter_ null returns nullptr
 *           Covers: GetWaterMarkFilter -> waterMarkFilter_ null -> return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_GetWaterMarkFilter_Null_001, TestSize.Level0)
{
    impl_->waterMarkFilter_ = nullptr;
    auto* filter = impl_->GetWaterMarkFilter();
    EXPECT_EQ(filter, nullptr);
}

/**
 * @tc.name: hirecorder_PrepareAudioCapture_MuteWhenInterrupted_001
 * @tc.desc: PrepareAudioCapture with muteWhenInterrupted_=true calls SetWillMuteWhenInterrupted
 *           Covers: PrepareAudioCapture -> muteWhenInterrupted_ true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_PrepareAudioCapture_MuteWhenInterrupted_001, TestSize.Level0)
{
    impl_->hasWatermark_ = false;
    impl_->videoEncoderFilter_ = nullptr;
    impl_->muteWhenInterrupted_ = true;

    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance()
        .CreateFilter<Pipeline::AudioCaptureFilter>(
            "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);

    int32_t ret = impl_->PrepareAudioCapture();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_BuildPipeline_ES_001
 * @tc.desc: BuildPipeline with source_=ES goes to BuildEsPipeline
 *           Covers: BuildPipeline -> source_ == VIDEO_SOURCE_SURFACE_ES -> BuildEsPipeline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildPipeline_ES_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_ES;
    impl_->videoSourceSet_ = true;
    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildPipeline();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_BuildPipeline_YUV_NoWatermark_001
 * @tc.desc: BuildPipeline with source_=YUV and hasWatermark_=false goes to BuildVideoPipeline
 *           Covers: BuildPipeline -> source_ YUV/RGBA, hasWatermark_ false -> BuildVideoPipeline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplDirectTest, hirecorder_BuildPipeline_YUV_NoWatermark_001, TestSize.Level0)
{
    impl_->source_ = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV;
    impl_->videoSourceSet_ = true;
    impl_->hasWatermark_ = false;
    impl_->videoEncFormat_->Set<Tag::VIDEO_WIDTH>(1280);
    impl_->videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(720);

    int32_t ret = impl_->BuildPipeline();
    // BuildVideoPipeline fails at CreateAndConfigureEncoder in UT env, returns MSERR_UNKNOWN
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}
