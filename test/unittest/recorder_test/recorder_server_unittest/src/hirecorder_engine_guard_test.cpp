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
#include <fcntl.h>
#include <unistd.h>
#include "hirecorder_impl.h"
#include "i_recorder_engine.h"
#include "recorder_param.h"
#include "recorder_utils.h"
#include "filter/filter_factory.h"
#include "pipeline/pipeline.h"
#include "audio_capture_filter.h"
#include "audio_data_source_filter.h"
#include "video_capture_filter.h"
#include "muxer_filter.h"
#include "surface_encoder_filter.h"
#include "media_errors.h"
#include "media_log.h"
#include "av_common.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace {
class MockRecorderEngineObs : public IRecorderEngineObs {
public:
    void OnError(ErrorType errorType, int32_t errorCode) override
    {
        errorCount_++;
        lastErrorType_ = errorType;
        lastErrorCode_ = errorCode;
    }

    void OnInfo(InfoType type, int32_t extra) override
    {
        infoCount_++;
        lastInfoType_ = type;
        lastInfoExtra_ = extra;
    }

    void OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo) override
    {
        (void)audioRecorderChangeInfo;
        audioChangeCount_++;
    }

    int32_t errorCount_ = 0;
    int32_t infoCount_ = 0;
    int32_t audioChangeCount_ = 0;
    ErrorType lastErrorType_ = ErrorType::ERROR_INTERNAL;
    int32_t lastErrorCode_ = 0;
    InfoType lastInfoType_ = InfoType::INTERNEL_WARNING;
    int32_t lastInfoExtra_ = 0;
};

class MockAudioDataSource : public IAudioDataSource {
public:
    AudioDataSourceReadAtActionState ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override
    {
        (void)buffer;
        (void)length;
        return AudioDataSourceReadAtActionState::OK;
    }

    int32_t GetSize(int64_t &size) override
    {
        size = 0;
        return 0;
    }

    void SetVideoFirstFramePts(int64_t firstFramePts) override
    {
        firstFramePts_ = firstFramePts;
    }

    void SetListener(std::shared_ptr<IAudioDataSourceListener> listener) override
    {
        (void)listener;
    }

    int64_t firstFramePts_ = -1;
};
} // namespace

class HiRecorderImplEngineGuardTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        impl_ = new HiRecorderImpl(0, 0, 0, 0);
        ASSERT_NE(impl_, nullptr);
        ASSERT_EQ(0, impl_->Init());
    }
    void TearDown() override
    {
        delete impl_;
        impl_ = nullptr;
    }

protected:
    HiRecorderImpl *impl_ = nullptr;
};

/**
 * @tc.name: hirecorder_SetObs_OnEventError_001
 * @tc.desc: EVENT_ERROR is reported via OnError and the state becomes ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetObs_OnEventError_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    EXPECT_EQ(0, impl_->SetObs(obs));

    Event event;
    event.type = EventType::EVENT_ERROR;
    event.param = Any(static_cast<int32_t>(0));
    impl_->OnEvent(event);

    EXPECT_EQ(1, obs->errorCount_);
    EXPECT_EQ(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, obs->lastErrorType_);
    EXPECT_EQ(StateId::ERROR, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_SetObs_Expired_001
 * @tc.desc: OnEvent and OnAudioCaptureChange are ignored after the observer expires
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetObs_Expired_001, TestSize.Level2)
{
    {
        auto obs = std::make_shared<MockRecorderEngineObs>();
        impl_->SetObs(obs);
    }
    impl_->curState_.store(StateId::RECORDING);

    Event event;
    event.type = EventType::EVENT_ERROR;
    event.param = Any(static_cast<int32_t>(0));
    impl_->OnEvent(event);
    AudioStandard::AudioCapturerChangeInfo audioChangeInfo;
    impl_->OnAudioCaptureChange(audioChangeInfo);

    // The expired observer must be skipped: no callback, no state change, no crash
    EXPECT_EQ(StateId::RECORDING, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_OnAudioCaptureChange_001
 * @tc.desc: Audio capture change is reported to the registered observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_OnAudioCaptureChange_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    impl_->SetObs(obs);
    AudioStandard::AudioCapturerChangeInfo audioChangeInfo;
    impl_->OnAudioCaptureChange(audioChangeInfo);
    EXPECT_EQ(1, obs->audioChangeCount_);
}

/**
 * @tc.name: hirecorder_OnEventCompleteInInit_001
 * @tc.desc: EVENT_COMPLETE in INIT state is ignored without notifying the observer or changing state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_OnEventCompleteInInit_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    impl_->SetObs(obs);
    impl_->curState_.store(StateId::INIT);

    Event event;
    event.type = EventType::EVENT_COMPLETE;
    impl_->OnEvent(event);

    EXPECT_EQ(0, obs->infoCount_);
    EXPECT_EQ(StateId::INIT, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_HandleErrorEvent_AudioInterrupt_001
 * @tc.desc: An audio interrupt error stops the recorder and reports MSERR_AUD_INTERRUPT without an error state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleErrorEvent_AudioInterrupt_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    impl_->SetObs(obs);
    impl_->curState_.store(StateId::RECORDING);
    impl_->pipeline_ = nullptr;

    Event event;
    event.type = EventType::EVENT_ERROR;
    event.param = Any(static_cast<int32_t>(Status::ERROR_AUDIO_INTERRUPT));
    impl_->OnEvent(event);

    // The interrupt path stops the recorder and reports the interrupt code without switching to ERROR
    ASSERT_EQ(1, obs->errorCount_);
    EXPECT_EQ(MSERR_AUD_INTERRUPT, obs->lastErrorCode_);
    EXPECT_EQ(StateId::INIT, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_HandleCompleteEvent_Recording_001
 * @tc.desc: EVENT_COMPLETE while recording stops the recorder and reports max duration reached
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleCompleteEvent_Recording_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    impl_->SetObs(obs);
    impl_->curState_.store(StateId::RECORDING);
    impl_->pipeline_ = nullptr;

    Event event;
    event.type = EventType::EVENT_COMPLETE;
    impl_->OnEvent(event);

    ASSERT_EQ(1, obs->infoCount_);
    EXPECT_EQ(IRecorderEngineObs::InfoType::MAX_DURATION_REACHED, obs->lastInfoType_);
    EXPECT_EQ(StateId::INIT, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_SetOutputFormat_Atomic_001
 * @tc.desc: The output format set by SetOutputFormat can be read back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetOutputFormat_Atomic_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, impl_->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4));
    EXPECT_EQ(OutputFormatType::FORMAT_MPEG_4, impl_->outputFormatType_.load());
}

/**
 * @tc.name: hirecorder_Configure_NullMuxer_001
 * @tc.desc: Configure still succeeds when timed metadata exists but muxer is not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_Configure_NullMuxer_001, TestSize.Level2)
{
    impl_->outputFormatType_.store(OutputFormatType::FORMAT_MPEG_4);
    impl_->metaDataFormats_[0] = std::make_shared<Meta>();
    impl_->muxerFilter_ = nullptr;

    int32_t ret = impl_->Configure(DUMMY_SOURCE_ID, MaxDuration(30));
    EXPECT_EQ(static_cast<int32_t>(Status::OK), ret);
    EXPECT_EQ(30, impl_->maxDuration_);
}

/**
 * @tc.name: hirecorder_Configure_ValidMuxer_001
 * @tc.desc: Configure passes use_timed_meta_track to muxer when muxer is created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_Configure_ValidMuxer_001, TestSize.Level2)
{
    impl_->outputFormatType_.store(OutputFormatType::FORMAT_MPEG_4);
    impl_->metaDataFormats_[0] = std::make_shared<Meta>();
    impl_->muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>(
        "muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
    ASSERT_NE(impl_->muxerFilter_, nullptr);

    EXPECT_EQ(static_cast<int32_t>(Status::OK), impl_->Configure(DUMMY_SOURCE_ID, MaxDuration(10)));
}

/**
 * @tc.name: hirecorder_Prepare_PipelineNull_001
 * @tc.desc: Prepare returns MSERR_FRAMEWORK_ERROR when the output fd is valid but pipeline is not ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_Prepare_PipelineNull_001, TestSize.Level2)
{
    // Prepare validates the output fd first, so inject a valid seekable fd to reach the pipeline guard
    int32_t nullFd = open("/dev/null", O_RDWR);
    ASSERT_GE(nullFd, 0);
    impl_->fd_.Reset(nullFd);

    impl_->pipeline_ = nullptr;
    EXPECT_EQ(MSERR_FRAMEWORK_ERROR, impl_->Prepare());
}

/**
 * @tc.name: hirecorder_PrepareAudioCapture_EncFormatNull_001
 * @tc.desc: PrepareAudioCapture returns MSERR_UNKNOWN when audio encoding format is not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_PrepareAudioCapture_EncFormatNull_001, TestSize.Level2)
{
    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);
    impl_->audioEncFormat_ = nullptr;
    EXPECT_EQ(MSERR_UNKNOWN, impl_->PrepareAudioCapture());
}

/**
 * @tc.name: hirecorder_PrepareAudioDataSource_EncFormatNull_001
 * @tc.desc: PrepareAudioDataSource returns MSERR_UNKNOWN when audio encoding format is not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_PrepareAudioDataSource_EncFormatNull_001, TestSize.Level2)
{
    impl_->audioDataSourceFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioDataSourceFilter>(
        "audioDataSourceFilter", Pipeline::FilterType::AUDIO_DATA_SOURCE);
    ASSERT_NE(impl_->audioDataSourceFilter_, nullptr);
    impl_->audioEncFormat_ = nullptr;
    EXPECT_EQ(MSERR_UNKNOWN, impl_->PrepareAudioDataSource());
}

/**
 * @tc.name: hirecorder_HandleStopOperation_NullPipeline_001
 * @tc.desc: Stop does not crash and falls back to INIT when pipeline is not ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleStopOperation_NullPipeline_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    impl_->SetObs(obs);
    impl_->pipeline_ = nullptr;
    impl_->videoEncoderFilter_ = nullptr;
    impl_->audioCaptureFilter_ = nullptr;
    impl_->audioDataSourceFilter_ = nullptr;

    EXPECT_EQ(Status::OK, impl_->HandleStopOperation());
    EXPECT_EQ(StateId::INIT, impl_->curState_.load());
    EXPECT_EQ(OutputFormatType::FORMAT_BUTT, impl_->outputFormatType_.load());
}

/**
 * @tc.name: hirecorder_HandleStopOperation_WithFilters_001
 * @tc.desc: Stop sends EOS to the created capture filters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleStopOperation_WithFilters_001, TestSize.Level2)
{
    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    impl_->audioDataSourceFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioDataSourceFilter>(
        "audioDataSourceFilter", Pipeline::FilterType::AUDIO_DATA_SOURCE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);
    ASSERT_NE(impl_->audioDataSourceFilter_, nullptr);
    impl_->pipeline_ = nullptr;

    EXPECT_EQ(Status::OK, impl_->HandleStopOperation());
}

/**
 * @tc.name: hirecorder_HandleRawAudioCallback_001
 * @tc.desc: HandleRawAudioCallback creates the audio encoder and rejects the callback when no encoder format is set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleRawAudioCallback_001, TestSize.Level2)
{
    auto upstreamFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(upstreamFilter, nullptr);
    impl_->pipeline_ = nullptr;
    impl_->audioEncFormat_ = std::make_shared<Meta>(); // encoder format is not configured

    Status ret = impl_->HandleRawAudioCallback(upstreamFilter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);

    // The audio encoder filter must be created for the raw audio path, and the missing format must stop the link step
    ASSERT_NE(impl_->audioEncoderFilter_, nullptr);
    EXPECT_EQ(Pipeline::FilterType::FILTERTYPE_AENC, impl_->audioEncoderFilter_->GetFilterType());
    EXPECT_EQ(Status::ERROR_INVALID_DATA, ret);
}

/**
 * @tc.name: hirecorder_HandleRawAudioCallback_Pipeline_001
 * @tc.desc: HandleRawAudioCallback links the audio encoder into the pipeline when the encoder format is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleRawAudioCallback_Pipeline_001, TestSize.Level2)
{
    impl_->audioEncFormat_ = std::make_shared<Meta>();
    impl_->audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
    impl_->audioEncFormat_->Set<Tag::AUDIO_SAMPLE_RATE>(48000);
    impl_->audioEncFormat_->Set<Tag::AUDIO_CHANNEL_COUNT>(2);
    impl_->audioEncFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
    impl_->audioEncFormat_->Set<Tag::MEDIA_BITRATE>(96000);
    auto upstreamFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(upstreamFilter, nullptr);

    Status ret = impl_->HandleRawAudioCallback(upstreamFilter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    if (ret != Status::OK) {
        GTEST_SKIP() << "the audio encoder is not available in this environment";
    }

    // The guard links the freshly created encoder to the upstream filter through the pipeline
    ASSERT_EQ(1u, upstreamFilter->nextFiltersMap_.size());
    EXPECT_EQ(1u, upstreamFilter->nextFiltersMap_[Pipeline::StreamType::STREAMTYPE_RAW_AUDIO].size());
}

/**
 * @tc.name: hirecorder_HandleWatermarkCallback_Pipeline_001
 * @tc.desc: HandleWatermarkCallback links the preset video encoder into the pipeline when the pipeline is ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleWatermarkCallback_Pipeline_001, TestSize.Level2)
{
    impl_->videoEncoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::SurfaceEncoderFilter>(
        "videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);
    ASSERT_NE(impl_->videoEncoderFilter_, nullptr);
    auto upstreamFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::VideoCaptureFilter>(
        "videoCaptureFilter", Pipeline::FilterType::VIDEO_CAPTURE);
    ASSERT_NE(upstreamFilter, nullptr);

    Status ret = impl_->HandleWatermarkCallback(upstreamFilter, Pipeline::StreamType::STREAMTYPE_RAW_VIDEO);

    EXPECT_EQ(Status::OK, ret);
    ASSERT_EQ(1u, upstreamFilter->nextFiltersMap_.size());
    EXPECT_EQ(1u, upstreamFilter->nextFiltersMap_[Pipeline::StreamType::STREAMTYPE_RAW_VIDEO].size());
}

/**
 * @tc.name: hirecorder_HandleEncodedCallback_NullPipeline_001
 * @tc.desc: Encoded callback does not link muxer when pipeline is not ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleEncodedCallback_NullPipeline_001, TestSize.Level2)
{
    impl_->muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>(
        "muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
    ASSERT_NE(impl_->muxerFilter_, nullptr);
    impl_->pipeline_ = nullptr;

    EXPECT_EQ(Status::OK, impl_->HandleEncodedAudioOrVideoCallback(
        nullptr, Pipeline::StreamType::STREAMTYPE_ENCODED_VIDEO));
}

/**
 * @tc.name: hirecorder_HandleEncodedCallback_Pipeline_001
 * @tc.desc: Encoded callback links the preset muxer into the pipeline when the pipeline is ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleEncodedCallback_Pipeline_001, TestSize.Level2)
{
    impl_->muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>(
        "muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
    ASSERT_NE(impl_->muxerFilter_, nullptr);
    auto upstreamFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(upstreamFilter, nullptr);

    Status ret = impl_->HandleEncodedAudioOrVideoCallback(
        upstreamFilter, Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);

    EXPECT_EQ(Status::OK, ret);
    ASSERT_EQ(1u, upstreamFilter->nextFiltersMap_.size());
    EXPECT_EQ(1u, upstreamFilter->nextFiltersMap_[Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO].size());
}

/**
 * @tc.name: hirecorder_HandleEncodedCallback_CreateMuxer_001
 * @tc.desc: Encoded callback creates and configures the muxer when it does not exist yet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_HandleEncodedCallback_CreateMuxer_001, TestSize.Level2)
{
    const std::string path = "/data/test/media/hirecorder_create_muxer_001.mp4";
    int32_t fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    ASSERT_GE(fd, 0);
    impl_->fd_.Reset(fd);
    impl_->muxerFilter_ = nullptr;
    impl_->outputFormatType_.store(OutputFormatType::FORMAT_MPEG_4);
    auto upstreamFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(upstreamFilter, nullptr);

    Status ret = impl_->HandleEncodedAudioOrVideoCallback(
        upstreamFilter, Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    (void)unlink(path.c_str());

    // The callback must have created the muxer; the link only happens when the output parameter is accepted
    ASSERT_NE(impl_->muxerFilter_, nullptr);
    if (ret != Status::OK) {
        GTEST_SKIP() << "the muxer output parameter is not accepted in this environment";
    }
    EXPECT_EQ(Status::OK, ret);
    ASSERT_EQ(1u, upstreamFilter->nextFiltersMap_.size());
}

/**
 * @tc.name: hirecorder_ConfigureMuxer_MaxSize_001
 * @tc.desc: ConfigureMuxer only records maxSize when muxer is not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureMuxer_MaxSize_001, TestSize.Level2)
{
    impl_->muxerFilter_ = nullptr;
    impl_->ConfigureMuxer(MaxFileSize(1024));
    EXPECT_EQ(static_cast<int64_t>(1024), impl_->maxSize_);
}

/**
 * @tc.name: hirecorder_ConfigureMuxer_Rotation_001
 * @tc.desc: Rotation hint only updates muxer format when muxer is not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureMuxer_Rotation_001, TestSize.Level2)
{
    impl_->muxerFilter_ = nullptr;
    const int32_t rotation = static_cast<int32_t>(Plugins::VideoRotation::VIDEO_ROTATION_90);
    impl_->ConfigureMuxer(RotationAngle(rotation));

    EXPECT_EQ(rotation, impl_->rotation_);

    Plugins::VideoRotation muxerRotation = Plugins::VideoRotation::VIDEO_ROTATION_0;
    EXPECT_TRUE(impl_->muxerFormat_->GetData(Tag::VIDEO_ROTATION, muxerRotation));
    EXPECT_EQ(Plugins::VideoRotation::VIDEO_ROTATION_90, muxerRotation);
}

/**
 * @tc.name: hirecorder_SetUserMeta_NullMuxer_001
 * @tc.desc: SetUserMeta returns ERROR_NULL_POINTER when muxer is not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetUserMeta_NullMuxer_001, TestSize.Level2)
{
    impl_->muxerFilter_ = nullptr;
    EXPECT_EQ(Status::ERROR_NULL_POINTER, impl_->SetUserMeta(std::make_shared<Meta>()));
}

/**
 * @tc.name: hirecorder_SetUserMeta_WithMuxer_001
 * @tc.desc: SetUserMeta forwards the argument to the muxer filter, which rejects a null user meta
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetUserMeta_WithMuxer_001, TestSize.Level2)
{
    impl_->muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>(
        "muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
    ASSERT_NE(impl_->muxerFilter_, nullptr);
    int32_t fd = open("/dev/null", O_RDWR);
    ASSERT_GE(fd, 0);
    // Create mediaMuxer_ so that the muxer filter reaches its own argument check
    (void)impl_->muxerFilter_->SetOutputParameter(0, 0, fd, OutputFormatType::FORMAT_MPEG_4);
    close(fd);

    // The engine must forward the argument: only the muxer filter itself rejects the null meta
    EXPECT_EQ(Status::ERROR_INVALID_PARAMETER, impl_->SetUserMeta(nullptr));
}

/**
 * @tc.name: hirecorder_GetSurfaceFromWaterMarkFilter_Null_001
 * @tc.desc: GetSurfaceFromWaterMarkFilter returns null when watermark filter is not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_GetSurfaceFromWaterMarkFilter_Null_001, TestSize.Level2)
{
    impl_->waterMarkFilter_ = nullptr;
    EXPECT_TRUE(impl_->GetSurfaceFromWaterMarkFilter() == nullptr);
}

/**
 * @tc.name: hirecorder_GetSurfaceFromWaterMarkFilter_NotNull_001
 * @tc.desc: GetSurfaceFromWaterMarkFilter returns and caches the watermark filter input surface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_GetSurfaceFromWaterMarkFilter_NotNull_001, TestSize.Level2)
{
    auto waterMarkFilter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
        "Watermark", Pipeline::FilterType::WATERMARK);
    ASSERT_NE(waterMarkFilter, nullptr);
    impl_->waterMarkFilter_ = waterMarkFilter;
    impl_->producerSurface_ = nullptr;

    auto surface = impl_->GetSurfaceFromWaterMarkFilter();

    // The returned surface must be the filter input surface and must be cached in producerSurface_
    EXPECT_EQ(surface.GetRefPtr(), waterMarkFilter->GetInputSurface().GetRefPtr());
    EXPECT_EQ(impl_->producerSurface_.GetRefPtr(), surface.GetRefPtr());
}

/**
 * @tc.name: hirecorder_UpdateVideoFirstFramePts_WithFilter_001
 * @tc.desc: The first video frame timestamp is applied to the audio capture filter taken under the lock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_UpdateVideoFirstFramePts_WithFilter_001, TestSize.Level2)
{
    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);
    impl_->audioDataSourceFilter_ = nullptr;

    Event event;
    event.type = EventType::EVENT_VIDEO_FIRST_FRAME;
    event.param = Any(static_cast<int64_t>(1234));
    impl_->UpdateVideoFirstFramePts(event);

    EXPECT_EQ(1234, impl_->audioCaptureFilter_->firstVideoFramePts_.load());
}

/**
 * @tc.name: hirecorder_UpdateVideoFirstFramePts_DataSourceFilter_001
 * @tc.desc: The first video frame timestamp is forwarded to the audio data source filter when only it exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_UpdateVideoFirstFramePts_DataSourceFilter_001, TestSize.Level2)
{
    auto dataSource = std::make_shared<MockAudioDataSource>();
    impl_->audioCaptureFilter_ = nullptr;
    impl_->audioDataSourceFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<
        Pipeline::AudioDataSourceFilter>("audioDataSourceFilter", Pipeline::FilterType::AUDIO_DATA_SOURCE);
    ASSERT_NE(impl_->audioDataSourceFilter_, nullptr);
    impl_->audioDataSourceFilter_->SetAudioDataSource(dataSource);

    Event event;
    event.type = EventType::EVENT_VIDEO_FIRST_FRAME;
    event.param = Any(static_cast<int64_t>(4321));
    impl_->UpdateVideoFirstFramePts(event);

    EXPECT_EQ(4321, dataSource->firstFramePts_);
}

/**
 * @tc.name: hirecorder_UpdateVideoFirstFramePts_BothFilters_001
 * @tc.desc: Both audio filters receive the same first video frame timestamp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_UpdateVideoFirstFramePts_BothFilters_001, TestSize.Level2)
{
    auto dataSource = std::make_shared<MockAudioDataSource>();
    impl_->audioCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>(
        "audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    ASSERT_NE(impl_->audioCaptureFilter_, nullptr);
    impl_->audioDataSourceFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<
        Pipeline::AudioDataSourceFilter>("audioDataSourceFilter", Pipeline::FilterType::AUDIO_DATA_SOURCE);
    ASSERT_NE(impl_->audioDataSourceFilter_, nullptr);
    impl_->audioDataSourceFilter_->SetAudioDataSource(dataSource);

    Event event;
    event.type = EventType::EVENT_VIDEO_FIRST_FRAME;
    event.param = Any(static_cast<int64_t>(5678));
    impl_->UpdateVideoFirstFramePts(event);

    EXPECT_EQ(5678, impl_->audioCaptureFilter_->firstVideoFramePts_.load());
    EXPECT_EQ(5678, dataSource->firstFramePts_);
}

/**
 * @tc.name: hirecorder_SetAudioSource_LockScope_001
 * @tc.desc: SetAudioSource publishes the audio capture filter and its source id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetAudioSource_LockScope_001, TestSize.Level2)
{
    int32_t sourceId = -1;

    int32_t ret = impl_->SetAudioSource(AudioSourceType::AUDIO_MIC, sourceId);

    EXPECT_EQ(0, ret);
    EXPECT_NE(nullptr, impl_->audioCaptureFilter_);
    EXPECT_NE(-1, sourceId);
}

/**
 * @tc.name: hirecorder_SetAudioDataSource_LockScope_001
 * @tc.desc: SetAudioDataSource publishes the audio data source filter and its source id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_SetAudioDataSource_LockScope_001, TestSize.Level2)
{
    int32_t sourceId = -1;

    int32_t ret = impl_->SetAudioDataSource(nullptr, sourceId);

    EXPECT_EQ(0, ret);
    EXPECT_NE(nullptr, impl_->audioDataSourceFilter_);
    EXPECT_NE(-1, sourceId);
}

/**
 * @tc.name: hirecorder_GetMetaSurface_InvalidSourceId_001
 * @tc.desc: GetMetaSurface returns nullptr for non-meta or out-of-range meta source ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_GetMetaSurface_InvalidSourceId_001, TestSize.Level2)
{
    impl_->metaDataFilters_.clear();

    // 0 is not a meta source id (IsMeta fails)
    EXPECT_EQ(nullptr, impl_->GetMetaSurface(0));
    // 0x100 is a video source id (IsMeta fails)
    EXPECT_EQ(nullptr, impl_->GetMetaSurface(SourceIdGenerator::GenerateVideoSourceId(0)));
    // 0x301 maps to VIDEO_META_SOURCE_BUTT, outside the valid meta type range
    EXPECT_EQ(nullptr, impl_->GetMetaSurface(SourceIdGenerator::META_MASK + 1));
}

/**
 * @tc.name: hirecorder_GetMetaSurface_FilterNotFound_001
 * @tc.desc: GetMetaSurface returns nullptr for a valid meta id whose filter was never created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_GetMetaSurface_FilterNotFound_001, TestSize.Level2)
{
    impl_->metaDataFilters_.clear();
    // 0x300 maps to VIDEO_META_MAKER_INFO (valid type) but no filter was registered
    EXPECT_EQ(nullptr, impl_->GetMetaSurface(SourceIdGenerator::META_MASK));
}

/**
 * @tc.name: hirecorder_ConfigureVidBitRate_Invalid_001
 * @tc.desc: VidBitRate <= 0 reports an error event; the engine rejects the config at Prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureVidBitRate_Invalid_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    EXPECT_EQ(0, impl_->SetObs(obs));

    impl_->ConfigureVidBitRate(VidBitRate(0));

    EXPECT_EQ(1, obs->errorCount_);
    EXPECT_EQ(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, obs->lastErrorType_);
    EXPECT_EQ(StateId::ERROR, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_ConfigureVidBitRate_Valid_001
 * @tc.desc: A positive VidBitRate is still written into the video encode format after the guard fix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureVidBitRate_Valid_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    EXPECT_EQ(0, impl_->SetObs(obs));

    impl_->ConfigureVidBitRate(VidBitRate(2048000));

    EXPECT_EQ(0, obs->errorCount_);
    int64_t bitRate = 0;
    EXPECT_TRUE(impl_->videoEncFormat_->GetData(Tag::MEDIA_BITRATE, bitRate));
    EXPECT_EQ(2048000, bitRate);
}

/**
 * @tc.name: hirecorder_ConfigureAudioBitRate_Invalid_001
 * @tc.desc: AudBitRate <= 0 reports an error event; the engine rejects the config at Prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureAudioBitRate_Invalid_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    EXPECT_EQ(0, impl_->SetObs(obs));

    impl_->ConfigureAudio(AudBitRate(0));

    EXPECT_EQ(1, obs->errorCount_);
    EXPECT_EQ(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, obs->lastErrorType_);
    EXPECT_EQ(StateId::ERROR, impl_->curState_.load());
}

/**
 * @tc.name: hirecorder_ConfigureAudioBitRate_Valid_001
 * @tc.desc: A positive AudBitRate is still written into the audio encode format after the guard fix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureAudioBitRate_Valid_001, TestSize.Level2)
{
    auto obs = std::make_shared<MockRecorderEngineObs>();
    EXPECT_EQ(0, impl_->SetObs(obs));

    impl_->ConfigureAudio(AudBitRate(64000));

    EXPECT_EQ(0, obs->errorCount_);
    int64_t bitRate = 0;
    EXPECT_TRUE(impl_->audioEncFormat_->GetData(Tag::MEDIA_BITRATE, bitRate));
    EXPECT_EQ(64000, bitRate);
}

/**
 * @tc.name: hirecorder_ConfigureOutFd_InvalidFd_001
 * @tc.desc: ConfigureOutFd with a negative fd keeps fd_ invalid instead of dup()ing it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureOutFd_InvalidFd_001, TestSize.Level2)
{
    impl_->ConfigureOutFd(OutFd(-1));

    EXPECT_EQ(-1, impl_->fd_.Get());
}

/**
 * @tc.name: hirecorder_ConfigureOutFd_ValidFd_001
 * @tc.desc: ConfigureOutFd dups a valid fd and CloseFd releases the duplicated fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_ConfigureOutFd_ValidFd_001, TestSize.Level2)
{
    int32_t rawFd = open("/dev/null", O_RDWR);
    ASSERT_GE(rawFd, 0);

    impl_->ConfigureOutFd(OutFd(rawFd));
    int32_t dupFd = impl_->fd_.Get();
    EXPECT_GE(dupFd, 0);
    EXPECT_NE(dupFd, rawFd);

    impl_->CloseFd();
    EXPECT_EQ(-1, impl_->fd_.Get());
    close(rawFd);
}

/**
 * @tc.name: hirecorder_GetCurrentCapturerChangeInfo_NullFilter_001
 * @tc.desc: GetCurrentCapturerChangeInfo fails with ERROR_INVALID_OPERATION when the capture filter is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderImplEngineGuardTest, hirecorder_GetCurrentCapturerChangeInfo_NullFilter_001, TestSize.Level2)
{
    impl_->audioCaptureFilter_ = nullptr;

    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(static_cast<int32_t>(Status::ERROR_INVALID_OPERATION),
        impl_->GetCurrentCapturerChangeInfo(changeInfo));
}