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

#include "media_errors.h"
#include "hiplayer_impl_unittest.h"
#include "i_player_engine.h"
#include "pipeline/pipeline.h"
#include "player.h"
#include "audio_device_descriptor.h"
#include "audio_capture_filter.h"
#include "avcodec_info.h"
#include "avcodec_list.h"
#include "plugin/plugin_event.h"
#include "demuxer/demuxer_plugin_manager.h"
#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <tuple>

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
namespace {
const std::string TEST_TRACK_FILTER_AUDIO_MIME = "audio/aac";
const std::string TEST_TRACK_FILTER_SUBTITLE_LANGUAGE = "en";
const std::string TEST_FILTER_NAME = "testname";
constexpr int32_t AUDIO_TRACK_EVENT_INDEX = 0;
constexpr int32_t INVALID_AUDIO_TRACK_ID = -1;
constexpr uint32_t ASYNC_TASK_WAIT_TIME = 1000;
const std::string TEST_AUDIO_MIME = "audio/test";
std::vector<std::tuple<std::string, int32_t, std::string, PlayerErrorType>> g_errorEvents = {
    {"audioDecoder", MSERR_UNSUPPORT_AUD_DEC_TYPE, "audio/test_mime", PlayerErrorType::AUD_DEC_ERR},
    {"audioDecoder", MSERR_DRM_VERIFICATION_FAILED, "audio/test_mime", PlayerErrorType::DRM_ERR},
    {"audio_sink_filter", MSERR_AUD_RENDER_FAILED, "null", PlayerErrorType::AUD_OUTPUT_ERR},
    {"DecoderSurfaceFilter", MSERR_EXT_API9_IO, "video/test_mime", PlayerErrorType::VID_DEC_ERR},
    {"DecoderSurfaceFilter", MSERR_EXT_API9_IO, "post_processor", PlayerErrorType::VPE_ERR},
    {"decoderSurface", MSERR_UNSUPPORT_VID_DEC_TYPE, "video/test_mime", PlayerErrorType::VID_DEC_ERR},
    {"decoderSurface", MSERR_VID_DEC_FAILED, "video/test_mime", PlayerErrorType::VID_DEC_ERR},
    {"decoderSurface", MSERR_UNSUPPORT_VID_SRC_TYPE, "video/test_mime", PlayerErrorType::VID_DEC_ERR},
    {"demuxer_filter", MSERR_DEMUXER_FAILED, "video/test_mime", PlayerErrorType::DEM_FMT_ERR},
    {"demuxer_filter", MSERR_UNSUPPORT_CONTAINER_TYPE, "video/test_mime", PlayerErrorType::DEM_FMT_ERR},
    {"demuxer_filter", MSERR_DATA_SOURCE_ERROR_UNKNOWN, "video/test_mime", PlayerErrorType::DEM_PARSE_ERR},
    {"demuxer_filter", MSERR_DEMUXER_BUFFER_NO_MEMORY, "video/test_mime", PlayerErrorType::DEM_PARSE_ERR},
    {"demuxer_filter", static_cast<int32_t>(Plugins::NetworkClientErrorCode::ERROR_TIME_OUT), "client",
        PlayerErrorType::NET_ERR},
    {"audioSinkPlugin", MSERR_UNSUPPORT_AUD_SAMPLE_RATE, "null", PlayerErrorType::AUD_OUTPUT_ERR},
    {"sampleRate isn't supported", MSERR_UNSUPPORT_AUD_SAMPLE_RATE, "sample_rate",
        PlayerErrorType::AUD_OUTPUT_ERR},
    {"channel isn't supported", MSERR_UNSUPPORT_AUD_CHANNEL_NUM, "channel_num", PlayerErrorType::AUD_OUTPUT_ERR},
    {"sampleFmt isn't supported", MSERR_UNSUPPORT_AUD_PARAMS, "sample_format", PlayerErrorType::AUD_OUTPUT_ERR}};
}

void PlayHiplayerImplUnitTest::SetUpTestCase(void)
{
}

void PlayHiplayerImplUnitTest::TearDownTestCase(void)
{
}

void PlayHiplayerImplUnitTest::SetUp(void)
{
    hiplayer_ = std::make_shared<HiPlayerImpl>(0, 0, 0, 0);
}

void PlayHiplayerImplUnitTest::TearDown(void)
{
    usleep(ASYNC_TASK_WAIT_TIME);
    hiplayer_ = nullptr;
}

/**
 * @tc.name  : Test AVMediaSource directoryPath API
 * @tc.number: AVMediaSource_directoryPath_001
 * @tc.desc  : Test AVMediaSource directoryPath interface
 */
HWTEST_F(PlayHiplayerImplUnitTest, AVMediaSource_DirectoryPath_001, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    auto mediaSource = std::make_shared<AVMediaSource>("file:///data/test/H264_AAC.mp4", header);
    auto path = mediaSource->GetDirectoryPath();
    EXPECT_EQ(path, "");
    mediaSource->SetDirectoryPath("0123456");
    path = mediaSource->GetDirectoryPath();
    EXPECT_EQ(path, "0123456");
}

// @tc.name     Test SetDefaultAudioRenderInfo API
// @tc.number   PHIUT_SetDefaultAudioRenderInfo_001
// @tc.desc     Test SetDefaultAudioRenderInfo interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetDefaultAudioRenderInfo_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    std::shared_ptr<Meta> testptr = nullptr;
    trackInfos.push_back(testptr);
    hiplayer_->SetDefaultAudioRenderInfo(trackInfos);
    int32_t isHdrVivid;
    hiplayer_->audioRenderInfo_->GetData(Tag::AUDIO_RENDER_INFO, isHdrVivid);
    EXPECT_EQ(isHdrVivid, 0);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_003
// @tc.desc     Test branch currentAudioTrackId_ < 0 in HandleAudioTrackChangeEvent.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    meta1->SetData(Tag::MIME_TYPE, std::string("audio/"));
    std::vector<std::shared_ptr<Meta>> metaInfos;
    metaInfos.push_back(meta1);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo())
        .WillRepeatedly(Return(metaInfos));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->defaultAudioTrackId_ = INVALID_AUDIO_TRACK_ID;

    Event event;
    event.param = AUDIO_TRACK_EVENT_INDEX;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, INVALID_AUDIO_TRACK_ID);
}

// @tc.name     Test SetSource API
// @tc.number   PHIUT_SetSource_001
// @tc.desc     Test SetSource interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetSource_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<IMediaDataSource> dataSrc;
    int32_t ret = hiplayer_->SetSource(dataSrc);
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test PrepareAsync API
// @tc.number   PHIUT_PrepareAsync_001
// @tc.desc     Test PrepareAsync interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PrepareAsync_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STATE_ERROR;
    int32_t ret = hiplayer_->PrepareAsync();
    EXPECT_EQ(ret, 331350054);
}

// @tc.name     Test UpdateMediaFirstPts API
// @tc.number   PHIUT_UpdateMediaFirstPts_001
// @tc.desc     Test UpdateMediaFirstPts interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_UpdateMediaFirstPts_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = nullptr;
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->UpdateMediaFirstPts();
    EXPECT_EQ(hiplayer_->demuxer_->GetStreamMetaInfo().empty(), false);
}

// @tc.name     Test SelectBitRate API
// @tc.number   PHIUT_SelectBitRate_001
// @tc.desc     Test SelectBitRate interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SelectBitRate_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    uint32_t bitRate = 1212;
    bool isAutoSelect = false;
    int32_t ret = hiplayer_->SelectBitRate(bitRate, isAutoSelect);
    EXPECT_NE(ret, 0);
}

// @tc.name     Test DoInitializeForHttp API
// @tc.number   PHIUT_DoInitializeForHttp_001
// @tc.desc     Test DoInitializeForHttp interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoInitializeForHttp_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isNetWorkPlay_ = true;
    string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->DoInitializeForHttp();
    EXPECT_NE(hiplayer_->isNetWorkPlay_, false);
}

// @tc.name     Test ReportAudioInterruptEvent API
// @tc.number   PHIUT_ReportAudioInterruptEvent_001
// @tc.desc     Test ReportAudioInterruptEvent interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ReportAudioInterruptEvent_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->interruptNotifyPlay_.store(true);
    hiplayer_->ReportAudioInterruptEvent();
    EXPECT_EQ(hiplayer_->interruptNotifyPlay_.load(), false);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_001
// @tc.desc     Test Seek interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    int32_t mSeconds = 5;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 0;
    hiplayer_->startTimeWithMode_ = 10;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    EXPECT_NE(ret, 0);
}

// @tc.name     Test NotifySubtitleSeek API
// @tc.number   PHIUT_NotifySubtitleSeek_001
// @tc.desc     PHIUT_NotifySubtitleSeek_001
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NotifySubtitleSeek_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);

    hiplayer_->hasExtSub_ = true;
    hiplayer_->subtitleSink_ = FilterFactory::Instance().CreateFilter<SubtitleSinkFilter>("player.subtitlesink",
        FilterType::FILTERTYPE_SSINK);
    
    // Call the function to be tested
    int32_t ret = hiplayer_->NotifySubtitleSeek();
 
    // Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test NotifySubtitleSeek API
// @tc.number   PHIUT_NotifySubtitleSeek_002
// @tc.desc     PHIUT_NotifySubtitleSeek_002
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NotifySubtitleSeek_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);

    hiplayer_->hasExtSub_ = false;
    hiplayer_->subtitleSink_ = FilterFactory::Instance().CreateFilter<SubtitleSinkFilter>("player.subtitlesink",
        FilterType::FILTERTYPE_SSINK);
    
    // Call the function to be tested
    int32_t ret = hiplayer_->NotifySubtitleSeek();
 
    // Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test NotifySubtitleSeek API
// @tc.number   PHIUT_NotifySubtitleSeek_003
// @tc.desc     PHIUT_NotifySubtitleSeek_003
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NotifySubtitleSeek_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);

    hiplayer_->hasExtSub_ = true;
    hiplayer_->subtitleSink_ = nullptr;
    
    // Call the function to be tested
    int32_t ret = hiplayer_->NotifySubtitleSeek();
 
    // Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test NotifySubtitleSeek API
// @tc.number   PHIUT_NotifySubtitleSeek_004
// @tc.desc     PHIUT_NotifySubtitleSeek_004
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NotifySubtitleSeek_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);

    hiplayer_->hasExtSub_ = false;
    hiplayer_->subtitleSink_ = nullptr;
    
    // Call the function to be tested
    int32_t ret = hiplayer_->NotifySubtitleSeek();
 
    // Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test NeedSeekClosest API
// @tc.number   PHIUT_NeedSeekClosest_001
// @tc.desc     Test Seek NeedSeekClosest, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NeedSeekClosest_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    bool ret = hiplayer_->NeedSeekClosest();
    EXPECT_NE(ret, false);
}

// @tc.name     Test SetVolumeMode API
// @tc.number   PHIUT_SetVolumMode_001
// @tc.desc     Test SetVolumeMode interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetVolumeMode_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    int32_t mode = 10;
    std::string name = "testname";
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    int32_t ret = hiplayer_->SetVolumeMode(mode);
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test SetVolume API
// @tc.number   PHIUT_SetVolume_001
// @tc.desc     Test SetVolume interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetVolume_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    float leftVolume = 0.5f;
    float rightVolume = 0.5f;
    std::string name = "testname";
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    int32_t ret = hiplayer_->SetVolume(leftVolume, rightVolume);
    EXPECT_NE(ret, -7);
}

// @tc.name     Test SetDecryptConfig API
// @tc.number   PHIUT_SetDecryptConfig_001
// @tc.desc     Test SetDecryptConfig interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetDecryptConfig_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    sptr<OHOS::DrmStandard::IMediaKeySessionService> keySessionProxy;
    bool svp = false;
    int32_t ret = hiplayer_->SetDecryptConfig(keySessionProxy, svp);
    EXPECT_EQ(ret, -7);
}

// @tc.name     Test InitDuration API
// @tc.number   PHIUT_InitDuration_001
// @tc.desc     Test InitDuration interface, 3.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InitDuration_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    hiplayer_->audioSink_->audioSink_ = std::make_shared<AudioSink>();
    int32_t ret = hiplayer_->InitDuration();
    EXPECT_NE(ret, 0);
}

// @tc.name     Test InitDuration API
// @tc.number   PHIUT_InitDuration_002
// @tc.desc     Test InitDuration interface, demuxer_ is nullptr (Branch 1).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InitDuration_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->demuxer_ = nullptr;
    int32_t ret = hiplayer_->InitDuration();
    auto errcode = 331350528;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test OnEventContinue API
// @tc.number   PHIUT_OnEventContinue_001
// @tc.desc     Test OnEventContinue interface, 3.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventContinue_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->currentVideoTrackId_ = 0;

    Event event;
    event.type = EventType::EVENT_RESOLUTION_CHANGE;
    std::pair<int32_t, int32_t> videoSize = {1920, 1080};
    event.param = videoSize;

    hiplayer_->OnEventContinue(event);
    EXPECT_EQ(hiplayer_->videoWidth_.load(), 1920);
    EXPECT_EQ(hiplayer_->videoHeight_.load(), 1080);
}

// @tc.name     Test OnEventContinue EVENT_HW_DECODER_UNSUPPORT_CAP
// @tc.number   PHIUT_OnEventContinue_003
// @tc.desc     Test OnEventContinue EVENT_HW_DECODER_UNSUPPORT_CAP
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventContinue_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isNeedSwDecoder_ = false;
    hiplayer_->notNotifyForSw_ = false;

    Event event;
    event.type = EventType::EVENT_HW_DECODER_UNSUPPORT_CAP;
    hiplayer_->OnEventContinue(event);
    EXPECT_EQ(hiplayer_->isNeedSwDecoder_, true);
    EXPECT_EQ(hiplayer_->notNotifyForSw_, true);
}

// @tc.name     Test OnEventSub API
// @tc.number   PHIUT_OnEventSub_001
// @tc.desc     Test OnEventSub interface, 4.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventSub_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isBufferingStartNotified_.store(true);
    hiplayer_->isSeekClosest_.store(false);
    {
        std::unique_lock<std::mutex> lock(hiplayer_->flvLiveMutex_);
        hiplayer_->isBufferingEnd_ = false;
    }

    Event event;
    event.type = EventType::BUFFERING_END;
    event.param = 10;
    hiplayer_->OnEventSub(event);

    {
        std::unique_lock<std::mutex> lock(hiplayer_->flvLiveMutex_);
        EXPECT_EQ(hiplayer_->isBufferingEnd_, true);
    }
}

// @tc.name     Test DoSetSource API
// @tc.number   PHIUT_DoSetSource_001
// @tc.desc     Test DoSetSource interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoSetSource_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string url = "";
    hiplayer_->mimeType_ = "testtype";
    AVPlayMediaStream avplayMediaStream;
    hiplayer_->playMediaStreamVec_.push_back(avplayMediaStream);
    std::shared_ptr<MediaSource> source = std::make_shared<MediaSource>(url);
    hiplayer_->DoSetSource(source);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
}

// @tc.name     Test HandleDrmInfoUpdatedEvent API
// @tc.number   PHIUT_HandleDrmInfoUpdatedEvent_001
// @tc.desc     Test HandleDrmInfoUpdatedEvent interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleDrmInfoUpdatedEvent_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    Event event;
    std::multimap<std::string, std::vector<uint8_t>> test1;
    event.param = test1;
    hiplayer_->HandleDrmInfoUpdatedEvent(event);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
}

// @tc.name     Test HandleResolutionChangeEvent API
// @tc.number   PHIUT_HandleResolutionChangeEvent_001
// @tc.desc     Test HandleResolutionChangeEvent interface, 4.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleResolutionChangeEvent_001, TestSize.Level0)
{
#ifdef SUPPORT_VIDEO
#undef SUPPORT_VIDEO
#endif
#define SUPPORT_VIDEO
    ASSERT_NE(hiplayer_, nullptr);
    Event event;
    Format format;
    format.meta_ = std::make_shared<Meta>();
    event.param = format;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->currentVideoTrackId_ = 0;
    hiplayer_->HandleResolutionChangeEvent(event);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
#undef SUPPORT_VIDEO
}

// @tc.name     Test NotifySeekDone API
// @tc.number   PHIUT_NotifySeekDone_001
// @tc.desc     Test NotifySeekDone interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_NotifySeekDone_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->curState_ = PlayerStateId::INIT;
    std::string name = "testname";
    int32_t testValue = 0;
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->isSeekClosest_.store(true);
    hiplayer_->isBufferingStartNotified_.store(true);
    hiplayer_->NotifySeekDone(testValue);
    EXPECT_NE(hiplayer_->isSeekClosest_.load(), true);
}

// @tc.name     Test OnStateChanged API
// @tc.number   PHIUT_OnStateChanged_001
// @tc.desc     Test OnStateChanged interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnStateChanged_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isDoCompletedSeek_.store(false);
    hiplayer_->curState_ = PlayerStateId::EOS;
    PlayerStateId state = PlayerStateId::PAUSE;
    bool isSystemOperation = false;
    hiplayer_->OnStateChanged(state, isSystemOperation);
    EXPECT_NE(hiplayer_->isSeekClosest_.load(), true);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_001
// @tc.desc     Test OnCallback interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Filter> filter;
    FilterCallBackCommand cmd = FilterCallBackCommand::NEXT_FILTER_NEEDED;
    OHOS::Media::Pipeline::StreamType outType = OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_VIDEO;
    Status ret = hiplayer_->OnCallback(filter, cmd, outType);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test SetAudioRendererParameter API
// @tc.number   PHIUT_SetAudioRendererParameter_001
// @tc.desc     Test SetAudioRendererParameter interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetAudioRendererParameter_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    hiplayer_->audioInterruptMode_ = std::make_shared<Meta>();;
    hiplayer_->SetAudioRendererParameter();
    EXPECT_NE(hiplayer_->isSeekClosest_.load(), true);
}

// @tc.name     Test IsInValidSeekTime API
// @tc.number   PHIUT_IsInValidSeekTime_001
// @tc.desc     Test if (seekTime > endTimeWithMode_)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsInValidSeekTime_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->endTimeWithMode_ = 0;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t seekPos = 1;
    auto mockPipeline = std::make_shared<MockPipeline>();
    EXPECT_CALL(*mockPipeline, SetPlayRange(_, _)).WillRepeatedly(Return(Status::OK));
    hiplayer_->pipeline_ = mockPipeline;
    auto ret = hiplayer_->IsInValidSeekTime(seekPos);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test AddSubSource API
// @tc.number   PHIUT_AddSubSource_001
// @tc.desc     Test if (result != MSERR_OK)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_AddSubSource_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string uriTest = "file:///path/../testfile.txt";
    auto ret = hiplayer_->AddSubSource(uriTest);
    EXPECT_NE(ret, 0);
}

// @tc.name     Test SetStartFrameRateOptEnabled API
// @tc.number   PHIUT_SetStartFrameRateOptEnabled_001
// @tc.desc     Test all
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetStartFrameRateOptEnabled_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool enabled = true;
    auto ret = hiplayer_->SetStartFrameRateOptEnabled(enabled);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(hiplayer_->isEnableStartFrameRateOpt_, true);
}

// @tc.name     Test SetInterruptState API
// @tc.number   PHIUT_SetInterruptState_001
// @tc.desc     Test if (isFlvLive_ && bufferDurationForPlaying_ > 0)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetInterruptState_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool isInterruptNeeded = false;
    hiplayer_->interruptMonitor_ = nullptr;
    hiplayer_->isDrmProtected_ = false;
    hiplayer_->isFlvLive_ = true;
    hiplayer_->bufferDurationForPlaying_ = 1;
    hiplayer_->SetInterruptState(isInterruptNeeded);
    EXPECT_EQ(hiplayer_->isInterruptNeeded_, false);
}

// @tc.name     Test SelectBitRate API
// @tc.number   PHIUT_SelectBitRate_002
// @tc.desc     Test return MSERR_INVALID_OPERATION;
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SelectBitRate_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, SelectBitRate(_, _)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    hiplayer_->demuxer_ = mockDemuxer;
    uint32_t bitRate = 0;
    bool isAutoSelect = false;
    auto ret = hiplayer_->SelectBitRate(bitRate, isAutoSelect);
    EXPECT_NE(ret, 0);
}

// @tc.name     Test DoInitializeForHttp API
// @tc.number   PHIUT_DoInitializeForHttp_002
// @tc.desc     Test if (ret == Status::OK && vBitRates.size() > 0)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoInitializeForHttp_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetBitRates(_)).WillRepeatedly(Invoke([](std::vector<uint32_t> vBitRates) {
        vBitRates.push_back(1);
        return Status::OK;
    }));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isNetWorkPlay_ = false;
    hiplayer_->DoInitializeForHttp();
    EXPECT_EQ(hiplayer_->isInterruptNeeded_, false);
}

// @tc.name     Test SetVolumeMode API
// @tc.number   PHIUT_SetVolumeMode_002
// @tc.desc     Test if (ret != Status::OK)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetVolumeMode_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    int32_t mode = 10;
    std::string name = "testname";
    auto mockAudioSink = std::make_shared<MockAudioSinkFilter>(name, FilterType::VIDEO_CAPTURE);
    EXPECT_CALL(*mockAudioSink, SetVolumeMode(_)).WillRepeatedly(Return(Status::ERROR_NULL_POINTER));
    hiplayer_->audioSink_ = mockAudioSink;
    auto ret = hiplayer_->SetVolumeMode(mode);
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test InnerSelectTrack API
// @tc.number   PHIUT_InnerSelectTrack_001
// @tc.desc     Test if (IsSubtitleMime(mime))else if (IsVideoMime(mime))
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InnerSelectTrack_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, SelectTrack(_)).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    std::string mime = "text/vtt";
    int32_t trackId = 1;
    PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SEGMENT;
    hiplayer_->InnerSelectTrack(mime, trackId, mode);
}

// @tc.name     Test InnerSelectTrack API
// @tc.number   PHIUT_InnerSelectTrack_002
// @tc.desc     Test mode == PlayerSwitchMode::SWITCH_SEGMENT & mode == PlayerSwitchMode::SWITCH_CLOSEST
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InnerSelectTrack_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, SelectTrack(_)).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    std::string mime = "video/test";
    int32_t trackId = 1;
    PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SEGMENT;
    hiplayer_->curState_ = PlayerStateId::EOS;
    auto ret = hiplayer_->InnerSelectTrack(mime, trackId, mode);
    EXPECT_NE(ret, MSERR_OK);
    mode = PlayerSwitchMode::SWITCH_CLOSEST;
    ret = hiplayer_->InnerSelectTrack(mime, trackId, mode);
    EXPECT_NE(ret, MSERR_OK);
}

// @tc.name     Test SelectTrack API
// @tc.number   PHIUT_SelectTrack_001
// @tc.desc     Test return MSERR_UNKNOWN;
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SelectTrack_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    meta1->SetData(Tag::MIME_TYPE, "test/invailed");
    std::vector<std::shared_ptr<Meta>> metaInfo;
    metaInfo.push_back(meta1);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(metaInfo));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t trackId = 0;
    PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SEGMENT;
    auto ret = hiplayer_->SelectTrack(trackId, mode);
    EXPECT_NE(ret, MSERR_OK);
}

// @tc.name     Test GetSubtitleTrackInfo API
// @tc.number   PHIUT_GetSubtitleTrackInfo_001
// @tc.desc     Test !(trackInfo->GetData(Tag::MIME_TYPE, mime))||mime.find("invalid") == 0)if(IsSubtitleMime(mime))
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_GetSubtitleTrackInfo_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    meta1->SetData(Tag::MIME_TYPE, "test/invailed");
    std::shared_ptr<Meta> meta2 = std::make_shared<Meta>();
    meta2->SetData(Tag::MIME_TYPE, "text/vtt");
    std::vector<std::shared_ptr<Meta>> metaInfo;
    metaInfo.push_back(meta2);
    metaInfo.push_back(meta1);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(metaInfo));
    hiplayer_->demuxer_ = mockDemuxer;
    std::vector<Format> subtitleTrack;
    auto ret = hiplayer_->GetSubtitleTrackInfo(subtitleTrack);
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_001
// @tc.desc     Test if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime)))
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> metaInfo;
    metaInfo.push_back(meta1);
    Event event;
    event.param = 0;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(metaInfo));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_NE(metaInfo.size(), 0);
}

// @tc.name     Test HandleVideoTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_002
// @tc.desc     Test if (Status::OK != demuxer_->StartTask(trackId))
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    meta1->SetData(Tag::MIME_TYPE, "video/test");
    std::vector<std::shared_ptr<Meta>> metaInfo;
    metaInfo.push_back(meta1);
    Event event;
    event.param = 0;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(metaInfo));
    EXPECT_CALL(*mockDemuxer, StartTask(_)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->HandleVideoTrackChangeEvent(event);
}

// @tc.name     Test HandleSubtitleTrackChangeEvent API
// @tc.number   PHIUT_HandleSubtitleTrackChangeEvent_001
// @tc.desc     Test if (!(metaInfo[trackId]->GetData(Tag::MIME_TYPE, mime)))
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleSubtitleTrackChangeEvent_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Meta> meta1 = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> metaInfo;
    metaInfo.push_back(meta1);
    Event event;
    event.param = 0;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetStreamMetaInfo()).WillRepeatedly(Return(metaInfo));
    EXPECT_CALL(*mockDemuxer, StartTask(_)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->HandleSubtitleTrackChangeEvent(event);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_002
// @tc.desc     Test default
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    auto mockFilter = std::make_shared<MockFilter>();
    std::shared_ptr<Filter> filter = mockFilter;
    FilterCallBackCommand cmd = FilterCallBackCommand::NEXT_FILTER_NEEDED;
    OHOS::Media::Pipeline::StreamType outType = OHOS::Media::Pipeline::StreamType::STREAMTYPE_MAX;
    auto ret = hiplayer_->OnCallback(filter, cmd, outType);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test DoRestartLiveLink API
// @tc.number   PHIUT_DoRestartLiveLink_001
// @tc.desc     Test audioDecoder_ == nullptr && audioSink_ == nullptr && videoDecoder_ == nullptr
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoRestartLiveLink_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isFlvLive_ = true;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillOnce(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->videoDecoder_ = nullptr;
    hiplayer_->audioDecoder_ = nullptr;
    
    hiplayer_->DoRestartLiveLink();
}

// @tc.name     Test LinkSeiDecoder API
// @tc.number   PHIUT_LinkSeiDecoder_001
// @tc.desc     Test seiDecoder_ != nullptr
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_LinkSeiDecoder_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockSeiDecoder = std::make_shared<SeiParserFilter>(name, type);
    hiplayer_->seiDecoder_ = mockSeiDecoder;
    auto mockFilter = std::make_shared<MockFilter>();
    std::shared_ptr<Filter> preFilter = mockFilter;
    auto ret = hiplayer_->LinkSeiDecoder(preFilter, OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test SetMediaMuted API
// @tc.number   PHIUT_SetMediaMuted_001
// @tc.desc     Test SetMediaMuted interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetMediaMuted_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->audioSink_ = nullptr;
    int32_t ret = hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true);
    EXPECT_NE(ret, MSERR_OK);

    std::string name = "testname";
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    ret = hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true);
    EXPECT_NE(ret, MSERR_OK);
}

// @tc.name     Test SetMediaMuted API
// @tc.number   PHIUT_SetMediaMuted_002
// @tc.desc     Test SetMediaMuted interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetMediaMuted_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->videoDecoder_ = std::make_shared<DecoderSurfaceFilter>(name, type);
    hiplayer_->demuxer_ = std::make_shared<MockDemuxerFilter>(name, type);
    int32_t ret = hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true);
    EXPECT_EQ(hiplayer_->isVideoMuted_, true);
    EXPECT_EQ(ret, MSERR_OK);

    hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, false);
    EXPECT_EQ(hiplayer_->isVideoMuted_, false);
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test SetMediaMuted API
// @tc.number   PHIUT_SetMediaMuted_003
// @tc.desc     Test SetMediaMuted interface, 3.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetMediaMuted_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    int32_t ret = hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_SUBTITLE, true);
    EXPECT_NE(ret, MSERR_OK);

    ret = hiplayer_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_SUBTITLE, false);
    EXPECT_NE(ret, MSERR_OK);
}

// @tc.name     Test ReportAllErrorEvents
// @tc.number   PHIUT_ReportAllErrorEvents_001
// @tc.desc     Test all error reporting points from various filters
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ReportAllErrorEvents_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    hiplayer_->SetObs(mockObs);
    hiplayer_->pipeline_ = std::make_shared<MockPipeline>();
    hiplayer_->Init();
    auto receiver = hiplayer_->playerEventReceiver_;
    ASSERT_NE(receiver, nullptr);
    std::vector<std::tuple<PlayerErrorType, int32_t, std::string>> actualEvents;
    EXPECT_CALL(*mockObs, OnError(_, _, _))
        .WillRepeatedly(Invoke([&](PlayerErrorType t, int32_t code, const std::string &desc) {
            actualEvents.emplace_back(t, code, desc);
        }));
    for (const auto& e : g_errorEvents) {
        Event event;
        event.srcFilter = std::get<0>(e);
        event.type = EventType::EVENT_ERROR;
        event.param = std::get<1>(e);
        event.description = std::get<2>(e);
        receiver->OnEvent(event);
    }
    for (int i = 0; i < 20 && actualEvents.size() < g_errorEvents.size(); ++i) {
        usleep(10000);
    }
    EXPECT_EQ(actualEvents.size(), g_errorEvents.size());
    for (size_t i = 0; i < g_errorEvents.size(); ++i) {
        EXPECT_EQ(std::get<0>(actualEvents[i]), std::get<3>(g_errorEvents[i]));
        EXPECT_EQ(std::get<1>(actualEvents[i]), std::get<1>(g_errorEvents[i]));
        EXPECT_EQ(std::get<2>(actualEvents[i]), std::get<2>(g_errorEvents[i]));
    }
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_002
// @tc.desc     Test Seek interface.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    testptr->SetData(Tag::MIME_TYPE, "video/test");
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetGlobalMetaInfo()).WillRepeatedly(Return(testptr));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 5;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = -1;
    hiplayer_->startTimeWithMode_ = 10;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_003
// @tc.desc     Test Seek interface, seekable range is empty (Branch 2).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> emptyRanges;
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(emptyRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_004
// @tc.desc     Test Seek interface, seek time found in seekable range (Branch 3).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_005
// @tc.desc     Test Seek interface, isLiveSeek_ flag is set (Branch 3a).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 10;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    hiplayer_->isLiveSeek_ = false;
    int32_t curPos = 80;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_006
// @tc.desc     Test Seek interface, seek time not in seekable range (Branch 4).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 50};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 100;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_007
// @tc.desc     Test Seek interface, seekPos < 0 (invalid parameter).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = -1;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_008
// @tc.desc     Test Seek interface, audioSink_ is nullptr (skip SetIsTransitent).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = nullptr;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_009
// @tc.desc     Test Seek interface, multiple seekable ranges, seek position in first range.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_009, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range1 = {0, 50};
    Plugins::SeekRange range2 = {100, 200};
    testRanges.push_back(range1);
    testRanges.push_back(range2);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 25;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_010
// @tc.desc     Test Seek interface, seek position in second range.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_010, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range1 = {0, 50};
    Plugins::SeekRange range2 = {100, 200};
    testRanges.push_back(range1);
    testRanges.push_back(range2);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 150;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_011
// @tc.desc     Test Seek interface, rtv != Status::OK after seek.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_011, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = -5;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_012
// @tc.desc     Test Seek interface, notifySeekDone is true.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_012, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    auto ret = hiplayer_->Seek(mSeconds, mode, true);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_013
// @tc.desc     Test Seek interface, isUnFreezeSeek is true.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_013, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 0;
    (void)hiplayer_->GetCurrentTime(curPos);
    auto ret = hiplayer_->Seek(mSeconds, mode, false, true);
    EXPECT_EQ(ret, Status::ERROR_INVALID_PARAMETER);
}

// @tc.name     Test Seek API
// @tc.number   PHIUT_Seek_014
// @tc.desc     Test Seek interface, curPosMs <= curPostAfterSeek (no live seek mode).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_Seek_014, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    std::vector<Plugins::SeekRange> testRanges;
    Plugins::SeekRange range = {0, 100};
    testRanges.push_back(range);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    int32_t mSeconds = 50;
    PlayerSeekMode mode = PlayerSeekMode::SEEK_NEXT_SYNC;
    hiplayer_->endTimeWithMode_ = 100;
    hiplayer_->startTimeWithMode_ = -1;
    int32_t curPos = 10;
    (void)hiplayer_->GetCurrentTime(curPos);
    hiplayer_->isLiveSeek_ = false;
    int32_t ret = hiplayer_->Seek(mSeconds, mode);
    auto errcode = 331350038;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_001
// @tc.desc     Test audioDecoder_ != nullptr, audioSink_ != nullptr, videoDecoder_ != nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockDemuxer, RebootPlugin()).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->videoDecoder_ = std::make_shared<DecoderSurfaceFilter>(name, type);
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_002
// @tc.desc     Test audioDecoder_ == nullptr, audioSink_ == nullptr, videoDecoder_ == nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockDemuxer, RebootPlugin()).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->videoDecoder_ = nullptr;
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_003
// @tc.desc     Test isLiveSeek_ == false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isLiveSeek_ = false;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_004
// @tc.desc     Test demuxer_ == nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_005
// @tc.desc     Test RebootPlugin returns error.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockDemuxer, RebootPlugin()).WillRepeatedly(Return(Status::ERROR_UNKNOWN));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_008
// @tc.desc     Test audioDecoder_ != nullptr, audioSink_ != nullptr, videoDecoder_ == nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockDemuxer, RebootPlugin()).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->videoDecoder_ = nullptr;
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test SeekToDefaultPosition API
// @tc.number   PHIUT_SeekToDefaultPosition_009
// @tc.desc     Test RebootPlugin returns ERROR_INVALID_PARAMETER.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekToDefaultPosition_009, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockDemuxer, RebootPlugin()).WillRepeatedly(Return(Status::ERROR_INVALID_PARAMETER));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isLiveSeek_ = true;
    int32_t ret = hiplayer_->SeekToDefaultPosition();
    auto errcode = 0;
    EXPECT_EQ(ret, errcode);
}

// @tc.name     Test InnerSelectTrack API
// @tc.number   PHIUT_InnerSelectTrack_003
// @tc.desc     Test InnerSelectTrack with audio mime, SelectTrack fails and returns early
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InnerSelectTrack_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    std::string mime = "audio/aac";
    int32_t trackId = 2;
    PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SMOOTH;
    auto ret = hiplayer_->InnerSelectTrack(mime, trackId, mode);
    EXPECT_NE(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, -1);
}

// @tc.name     Test InnerSelectTrack API
// @tc.number   PHIUT_InnerSelectTrack_004
// @tc.desc     Test InnerSelectTrack with audio mime in EOS state, SelectTrack fails and returns early
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_InnerSelectTrack_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->curState_ = PlayerStateId::EOS;
    std::string mime = "audio/aac";
    int32_t trackId = 2;
    PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SMOOTH;
    auto ret = hiplayer_->InnerSelectTrack(mime, trackId, mode);
    EXPECT_NE(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, -1);
}

// @tc.name     Test GetSeekableRanges API
// @tc.number   PHIUT_GetSeekableRanges_001
// @tc.desc     Test demuxer_ != nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_GetSeekableRanges_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::vector<Plugins::SeekRange> testSeekableRanges;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetSeekableRanges()).WillRepeatedly(Return(testSeekableRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    auto ret = hiplayer_->GetSeekableRanges();
    EXPECT_EQ(ret.size(), 0);
}

// @tc.name     Test GetLoadedRanges API
// @tc.number   PHIUT_GetLoadedRanges_001
// @tc.desc     Test demuxer_ != nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_GetLoadedRanges_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::vector<Plugins::SeekRange> testLoadedRanges;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetLoadedRanges()).WillRepeatedly(Return(testLoadedRanges));
    hiplayer_->demuxer_ = mockDemuxer;
    auto ret = hiplayer_->GetLoadedRanges();
    EXPECT_EQ(ret.size(), 0);
}

// @tc.name     Test IsNeedChangePlaySpeed API
// @tc.number   PHIUT_IsNeedChangePlaySpeed_001
// @tc.desc     Test demuxer_ == nullptr.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsNeedChangePlaySpeed_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    bool isXSpeedPlay = false;
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->isFlvLive_ = true;
    bool ret = hiplayer_->IsNeedChangePlaySpeed(mode, isXSpeedPlay);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test IsNeedChangePlaySpeed API
// @tc.number   PHIUT_IsNeedChangePlaySpeed_002
// @tc.desc     Test isFlvLive_ == false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsNeedChangePlaySpeed_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isFlvLive_ = false;
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    bool isXSpeedPlay = false;
    bool ret = hiplayer_->IsNeedChangePlaySpeed(mode, isXSpeedPlay);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test IsNeedChangePlaySpeed API
// @tc.number   PHIUT_IsNeedChangePlaySpeed_003
// @tc.desc     Test isLiveSeek_ == false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsNeedChangePlaySpeed_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isFlvLive_ = true;
    hiplayer_->isLiveSeek_ = false;
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    bool isXSpeedPlay = false;
    bool ret = hiplayer_->IsNeedChangePlaySpeed(mode, isXSpeedPlay);
    EXPECT_EQ(ret, true);
}

// @tc.name     Test IsNeedChangePlaySpeed API
// @tc.number   PHIUT_IsNeedChangePlaySpeed_004
// @tc.desc     Test cacheDuration < bufferDurationForPlaying_ * TIME_CONVERSION_UNIT && isXSpeedPlay == true.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsNeedChangePlaySpeed_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetCachedDuration()).WillRepeatedly(Return(100));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isFlvLive_ = true;
    hiplayer_->isLiveSeek_ = true;
    hiplayer_->bufferDurationForPlaying_ = 2.0;
    hiplayer_->maxLivingDelayTime_ = 10.0;
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    bool isXSpeedPlay = true;
    bool ret = hiplayer_->IsNeedChangePlaySpeed(mode, isXSpeedPlay);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(mode, PlaybackRateMode::SPEED_FORWARD_1_00_X);
    EXPECT_EQ(isXSpeedPlay, true);
}

// @tc.name     Test IsNeedChangePlaySpeed API
// @tc.number   PHIUT_IsNeedChangePlaySpeed_005
// @tc.desc     Test no condition met, return false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsNeedChangePlaySpeed_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, GetCachedDuration()).WillRepeatedly(Return(5000));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->isFlvLive_ = true;
    hiplayer_->isLiveSeek_ = true;
    hiplayer_->bufferDurationForPlaying_ = 2.0;
    hiplayer_->maxLivingDelayTime_ = 10.0;
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    bool isXSpeedPlay = false;
    bool ret = hiplayer_->IsNeedChangePlaySpeed(mode, isXSpeedPlay);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test IsLiveSeek API
// @tc.number   PHIUT_IsLiveSeek_001
// @tc.desc     Test no live, return false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsLiveSeek_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    EXPECT_FALSE(hiplayer_->IsLiveSeek());
}

// ===========================================================================
// Tests for HiPlayerImpl::IsAudioTrackPlayable
// ===========================================================================
 
// @tc.name     Test IsAudioTrackPlayable with empty mime
// @tc.number   PHIUT_IsAudioTrackPlayable_001
// @tc.desc     Empty mime string returns false (invalid input branch).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsAudioTrackPlayable("", 44100, 2);
    EXPECT_FALSE(ret);
}
 
// @tc.name     Test IsAudioTrackPlayable with mime prefixed by "invalid"
// @tc.number   PHIUT_IsAudioTrackPlayable_002
// @tc.desc     Mime starting with "invalid" returns false (invalid prefix branch).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsAudioTrackPlayable("invalid_audio", 44100, 2);
    EXPECT_FALSE(ret);
}
 
// @tc.name     Test IsAudioTrackPlayable with dolby mime and passthrough supported
// @tc.number   PHIUT_IsAudioTrackPlayable_003
// @tc.desc     Dolby mime with IsAudioPass returning true returns true.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    const std::string dolbyMime = "audio/eac3";
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{dolbyMime}));
    EXPECT_CALL(*mockObs, IsAudioPass(::testing::StrEq(dolbyMime)))
        .WillOnce(Return(true));
    // Directly set obs_ (weak_ptr) to avoid starting the callback looper thread.
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable(dolbyMime, 48000, 6);
    EXPECT_TRUE(ret);
}
 
// @tc.name     Test IsAudioTrackPlayable with dolby mime, passthrough not supported, fall back to local decoder
// @tc.number   PHIUT_IsAudioTrackPlayable_004
// @tc.desc     Dolby mime with IsAudioPass returning false falls back to local decoder capability
//              check. audio/eac3 may have a local decoder on the device, so the result depends on
//              AVCodecList::GetCapability. The test verifies the fallback path is taken (not an
//              unconditional false) by checking that the return value is consistent with local
//              decoder availability.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    const std::string dolbyMime = "audio/eac3";
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{dolbyMime}));
    EXPECT_CALL(*mockObs, IsAudioPass(::testing::StrEq(dolbyMime)))
        .WillOnce(Return(false));
    // Directly set obs_ (weak_ptr) to avoid starting the callback looper thread.
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable(dolbyMime, 48000, 6);
    // Passthrough not supported: fall back to local decoder check. On a device
    // with an eac3 decoder, ret is true; without one, ret is false. The key
    // assertion is that the function does NOT unconditionally return false.
    std::shared_ptr<MediaAVCodec::AVCodecList> codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    if (codecList == nullptr) {
        // AVCodecList unavailable: function assumes playable.
        EXPECT_TRUE(ret);
        return;
    }
    MediaAVCodec::CapabilityData *capabilityData =
        codecList->GetCapability(dolbyMime, false, MediaAVCodec::AVCodecCategory::AVCODEC_NONE);
    if (capabilityData == nullptr) {
        EXPECT_FALSE(ret);
        return;
    }
    // Decoder exists; result depends on sample rate / channel support.
    MediaAVCodec::AudioCaps audioCaps(capabilityData);
    auto srRanges = audioCaps.GetSupportedSampleRateRanges();
    auto chRange = audioCaps.GetSupportedChannel();
    bool srOk = false;
    for (const auto &r : srRanges) {
        if (48000 >= r.minVal && 48000 <= r.maxVal) {
            srOk = true;
            break;
        }
    }
    bool chOk = (6 >= chRange.minVal && 6 <= chRange.maxVal);
    EXPECT_EQ(ret, srOk && chOk);
}
 
// @tc.name     Test IsAudioTrackPlayable with non-dolby mime (decoder capability path)
// @tc.number   PHIUT_IsAudioTrackPlayable_005
// @tc.desc     Non-dolby mime queries AVCodecList; on a standard OpenHarmony device
//              audio/mp4a-latm (AAC) has a decoder with standard 44100Hz / 2ch support.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 44100, 2);
    // audio/mp4a-latm (AAC) is a standard codec with a decoder on OpenHarmony devices,
    // and 44100Hz stereo is within standard capability ranges.
    EXPECT_TRUE(ret) << "audio/mp4a-latm 44100Hz 2ch should be playable when a decoder exists";
}
 
// @tc.name     Test IsAudioTrackPlayable with non-dolby mime when obs not set
// @tc.number   PHIUT_IsAudioTrackPlayable_006
// @tc.desc     Non-dolby mime with no obs set (GetDolbyList returns empty by default),
//              falls through to AVCodecList capability check. audio/mpeg with standard
//              48000Hz / 2ch has a decoder on standard devices.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    // No obs set: callbackLooper_.GetDolbyList() returns empty, not a dolby mime.
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/mpeg", 48000, 2);
    EXPECT_TRUE(ret) << "audio/mpeg 48000Hz 2ch should be playable when a decoder exists";
}
 
// @tc.name     Test IsAudioTrackPlayable with unsupported non-dolby mime
// @tc.number   PHIUT_IsAudioTrackPlayable_007
// @tc.desc     Non-dolby mime with no decoder capability returns false. This targets
//              the capabilityData == nullptr branch.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    // Use a fabricated mime that is very unlikely to have a registered decoder,
    // to trigger the capabilityData == nullptr branch.
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/fake_nonexistent_codec_xyz", 44100, 2);
    // On a device with AVCodecList: no decoder for fabricated mime, expect false.
    // (If AVCodecListFactory returns null on a minimal environment, this may be true.)
    EXPECT_FALSE(ret) << "fabricated mime should not be playable when no decoder exists";
}
 
// @tc.name     Test IsAudioTrackPlayable with zero sample rate and channel
// @tc.number   PHIUT_IsAudioTrackPlayable_008
// @tc.desc     When sampleRate or channelCount is 0, the track is not playable.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 0, 0);
    EXPECT_FALSE(ret) << "audio/mp4a-latm with zero sampleRate/channelCount should not be playable";
}
 
// @tc.name     Test IsAudioTrackPlayable with unsupported sample rate
// @tc.number   PHIUT_IsAudioTrackPlayable_009
// @tc.desc     A very high sample rate (e.g. 999999) that is outside any decoder's
//              supported range should return false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_009, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 999999, 2);
    // 999999 Hz is far beyond any standard audio decoder's supported sample rate range.
    EXPECT_FALSE(ret) << "Unsupported sample rate should not be playable";
}
 
// @tc.name     Test IsAudioTrackPlayable with unsupported channel count
// @tc.number   PHIUT_IsAudioTrackPlayable_010
// @tc.desc     A very high channel count (e.g. 999) that is outside any decoder's
//              supported range should return false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_010, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 44100, 999);
    // 999 channels is far beyond any standard audio decoder's supported channel range.
    EXPECT_FALSE(ret) << "Unsupported channel count should not be playable";
}
 
// @tc.name     Test IsAudioTrackPlayable with standard sample rates
// @tc.number   PHIUT_IsAudioTrackPlayable_011
// @tc.desc     Common sample rates (8000, 22050, 44100, 48000) should be playable
//              for AAC with 2 channels on a standard device.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_011, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    // Standard AAC decoder supports common sample rates.
    int32_t commonRates[] = {8000, 22050, 44100, 48000};
    for (int32_t sr : commonRates) {
        bool ret = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", sr, 2);
        EXPECT_TRUE(ret) << "audio/mp4a-latm " << sr << "Hz 2ch should be playable";
    }
}
 
// @tc.name     Test IsAudioTrackPlayable with mono and stereo channels
// @tc.number   PHIUT_IsAudioTrackPlayable_012
// @tc.desc     1-channel (mono) and 2-channel (stereo) should be playable for AAC
//              at 44100Hz on a standard device.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsAudioTrackPlayable_012, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    EXPECT_CALL(*mockObs, GetDolbyList())
        .WillRepeatedly(Return(std::vector<std::string>{}));
    hiplayer_->callbackLooper_.obs_ = mockObs;
 
    bool ret1 = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 44100, 1);
    EXPECT_TRUE(ret1) << "audio/mp4a-latm 44100Hz 1ch should be playable";
    bool ret2 = hiplayer_->IsAudioTrackPlayable("audio/mp4a-latm", 44100, 2);
    EXPECT_TRUE(ret2) << "audio/mp4a-latm 44100Hz 2ch should be playable";
}
 
// ===========================================================================
// Tests for HiPlayerImpl::IsDolbyStream
// ===========================================================================
 
// @tc.name     Test IsDolbyStream default value
// @tc.number   PHIUT_IsDolbyStream_001
// @tc.desc     Default isDolbyStream_ is false, IsDolbyStream returns false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsDolbyStream_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    EXPECT_FALSE(hiplayer_->isDolbyStream_);
    bool ret = hiplayer_->IsDolbyStream();
    EXPECT_FALSE(ret);
}
 
// @tc.name     Test IsDolbyStream after setting isDolbyStream_ to true
// @tc.number   PHIUT_IsDolbyStream_002
// @tc.desc     When isDolbyStream_ is set to true, IsDolbyStream returns true.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsDolbyStream_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isDolbyStream_ = true;
    bool ret = hiplayer_->IsDolbyStream();
    EXPECT_TRUE(ret);
    hiplayer_->isDolbyStream_ = false;
}

// ===========================================================================
// Tests for HiPlayerImpl::IsVideoTrackPlayable
// ===========================================================================
 
// @tc.name     Test IsVideoTrackPlayable with empty mime
// @tc.number   PHIUT_IsVideoTrackPlayable_001
// @tc.desc     Empty mime string returns false (invalid input branch).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("", 1920, 1080);
    EXPECT_FALSE(ret);
}
 
// @tc.name     Test IsVideoTrackPlayable with mime prefixed by "invalid"
// @tc.number   PHIUT_IsVideoTrackPlayable_002
// @tc.desc     Mime starting with "invalid" returns false (invalid prefix branch).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("invalid_video", 1920, 1080);
    EXPECT_FALSE(ret);
}
 
// @tc.name     Test IsVideoTrackPlayable with invalid video size (zero width)
// @tc.number   PHIUT_IsVideoTrackPlayable_003
// @tc.desc     When videoWidth <= 0, assume playable (returns true).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/avc", 0, 1080);
    EXPECT_TRUE(ret);
}
 
// @tc.name     Test IsVideoTrackPlayable with invalid video size (zero height)
// @tc.number   PHIUT_IsVideoTrackPlayable_004
// @tc.desc     When videoHeight <= 0, assume playable (returns true).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/avc", 1920, 0);
    EXPECT_TRUE(ret);
}
 
// @tc.name     Test IsVideoTrackPlayable with supported video size (H.264 1920x1080)
// @tc.number   PHIUT_IsVideoTrackPlayable_005
// @tc.desc     Standard H.264 1080p should be playable if a decoder exists on the device.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/avc", 1920, 1080);
    // On a standard OpenHarmony device, H.264 1080p is supported by HW or SW decoder.
    EXPECT_TRUE(ret) << "H.264 1920x1080 should be playable when a decoder exists";
}
 
// @tc.name     Test IsVideoTrackPlayable with odd dimensions (alignment check)
// @tc.number   PHIUT_IsVideoTrackPlayable_006
// @tc.desc     Odd dimensions (1921x1081) are aligned to even (1922x1082) before
//              capability check. Standard codec should still support the aligned size.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/avc", 1921, 1081);
    // Odd dimensions aligned to 1922x1082; H.264 decoder typically supports this.
    EXPECT_TRUE(ret) << "Odd dimensions should be aligned and checked against decoder capability";
}
 
// @tc.name     Test IsVideoTrackPlayable with unsupported video size
// @tc.number   PHIUT_IsVideoTrackPlayable_007
// @tc.desc     Extremely large resolution (e.g. 65536x65536) is unlikely to be supported
//              by any decoder, so the function should return false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/avc", 65536, 65536);
    EXPECT_FALSE(ret) << "Extremely large resolution should not be playable";
}
 
// @tc.name     Test IsVideoTrackPlayable with unsupported mime type
// @tc.number   PHIUT_IsVideoTrackPlayable_008
// @tc.desc     Fabricated mime type with no registered decoder returns false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsVideoTrackPlayable_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    bool ret = hiplayer_->IsVideoTrackPlayable("video/fake_nonexistent_codec", 1920, 1080);
    EXPECT_FALSE(ret) << "Fabricated mime should not be playable when no decoder exists";
}

namespace {
const std::string UNSUPPORTED_AUDIO_MIME = "audio/xyz_no_such_codec";

// Build a mock demuxer whose real inner MediaDemuxer is safe to call:
// inject a fresh DemuxerPluginManager (null-checked by MediaDemuxer::StartTask)
// and the given track metas so the real GetStreamMetaInfo returns them.
std::shared_ptr<MockDemuxerFilter> CreateRebuildTestDemuxer(
    const std::vector<std::shared_ptr<Meta>>& trackMetas, bool enableSampleQueue)
{
    auto demuxer = std::make_shared<MockDemuxerFilter>(TEST_FILTER_NAME, FilterType::VIDEO_CAPTURE);
    demuxer->demuxer_->demuxerPluginManager_ = std::make_shared<DemuxerPluginManager>();
    demuxer->demuxer_->mediaMetaData_.trackMetas = trackMetas;
    demuxer->demuxer_->enableSampleQueue_ = enableSampleQueue;
    return demuxer;
}
} // namespace

// ===========================================================================
// Tests for HiPlayerImpl::GetCurrentAudioMeta
// ===========================================================================

// @tc.name     Test GetCurrentAudioMeta API
// @tc.number   PHIUT_GetCurrentAudioMeta_001
// @tc.desc     Null-return branches: no demuxer, no current audio track and a
//               track id out of range all return nullptr, while a valid track
//               returns its meta.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_GetCurrentAudioMeta_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    // branch 1: demuxer_ is nullptr
    hiplayer_->demuxer_ = nullptr;
    EXPECT_EQ(hiplayer_->GetCurrentAudioMeta(), nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    // branch 2: currentAudioTrackId_ < 0
    hiplayer_->currentAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    EXPECT_EQ(hiplayer_->GetCurrentAudioMeta(), nullptr);
    // branch 3: currentAudioTrackId_ is out of range of the stream meta info
    hiplayer_->currentAudioTrackId_ = 1; // only one track is pushed
    EXPECT_EQ(hiplayer_->GetCurrentAudioMeta(), nullptr);
    // a valid current audio track returns the meta of that track
    hiplayer_->currentAudioTrackId_ = 0;
    auto ret = hiplayer_->GetCurrentAudioMeta();
    ASSERT_NE(ret, nullptr);
    std::string mime;
    EXPECT_EQ(ret->GetData(Tag::MIME_TYPE, mime), true);
    EXPECT_EQ(mime, TEST_TRACK_FILTER_AUDIO_MIME);
}

// @tc.name     Test GetCurrentAudioMeta API
// @tc.number   PHIUT_GetCurrentAudioMeta_002
// @tc.desc     Valid current audio track returns exactly the track meta,
//               enriched with REGULAR_TRACK_ID by the demuxer.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_GetCurrentAudioMeta_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    auto ret = hiplayer_->GetCurrentAudioMeta();
    EXPECT_EQ(ret, meta);
    int32_t trackId = -1;
    EXPECT_EQ(ret->GetData(Tag::REGULAR_TRACK_ID, trackId), true);
    EXPECT_EQ(trackId, 0);
}

// ===========================================================================
// Tests for HiPlayerImpl::CheckAudioSupportOnDevice
// ===========================================================================

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_001
// @tc.desc     No current audio track: returns before any mute/report happens.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_002
// @tc.desc     Current track meta has no MIME_TYPE: returns without mute/report.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>(); // no MIME_TYPE
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_003
// @tc.desc     Current track is not an audio mime: returns without mute/report.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "video/test");
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_004
// @tc.desc     Audio not supported on device and audio filters still exist:
//               teardown to video-only and report the warning.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_005
// @tc.desc     Audio not supported but already torn down: re-notify only,
//               the old topology is not unlinked again.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    EXPECT_CALL(*mockDemuxer, UnLinkNext(_, _)).Times(0);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(&(*mockDemuxer)));
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_006
// @tc.desc     Warning already reported this play cycle: dedup branch skips
//               mute/report entirely.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_007
// @tc.desc     Audio is supported, but the audio pipeline was already torn down
//               for a non-default track: re-notify the warning.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->defaultAudioTrackId_ = 1;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test CheckAudioSupportOnDevice API
// @tc.number   PHIUT_CheckAudioSupportOnDevice_008
// @tc.desc     Audio is supported and topology is unchanged: no rebuild, no report.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioSupportOnDevice_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->defaultAudioTrackId_ = 0;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    hiplayer_->CheckAudioSupportOnDevice();
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// ===========================================================================
// Tests for HiPlayerImpl::CheckAudioTopologyRebuild
// ===========================================================================

// @tc.name     Test CheckAudioTopologyRebuild API
// @tc.number   PHIUT_CheckAudioTopologyRebuild_001
// @tc.desc     Rebuild needed but audio filters were already released:
//               skip rebuild branch.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioTopologyRebuild_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->CheckAudioTopologyRebuild(meta, TEST_TRACK_FILTER_AUDIO_MIME);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test CheckAudioTopologyRebuild API
// @tc.number   PHIUT_CheckAudioTopologyRebuild_002
// @tc.desc     Cross-topology rebuild fails when LinkNext fails: HandleRebuildFailure
//               resets the stream type and reports the warning.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_CheckAudioTopologyRebuild_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    ASSERT_EQ(hiplayer_->Init(), Status::OK);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "audio/raw"); // resolves to RAW_AUDIO, differs from ENCODED_AUDIO
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    EXPECT_CALL(*mockDemuxer, LinkNext(_, _)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    auto ret = hiplayer_->CheckAudioTopologyRebuild(meta, "audio/raw");
    EXPECT_EQ(ret, false);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// ===========================================================================
// Tests for HiPlayerImpl::ChangeAudioTrackSameTopology
// ===========================================================================

// @tc.name     Test ChangeAudioTrackSameTopology API
// @tc.number   PHIUT_ChangeAudioTrackSameTopology_001
// @tc.desc     Same topology track switch succeeds when no decoder plugin is
//               linked and the audio sink does not need a track change.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioTrackSameTopology_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    std::vector<std::shared_ptr<Meta>> metaInfo = {meta};
    auto ret = hiplayer_->ChangeAudioTrackSameTopology(meta, 0, 0, metaInfo);
    EXPECT_EQ(ret, true);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test ChangeAudioTrackSameTopology API
// @tc.number   PHIUT_ChangeAudioTrackSameTopology_002
// @tc.desc     Same topology track switch fails when StartTask fails.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioTrackSameTopology_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    // sample-queue path returns ERROR_INVALID_PARAMETER for an unknown track id
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, true);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    std::vector<std::shared_ptr<Meta>> metaInfo = {meta};
    auto ret = hiplayer_->ChangeAudioTrackSameTopology(meta, 0, 0, metaInfo);
    EXPECT_EQ(ret, false);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test ChangeAudioTrackSameTopology API
// @tc.number   PHIUT_ChangeAudioTrackSameTopology_003
// @tc.desc     Audio decoder plugin change fails: pipeline is muted to video-only.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioTrackSameTopology_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockDecoder, ChangePlugin(_)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    std::vector<std::shared_ptr<Meta>> metaInfo = {meta};
    auto ret = hiplayer_->ChangeAudioTrackSameTopology(meta, 0, 0, metaInfo);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test ChangeAudioTrackSameTopology API
// @tc.number   PHIUT_ChangeAudioTrackSameTopology_004
// @tc.desc     Audio sink needs a track change but is null: skip the sink change
//               and fail on StartTask.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioTrackSameTopology_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, true);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 1; // differs from index, meta has no sample rate
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    std::vector<std::shared_ptr<Meta>> metaInfo = {meta};
    auto ret = hiplayer_->ChangeAudioTrackSameTopology(meta, 0, 0, metaInfo);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// ===========================================================================
// Tests for HiPlayerImpl::ChangeAudioDecoderSameTopology
// ===========================================================================

// @tc.name     Test ChangeAudioDecoderSameTopology API
// @tc.number   PHIUT_ChangeAudioDecoderSameTopology_001
// @tc.desc     audioSink_ is nullptr: returns false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioDecoderSameTopology_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->ChangeAudioDecoderSameTopology(meta, TEST_TRACK_FILTER_AUDIO_MIME, false);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test ChangeAudioDecoderSameTopology API
// @tc.number   PHIUT_ChangeAudioDecoderSameTopology_002
// @tc.desc     Not a stream switch and sink parameters are unchanged: only
//               StartTask(AUDIO) is triggered, returns false.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioDecoderSameTopology_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->ChangeAudioDecoderSameTopology(meta, TEST_TRACK_FILTER_AUDIO_MIME, false);
    EXPECT_EQ(ret, false);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
}

// @tc.name     Test ChangeAudioDecoderSameTopology API
// @tc.number   PHIUT_ChangeAudioDecoderSameTopology_003
// @tc.desc     Stream switch without decoder and without sink change: succeeds
//               after StartTask(AUDIO).
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioDecoderSameTopology_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->ChangeAudioDecoderSameTopology(meta, TEST_TRACK_FILTER_AUDIO_MIME, true);
    EXPECT_EQ(ret, true);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
}

// @tc.name     Test ChangeAudioDecoderSameTopology API
// @tc.number   PHIUT_ChangeAudioDecoderSameTopology_004
// @tc.desc     Audio decoder plugin change fails: pipeline is muted to video-only.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ChangeAudioDecoderSameTopology_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockDecoder, ChangePlugin(_)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    auto ret = hiplayer_->ChangeAudioDecoderSameTopology(meta, TEST_TRACK_FILTER_AUDIO_MIME, true);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// ===========================================================================
// Tests for HiPlayerImpl::StopAudioDataFlow / UnlinkOldAudioTopology /
// ReleaseOldAudioFilters / BuildNewAudioTopology
// ===========================================================================

// @tc.name     Test StopAudioDataFlow API
// @tc.number   PHIUT_StopAudioDataFlow_001
// @tc.desc     Both audio filters are flushed.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StopAudioDataFlow_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    bool decoderFlushed = false;
    bool sinkFlushed = false;
    EXPECT_CALL(*mockDecoder, DoFlush()).WillRepeatedly(
        Invoke([&]() { decoderFlushed = true; return Status::OK; }));
    EXPECT_CALL(*mockSink, DoFlush()).WillRepeatedly(
        Invoke([&]() { sinkFlushed = true; return Status::OK; }));
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    hiplayer_->StopAudioDataFlow();
    EXPECT_EQ(decoderFlushed, true);
    EXPECT_EQ(sinkFlushed, true);
}

// @tc.name     Test UnlinkOldAudioTopology API
// @tc.number   PHIUT_UnlinkOldAudioTopology_001
// @tc.desc     Audio filters already released: nothing is unlinked.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_UnlinkOldAudioTopology_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    EXPECT_CALL(*mockDemuxer, UnLinkNext(_, _)).Times(0);
    hiplayer_->UnlinkOldAudioTopology();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(&(*mockDemuxer)));
}

// @tc.name     Test UnlinkOldAudioTopology API
// @tc.number   PHIUT_UnlinkOldAudioTopology_002
// @tc.desc     ENCODED_AUDIO topology: demuxer and decoder links are both unlinked.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_UnlinkOldAudioTopology_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    OHOS::Media::Pipeline::StreamType demuxerStreamType = OHOS::Media::Pipeline::StreamType::STREAMTYPE_MAX;
    OHOS::Media::Pipeline::StreamType decoderStreamType = OHOS::Media::Pipeline::StreamType::STREAMTYPE_MAX;
    int32_t demuxerUnlinkCount = 0;
    int32_t decoderUnlinkCount = 0;
    auto onDemuxerUnlink = [&](const std::shared_ptr<Filter>&, OHOS::Media::Pipeline::StreamType type) {
        demuxerStreamType = type;
        demuxerUnlinkCount++;
        return Status::OK;
    };
    EXPECT_CALL(*mockDemuxer, UnLinkNext(_, _)).WillRepeatedly(Invoke(onDemuxerUnlink));
    auto onDecoderUnlink = [&](const std::shared_ptr<Filter>&, OHOS::Media::Pipeline::StreamType type) {
        decoderStreamType = type;
        decoderUnlinkCount++;
        return Status::OK;
    };
    EXPECT_CALL(*mockDecoder, UnLinkNext(_, _)).WillRepeatedly(Invoke(onDecoderUnlink));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    hiplayer_->UnlinkOldAudioTopology();
    EXPECT_EQ(demuxerUnlinkCount, 1);
    EXPECT_EQ(demuxerStreamType, OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(decoderUnlinkCount, 1);
    EXPECT_EQ(decoderStreamType, OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
}

// @tc.name     Test UnlinkOldAudioTopology API
// @tc.number   PHIUT_UnlinkOldAudioTopology_003
// @tc.desc     Non-encoded topology: only the demuxer link is unlinked.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_UnlinkOldAudioTopology_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    OHOS::Media::Pipeline::StreamType demuxerStreamType = OHOS::Media::Pipeline::StreamType::STREAMTYPE_MAX;
    int32_t demuxerUnlinkCount = 0;
    auto onDemuxerUnlink = [&](const std::shared_ptr<Filter>&, OHOS::Media::Pipeline::StreamType type) {
        demuxerStreamType = type;
        demuxerUnlinkCount++;
        return Status::OK;
    };
    EXPECT_CALL(*mockDemuxer, UnLinkNext(_, _)).WillRepeatedly(Invoke(onDemuxerUnlink));
    EXPECT_CALL(*mockDecoder, UnLinkNext(_, _)).Times(0);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO;
    hiplayer_->UnlinkOldAudioTopology();
    EXPECT_EQ(demuxerUnlinkCount, 1);
    EXPECT_EQ(demuxerStreamType, OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(&(*mockDecoder)));
}

// @tc.name     Test ReleaseOldAudioFilters API
// @tc.number   PHIUT_ReleaseOldAudioFilters_001
// @tc.desc     Both audio filters are stopped, released and reset, and their
//               complete/initial states are erased.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ReleaseOldAudioFilters_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    bool decoderStopped = false;
    bool decoderReleased = false;
    bool sinkStopped = false;
    bool sinkReleased = false;
    EXPECT_CALL(*mockDecoder, DoStop()).WillRepeatedly(
        Invoke([&]() { decoderStopped = true; return Status::OK; }));
    EXPECT_CALL(*mockDecoder, DoRelease()).WillRepeatedly(
        Invoke([&]() { decoderReleased = true; return Status::OK; }));
    EXPECT_CALL(*mockSink, DoStop()).WillRepeatedly(
        Invoke([&]() { sinkStopped = true; return Status::OK; }));
    EXPECT_CALL(*mockSink, DoRelease()).WillRepeatedly(
        Invoke([&]() { sinkReleased = true; return Status::OK; }));
    hiplayer_->completeState_.push_back({"AudioSink", false});
    hiplayer_->completeState_.push_back({"VideoSink", false});
    hiplayer_->initialAVStates_.push_back({EventType::EVENT_AUDIO_FIRST_FRAME, false});
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    hiplayer_->ReleaseOldAudioFilters();
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(decoderStopped, true);
    EXPECT_EQ(decoderReleased, true);
    EXPECT_EQ(sinkStopped, true);
    EXPECT_EQ(sinkReleased, true);
    EXPECT_EQ(hiplayer_->completeState_.size(), 1);
    EXPECT_EQ(hiplayer_->completeState_[0].first, "VideoSink");
    EXPECT_EQ(hiplayer_->initialAVStates_.empty(), true);
}

// @tc.name     Test BuildNewAudioTopology API
// @tc.number   PHIUT_BuildNewAudioTopology_001
// @tc.desc     RAW_AUDIO topology: stale track id map entries are cleared and
//               the new entry is registered.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_BuildNewAudioTopology_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME); // link skips creation
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    auto ret = hiplayer_->BuildNewAudioTopology(OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO, 3);
    EXPECT_EQ(ret, Status::OK);
    auto iter = mockDemuxer->track_id_map_.find(OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    ASSERT_NE(iter, mockDemuxer->track_id_map_.end());
    EXPECT_EQ(iter->second.size(), 1);
    EXPECT_EQ(iter->second[0], 3);
}

// @tc.name     Test BuildNewAudioTopology API
// @tc.number   PHIUT_BuildNewAudioTopology_002
// @tc.desc     ENCODED_AUDIO topology: the decoder link path is taken and the
//               track id map entry is registered.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_BuildNewAudioTopology_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC); // link skips creation
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    auto ret = hiplayer_->BuildNewAudioTopology(OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO, 2);
    EXPECT_EQ(ret, Status::OK);
    auto iter = mockDemuxer->track_id_map_.find(OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    ASSERT_NE(iter, mockDemuxer->track_id_map_.end());
    EXPECT_EQ(iter->second.size(), 1);
    EXPECT_EQ(iter->second[0], 2);
}

// ===========================================================================
// Tests for HiPlayerImpl::PrepareNewAudioFilters / StartThenPauseFilter /
// StartAudioDataFlow
// ===========================================================================

// @tc.name     Test PrepareNewAudioFilters API
// @tc.number   PHIUT_PrepareNewAudioFilters_001
// @tc.desc     Both audio filters are null: nothing to prepare, returns OK.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PrepareNewAudioFilters_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->PrepareNewAudioFilters();
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test PrepareNewAudioFilters API
// @tc.number   PHIUT_PrepareNewAudioFilters_002
// @tc.desc     Audio decoder Prepare fails: the error is returned.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PrepareNewAudioFilters_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    EXPECT_CALL(*mockDecoder, DoPrepare()).WillOnce(Return(Status::ERROR_INVALID_OPERATION));
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->PrepareNewAudioFilters();
    EXPECT_EQ(ret, Status::ERROR_INVALID_OPERATION);
}

// @tc.name     Test PrepareNewAudioFilters API
// @tc.number   PHIUT_PrepareNewAudioFilters_003
// @tc.desc     Audio sink Prepare fails: the error is returned.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PrepareNewAudioFilters_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockDecoder, DoPrepare()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockSink, DoPrepare()).WillOnce(Return(Status::ERROR_UNSUPPORTED_FORMAT));
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    auto ret = hiplayer_->PrepareNewAudioFilters();
    EXPECT_EQ(ret, Status::ERROR_UNSUPPORTED_FORMAT);
}

// @tc.name     Test PrepareNewAudioFilters API
// @tc.number   PHIUT_PrepareNewAudioFilters_004
// @tc.desc     Both audio filters reach the READY state: returns OK.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PrepareNewAudioFilters_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockDecoder, DoPrepare()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockSink, DoPrepare()).WillRepeatedly(Return(Status::OK));
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    auto ret = hiplayer_->PrepareNewAudioFilters();
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test StartThenPauseFilter API
// @tc.number   PHIUT_StartThenPauseFilter_001
// @tc.desc     Null filter: skipped, returns OK.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartThenPauseFilter_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Filter> filter = nullptr;
    auto ret = hiplayer_->StartThenPauseFilter(filter, false);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test StartThenPauseFilter API
// @tc.number   PHIUT_StartThenPauseFilter_002
// @tc.desc     Player was not running: the filter is started and then paused.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartThenPauseFilter_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    bool paused = false;
    EXPECT_CALL(*mockSink, DoStart()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockSink, DoPause()).WillOnce(Invoke([&]() { paused = true; return Status::OK; }));
    std::shared_ptr<Filter> filter = mockSink;
    auto ret = hiplayer_->StartThenPauseFilter(filter, false);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(paused, true);
}

// @tc.name     Test StartThenPauseFilter API
// @tc.number   PHIUT_StartThenPauseFilter_003
// @tc.desc     Player was running: the filter is started but not paused.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartThenPauseFilter_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockSink, DoStart()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockSink, DoPause()).Times(0);
    std::shared_ptr<Filter> filter = mockSink;
    auto ret = hiplayer_->StartThenPauseFilter(filter, true);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(&(*mockSink)));
}

// @tc.name     Test StartThenPauseFilter API
// @tc.number   PHIUT_StartThenPauseFilter_004
// @tc.desc     Filter fails to reach the RUNNING state: the error is returned.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartThenPauseFilter_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockSink, DoStart()).WillOnce(Return(Status::ERROR_INVALID_OPERATION));
    std::shared_ptr<Filter> filter = mockSink;
    auto ret = hiplayer_->StartThenPauseFilter(filter, false);
    EXPECT_EQ(ret, Status::ERROR_INVALID_OPERATION);
}

// @tc.name     Test StartAudioDataFlow API
// @tc.number   PHIUT_StartAudioDataFlow_001
// @tc.desc     Audio filters are null and StartTask succeeds: returns OK.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartAudioDataFlow_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->StartAudioDataFlow(false, 0);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test StartAudioDataFlow API
// @tc.number   PHIUT_StartAudioDataFlow_002
// @tc.desc     StartTask fails: returns ERROR_UNKNOWN.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartAudioDataFlow_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, true);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = nullptr;
    auto ret = hiplayer_->StartAudioDataFlow(false, 0);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
}

// @tc.name     Test StartAudioDataFlow API
// @tc.number   PHIUT_StartAudioDataFlow_003
// @tc.desc     Audio decoder fails to reach the RUNNING state: the error is
//               propagated.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartAudioDataFlow_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    EXPECT_CALL(*mockDecoder, DoStart()).WillOnce(Return(Status::ERROR_INVALID_OPERATION));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->StartAudioDataFlow(false, 0);
    EXPECT_EQ(ret, Status::ERROR_INVALID_OPERATION);
}

// @tc.name     Test StartAudioDataFlow API
// @tc.number   PHIUT_StartAudioDataFlow_004
// @tc.desc     Both audio filters reach the RUNNING state and StartTask
//               succeeds: returns OK.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StartAudioDataFlow_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto mockDecoder = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME, FilterType::FILTERTYPE_ADEC);
    auto mockSink = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    EXPECT_CALL(*mockDecoder, DoStart()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*mockSink, DoStart()).WillRepeatedly(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = mockDecoder;
    hiplayer_->audioSink_ = mockSink;
    auto ret = hiplayer_->StartAudioDataFlow(false, 0);
    EXPECT_EQ(ret, Status::OK);
}

// ===========================================================================
// Tests for HiPlayerImpl::HandleRebuildFailure / EVENT_WARN /
// EVENT_AUDIO_PREFERRED_OUTPUT_DEVICE_CHANGE
// ===========================================================================

// @tc.name     Test HandleRebuildFailure API
// @tc.number   PHIUT_HandleRebuildFailure_001
// @tc.desc     Rebuild failure resets the stream type to PACKED and reports
//               MSERR_UNSUPPORT_AUD_DEC_TYPE via INFO_TYPE_WARN_MSG.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleRebuildFailure_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    hiplayer_->SetObs(mockObs);
    std::vector<PlayerOnInfoType> infoTypes;
    std::vector<int32_t> infoCodes;
    EXPECT_CALL(*mockObs, OnInfo(_, _, _)).WillRepeatedly(Invoke(
        [&](PlayerOnInfoType type, int32_t extra, const Format&) {
            infoTypes.push_back(type);
            infoCodes.push_back(extra);
        }));
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO;
    hiplayer_->HandleRebuildFailure("unit_test");
    for (int i = 0; i < 20 && infoTypes.empty(); ++i) {
        usleep(10000);
    }
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
    ASSERT_EQ(infoTypes.empty(), false);
    EXPECT_EQ(infoTypes[0], INFO_TYPE_WARN_MSG);
    EXPECT_EQ(infoCodes[0], static_cast<int32_t>(MSERR_UNSUPPORT_AUD_DEC_TYPE));
}

// @tc.name     Test OnEvent EVENT_WARN
// @tc.number   PHIUT_OnEventWarn_001
// @tc.desc     EVENT_WARN with MSERR_UNSUPPORT_AUD_DEC_TYPE notifies the app
//               through INFO_TYPE_WARN_MSG and sets the play-cycle guards.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventWarn_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    hiplayer_->SetObs(mockObs);
    std::vector<PlayerOnInfoType> infoTypes;
    std::vector<int32_t> infoCodes;
    EXPECT_CALL(*mockObs, OnInfo(_, _, _)).WillRepeatedly(Invoke(
        [&](PlayerOnInfoType type, int32_t extra, const Format&) {
            infoTypes.push_back(type);
            infoCodes.push_back(extra);
        }));
    Event event;
    event.type = EventType::EVENT_WARN;
    event.param = static_cast<int32_t>(MSERR_UNSUPPORT_AUD_DEC_TYPE);
    hiplayer_->OnEvent(event);
    for (int i = 0; i < 20 && infoTypes.empty(); ++i) {
        usleep(10000);
    }
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
    EXPECT_EQ(hiplayer_->audioUnsupportedInPrepare_.load(), true);
    ASSERT_EQ(infoTypes.empty(), false);
    EXPECT_EQ(infoTypes[0], INFO_TYPE_WARN_MSG);
    EXPECT_EQ(infoCodes[0], static_cast<int32_t>(MSERR_UNSUPPORT_AUD_DEC_TYPE));
}

// @tc.name     Test OnEvent EVENT_WARN
// @tc.number   PHIUT_OnEventWarn_002
// @tc.desc     EVENT_WARN with a non audio decoder error code notifies the app
//               but does not set the play-cycle guards.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventWarn_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockObs = std::make_shared<MockIPlayerEngineObs>();
    hiplayer_->SetObs(mockObs);
    std::vector<PlayerOnInfoType> infoTypes;
    std::vector<int32_t> infoCodes;
    EXPECT_CALL(*mockObs, OnInfo(_, _, _)).WillRepeatedly(Invoke(
        [&](PlayerOnInfoType type, int32_t extra, const Format&) {
            infoTypes.push_back(type);
            infoCodes.push_back(extra);
        }));
    Event event;
    event.type = EventType::EVENT_WARN;
    event.param = static_cast<int32_t>(MSERR_UNSUPPORT_AUD_SAMPLE_RATE);
    hiplayer_->OnEvent(event);
    for (int i = 0; i < 20 && infoTypes.empty(); ++i) {
        usleep(10000);
    }
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
    EXPECT_EQ(hiplayer_->audioUnsupportedInPrepare_.load(), false);
    ASSERT_EQ(infoTypes.empty(), false);
    EXPECT_EQ(infoTypes[0], INFO_TYPE_WARN_MSG);
    EXPECT_EQ(infoCodes[0], static_cast<int32_t>(MSERR_UNSUPPORT_AUD_SAMPLE_RATE));
}

// @tc.name     Test OnEventSub EVENT_AUDIO_PREFERRED_OUTPUT_DEVICE_CHANGE
// @tc.number   PHIUT_OnEventPreferredDeviceChange_001
// @tc.desc     Preferred output device changed while audio is not supported on
//               the new device: audio pipeline is muted to video-only.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventPreferredDeviceChange_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    Event event;
    event.type = EventType::EVENT_AUDIO_PREFERRED_OUTPUT_DEVICE_CHANGE;
    hiplayer_->OnEventSub(event);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// ===========================================================================
// Tests for HiPlayerImpl::OnCallback stream type branches
// ===========================================================================

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_003
// @tc.desc     RAW_AUDIO reported by the demuxer: currentAudioStreamType_ is
//               updated to STREAMTYPE_RAW_AUDIO.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_003, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->OnCallback(mockDemuxer, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_004
// @tc.desc     DOLBY reported by the demuxer: currentAudioStreamType_ is updated
//               to STREAMTYPE_DOLBY.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->OnCallback(mockDemuxer, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_DOLBY);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_DOLBY);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_005
// @tc.desc     ENCODED_AUDIO reported by the demuxer with a decoder already
//               linked: currentAudioStreamType_ is updated to
//               STREAMTYPE_ENCODED_AUDIO.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    auto ret = hiplayer_->OnCallback(mockDemuxer, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_006
// @tc.desc     RAW_AUDIO reported by a filter other than the demuxer:
//               currentAudioStreamType_ is not updated.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto otherFilter = std::make_shared<MockFilter>();
    auto ret = hiplayer_->OnCallback(otherFilter, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_007
// @tc.desc     RAW_AUDIO reported by the demuxer with no sink linked yet: a new
//               audio sink is linked and the non-dolby branch clears
//               isDolbyStream_.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    ASSERT_EQ(hiplayer_->Init(), Status::OK);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->isDolbyStream_ = true;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    auto ret = hiplayer_->OnCallback(mockDemuxer, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->isDolbyStream_, false);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
}

// @tc.name     Test OnCallback API
// @tc.number   PHIUT_OnCallback_008
// @tc.desc     DOLBY reported by the demuxer with no sink linked yet: a new
//               audio sink is linked and the dolby branch sets isDolbyStream_.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnCallback_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    ASSERT_EQ(hiplayer_->Init(), Status::OK);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->audioSink_ = nullptr;
    hiplayer_->isDolbyStream_ = false;
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED;
    auto ret = hiplayer_->OnCallback(mockDemuxer, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        OHOS::Media::Pipeline::StreamType::STREAMTYPE_DOLBY);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_NE(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->isDolbyStream_, true);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_DOLBY);
}

// ===========================================================================
// Tests for play-cycle guard reset in Pause / Play / Stop / DoPausedPlay / Resume
// ===========================================================================

// @tc.name     Test Pause audio guard
// @tc.number   PHIUT_PauseAudioGuard_001
// @tc.desc     Pause resets the per-play-cycle warning guard when Prepare did
//               not report it.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PauseAudioGuard_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STARTED;
    hiplayer_->curState_ = PlayerStateId::INIT;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(false);
    auto ret = hiplayer_->Pause(false);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test Pause audio guard
// @tc.number   PHIUT_PauseAudioGuard_002
// @tc.desc     Pause keeps the warning guard when Prepare already reported it.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PauseAudioGuard_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STARTED;
    hiplayer_->curState_ = PlayerStateId::INIT;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(true);
    auto ret = hiplayer_->Pause(false);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test Play audio guard
// @tc.number   PHIUT_PlayAudioGuard_001
// @tc.desc     Play from STOPPED with empty pipeline returns OK; the warning
//               guard is not reset in the generic Play branch.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PlayAudioGuard_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STOPPED;
    hiplayer_->durationMs_.store(100);
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(false);
    auto ret = hiplayer_->Play();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test Play audio guard
// @tc.number   PHIUT_PlayAudioGuard_002
// @tc.desc     Play from STOPPED with empty pipeline returns OK; the warning
//               guard is kept when Prepare already reported it.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_PlayAudioGuard_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STOPPED;
    hiplayer_->durationMs_.store(100);
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(true);
    auto ret = hiplayer_->Play();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test Stop audio guard
// @tc.number   PHIUT_StopAudioGuard_001
// @tc.desc     Stop resets both the play-cycle guard and the Prepare guard.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_StopAudioGuard_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_PREPARED;
    hiplayer_->curState_ = PlayerStateId::INIT;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(true);
    auto ret = hiplayer_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
    EXPECT_EQ(hiplayer_->audioUnsupportedInPrepare_.load(), false);
}

// @tc.name     Test DoPausedPlay audio guard
// @tc.number   PHIUT_DoPausedPlayGuard_001
// @tc.desc     DoPausedPlay resets the warning guard when Prepare did not
//               report it.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoPausedPlayGuard_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(false);
    int32_t ret = -1;
    hiplayer_->DoPausedPlay(ret);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test DoPausedPlay audio guard
// @tc.number   PHIUT_DoPausedPlayGuard_002
// @tc.desc     DoPausedPlay keeps the warning guard when Prepare already
//               reported it.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoPausedPlayGuard_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->audioMutedReportedInPlayCycle_.store(true);
    hiplayer_->audioUnsupportedInPrepare_.store(true);
    int32_t ret = -1;
    hiplayer_->DoPausedPlay(ret);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test Resume audio support re-check
// @tc.number   PHIUT_ResumeCheckAudioSupport_001
// @tc.desc     Resume re-checks audio support: unsupported audio is muted to
//               video-only.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ResumeCheckAudioSupport_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    auto ret = hiplayer_->Resume();
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// ===========================================================================
// Tests for SeekAgent::SetAudioMuted
// ===========================================================================

// @tc.name     Test SeekAgent SetAudioMuted API
// @tc.number   PHIUT_SeekAgentSetAudioMuted_001
// @tc.desc     SetAudioMuted toggles the internal muted flag used to skip audio
//               target waiting.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SeekAgentSetAudioMuted_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto mockDemuxer = CreateRebuildTestDemuxer({}, false);
    auto seekAgent = std::make_shared<SeekAgent>(mockDemuxer, 0);
    seekAgent->SetAudioMuted(true);
    EXPECT_EQ(seekAgent->isAudioMuted_, true);
    seekAgent->SetAudioMuted(false);
    EXPECT_EQ(seekAgent->isAudioMuted_, false);
}

// ===========================================================================
// Tests for HiPlayerImpl::HandleAudioTrackChangeEvent new branches
// ===========================================================================

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_004
// @tc.desc     New audio track is not supported on the device: audio pipeline
//               is muted to video-only and the track id is updated.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_004, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, UNSUPPORTED_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    ASSERT_NE(codecList, nullptr);
    mockDemuxer->demuxer_->codecList_ = codecList;
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->defaultAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    Event event;
    event.param = 0;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, 0);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_005
// @tc.desc     Same topology track switch fails on StartTask: stream type is
//               reset to PACKED and the track id is updated.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_005, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, true); // StartTask fails
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    Event event;
    event.param = 0;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, 0);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_006
// @tc.desc     Same topology track switch succeeds: track id and stream type
//               are updated without muting.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_006, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    Event event;
    event.param = 0;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, 0);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_007
// @tc.desc     currentAudioTrackId_ < 0 branch: InitAudioDefaultTrackIndex
//               initializes the current audio track before switching.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_007, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, TEST_TRACK_FILTER_AUDIO_MIME);
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->defaultAudioTrackId_ = INVALID_AUDIO_TRACK_ID;
    hiplayer_->audioDecoder_ = nullptr;
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    Event event;
    event.param = 0;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, 0);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), false);
}

// @tc.name     Test HandleAudioTrackChangeEvent API
// @tc.number   PHIUT_HandleAudioTrackChangeEvent_008
// @tc.desc     Cross-topology rebuild fails: HandleRebuildFailure resets the
//               stream type and reports the warning, track id stays unchanged.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleAudioTrackChangeEvent_008, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    ASSERT_EQ(hiplayer_->Init(), Status::OK);
    auto meta = std::make_shared<Meta>();
    meta->SetData(Tag::MIME_TYPE, "audio/raw"); // resolves to RAW_AUDIO, differs from ENCODED_AUDIO
    auto mockDemuxer = CreateRebuildTestDemuxer({meta}, false);
    hiplayer_->demuxer_ = mockDemuxer;
    hiplayer_->currentAudioTrackId_ = 0;
    hiplayer_->audioDecoder_ = std::make_shared<MockAudioDecoderFilter>(TEST_FILTER_NAME,
        FilterType::FILTERTYPE_ADEC);
    hiplayer_->audioSink_ = std::make_shared<MockAudioSinkFilter>(TEST_FILTER_NAME);
    hiplayer_->currentAudioStreamType_ = OHOS::Media::Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO;
    EXPECT_CALL(*mockDemuxer, LinkNext(_, _)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
    Event event;
    event.param = 0;
    hiplayer_->HandleAudioTrackChangeEvent(event);
    EXPECT_EQ(hiplayer_->currentAudioTrackId_, 0);
    EXPECT_EQ(hiplayer_->currentAudioStreamType_, OHOS::Media::Pipeline::StreamType::STREAMTYPE_PACKED);
    EXPECT_EQ(hiplayer_->audioMutedReportedInPlayCycle_.load(), true);
}
} // namespace Media
} // namespace OHOS
