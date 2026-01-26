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
#include "plugin/plugin_event.h"
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
    hiplayer_ = nullptr;
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
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, false);
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
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, false);
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

// @tc.name     Test OnEventContinue API
// @tc.number   PHIUT_OnEventContinue_001
// @tc.desc     Test OnEventContinue interface, 3.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventContinue_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    Event event;
    event.type = EventType::EVENT_RESOLUTION_CHANGE;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    Format format;
    format.meta_ = std::make_shared<Meta>();
    event.param = format;
    hiplayer_->OnEventContinue(event);
    
    event.type = EventType::EVENT_SEI_INFO;
    hiplayer_->OnEventContinue(event);
    
    event.type = EventType::EVENT_FLV_AUTO_SELECT_BITRATE;
    hiplayer_->OnEventContinue(event);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
}

// @tc.name     Test OnEventSub API
// @tc.number   PHIUT_OnEventSub_001
// @tc.desc     Test OnEventSub interface, 4.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventSub_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    Event event;
    event.type = EventType::EVENT_AUDIO_DEVICE_CHANGE;
    AudioStandard::AudioDeviceDescriptor test1;
    AudioStandard::AudioStreamDeviceChangeReason test2;
    std::pair<AudioStandard::AudioDeviceDescriptor, AudioStandard::AudioStreamDeviceChangeReason> p1(test1, test2);
    event.param = p1;
    hiplayer_->OnEventSub(event);
    
    event.type = EventType::BUFFERING_END;
    hiplayer_->isBufferingStartNotified_.store(true);
    hiplayer_->isSeekClosest_.store(false);
    int32_t test3 = 10;
    event.param = test3;
    hiplayer_->OnEventSub(event);
    
    event.type = EventType::BUFFERING_START;
    hiplayer_->isBufferingStartNotified_.store(true);
    hiplayer_->OnEventSub(event);
    
    event.type = EventType::EVENT_SOURCE_BITRATE_START;
    uint32_t test4 = 10;
    event.param = test4;
    hiplayer_->OnEventSub(event);
    EXPECT_EQ(hiplayer_->audioSink_, nullptr);
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
    StreamType outType = StreamType::STREAMTYPE_RAW_VIDEO;
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
    StreamType outType = StreamType::STREAMTYPE_MAX;
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
    auto ret = hiplayer_->LinkSeiDecoder(preFilter, StreamType::STREAMTYPE_ENCODED_AUDIO);
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
} // namespace Media
} // namespace OHOS
