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
#include "pipeline/pipeline.h"
#include "player.h"
#include "audio_device_descriptor.h"
#include "audio_capture_filter.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

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

// @tc.name     Test OnEventSubTrackChange API
// @tc.number   PHIUT_OnEventSubTrackChange_001
// @tc.desc     Test OnEventSubTrackChange interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_OnEventSubTrackChange_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    Event event;
    int32_t test1 = 10;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    event.param = test1;
    event.type = EventType::EVENT_VIDEO_TRACK_CHANGE;
    hiplayer_->OnEventSubTrackChange(event);
    
    event.type = EventType::EVENT_SUBTITLE_TRACK_CHANGE;
    hiplayer_->subtitleSink_ = std::make_shared<SubtitleSinkFilter>("test");
    hiplayer_->OnEventSubTrackChange(event);
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

// @tc.name     Test HandleVideoTrackChangeEvent API
// @tc.number   PHIUT_HandleVideoTrackChangeEvent_001
// @tc.desc     Test HandleVideoTrackChangeEvent interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleVideoTrackChangeEvent_001, TestSize.Level0)
{
#define SUPPORT_VIDEO
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    Event event;
    Format format;
    format.meta_ = std::make_shared<Meta>();
    event.param = format;
    hiplayer_->HandleVideoTrackChangeEvent(event);
    EXPECT_NE(hiplayer_->isSeekClosest_.load(), true);
#undef SUPPORT_VIDEO
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
    EXPECT_CALL(*mockPipeline, SetPlayRange(_,_)).WillRepeatedly(Return(Status::OK));
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
    EXPECT_CALL(*mockDemuxer, SelectBitRate(_,_)).WillRepeatedly(Return(Status::ERROR_INVALID_OPERATION));
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

// @tc.name     Test DoRestartLiveLink API
// @tc.number   PHIUT_DoRestartLiveLink_002
// @tc.desc     Test audioDecoder_ != nullptr && audioSink_ != nullptr && videoDecoder_ != nullptr
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoRestartLiveLink_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isFlvLive_ = true;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    EXPECT_CALL(*mockDemuxer, DoFlush()).WillOnce(Return(Status::OK));
    hiplayer_->demuxer_ = mockDemuxer;
    auto mockAudioSink = std::make_shared<MockAudioSinkFilter>(name, FilterType::VIDEO_CAPTURE);
    EXPECT_CALL(*mockAudioSink, DoFlush()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockAudioSink, DoStart()).WillOnce(Return(Status::OK));
    hiplayer_->audioSink_ = mockAudioSink;
    auto mockVideoDemuxer = std::make_shared<DecoderSurfaceFilter>(name, type);
    EXPECT_CALL(*mockVideoDemuxer, DoFlush()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockVideoDemuxer, DoStart()).WillOnce(Return(Status::OK));
    hiplayer_->videoDecoder_ = mockVideoDemuxer;
    auto mockAudioDecoder = std::make_shared<AudioDecoderFilter>(name, type);
    EXPECT_CALL(*mockAudioDecoder, DoFlush()).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockAudioDecoder, DoStart()).WillOnce(Return(Status::OK));
    hiplayer_->audioDecoder_ = mockAudioDecoder;
    
    hiplayer_->DoRestartLiveLink();
}

// @tc.name     Test SetReopenFd API
// @tc.number   PHIUT_SetReopenFd_001
// @tc.desc     Test all
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetReopenFd_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    int32_t fd = 0;
    
    int32_t ret = hiplayer_->SetReopenFd(fd);
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test EnableCameraPostprocessing API
// @tc.number   PHIUT_EnableCameraPostprocessing_001
// @tc.desc     Test all
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_EnableCameraPostprocessing_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->enableCameraPostprocessing_ = true;
    
    int32_t ret = hiplayer_->EnableCameraPostprocessing();
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test SetSeiMessageListener API
// @tc.number   PHIUT_SetSeiMessageListener_001
// @tc.desc     Test !(videoDecoder_ != nullptr && surface_ != nullptr)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetSeiMessageListener_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->videoDecoder_ = nullptr;
    hiplayer_->surface_ = nullptr;
    
    auto ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);

    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockVideoDemuxer = std::make_shared<DecoderSurfaceFilter>(name, type);
    hiplayer_->videoDecoder_ = mockVideoDemuxer;
    hiplayer_->surface_ = nullptr;
    ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);

    auto mockCodecSurface = sptr<MockCodecSurface>(new MockCodecSurface());
    hiplayer_->surface_ = mockCodecSurface;
    hiplayer_->videoDecoder_ = nullptr;
    ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test SetSeiMessageListener API
// @tc.number   PHIUT_SetSeiMessageListener_002
// @tc.desc     Test !(seiDecoder_ != nullptr && surface_ == nullptr)
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetSeiMessageListener_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->surface_ = nullptr;
    hiplayer_->seiDecoder_ = nullptr;
    auto ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);

    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockSeiDecoder = std::make_shared<SeiParserFilter>(name, type);
    hiplayer_->seiDecoder_ = mockSeiDecoder;
    auto mockCodecSurface = sptr<MockCodecSurface>(new MockCodecSurface());
    hiplayer_->surface_ = mockCodecSurface;
    ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);

    hiplayer_->seiDecoder_ = nullptr;
    mockCodecSurface = sptr<MockCodecSurface>(new MockCodecSurface());
    hiplayer_->surface_ = mockCodecSurface;
    ret = hiplayer_->SetSeiMessageListener();
    EXPECT_EQ(ret, Status::OK);
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

// @tc.name     Test IsLiveStream API
// @tc.number   PHIUT_IsLiveStream_001
// @tc.desc     Test all
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_IsLiveStream_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    auto ret = hiplayer_->IsLiveStream();
    EXPECT_EQ(ret, false);
}

// @tc.name     Test ResumeDemuxer API
// @tc.number   PHIUT_ResumeDemuxer_001
// @tc.desc     Test all
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_ResumeDemuxer_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_STATE_ERROR;

    auto ret = hiplayer_->ResumeDemuxer();
    EXPECT_EQ(ret, 0);
}

// @tc.name     Test HandleSeek API
// @tc.number   PHIUT_HandleSeek_001
// @tc.desc     Test case PlayerStates::PLAYER_FROZEN
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_HandleSeek_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_FROZEN;
    auto mockPipeline = std::make_shared<MockPipeline>();
    hiplayer_->pipeline_ = mockPipeline;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    auto mockDemuxer = std::make_shared<MockDemuxerFilter>(name, type);
    hiplayer_->demuxer_ = mockDemuxer;
    auto ret = hiplayer_->HandleSeek(0, PlayerSeekMode::SEEK_NEXT_SYNC);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test doFrozenSeek API
// @tc.number   PHIUT_doFrozenSeek_001
// @tc.desc     Test isUnFreezeSeek = true
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_doFrozenSeek_001, TestSize.Level0)
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
    hiplayer_->demuxer_ = mockDemuxer;
    auto mockPipeline = std::make_shared<MockPipeline>();
    hiplayer_->pipeline_ = mockPipeline;
    auto ret = hiplayer_->doFrozenSeek(0, PlayerSeekMode::SEEK_NEXT_SYNC, true);
    EXPECT_EQ(ret, Status::OK);
}

// @tc.name     Test doFrozenSeek API
// @tc.number   PHIUT_doFrozenSeek_002
// @tc.desc     Test isUnFreezeSeek = false
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_doFrozenSeek_002, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    auto ret = hiplayer_->doFrozenSeek(0, PlayerSeekMode::SEEK_CLOSEST, false);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_EQ(hiplayer_->isForzenSeekRecv_, true);
}

// @tc.name     Test EnableStartFrameRateOpt API
// @tc.number   PHIUT_EnableStartFrameRateOpt_001
// @tc.desc     Test videoTrack.GetDoubleValue("frame_rate", frameRate) && syncManager_ != nullptr
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_EnableStartFrameRateOpt_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    double frameRate = 1;
    Format format1;
    format1.PutDoubleValue("frame_rate", frameRate);
    hiplayer_->syncManager_ = nullptr;
    hiplayer_->EnableStartFrameRateOpt(format1);
    EXPECT_TRUE(format1.GetDoubleValue("frame_rate", frameRate));

    Format format2;
    format2.PutDoubleValue("frame_rate", 2.0);
    hiplayer_->EnableStartFrameRateOpt(format2);

    hiplayer_->syncManager_ = std::make_shared<MediaSyncManager>();
    hiplayer_->EnableStartFrameRateOpt(format2);
    EXPECT_NE(hiplayer_->syncManager_->videoInitialFrameRate_, 0.01);
    hiplayer_->EnableStartFrameRateOpt(format1);
    EXPECT_EQ(hiplayer_->syncManager_->videoInitialFrameRate_, 0.01);
}
} // namespace Media
} // namespace OHOS
