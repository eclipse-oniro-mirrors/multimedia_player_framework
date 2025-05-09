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
    int32_t test_value = 0;
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->isSeekClosest_.store(true);
    hiplayer_->isBufferingStartNotified_.store(true);
    hiplayer_->NotifySeekDone(test_value);
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

// @tc.name     Test SetSeiMessageListener API
// @tc.number   PHIUT_SetSeiMessageListener_001
// @tc.desc     Test SetSeiMessageListener interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_SetSeiMessageListener_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->seiDecoder_ =
        FilterFactory::Instance().CreateFilter<SeiParserFilter>("player.sei", FilterType::FILTERTYPE_SEI);
    Status ret = hiplayer_->SetSeiMessageListener();
    EXPECT_NE(ret, Status::OK);
}

// @tc.name     Test DoRestartLiveLink API
// @tc.number   PHIUT_DoRestartLiveLink_001
// @tc.desc     Test DoRestartLiveLink interface, 6.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_DoRestartLiveLink_001, TestSize.Level0)
{
    ASSERT_NE(hiplayer_, nullptr);
    hiplayer_->isFlvLive_ = true;
    std::string name = "testname";
    FilterType type = FilterType::VIDEO_CAPTURE;
    hiplayer_->demuxer_ = std::make_shared<DemuxerFilter>(name, type);
    std::shared_ptr<Meta> testptr = std::make_shared<Meta>();
    hiplayer_->demuxer_->demuxer_ = std::make_shared<MediaDemuxer>();
    hiplayer_->demuxer_->demuxer_->mediaMetaData_.trackMetas.push_back(testptr);
    hiplayer_->audioSink_ = std::make_shared<AudioSinkFilter>(name);
    
    auto videoDecoder = std::make_shared<MockDecoderSurfaceFilter>();
    hiplayer_->videoDecoder_ = videoDecoder;
    EXPECT_CALL(*videoDecoder, DoInitAfterLink()).WillRepeatedly(Return(Status::OK));

    hiplayer_->DoRestartLiveLink();
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->playerEventReceiver_ = nullptr;
    hiplayer_->playerFilterCallback_ = nullptr;
    EXPECT_NE(hiplayer_->isSeekClosest_.load(), true);
}

// @tc.name     Test LinkAudioDecoderFilter API
// @tc.number   PHIUT_LinkAudioDecoderFilter_001
// @tc.desc     Test LinkAudioDecoderFilter interface, 4.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_LinkAudioDecoderFilter_001, TestSize.Level0)
{
#ifdef SUPPORT_AVPLAYER_DRM
#undef SUPPORT_AVPLAYER_DRM
#endif
#define SUPPORT_AVPLAYER_DRM
#define SUPPORT_START_STOP_ON_DEMAND
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Filter> filter = std::make_shared<MockFilter>();
    StreamType type = StreamType::STREAMTYPE_RAW_VIDEO;
    Status ret;
    hiplayer_->isDrmProtected_ = true;
    hiplayer_->isDrmPrepared_ = true;
    hiplayer_->interruptMonitor_ = std::make_shared<InterruptMonitor>();
    hiplayer_->Init();
    ret = hiplayer_->LinkAudioDecoderFilter(filter, type);
    hiplayer_->dfxAgent_ = nullptr;
    hiplayer_->playerEventReceiver_ = nullptr;
    hiplayer_->playerFilterCallback_ = nullptr;
    hiplayer_->demuxer_ = nullptr;
    hiplayer_->playerId_ = "0";
    EXPECT_EQ(ret, Status::OK);
#undef SUPPORT_START_STOP_ON_DEMAND
#undef SUPPORT_AVPLAYER_DRM
}

// @tc.name     Test LinkAudioSinkFilter API
// @tc.number   PHIUT_LinkAudioSinkFilter_001
// @tc.desc     Test LinkAudioSinkFilter interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_LinkAudioSinkFilter_001, TestSize.Level0)
{
#ifdef SUPPORT_START_STOP_ON_DEMAND
#undef SUPPORT_START_STOP_ON_DEMAND
#endif
#define SUPPORT_START_STOP_ON_DEMAND
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Filter> filter = std::make_shared<MockFilter>();
    StreamType outType = StreamType::STREAMTYPE_RAW_VIDEO;
    hiplayer_->mutedMediaType_ = OHOS::Media::MediaType::MEDIA_TYPE_AUD;
    Status ret = hiplayer_->LinkAudioSinkFilter(filter, outType);
    EXPECT_EQ(ret, Status::OK);
#undef SUPPORT_START_STOP_ON_DEMAND
}

// @tc.name     Test LinkSeiDecoder API
// @tc.number   PHIUT_LinkSeiDecoder_001
// @tc.desc     Test LinkSeiDecoder interface, 2.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_LinkSeiDecoder_001, TestSize.Level0)
{
#ifdef SUPPORT_VIDEO
#undef SUPPORT_VIDEO
#endif
#define SUPPORT_VIDEO
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<Filter> preFilter = std::make_shared<MockFilter>();
    StreamType type = StreamType::STREAMTYPE_RAW_VIDEO;
    hiplayer_->interruptMonitor_ = std::make_shared<InterruptMonitor>();
    Status ret = hiplayer_->LinkSeiDecoder(preFilter, type);
    EXPECT_EQ(ret, Status::OK);
#undef SUPPORT_VIDEO
}

// @tc.name     Test LinkVideoDecoderFilter API
// @tc.number   PHIUT_LinkVideoDecoderFilter_001
// @tc.desc     Test LinkVideoDecoderFilter interface, 1.
HWTEST_F(PlayHiplayerImplUnitTest, PHIUT_LinkVideoDecoderFilter_001, TestSize.Level0)
{
#ifdef SUPPORT_AVPLAYER_DRM
#undef SUPPORT_AVPLAYER_DRM
#endif
#define SUPPORT_AVPLAYER_DRM
    ASSERT_NE(hiplayer_, nullptr);
    std::shared_ptr<MockFilter> preFilter = std::make_shared<MockFilter>();
    std::shared_ptr<Filter> filter = preFilter;
    StreamType type = StreamType::STREAMTYPE_RAW_VIDEO;
    hiplayer_->seiMessageCbStatus_ = true;
    hiplayer_->isDrmProtected_ = true;
    hiplayer_->isDrmPrepared_ = true;
    auto videoDecoder = std::make_shared<MockDecoderSurfaceFilter>();
    hiplayer_->videoDecoder_ = videoDecoder;
    EXPECT_CALL(*preFilter, DoInitAfterLink()).WillRepeatedly(Return(Status::OK));
    EXPECT_CALL(*videoDecoder, DoInitAfterLink()).WillRepeatedly(Return(Status::OK));
    hiplayer_->Init();
    Status ret = hiplayer_->LinkVideoDecoderFilter(filter, type);
    EXPECT_EQ(ret, Status::OK);
#undef SUPPORT_AVPLAYER_DRM
}
} // namespace Media
} // namespace OHOS