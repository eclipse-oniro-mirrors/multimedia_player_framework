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

#include <gmock/gmock.h>
#include "seek_agent.h"
#include "media_demuxer.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue_producer.h"

namespace OHOS {
namespace Media {
using namespace testing;
using namespace testing::ext;
namespace {
class SeekBufferProducerMock : public IRemoteStub<AVBufferQueueProducer> {
public:
    MOCK_METHOD(uint32_t, GetQueueSize, (), (override));
    MOCK_METHOD(Status, SetQueueSize, (uint32_t), (override));
    MOCK_METHOD(Status, RequestBuffer, (std::shared_ptr<AVBuffer>&, const AVBufferConfig&, int32_t), (override));
    MOCK_METHOD(Status, PushBuffer, (const std::shared_ptr<AVBuffer>&, bool), (override));
    MOCK_METHOD(Status, ReturnBuffer, (const std::shared_ptr<AVBuffer>&, bool), (override));
    MOCK_METHOD(Status, AttachBuffer, (std::shared_ptr<AVBuffer>&, bool), (override));
    MOCK_METHOD(Status, DetachBuffer, (const std::shared_ptr<AVBuffer>&), (override));
    MOCK_METHOD(Status, SetBufferFilledListener, (sptr<IBrokerListener>&), (override));
    MOCK_METHOD(Status, RemoveBufferFilledListener, (sptr<IBrokerListener>&), (override));
    MOCK_METHOD(Status, SetBufferAvailableListener, (sptr<IProducerListener>&), (override));
    MOCK_METHOD(Status, Clear, (), (override));
    MOCK_METHOD(Status, ClearBufferIf, (std::function<bool(const std::shared_ptr<AVBuffer>&)>), (override));
};
constexpr int32_t AUDIO_TRACK_ID = 2;
constexpr int64_t TARGET_PTS = 1000000;
}

class SeekAgentUnitTest : public Test {
public:
    void SetUp() override
    {
        demuxer_ = std::make_shared<Pipeline::DemuxerFilter>("seek_test", Pipeline::FilterType::FILTERTYPE_DEMUXER);
        agent_ = std::make_shared<SeekAgent>(demuxer_);
        producer_ = new StrictMock<SeekBufferProducerMock>();
        buffer_ = AVBuffer::CreateAVBuffer();
        ASSERT_NE(buffer_, nullptr);
        agent_->seekTargetPts_ = TARGET_PTS;
        agent_->isAudioTargetArrived_ = false;
        agent_->isVideoTargetArrived_ = false;
    }

    std::shared_ptr<Meta> MakeTrack(int32_t id, const std::string& mime)
    {
        auto meta = std::make_shared<Meta>();
        meta->SetData(Tag::REGULAR_TRACK_ID, id);
        meta->SetData(Tag::MIME_TYPE, mime);
        return meta;
    }

    std::shared_ptr<Pipeline::DemuxerFilter> demuxer_;
    std::shared_ptr<SeekAgent> agent_;
    sptr<StrictMock<SeekBufferProducerMock>> producer_;
    std::shared_ptr<AVBuffer> buffer_;
};

/**
 * @tc.name  : AudioBeforeTarget
 * @tc.number: SeekAgent_AudioBeforeTarget_001
 * @tc.desc  : Discard pre-target audio without completing the seek.
 */
HWTEST_F(SeekAgentUnitTest, AudioBeforeTarget, TestSize.Level0)
{
    buffer_->pts_ = TARGET_PTS - 1;
    EXPECT_CALL(*producer_, ReturnBuffer(buffer_, false)).WillOnce(Return(Status::OK));
    EXPECT_EQ(agent_->OnAudioBufferFilled(buffer_, producer_, AUDIO_TRACK_ID), Status::OK);
    EXPECT_FALSE(agent_->isAudioTargetArrived_);
    EXPECT_FALSE(agent_->isVideoTargetArrived_);
}

/**
 * @tc.name  : AudioTargetAndEos
 * @tc.number: SeekAgent_AudioTargetAndEos_001
 * @tc.desc  : Both an exact target and EOS before the target complete audio seeking.
 */
HWTEST_F(SeekAgentUnitTest, AudioTargetAndEos, TestSize.Level0)
{
    for (bool eos : {false, true}) {
        SCOPED_TRACE(eos);
        agent_->isAudioTargetArrived_ = false;
        buffer_->pts_ = eos ? TARGET_PTS - 1 : TARGET_PTS;
        buffer_->flag_ = eos ? static_cast<uint32_t>(AVBufferFlag::EOS) : 0;
        EXPECT_CALL(*producer_, ReturnBuffer(buffer_, false)).WillOnce(Return(Status::OK));
        EXPECT_EQ(agent_->OnAudioBufferFilled(buffer_, producer_, AUDIO_TRACK_ID), Status::OK);
        EXPECT_TRUE(agent_->isAudioTargetArrived_);
        EXPECT_FALSE(agent_->isVideoTargetArrived_);
    }
}

/**
 * @tc.name  : VideoBeforeTarget
 * @tc.number: SeekAgent_VideoBeforeTarget_001
 * @tc.desc  : Preserve reference frames and drop only frames marked droppable.
 */
HWTEST_F(SeekAgentUnitTest, VideoBeforeTarget, TestSize.Level0)
{
    buffer_->pts_ = TARGET_PTS - 1;
    for (bool canDrop : {false, true}) {
        SCOPED_TRACE(canDrop);
        buffer_->meta_->SetData(Tag::VIDEO_BUFFER_CAN_DROP, canDrop);
        EXPECT_CALL(*producer_, ReturnBuffer(buffer_, !canDrop)).WillOnce(Return(Status::OK));
        EXPECT_EQ(agent_->OnVideoBufferFilled(buffer_, producer_, 0), Status::OK);
        EXPECT_FALSE(agent_->isVideoTargetArrived_);
    }
}

/**
 * @tc.name  : VideoTargetAndEos
 * @tc.number: SeekAgent_VideoTargetAndEos_001
 * @tc.desc  : Target and EOS must reach the decoder even when marked droppable.
 */
HWTEST_F(SeekAgentUnitTest, VideoTargetAndEos, TestSize.Level0)
{
    buffer_->meta_->SetData(Tag::VIDEO_BUFFER_CAN_DROP, true);
    for (bool eos : {false, true}) {
        SCOPED_TRACE(eos);
        agent_->isVideoTargetArrived_ = false;
        buffer_->pts_ = eos ? TARGET_PTS - 1 : TARGET_PTS;
        buffer_->flag_ = eos ? static_cast<uint32_t>(AVBufferFlag::EOS) : 0;
        EXPECT_CALL(*producer_, ReturnBuffer(buffer_, true)).WillOnce(Return(Status::OK));
        EXPECT_EQ(agent_->OnVideoBufferFilled(buffer_, producer_, 0), Status::OK);
        EXPECT_TRUE(agent_->isVideoTargetArrived_);
        EXPECT_FALSE(agent_->isAudioTargetArrived_);
    }
}

/**
 * @tc.name  : TrackClassification
 * @tc.number: SeekAgent_TrackClassification_001
 * @tc.desc  : Ignore missing MIME and subtitle metadata; select audio by the normalized track ID.
 */
HWTEST_F(SeekAgentUnitTest, TrackClassification, TestSize.Level0)
{
    demuxer_->demuxer_->mediaMetaData_.trackMetas = {
        MakeTrack(12, "video/avc"), std::make_shared<Meta>(), MakeTrack(7, "audio/aac"),
        MakeTrack(9, "text/vtt"), std::make_shared<Meta>()};
    std::vector<int32_t> videoIds;
    std::vector<int32_t> audioIds;
    ASSERT_EQ(agent_->GetAllTrackInfo(videoIds, audioIds), Status::OK);
    EXPECT_EQ(videoIds, std::vector<int32_t>({0}));
    EXPECT_EQ(audioIds, std::vector<int32_t>({AUDIO_TRACK_ID}));
    agent_->producerMap_ = {{AUDIO_TRACK_ID, nullptr}};
    int32_t selectedId = -1;
    EXPECT_FALSE(agent_->GetAudioTrackId(selectedId));
    EXPECT_EQ(selectedId, -1);
    agent_->producerMap_[AUDIO_TRACK_ID] = producer_;
    EXPECT_TRUE(agent_->GetAudioTrackId(selectedId));
    EXPECT_EQ(selectedId, AUDIO_TRACK_ID);
}

/**
 * @tc.name  : MutedAudioListener
 * @tc.number: SeekAgent_MutedAudioListener_001
 * @tc.desc  : Muted audio must not block seeking; unmuting installs and removes its listener.
 */
HWTEST_F(SeekAgentUnitTest, MutedAudioListener, TestSize.Level0)
{
    demuxer_->demuxer_->mediaMetaData_.trackMetas = {
        std::make_shared<Meta>(), std::make_shared<Meta>(), MakeTrack(AUDIO_TRACK_ID, "audio/aac")};
    demuxer_->demuxer_->bufferQueueMap_ = {{AUDIO_TRACK_ID, producer_}, {9, nullptr}};
    agent_->isAudioTargetArrived_ = true;
    agent_->SetAudioMuted(true);
    EXPECT_EQ(agent_->SetBufferFilledListener(), Status::OK);
    EXPECT_TRUE(agent_->listenerMap_.empty());
    EXPECT_TRUE(agent_->isAudioTargetArrived_);
    agent_->SetAudioMuted(false);
    sptr<IBrokerListener> installedListener;
    EXPECT_CALL(*producer_, SetBufferFilledListener(_))
        .WillOnce(DoAll(SaveArg<0>(&installedListener), Return(Status::OK)));
    ASSERT_EQ(agent_->SetBufferFilledListener(), Status::OK);
    ASSERT_NE(installedListener, nullptr);
    EXPECT_FALSE(agent_->isAudioTargetArrived_);
    EXPECT_EQ(agent_->listenerMap_.at(AUDIO_TRACK_ID), installedListener);
    // Invalid entries must not prevent removal of the valid audio listener.
    agent_->listenerMap_[99] = installedListener;
    agent_->listenerMap_[100] = installedListener;
    agent_->producerMap_[100] = nullptr;
    agent_->listenerMap_[101] = nullptr;
    agent_->producerMap_[101] = producer_;
    EXPECT_CALL(*producer_, RemoveBufferFilledListener(Eq(installedListener))).WillOnce(Return(Status::OK));
    EXPECT_EQ(agent_->RemoveBufferFilledListener(), Status::OK);
}

/**
 * @tc.name  : InstallAudioAndVideoListeners
 * @tc.number: SeekAgent_InstallAudioAndVideoListeners_001
 * @tc.desc  : Install typed listeners for audio/video, ignore subtitles and remove the exact listeners.
 */
HWTEST_F(SeekAgentUnitTest, InstallAudioAndVideoListeners, TestSize.Level0)
{
    demuxer_->demuxer_->mediaMetaData_.trackMetas = {
        MakeTrack(0, "video/avc"), MakeTrack(1, "text/vtt"), MakeTrack(AUDIO_TRACK_ID, "audio/aac")};
    demuxer_->demuxer_->bufferQueueMap_ = {{0, producer_}, {1, producer_}, {AUDIO_TRACK_ID, producer_}};
    sptr<IBrokerListener> videoListener;
    sptr<IBrokerListener> audioListener;
    {
        InSequence sequence;
        EXPECT_CALL(*producer_, SetBufferFilledListener(_))
            .WillOnce(DoAll(SaveArg<0>(&videoListener), Return(Status::OK)));
        EXPECT_CALL(*producer_, SetBufferFilledListener(_))
            .WillOnce(DoAll(SaveArg<0>(&audioListener), Return(Status::OK)));
    }
    ASSERT_EQ(agent_->SetBufferFilledListener(), Status::OK);
    ASSERT_EQ(agent_->listenerMap_.size(), 2U);
    ASSERT_NE(videoListener, nullptr);
    ASSERT_NE(audioListener, nullptr);
    buffer_->pts_ = TARGET_PTS;
    EXPECT_CALL(*producer_, ReturnBuffer(buffer_, true)).WillOnce(Return(Status::OK));
    videoListener->OnBufferFilled(buffer_);
    EXPECT_TRUE(agent_->isVideoTargetArrived_);
    EXPECT_FALSE(agent_->isAudioTargetArrived_);
    EXPECT_CALL(*producer_, ReturnBuffer(buffer_, false)).WillOnce(Return(Status::OK));
    audioListener->OnBufferFilled(buffer_);
    EXPECT_TRUE(agent_->isAudioTargetArrived_);
    EXPECT_CALL(*producer_, RemoveBufferFilledListener(Eq(videoListener))).WillOnce(Return(Status::OK));
    EXPECT_CALL(*producer_, RemoveBufferFilledListener(Eq(audioListener))).WillOnce(Return(Status::OK));
    EXPECT_EQ(agent_->RemoveBufferFilledListener(), Status::OK);
}

/**
 * @tc.name  : ListenerForwardsAudio
 * @tc.number: SeekAgent_ListenerForwardsAudio_001
 * @tc.desc  : Listener forwards audio buffers and safely ignores callbacks after agent destruction.
 */
HWTEST_F(SeekAgentUnitTest, ListenerForwardsAudio, TestSize.Level0)
{
    AudioBufferFilledListener listener(agent_, producer_, AUDIO_TRACK_ID);
    buffer_->pts_ = TARGET_PTS;
    EXPECT_CALL(*producer_, ReturnBuffer(buffer_, false)).WillOnce(Return(Status::OK));
    listener.OnBufferFilled(buffer_);
    EXPECT_TRUE(agent_->isAudioTargetArrived_);
    agent_.reset();
    listener.OnBufferFilled(buffer_);
}
/**
 * @tc.name  : ListenerForwardsVideo
 * @tc.number: SeekAgent_ListenerForwardsVideo_001
 * @tc.desc  : Video listener forwards the target frame and ignores callbacks after agent destruction.
 */
HWTEST_F(SeekAgentUnitTest, ListenerForwardsVideo, TestSize.Level0)
{
    VideoBufferFilledListener listener(agent_, producer_, 0);
    buffer_->pts_ = TARGET_PTS;
    EXPECT_CALL(*producer_, ReturnBuffer(buffer_, true)).WillOnce(Return(Status::OK));
    listener.OnBufferFilled(buffer_);
    EXPECT_TRUE(agent_->isVideoTargetArrived_);
    agent_.reset();
    listener.OnBufferFilled(buffer_);
}

/**
 * @tc.name  : MissingDemuxerRejectsSeek
 * @tc.number: SeekAgent_MissingDemuxerRejectsSeek_001
 * @tc.desc  : A missing demuxer rejects seeking without setting timeout or changing the target.
 */
HWTEST_F(SeekAgentUnitTest, MissingDemuxerRejectsSeek, TestSize.Level0)
{
    agent_->demuxer_.reset();
    bool timeout = false;
    EXPECT_EQ(agent_->Seek(1000, timeout, nullptr), Status::ERROR_INVALID_PARAMETER);
    EXPECT_FALSE(timeout);
    EXPECT_EQ(agent_->seekTargetPts_, TARGET_PTS);
    EXPECT_EQ(agent_->AlignAudioPosition(1000), Status::OK);
    EXPECT_EQ(agent_->SetBufferFilledListener(), Status::ERROR_INVALID_PARAMETER);
}
} // namespace Media
} // namespace OHOS
