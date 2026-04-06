/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "player_impl_unittest.h"
#include "media_errors.h"
#include "../hitranscode_impl_unittest/mock/mock_imediakeysessionServices.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

static const int32_t NUM_0 = 0;
static const int32_t NUM_1 = 1;
static const int32_t ERROR = -1;
static const float FLOAT_0 = 0.0f;

void PlayerImplUnitTest::SetUpTestCase(void) {}

void PlayerImplUnitTest::TearDownTestCase(void) {}

void PlayerImplUnitTest::SetUp(void)
{
    playerImpl_ = std::make_shared<PlayerImpl>();
}

void PlayerImplUnitTest::TearDown(void)
{
    playerImpl_ = nullptr;
}

/**
 * @tc.name  : Test PlayerFactory::GetPlayerPids
 * @tc.number: GetPlayerPids_001
 * @tc.desc  : Test pid.size() == 0
 */
HWTEST_F(PlayerImplUnitTest, GetPlayerPids_001, TestSize.Level0)
{
    auto ret = PlayerFactory::GetPlayerPids();
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name  : Test SetSourceTask
 * @tc.number: SetSourceTask_001
 * @tc.desc  : Test reopenFd.Get() >= 0
 *             Test fdsanFd_ != nullptr
 */
HWTEST_F(PlayerImplUnitTest, SetSourceTask_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    EXPECT_CALL(*mockService, SetSource(_, _, _)).WillOnce(Return(MSERR_OK));
    int32_t fd = open("test.txt", O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, ERROR);
    // Test fdsanFd_ != nullptr
    playerImpl_->fdsanFd_ = std::make_unique<FdsanFd>();
    int32_t offset = NUM_1;
    int32_t size = NUM_1;
    // Test reopenFd.Get() >= 0
    playerImpl_->SetSourceTask(fd, offset, size);
    close(fd);
}

/**
 * @tc.name  : Test Seek
 * @tc.number: Seek_001
 * @tc.desc  : Test ((mSeekPosition != mCurrentPosition || mSeekMode != mCurrentSeekMode) && !isSeeking_) == false
 */
HWTEST_F(PlayerImplUnitTest, Seek_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->isSeeking_ = true;
    auto ret = playerImpl_->Seek(NUM_1, PlayerSeekMode::SEEK_CLOSEST);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test HandleSeekDoneInfo
 * @tc.number: HandleSeekDoneInfo_001
 * @tc.desc  : Test extra == -1
 */
HWTEST_F(PlayerImplUnitTest, HandleSeekDoneInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->isSeeking_ = true;
    playerImpl_->HandleSeekDoneInfo(INFO_TYPE_SEEKDONE, ERROR);
    EXPECT_FALSE(playerImpl_->isSeeking_);
}

/**
 * @tc.name  : Test HandleSeekDoneInfo
 * @tc.number: HandleSeekDoneInfo_002
 * @tc.desc  : Test mSeekPosition != mCurrentPosition || mSeekMode != mCurrentSeekMode
 */
HWTEST_F(PlayerImplUnitTest, HandleSeekDoneInfo_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->mSeekPosition = playerImpl_->mCurrentPosition + NUM_1;
    EXPECT_CALL(*mockService, Seek(_, _)).WillOnce(Return(NUM_1));
    playerImpl_->HandleSeekDoneInfo(INFO_TYPE_SEEKDONE, NUM_1);
    EXPECT_EQ(playerImpl_->mSeekPosition, playerImpl_->mCurrentPosition);
}

/**
 * @tc.name  : Test OnInfo
 * @tc.number: OnInfo_001
 * @tc.desc  : Test extra == -1
 *             Test isSeeking_ == true
 */
HWTEST_F(PlayerImplUnitTest, OnInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto callback = std::make_shared<MockPlayerCallback>();
    playerImpl_->callback_ = callback;
    PlayerOnInfoType type = INFO_TYPE_SEEKDONE;
    int32_t extra = ERROR;
    Format infoBofy = Format();

    EXPECT_CALL(*callback, OnInfo(_, _, _)).Times(0);
    // Test extra == -1
    playerImpl_->OnInfo(type, extra, infoBofy);
    extra = NUM_1;
    playerImpl_->isSeeking_ = true;
    // Test isSeeking_ == true
    playerImpl_->OnInfo(type, extra, infoBofy);
}

/**
 * @tc.name  : Test OnInfo
 * @tc.number: OnInfo_002
 * @tc.desc  : 1. Test IsInListMode() == false
 *             2. Test IsInListMode() == true
 */
HWTEST_F(PlayerImplUnitTest, OnInfo_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto callback = std::make_shared<MockPlayerCallback>();
    playerImpl_->callback_ = callback;
    PlayerOnInfoType type = INFO_TYPE_SEEKDONE;
    int32_t extra = ERROR;
    Format infoBofy = Format();
    //Test IsInListMode() == false
    type = PlayerOnInfoType::INFO_TYPE_STATE_CHANGE;
    playerImpl_->OnInfo(type, extra, infoBofy);
    type = PlayerOnInfoType::INFO_TYPE_EOS;
    playerImpl_->OnInfo(type, extra, infoBofy);

    //Test IsInListMode() == true
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    ret = playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    type = PlayerOnInfoType::INFO_TYPE_STATE_CHANGE;
    playerImpl_->OnInfo(type, extra, infoBofy);
    type = PlayerOnInfoType::INFO_TYPE_EOS;
    playerImpl_->OnInfo(type, extra, infoBofy);
}

/**
 * @tc.name  : Test OnInfo
 * @tc.number: OnInfo_003
 * @tc.desc  : Test callback == nullptr
 */
HWTEST_F(PlayerImplUnitTest, OnInfo_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    playerImpl_->callback_ = nullptr;
    PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_STATE_CHANGE;
    int32_t extra = NUM_1;
    Format infoBofy = Format();
    playerImpl_->OnInfo(type, extra, infoBofy);
}

/**
 * @tc.name  : Test OnInfo
 * @tc.number: OnInfo_004
 * @tc.desc  : 1. Test INFO_TYPE_STATE_CHANGE with shouldUpdateState=false
 *             2. Test shouldUpdateState=true and callback is called
 */
HWTEST_F(PlayerImplUnitTest, OnInfo_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto callback = std::make_shared<MockPlayerCallback>();
    playerImpl_->callback_ = callback;
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    EXPECT_EQ(ret, MSERR_OK);
    ret = playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    EXPECT_EQ(ret, MSERR_OK);
    
    playerImpl_->curSrcId_ = id1;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    playerImpl_->listState_ = PLAYER_IDLE;
    
    Format infoBofy = Format();
    PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_STATE_CHANGE;
    int32_t extra = static_cast<int32_t>(PLAYER_PLAYBACK_COMPLETE);
    
    EXPECT_CALL(*callback, OnInfo(_, _, _)).Times(0);
    playerImpl_->OnInfo(type, extra, infoBofy);
    
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    playerImpl_->curSrcId_ = id2;
    extra = static_cast<int32_t>(PLAYER_PLAYBACK_COMPLETE);
    playerImpl_->OnInfo(type, extra, infoBofy);
    
    extra = static_cast<int32_t>(PLAYER_STARTED);
    EXPECT_CALL(*callback, OnInfo(_, _, _)).Times(2);
    playerImpl_->OnInfo(type, extra, infoBofy);
}

/**
 * @tc.name  : Test OnInfo
 * @tc.number: OnInfo_005
 * @tc.desc  : 1. Test INFO_TYPE_EOS with notifyEOS=false
 *             2. Test notifyEOS=true and callback is called
 */
HWTEST_F(PlayerImplUnitTest, OnInfo_005, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto callback = std::make_shared<MockPlayerCallback>();
    playerImpl_->callback_ = callback;
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    EXPECT_EQ(ret, MSERR_OK);
    ret = playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    EXPECT_EQ(ret, MSERR_OK);
    
    playerImpl_->curSrcId_ = id1;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    playerImpl_->listState_ = PLAYER_PLAYBACK_COMPLETE;
    
    Format infoBofy = Format();
    PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_EOS;
    int32_t extra = NUM_1;
    
    EXPECT_CALL(*callback, OnInfo(PlayerOnInfoType::INFO_TYPE_PLAYBACK_CONTENT_CHANGE, _, _)).Times(1);
    playerImpl_->OnInfo(type, extra, infoBofy);
    
    playerImpl_->listState_ = PLAYER_STOPPED;
    EXPECT_CALL(*callback, OnInfo(_, _, _)).Times(1);
    playerImpl_->OnInfo(type, extra, infoBofy);
    
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    playerImpl_->listState_ = PLAYER_PLAYBACK_COMPLETE;
    EXPECT_CALL(*callback, OnInfo(PlayerOnInfoType::INFO_TYPE_EOS, _, _)).Times(1);
    playerImpl_->OnInfo(type, extra, infoBofy);
}

/**
 * @tc.name  : Test SetPlaybackRate
 * @tc.number: SetPlaybackRate_001
 * @tc.desc  : Test ((rate < minRate - eps) || (rate > maxRate + eps)) == true
 */
HWTEST_F(PlayerImplUnitTest, SetPlaybackRate_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    float rate = FLOAT_0;
    EXPECT_EQ(playerImpl_->SetPlaybackRate(rate), MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SelectTrack
 * @tc.number: SelectTrack_001
 * @tc.desc  : Test index == prevTrackIndex_
 */
HWTEST_F(PlayerImplUnitTest, SelectTrack_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->prevTrackIndex_ = NUM_1;
    auto ret = playerImpl_->SelectTrack(NUM_1, PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(ret, NUM_0);
}

/**
 * @tc.name  : Test GetPlaybackStatisticMetrics
 * @tc.number: GetPlaybackStatisticMetrics_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetPlaybackStatisticMetrics_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    Format playbackStatisticMetrics;
    EXPECT_CALL(*mockService, GetPlaybackStatisticMetrics(_)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->GetPlaybackStatisticMetrics(playbackStatisticMetrics);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetCurrentPresentationTimestamp
 * @tc.number: GetCurrentPresentationTimestamp_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetCurrentPresentationTimestamp_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    int64_t currentPresentation = 0;
    EXPECT_CALL(*mockService, GetCurrentPresentationTimestamp(_)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->GetCurrentPresentationTimestamp(currentPresentation);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetMediaDescription
 * @tc.number: GetMediaDescription_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetMediaDescription_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    Format format;
    EXPECT_CALL(*mockService, GetMediaDescription(_)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->GetMediaDescription(format);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetTrackDescription
 * @tc.number: GetTrackDescription_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetTrackDescription_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    Format format;
    uint32_t trackIndex = 0;
    EXPECT_CALL(*mockService, GetTrackDescription(_, _)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->GetTrackDescription(format, trackIndex);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetLoudnessGain
 * @tc.number: SetLoudnessGain_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SetLoudnessGain_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    float gain = 1.0f;
    EXPECT_CALL(*mockService, SetLoudnessGain(gain)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->SetLoudnessGain(gain);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetReopenFd
 * @tc.number: SetReopenFd_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SetReopenFd_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    int32_t fd = NUM_1;
    EXPECT_CALL(*mockService, SetReopenFd(fd)).WillOnce(Return(MSERR_OK));

    auto ret = playerImpl_->SetReopenFd(fd);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetDecryptConfig
 * @tc.number: SetDecryptConfig_001
 * @tc.desc  : Test return value when keySessionProxy is nullptr
 */
HWTEST_F(PlayerImplUnitTest, SetDecryptConfig_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    sptr<DrmStandard::IMediaKeySessionService> keySessionProxy;
    auto ret = playerImpl_->SetDecryptConfig(keySessionProxy, false);
#ifdef SUPPORT_AVPLAYER_DRM
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
#else
    EXPECT_EQ(ret, 0);
#endif
}

/**
 * @tc.name  : Test SetTrackSelectionFilter
 * @tc.number: SetTrackSelectionFilter_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SetTrackSelectionFilter_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    AVPlayTrackSelectionFilter trackFilter;
    EXPECT_CALL(*mockService, SetTrackSelectionFilter(_)).WillOnce(Return(MSERR_OK));
    auto ret = playerImpl_->SetTrackSelectionFilter(trackFilter);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetTrackSelectionFilter
 * @tc.number: GetTrackSelectionFilter_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetTrackSelectionFilter_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    AVPlayTrackSelectionFilter trackFilter;
    EXPECT_CALL(*mockService, GetTrackSelectionFilter(_)).WillOnce(Return(MSERR_OK));
    auto ret = playerImpl_->GetTrackSelectionFilter(trackFilter);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SeekToDefaultPosition
 * @tc.number: SeekToDefaultPosition_001
 * @tc.desc  : Test playerService_ != nullptr
 */
HWTEST_F(PlayerImplUnitTest, SeekToDefaultPosition_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    EXPECT_CALL(*mockService, SeekToDefaultPosition()).WillOnce(Return(MSERR_OK));
    playerImpl_->playerService_ = mockService;
    auto ret = playerImpl_->SeekToDefaultPosition();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetSeekableRanges
 * @tc.number: GetSeekableRanges_001
 * @tc.desc  : Test playerService_ != nullptr
 */
HWTEST_F(PlayerImplUnitTest, GetSeekableRanges_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    EXPECT_CALL(*mockService, GetSeekableRanges(_)).WillOnce(Return(MSERR_OK));
    playerImpl_->playerService_ = mockService;
    std::vector<Plugins::SeekRange> testLoadedRanges;
    auto ret = playerImpl_->GetSeekableRanges(testLoadedRanges);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetLoadedRanges
 * @tc.number: GetLoadedRanges_001
 * @tc.desc  : Test playerService_ != nullptr
 */
HWTEST_F(PlayerImplUnitTest, GetLoadedRanges_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    EXPECT_CALL(*mockService, GetLoadedRanges(_)).WillOnce(Return(MSERR_OK));
    playerImpl_->playerService_ = mockService;
    std::vector<Plugins::SeekRange> testLoadedRanges;
    auto ret = playerImpl_->GetLoadedRanges(testLoadedRanges);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AddPlaybackMediaSource
 * @tc.number: AddPlaybackMediaSource_001
 * @tc.desc  : 1. Empty list (first add) 2. Insert at valid position 3. Insert at invalid position
 */
HWTEST_F(PlayerImplUnitTest, AddPlaybackMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string generateId;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto mediaSource = std::make_shared<AVMediaSource>("url1", headers);
    auto mediaSource2 = std::make_shared<AVMediaSource>("url2", headers);

    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, "", generateId);
    EXPECT_EQ(ret, MSERR_OK);

    std::string generateId2;

    ret = playerImpl_->AddPlaybackMediaSource(mediaSource2, generateId, generateId2);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, "invalid_id", generateId);
    EXPECT_EQ(ret, MSERR_PARAM_OUT_OF_RANGE);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test AddPlaybackMediaSource
 * @tc.number: AddPlaybackMediaSource_002
 * @tc.desc  : 1. Empty list (first add) 2. listState_ = PLAYER_INITIALIZED 3. listState_ = PLAYER_IDLE
 */
HWTEST_F(PlayerImplUnitTest, AddPlaybackMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string generateId;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    FileDescriptor fileDescriptor {10, 0, 100};
    auto mediaSource = std::make_shared<AVMediaSource>("url1", headers);
    auto mediaSource2 = std::make_shared<AVMediaSource>(fileDescriptor);

    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, "", generateId);
    EXPECT_EQ(ret, MSERR_OK);
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource2, "", generateId);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->listState_ = PLAYER_INITIALIZED;
    std::string generateId2;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, generateId, generateId2);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->listState_ = PLAYER_IDLE;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, generateId, generateId2);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test RemovePlaybackMediaSource
 * @tc.number: RemovePlaybackMediaSource_001
 * @tc.desc  : 1. Remove middle item 2. Remove last item 3. Remove current item 4. Remove makes list empty
 */
HWTEST_F(PlayerImplUnitTest, RemovePlaybackMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2, id3;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    auto src3 = std::make_shared<AVMediaSource>("url3", headers);

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->AddPlaybackMediaSource(src3, id2, id3);

    playerImpl_->curSrcId_ = id2;

    auto ret = playerImpl_->RemovePlaybackMediaSource(id2);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->RemovePlaybackMediaSource("invalid");
    EXPECT_EQ(ret, MSERR_PARAM_OUT_OF_RANGE);

    playerImpl_->ClearPlaybackList();

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    ret = playerImpl_->RemovePlaybackMediaSource(id1);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_IDLE);
}

/**
 * @tc.name  : Test RemovePlaybackMediaSource
 * @tc.number: RemovePlaybackMediaSource_002
 * @tc.desc  : 1. Remove head item when listState_ == PLAYER_INITIALIZED
 */
HWTEST_F(PlayerImplUnitTest, RemovePlaybackMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2, id3;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);

    playerImpl_->listState_ = PLAYER_INITIALIZED;
    auto ret = playerImpl_->RemovePlaybackMediaSource(id1);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ClearPlaybackList
 * @tc.number: ClearPlaybackList_001
 * @tc.desc  : 1. Normal clear 2. Clear when list is already empty
 */
HWTEST_F(PlayerImplUnitTest, ClearPlaybackList_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string generateId;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto mediaSource = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(mediaSource, "", generateId);

    auto ret = playerImpl_->ClearPlaybackList();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_IDLE);

    ret = playerImpl_->ClearPlaybackList();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetCurrentMediaSource & GetMediaSources
 * @tc.number: GetInfo_001
 * @tc.desc  : 1. Get current ID 2. Get count 3. Get all sources
 */
HWTEST_F(PlayerImplUnitTest, GetInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string srcId;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto mediaSource = std::make_shared<AVMediaSource>("url1", headers);

    std::string curId;
    auto ret = playerImpl_->GetCurrentMediaSource(curId);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(curId, "");

    EXPECT_EQ(ret, MSERR_OK);

    std::vector<std::shared_ptr<AVMediaSource>> sources;
    ret = playerImpl_->GetMediaSources(sources);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(sources.size(), 0);

    playerImpl_->AddPlaybackMediaSource(mediaSource, "", srcId);
    playerImpl_->curSrcId_ = srcId;

    ret = playerImpl_->GetCurrentMediaSource(curId);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(curId, srcId);

    ret = playerImpl_->GetMediaSources(sources);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(sources.size(), 1);
    EXPECT_EQ(sources[0], mediaSource);
}

/**
 * @tc.name  : Test AdvanceToNextMediaSource
 * @tc.number: AdvanceToNext_001
 * @tc.desc  : 1. Normal advance 2. Loop mode (PLAYLIST_LOOP_MODE_ONE) 3. End of list (no loop)
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToNextMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->curSrcId_ = id1;

    auto ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    playerImpl_->curSrcId_ = id2;
    ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_NONE);
    playerImpl_->curSrcId_ = id1;
    ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_PARAM_OUT_OF_RANGE);

    playerImpl_->ClearPlaybackList();
    ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_INVALID_STATE);
}

/**
 * @tc.name  : Test AdvanceToPrevMediaSource
 * @tc.number: AdvanceToPrev_001
 * @tc.desc  : 1. Normal back 2. Loop mode 3. First item (no loop)
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToPrevMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->curSrcId_ = id2;

    auto ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    playerImpl_->curSrcId_ = id1;
    ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_NONE);
    playerImpl_->curSrcId_ = id2;
    ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_PARAM_OUT_OF_RANGE);

    playerImpl_->ClearPlaybackList();
    ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_INVALID_STATE);
}

/**
 * @tc.name  : Test AdvanceToMediaSource
 * @tc.number: AdvanceToMediaSource_001
 * @tc.desc  : 1. Valid ID 2. Invalid ID 3. Not in list mode
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);

    auto ret = playerImpl_->AdvanceToMediaSource("any_id");
    EXPECT_EQ(ret, MSERR_INVALID_STATE);

    playerImpl_->AddPlaybackMediaSource(src1, "", id1);

    ret = playerImpl_->AdvanceToMediaSource(id1);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->AdvanceToMediaSource("invalid_id");
    EXPECT_EQ(ret, MSERR_PARAM_OUT_OF_RANGE);
}

/**
 * @tc.name  : Test SetPlaylistLoopMode
 * @tc.number: SetPlaylistLoopMode_001
 * @tc.desc  : 1. Set valid modes (ALL, SHUFFLE, NONE) 2. Set invalid mode
 */
HWTEST_F(PlayerImplUnitTest, SetPlaylistLoopMode_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ALL);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ALL);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_NONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_NONE);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    playerImpl_->SetPlaylistLoopMode(static_cast<PlaylistLoopMode>(999));
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_001
 * @tc.desc  : 1. Playback complete with loop 2. Playback complete last item 2. Playback complete not last item
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    bool shouldUpdateState = true;
    int32_t extra = 0;
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->curSrcId_ = id1;

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    playerImpl_->listState_ = PLAYER_IDLE;
    playerImpl_->HandleListStateInfo(PLAYER_PLAYBACK_COMPLETE, shouldUpdateState, extra);
    EXPECT_EQ(shouldUpdateState, false);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_IDLE);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    playerImpl_->curSrcId_ = id1;
    playerImpl_->listState_ = PLAYER_IDLE;
    playerImpl_->HandleListStateInfo(PLAYER_PLAYBACK_COMPLETE, shouldUpdateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_PLAYBACK_COMPLETE);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    playerImpl_->curSrcId_ = id2;
    playerImpl_->listState_ = PLAYER_IDLE;
    playerImpl_->HandleListStateInfo(PLAYER_PLAYBACK_COMPLETE, shouldUpdateState, extra);
    EXPECT_EQ(shouldUpdateState, false);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_IDLE);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    playerImpl_->curSrcId_ = id2;
    playerImpl_->listState_ = PLAYER_IDLE;
    playerImpl_->HandleListStateInfo(PLAYER_PLAYBACK_COMPLETE, shouldUpdateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_IDLE);
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_002
 * @tc.desc  : Switching item states
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    bool shouldUpdateState = true;
    int32_t extra = 0;
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->curSrcId_ = id1;
    playerImpl_->isSwitchingItem_ = true;
    playerImpl_->isSwitchUpdate_ = false;
    playerImpl_->HandleListStateInfo(PLAYER_STARTED, shouldUpdateState, extra);
    EXPECT_EQ(shouldUpdateState, false);
    EXPECT_EQ(playerImpl_->isSwitchingItem_, false);

    playerImpl_->HandleListStateInfo(PLAYER_PAUSED, shouldUpdateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_PAUSED);

    playerImpl_->HandleListStateInfo(PLAYER_FROZEN, shouldUpdateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_FROZEN);

    playerImpl_->isSwitchingItem_ = true;
    playerImpl_->HandleListStateInfo(PLAYER_IDLE, shouldUpdateState, extra);
    EXPECT_EQ(shouldUpdateState, false);

    playerImpl_->isSwitchingItem_ = false;
    playerImpl_->HandleListStateInfo(PLAYER_STARTED, shouldUpdateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_STARTED);
    EXPECT_EQ(extra, static_cast<int32_t>(PLAYER_STARTED));
}

/**
 * @tc.name  : Test HandleListEOSInfo
 * @tc.number: HandleListEOSInfo_001
 * @tc.desc  : 1. EOS in loop mode 2. EOS at end of list
 */
HWTEST_F(PlayerImplUnitTest, HandleListEOSInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    bool notifyEOS = true;

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->curSrcId_ = id1;

    playerImpl_->listState_ = PLAYER_PLAYBACK_COMPLETE;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, true);

    playerImpl_->listState_ = PLAYER_PLAYBACK_COMPLETE;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    notifyEOS = true;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, false);

    playerImpl_->listState_ = PLAYER_STOPPED;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    notifyEOS = true;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, false);

    playerImpl_->listState_ = PLAYER_STOPPED;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    notifyEOS = true;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, false);
}

/**
 * @tc.name  : Test SelectAndSwitchAfterRemove
 * @tc.number: SelectAndSwitchAfterRemove_001
 * @tc.desc  : 1. Remove last item 2. Remove middle item 3. In Shuffle mode 4. listState_ == PLAYER_STARTED
 */
HWTEST_F(PlayerImplUnitTest, SelectAndSwitchAfterRemove_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->curSrcId_ = id1;

    playerImpl_->SelectAndSwitchAfterRemove(true, playerImpl_->itemList_.end());

    playerImpl_->curSrcId_ = id1;
    playerImpl_->isSwitchingItem_ = false;
    playerImpl_->SelectAndSwitchAfterRemove(false, playerImpl_->itemList_.begin() + 1);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    playerImpl_->curSrcId_ = id1;
    playerImpl_->isSwitchingItem_ = false;
    playerImpl_->SelectAndSwitchAfterRemove(false, playerImpl_->itemList_.end());

    playerImpl_->listState_ = PLAYER_STARTED;
    playerImpl_->SelectAndSwitchAfterRemove(true, playerImpl_->itemList_.end());
}

/**
 * @tc.name  : Test State Query Functions
 * @tc.number: StateQueryFunctions_001
 * @tc.desc  : Test IsInListMode, ShouldLoopCurrent, ShouldShuffle
 */
HWTEST_F(PlayerImplUnitTest, StateQueryFunctions_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    EXPECT_EQ(playerImpl_->IsInListMode(), false);
    std::string id;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(src, "", id);
    EXPECT_EQ(playerImpl_->IsInListMode(), true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ALL);
    EXPECT_EQ(playerImpl_->ShouldLoopCurrent(), false);
    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->ShouldLoopCurrent(), true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ALL);
    EXPECT_EQ(playerImpl_->ShouldShuffle(), false);
    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->ShouldShuffle(), true);
}

/**
 * @tc.name  : Test RestoreLoopIfNeeded
 * @tc.number: RestoreLoopIfNeeded_001
 * @tc.desc  : 1. Was in list mode, restore loop 2. Not in list mode, do nothing
 */
HWTEST_F(PlayerImplUnitTest, RestoreLoopIfNeeded_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    playerImpl_->RestoreLoopIfNeeded(true, true);
    playerImpl_->RestoreLoopIfNeeded(false, true);
    playerImpl_->RestoreLoopIfNeeded(true, false);
    playerImpl_->RestoreLoopIfNeeded(false, false);
}

/**
 * @tc.name  : Test SelectNextIndex
 * @tc.number: SelectNextIndex_001
 * @tc.desc  : 1. Normal sequence (next/prev) 2. Loop current 3. Shuffle 4. Edge cases
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    PlayerImpl::MediaSourceIterator nextIdx;
    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    playerImpl_->curSrcId_ = id1;
    nextIdx = playerImpl_->SelectNextIndex(true);
    EXPECT_EQ(nextIdx->first, id1);
    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    nextIdx = playerImpl_->SelectNextIndex(true);
    EXPECT_NE(nextIdx->first, id1);
    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ALL);
    playerImpl_->curSrcId_ = id2;
    nextIdx = playerImpl_->SelectNextIndex(true);
    EXPECT_EQ(nextIdx->first, id1);
    playerImpl_->curSrcId_ = id1;
    nextIdx = playerImpl_->SelectNextIndex(false);
    EXPECT_EQ(nextIdx->first, id2);
    playerImpl_->ResetListParameters();
    nextIdx = playerImpl_->SelectNextIndex(true);
    EXPECT_EQ(nextIdx, playerImpl_->itemList_.end());
    playerImpl_->curSrcId_ = id2;
    nextIdx = playerImpl_->SelectNextIndex(true);
    EXPECT_EQ(nextIdx, playerImpl_->itemList_.begin());
}

/**
 * @tc.name  : Test SwitchSetMediaSource
 * @tc.number: SwitchSetMediaSource_001
 * @tc.desc  : 1. Valid switch 2. Invalid iterator 3. Empty list
 */
HWTEST_F(PlayerImplUnitTest, SwitchSetMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    auto it = playerImpl_->FindSourceInList(id1);
    ASSERT_NE(it, playerImpl_->itemList_.end());

    std::string prevId = playerImpl_->curSrcId_;
    auto ret = playerImpl_->SwitchSetMediaSource(it);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->SwitchSetMediaSource(playerImpl_->itemList_.end());
    EXPECT_EQ(ret, MSERR_INVALID_VAL);

    playerImpl_->ResetListParameters();
    ret = playerImpl_->SwitchSetMediaSource(playerImpl_->itemList_.begin());
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SwitchToIndex
 * @tc.number: SwitchToIndex_001
 * @tc.desc  : 1. Valid switch 2. Invalid iterator 3. Flow: Reset->Set->Prepare->Play
 */
HWTEST_F(PlayerImplUnitTest, SwitchToIndex_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    auto it = playerImpl_->FindSourceInList(id1);

    auto ret = playerImpl_->SwitchToIndex(it);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(playerImpl_->isSwitchingItem_);

    ret = playerImpl_->SwitchToIndex(playerImpl_->itemList_.end());
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test NotifyPlaybackContentChange
 * @tc.number: NotifyPlaybackContentChange_001
 * @tc.desc  : With valid callback
 */
HWTEST_F(PlayerImplUnitTest, NotifyPlaybackContentChange_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    playerImpl_->NotifyPlaybackContentChange();
    auto callback = std::make_shared<MockPlayerCallback>();
    playerImpl_->callback_ = callback;
    playerImpl_->NotifyPlaybackContentChange();
}

/**
 * @tc.name  : Test FindSourceInList
 * @tc.number: FindSourceInList_001
 * @tc.desc  : 1. Found 2. Not Found
 */
HWTEST_F(PlayerImplUnitTest, FindSourceInList_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);

    auto it = playerImpl_->FindSourceInList(id1);
    EXPECT_NE(it, playerImpl_->itemList_.end());

    it = playerImpl_->FindSourceInList("invalid_id");
    EXPECT_EQ(it, playerImpl_->itemList_.end());
}

/**
 * @tc.name  : Test DealWithSwitchingOpt
 * @tc.number: DealWithSwitchingOpt_001
 * @tc.desc  : 1. Normal switch 2. Switch while paused 3. Switch while stopped
 */
HWTEST_F(PlayerImplUnitTest, DealWithSwitchingOpt_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->isListPaused_ = false;
    playerImpl_->isListStopped_ = false;
    auto ret = playerImpl_->DealWithSwitchingOpt();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->isListPaused_ = true;
    playerImpl_->isListStopped_ = false;
    ret = playerImpl_->DealWithSwitchingOpt();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->isListPaused_ = false;
    playerImpl_->isListStopped_ = true;
    ret = playerImpl_->DealWithSwitchingOpt();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->isListPaused_ = false;
    playerImpl_->isListStopped_ = false;
    ret = playerImpl_->DealWithSwitchingOpt();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test Pause
 * @tc.number: Pause_001
 * @tc.desc  : 1.Not in list mode 2.In list mode but isSwitchingItem_ = false
 *             3.In list mode and isSwitchingItem_ = true;
 */
HWTEST_F(PlayerImplUnitTest, Pause_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    auto ret = playerImpl_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
    playerImpl_->isSwitchingItem_ = true;
    ret = playerImpl_->Pause();
    EXPECT_EQ(ret, MSERR_OK);

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->isSwitchingItem_ = false;
    ret = playerImpl_->Pause();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->isSwitchingItem_ = true;
    ret = playerImpl_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
    playerImpl_->isListStopped_ = true;
    ret = playerImpl_->Pause();
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test Stop
 * @tc.number: Stop_001
 * @tc.desc  : 1.Not in list mode 2.In list mode but isSwitchingItem_ = false
 *             3.In list mode and isSwitchingItem_ = true;
 */
HWTEST_F(PlayerImplUnitTest, Stop_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    auto ret = playerImpl_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
    playerImpl_->isSwitchingItem_ = true;
    ret = playerImpl_->Stop();
    EXPECT_EQ(ret, MSERR_OK);

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->isSwitchingItem_ = false;
    ret = playerImpl_->Stop();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->isSwitchingItem_ = true;
    ret = playerImpl_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test IsLooping
 * @tc.number: IsLooping_001
 * @tc.desc  : 1.Not in list mode 2.In list mode
 */
HWTEST_F(PlayerImplUnitTest, IsLooping_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto ret = playerImpl_->IsLooping();
    EXPECT_EQ(ret, false);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    ret = playerImpl_->IsLooping();
    EXPECT_EQ(ret, false);

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    ret = playerImpl_->IsLooping();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : Test SetLooping
 * @tc.number: SetLooping_001
 * @tc.desc  : Test SetLooping in list mode with different loop modes
 */
HWTEST_F(PlayerImplUnitTest, SetLooping_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    auto ret = playerImpl_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ONE;
    ret = playerImpl_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_ALL;
    ret = playerImpl_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    ret = playerImpl_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_SHUFFLE;
    ret = playerImpl_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AdvanceToNextMediaSource
 * @tc.number: AdvanceToNextMediaSource_003
 * @tc.desc  : Test AdvanceToNextMediaSource when at last item with no loop mode
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToNextMediaSource_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    std::string id1, id2;
    std::map<std::string, std::string> headers = {{"test", "val"}};
    auto src1 = std::make_shared<AVMediaSource>("url1", headers);
    auto src2 = std::make_shared<AVMediaSource>("url2", headers);
    playerImpl_->AddPlaybackMediaSource(src1, "", id1);
    playerImpl_->AddPlaybackMediaSource(src2, id1, id2);

    playerImpl_->curSrcId_ = id2;
    playerImpl_->listLoopMode_ = PLAYLIST_LOOP_MODE_NONE;
    auto ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SwitchToIndex
 * @tc.number: SwitchToIndex_004
 * @tc.desc  : Test SwitchToIndex with empty list
 */
HWTEST_F(PlayerImplUnitTest, SwitchToIndex_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    PlayerImpl::MediaSourceIterator nextIndex;
    auto ret = playerImpl_->SwitchToIndex(nextIndex);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SwitchSetMediaSource
 * @tc.number: SwitchSetMediaSource_004
 * @tc.desc  : Test SwitchSetMediaSource with end iterator
 */
HWTEST_F(PlayerImplUnitTest, SwitchSetMediaSource_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    playerImpl_->playerService_ = mockService;

    PlayerImpl::MediaSourceIterator nextIndex;
    auto ret = playerImpl_->SwitchSetMediaSource(nextIndex);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}
} // namespace Media
} // namespace OHOS