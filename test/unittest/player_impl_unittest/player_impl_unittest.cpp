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
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AddPlaybackMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    std::map<std::string, std::string> headers2 = {{"bb", "bb"}};
    std::map<std::string, std::string> headers3 = {{"cc", "cc"}};

    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto mediaSource2 = std::make_shared<AVMediaSource>("bb", headers2);
    auto mediaSource3 = std::make_shared<AVMediaSource>("cc", headers3);

    int32_t pos = 0;
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = -1;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource2, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 5;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource3, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 0;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test RemovePlaybackMediaSource
 * @tc.number: RemovePlaybackMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_VAL
 */
HWTEST_F(PlayerImplUnitTest, RemovePlaybackMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = -1;
    auto ret = playerImpl_->RemovePlaybackMediaSource(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
    pos = 2;
    ret = playerImpl_->RemovePlaybackMediaSource(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test RemovePlaybackMediaSource
 * @tc.number: RemovePlaybackMediaSource_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, RemovePlaybackMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    std::map<std::string, std::string> headers2 = {{"bb", "bb"}};
    std::map<std::string, std::string> headers3 = {{"cc", "cc"}};

    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto mediaSource2 = std::make_shared<AVMediaSource>("bb", headers2);
    auto mediaSource3 = std::make_shared<AVMediaSource>("cc", headers3);

    int32_t pos = 0;
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 1;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 2;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->currItemIdx_, pos);

    pos = 0;
    ret = playerImpl_->RemovePlaybackMediaSource(pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 1;
    ret = playerImpl_->RemovePlaybackMediaSource(pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 0;
    ret = playerImpl_->RemovePlaybackMediaSource(pos);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ClearPlaybackList
 * @tc.number: ClearPlaybackList_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, ClearPlaybackList_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);

    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, 0);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->ClearPlaybackList();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetCurrentMediaSource
 * @tc.number: GetCurrentMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetCurrentMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    auto ret = playerImpl_->GetCurrentMediaSource(pos);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetMediaSourceCount
 * @tc.number: GetMediaSourceCount_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetMediaSourceCount_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t count = 0;
    auto ret = playerImpl_->GetMediaSourceCount(count);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetMediaSources
 * @tc.number: GetMediaSources_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, GetMediaSources_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::vector<std::shared_ptr<AVMediaSource>> mediaSources;
    auto ret = playerImpl_->GetMediaSources(mediaSources);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AdvanceToNextMediaSource
 * @tc.number: AdvanceToNextMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToNextMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test AdvanceToNextMediaSource
 * @tc.number: AdvanceToNextMediaSource_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToNextMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    ret = playerImpl_->AdvanceToNextMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test AdvanceToPrevMediaSource
 * @tc.number: AdvanceToPrevMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToPrevMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test AdvanceToPrevMediaSource
 * @tc.number: AdvanceToPrevMediaSource_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToPrevMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    ret = playerImpl_->AdvanceToPrevMediaSource();
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test AdvanceToMediaSource
 * @tc.number: AdvanceToMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, AdvanceToMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::string id = "";
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, id);
    EXPECT_EQ(ret, MSERR_OK);

    id = "";
    ret = playerImpl_->AdvanceToMediaSource(id);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_001
 * @tc.desc  : Test state == PLAYER_PLAYBACK_COMPLETE && updateState == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    PlayerStates state = PLAYER_PLAYBACK_COMPLETE;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_FALSE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_002
 * @tc.desc  : Test state == PLAYER_PLAYBACK_COMPLETE && updateState == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 1;
    std::map<std::string, std::string> headers2 = {{"bb", "bb"}};
    auto mediaSource2 = std::make_shared<AVMediaSource>("bb", headers2);
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource2, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    PlayerStates state = PLAYER_PLAYBACK_COMPLETE;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_FALSE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_003
 * @tc.desc  : Test state == PLAYER_PLAYBACK_COMPLETE && updateState == true
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    PlayerStates state = PLAYER_PLAYBACK_COMPLETE;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_TRUE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_004
 * @tc.desc  : Test state == PLAYER_IDLE && updateState == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->isSwitchingItem_, true);

    PlayerStates state = PLAYER_IDLE;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_FALSE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_005
 * @tc.desc  : Test state == PLAYER_INITIALIZED && updateState == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_005, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->isSwitchingItem_, true);

    PlayerStates state = PLAYER_INITIALIZED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_FALSE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_006
 * @tc.desc  : Test state == PLAYER_PREPARED && updateState == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_006, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->isSwitchingItem_, true);

    PlayerStates state = PLAYER_PREPARED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_FALSE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_007
 * @tc.desc  : Test state == PLAYER_STARTED && updateState == true
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_007, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->isSwitchingItem_, true);

    PlayerStates state = PLAYER_STARTED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_TRUE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListStateInfo
 * @tc.number: HandleListStateInfo_008
 * @tc.desc  : Test state == PLAYER_PAUSED && updateState == true
 */
HWTEST_F(PlayerImplUnitTest, HandleListStateInfo_008, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    PlayerStates state = PLAYER_PAUSED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_TRUE(updateState);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListEOSInfo
 * @tc.number: HandleListEOSInfo_001
 * @tc.desc  : Test state == PLAYER_PLAYBACK_COMPLETE && notifyEOS == true
 */
HWTEST_F(PlayerImplUnitTest, HandleListEOSInfo_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    PlayerStates state = PLAYER_PLAYBACK_COMPLETE;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_PLAYBACK_COMPLETE);

    bool notifyEOS = true;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, true);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleListEOSInfo
 * @tc.number: HandleListEOSInfo_002
 * @tc.desc  : Test state == PLAYER_PLAYBACK_COMPLETE && notifyEOS == false
 */
HWTEST_F(PlayerImplUnitTest, HandleListEOSInfo_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    bool notifyEOS = true;
    playerImpl_->HandleListEOSInfo(notifyEOS);
    EXPECT_EQ(notifyEOS, false);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleRemovePlaybackMediaSource
 * @tc.number: HandleRemovePlaybackMediaSource_001
 * @tc.desc  : Test state == PLAYER_STARTED
 */
HWTEST_F(PlayerImplUnitTest, HandleRemovePlaybackMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    PlayerStates state = PLAYER_STARTED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_STARTED);

    playerImpl_->HandleRemovePlaybackMediaSource();
    EXPECT_EQ(playerImpl_->currItemIdx_, 0);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleRemovePlaybackMediaSource
 * @tc.number: HandleRemovePlaybackMediaSource_002
 * @tc.desc  : Test state == PLAYER_STARTED
 */
HWTEST_F(PlayerImplUnitTest, HandleRemovePlaybackMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    PlayerStates state = PLAYER_STARTED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_STARTED);

    playerImpl_->HandleRemovePlaybackMediaSource();
    EXPECT_EQ(playerImpl_->currItemIdx_, 0);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleRemovePlaybackMediaSource
 * @tc.number: HandleRemovePlaybackMediaSource_003
 * @tc.desc  : Test state == PLAYER_PAUSED
 */
HWTEST_F(PlayerImplUnitTest, HandleRemovePlaybackMediaSource_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    PlayerStates state = PLAYER_PAUSED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_PAUSED);

    playerImpl_->HandleRemovePlaybackMediaSource();
    EXPECT_EQ(playerImpl_->currItemIdx_, 0);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test HandleRemovePlaybackMediaSource
 * @tc.number: HandleRemovePlaybackMediaSource_004
 * @tc.desc  : Test state == PLAYER_PAUSED
 */
HWTEST_F(PlayerImplUnitTest, HandleRemovePlaybackMediaSource_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    PlayerStates state = PLAYER_PAUSED;
    bool updateState = true;
    int32_t extra = 0;
    playerImpl_->HandleListStateInfo(state, updateState, extra);
    EXPECT_EQ(playerImpl_->listState_, PLAYER_PAUSED);

    playerImpl_->HandleRemovePlaybackMediaSource();
    EXPECT_EQ(playerImpl_->currItemIdx_, 0);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test IsInListMode
 * @tc.number: IsInListMode_001
 * @tc.desc  : Test playerService_ is valid and returns true
 */
HWTEST_F(PlayerImplUnitTest, IsInListMode_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    EXPECT_EQ(playerImpl_->IsInListMode(), true);
    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test ShouldLoopCurrent
 * @tc.number: ShouldLoopCurrent_001
 * @tc.desc  : Test playerService_ is valid and returns true
 */
HWTEST_F(PlayerImplUnitTest, ShouldLoopCurrent_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    EXPECT_EQ(playerImpl_->ShouldLoopCurrent(), true);
    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : Test ShouldShuffle
 * @tc.number: ShouldShuffle_001
 * @tc.desc  : Test playerService_ is valid and returns true
 */
HWTEST_F(PlayerImplUnitTest, ShouldShuffle_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    EXPECT_EQ(playerImpl_->ShouldShuffle(), true);
    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : RestoreLoopIfNeeded
 * @tc.number: RestoreLoopIfNeeded_001
 * @tc.desc  : Test playerService_ is valid and returns true
 */
HWTEST_F(PlayerImplUnitTest, RestoreLoopIfNeeded_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    bool wasInListMode = true;
    bool loop = true;
    playerImpl_->RestoreLoopIfNeeded(wasInListMode, loop);
    EXPECT_EQ(playerImpl_->userLoop_, true);
    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SelectNextIndex
 * @tc.number: SelectNextIndex_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_STATE
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t nextIndex = 0;
    bool isNext = true;
    auto ret = playerImpl_->SelectNextIndex(isNext, nextIndex);
    EXPECT_EQ(ret, MSERR_INVALID_STATE);
}

/**
 * @tc.name  : SelectNextIndex
 * @tc.number: SelectNextIndex_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    int32_t nextIndex = 0;
    bool isNext = true;
    ret = playerImpl_->SelectNextIndex(isNext, nextIndex);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SelectNextIndex
 * @tc.number: SelectNextIndex_003
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_SHUFFLE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_SHUFFLE);

    int32_t nextIndex = 0;
    bool isNext = true;
    ret = playerImpl_->SelectNextIndex(isNext, nextIndex);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SelectNextIndex
 * @tc.number: SelectNextIndex_004
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_004, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    int32_t nextIndex = 0;
    bool isNext = true;
    ret = playerImpl_->SelectNextIndex(isNext, nextIndex);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SelectNextIndex
 * @tc.number: SelectNextIndex_005
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SelectNextIndex_005, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    int32_t nextIndex = 0;
    bool isNext = false;
    ret = playerImpl_->SelectNextIndex(isNext, nextIndex);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SwitchToIndex
 * @tc.number: SwitchToIndex_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_VAL
 */
HWTEST_F(PlayerImplUnitTest, SwitchToIndex_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = -1;
    auto ret = playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : SwitchToIndex
 * @tc.number: SwitchToIndex_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_VAL
 */
HWTEST_F(PlayerImplUnitTest, SwitchToIndex_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 1;
    auto ret = playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : SwitchToIndex
 * @tc.number: SwitchToIndex_003
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SwitchToIndex_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : SwitchSetMediaSource
 * @tc.number: SwitchSetMediaSource_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_VAL
 */
HWTEST_F(PlayerImplUnitTest, SwitchSetMediaSource_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = -1;
    auto ret = playerImpl_->SwitchSetMediaSource(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : SwitchSetMediaSource
 * @tc.number: SwitchSetMediaSource_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_INVALID_VAL
 */
HWTEST_F(PlayerImplUnitTest, SwitchSetMediaSource_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 1;
    auto ret = playerImpl_->SwitchSetMediaSource(pos);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : SwitchSetMediaSource
 * @tc.number: SwitchSetMediaSource_003
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, SwitchSetMediaSource_003, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    ret = playerImpl_->SwitchSetMediaSource(pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : NotifyPlaybackContentChange
 * @tc.number: NotifyPlaybackContentChange_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, NotifyPlaybackContentChange_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t prevIndex = 0;
    int32_t curIndex = 0;
    playerImpl_->NotifyPlaybackContentChange(prevIndex, curIndex);
}

/**
 * @tc.name  : CheckPlaybackContentChange
 * @tc.number: CheckPlaybackContentChange_001
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, CheckPlaybackContentChange_001, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    int32_t pos = 0;
    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(true);
    EXPECT_EQ(playerImpl_->userLoop_, true);

    playerImpl_->SetPlaylistLoopMode(PLAYLIST_LOOP_MODE_ONE);
    EXPECT_EQ(playerImpl_->GetPlaylistLoopMode(), PLAYLIST_LOOP_MODE_ONE);

    playerImpl_->SwitchToIndex(0);
    EXPECT_EQ(playerImpl_->currItemIdx_, 0);

    playerImpl_->CheckPlaybackContentChange();
    playerImpl_->ResetListParameters();
}

/**
 * @tc.name  : CheckPlaybackContentChange
 * @tc.number: CheckPlaybackContentChange_002
 * @tc.desc  : Test playerService_ is valid and returns MSERR_OK
 */
HWTEST_F(PlayerImplUnitTest, CheckPlaybackContentChange_002, TestSize.Level0)
{
    ASSERT_NE(playerImpl_, nullptr);
    auto mockService = std::make_shared<MockIPlayerService>();
    ASSERT_NE(mockService, nullptr);
    playerImpl_->playerService_ = mockService;

    std::map<std::string, std::string> headers = {{"aa", "aa"}};
    std::map<std::string, std::string> headers2 = {{"bb", "bb"}};

    auto mediaSource = std::make_shared<AVMediaSource>("aa", headers);
    auto mediaSource2 = std::make_shared<AVMediaSource>("bb", headers2);

    int32_t pos = 0;
    auto ret = playerImpl_->AddPlaybackMediaSource(mediaSource, pos);
    EXPECT_EQ(ret, MSERR_OK);
    pos = 1;
    ret = playerImpl_->AddPlaybackMediaSource(mediaSource2, pos);
    EXPECT_EQ(ret, MSERR_OK);

    playerImpl_->SetLooping(false);
    EXPECT_EQ(playerImpl_->userLoop_, false);

    playerImpl_->SwitchToIndex(pos);
    EXPECT_EQ(playerImpl_->pendingSwitchPrevIdx_, 0);
    EXPECT_EQ(playerImpl_->pendingSwitchCurIdx_, 1);

    playerImpl_->CheckPlaybackContentChange();
    playerImpl_->ResetListParameters();
}
} // namespace Media
} // namespace OHOS