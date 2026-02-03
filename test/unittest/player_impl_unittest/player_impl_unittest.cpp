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
} // namespace Media
} // namespace OHOS