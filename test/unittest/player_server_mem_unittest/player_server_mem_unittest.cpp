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

#include "player_server_mem_unittest.h"
#include "media_errors.h"
#include "hiplayer_impl.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
const static int32_t TEST_TIMES_ONE = 1;
const static int32_t TEST_FD = -1;
const static int64_t TEST_OFFSET = 0;
const static int64_t TEST_SIZE = 0;
const static int32_t TEST_PLAY_BACK_POSITION = 1;
const static int32_t TEST_PLAY_BACK_POSITION_DEF = 0;
const static uint32_t TEST_BIT_RATE = 1000;
constexpr int32_t CONTINUE_RESET_MAX_NUM = 5;

void PlayerServerMemUnitTest::SetUpTestCase(void)
{
}

void PlayerServerMemUnitTest::TearDownTestCase(void)
{
}

void PlayerServerMemUnitTest::SetUp(void)
{
    playerServerMem_ = std::make_shared<PlayerServerMem>();
}

void PlayerServerMemUnitTest::TearDown(void)
{
    playerServerMem_ = nullptr;
}

/**
 * @tc.name  : Test PlayerServerMem SetSourceInternal API
 * @tc.number: SetSourceInternal_001
 * @tc.desc  : Test SetSourceInternal recoverConfig_.sourceType == PlayerSourceType::SOURCE_TYPE_DATASRC
 */
HWTEST_F(PlayerServerMemUnitTest, SetSourceInternal_001, TestSize.Level1)
{
    playerServerMem_->recoverConfig_.sourceType = static_cast<int32_t>(PlayerSourceType::SOURCE_TYPE_DATASRC);
    int32_t ret = playerServerMem_->SetSourceInternal();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test PlayerServerMem SetSourceInternal API
 * @tc.number: SetSourceInternal_002
 * @tc.desc  : Test SetSourceInternal recoverConfig_.sourceType == PlayerSourceType::SOURCE_TYPE_FD
 */
HWTEST_F(PlayerServerMemUnitTest, SetSourceInternal_002, TestSize.Level1)
{
    playerServerMem_->recoverConfig_.sourceType = static_cast<int32_t>(PlayerSourceType::SOURCE_TYPE_FD);
    int32_t ret = playerServerMem_->SetSourceInternal();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test PlayerServerMem SetConfigInternal API
 * @tc.number: SetConfigInternal_001
 * @tc.desc  : Test SetConfigInternal recoverConfig_.bitRate != 0
 */
HWTEST_F(PlayerServerMemUnitTest, SetConfigInternal_001, TestSize.Level1)
{
    std::unique_ptr<MockIPlayerEngine> mockPlayerEngine = std::make_unique<MockIPlayerEngine>();
    EXPECT_CALL(*(mockPlayerEngine), SetVideoScaleType(_))
        .Times(TEST_TIMES_ONE)
        .WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*(mockPlayerEngine), SelectBitRate(_, _))
        .Times(TEST_TIMES_ONE)
        .WillOnce(Return(MSERR_OK));
    playerServerMem_->playerEngine_ = std::move(mockPlayerEngine);
    playerServerMem_->recoverConfig_.videoScaleType = static_cast<int32_t>(VideoScaleType::VIDEO_SCALE_TYPE_FIT);
    playerServerMem_->recoverConfig_.bitRate = TEST_BIT_RATE;
    playerServerMem_->SetConfigInternal();
}

/**
 * @tc.name  : Test PlayerServerMem SetSource API
 * @tc.number: SetSource_001
 * @tc.desc  : Test SetSource PlayerServer::SetSource(url) != MSERR_OK
 */
HWTEST_F(PlayerServerMemUnitTest, SetSource_001, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t ret = playerServerMem_->SetSource("");
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test PlayerServerMem SetSource API
 * @tc.number: SetSource_002
 * @tc.desc  : Test SetSource PlayerServer::SetSource(fd, offset, size) != MSERR_OK
 */
HWTEST_F(PlayerServerMemUnitTest, SetSource_002, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t fd = TEST_FD;
    int64_t offset = TEST_OFFSET;
    int64_t size = TEST_SIZE;
    playerServerMem_->SetSource(fd, offset, size);
    EXPECT_EQ(playerServerMem_->isLocalResource_, false);
}

/**
 * @tc.name  : Test PlayerServerMem GetPlaybackPosition API
 * @tc.number: GetPlaybackPosition_001
 * @tc.desc  : Test Release RecoverMemByUser() != MSERR_OK
 *             Test GetPlaybackPosition isLocalResource_ == false && isReleaseMemByManage_ == false
 */
HWTEST_F(PlayerServerMemUnitTest, GetPlaybackPosition_001, TestSize.Level1)
{
    // Test Release RecoverMemByUser() != MSERR_OK
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->Release();

    // Test GetPlaybackPosition isLocalResource_ == false && isReleaseMemByManage_ == false
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t playbackPosition = TEST_PLAY_BACK_POSITION;
    int32_t ret = playerServerMem_->GetPlaybackPosition(playbackPosition);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test PlayerServerMem GetPlaybackPosition API
 * @tc.number: GetPlaybackPosition_002
 * @tc.desc  : Test GetPlaybackPosition isLocalResource_ == false && isReleaseMemByManage_ == true
 */
HWTEST_F(PlayerServerMemUnitTest, GetPlaybackPosition_002, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = true;
    int32_t playbackPosition = TEST_PLAY_BACK_POSITION;
    int32_t ret = playerServerMem_->GetPlaybackPosition(playbackPosition);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test PlayerServerMem GetPlaybackPosition API
 * @tc.number: GetPlaybackPosition_003
 * @tc.desc  : Test GetPlaybackPosition isLocalResource_ == true && isReleaseMemByManage_ == false
 */
HWTEST_F(PlayerServerMemUnitTest, GetPlaybackPosition_003, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t playbackPosition = TEST_PLAY_BACK_POSITION;
    int32_t ret = playerServerMem_->GetPlaybackPosition(playbackPosition);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test PlayerServerMem GetPlaybackPosition API
 * @tc.number: GetPlaybackPosition_004
 * @tc.desc  : Test GetPlaybackPosition isLocalResource_ == true && isReleaseMemByManage_ == true
 */
HWTEST_F(PlayerServerMemUnitTest, GetPlaybackPosition_004, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    int32_t playbackPosition = TEST_PLAY_BACK_POSITION;
    int32_t ret = playerServerMem_->GetPlaybackPosition(playbackPosition);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(playbackPosition, TEST_PLAY_BACK_POSITION_DEF);
}

/**
 * @tc.name  : Test PlayerServerMem ResetFrontGroundForMemManage API
 * @tc.number: ResetFrontGroundForMemManage_001
 * @tc.desc  : Test ResetFrontGroundForMemManage lastSetToNow.count() <= APP_FRONT_GROUND_DESTROY_MEMERY_LAST_SET_TIME
 */
HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_001, TestSize.Level1)
{
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->continueReset = CONTINUE_RESET_MAX_NUM;
    playerServerMem_->lastestUserSetTime_ = std::chrono::steady_clock::now();
    playerServerMem_->isReleaseMemByManage_ = false;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

/**
 * @tc.name  : Test PlayerServerMem ResetFrontGroundForMemManage API
 * @tc.number: ResetFrontGroundForMemManage_002
 * @tc.desc  : Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = false
 *             Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = false
 *             Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = true
 *             Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = true
 */
HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_002, TestSize.Level1)
{
    // Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = false
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);

    // Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = false
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_PREPARED;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 1);

        // Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = true
    playerServerMem_->isAudioPlayer_ = true;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);

    // Test ResetFrontGroundForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = true
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_PREPARED;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

/**
 * @tc.name  : Test PlayerServerMem ResetBackGroundForMemManage API
 * @tc.number: ResetBackGroundForMemManage_001
 * @tc.desc  : Test ResetBackGroundForMemManage lastSetToNow.count() <= APP_BACK_GROUND_DESTROY_MEMERY_LAST_SET_TIME
 */
HWTEST_F(PlayerServerMemUnitTest, ResetBackGroundForMemManage_001, TestSize.Level1)
{
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->continueReset = CONTINUE_RESET_MAX_NUM;
    playerServerMem_->lastestUserSetTime_ = std::chrono::steady_clock::now();
    playerServerMem_->isReleaseMemByManage_ = false;
    playerServerMem_->ResetBackGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

/**
 * @tc.name  : Test PlayerServerMem ResetMemmgrForMemManage API
 * @tc.number: ResetMemmgrForMemManage_001
 * @tc.desc  : Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = false
 *             Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = false
 *             Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = true
 *             Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = true
 */
HWTEST_F(PlayerServerMemUnitTest, ResetMemmgrForMemManage_001, TestSize.Level1)
{
    // Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = false
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->ResetMemmgrForMemManage();

    // Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = false
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_PREPARED;
    playerServerMem_->ResetMemmgrForMemManage();

    // Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = false || isAudioPlayer_ = true
    playerServerMem_->isAudioPlayer_ = true;
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    playerServerMem_->ResetMemmgrForMemManage();

    // Test ResetMemmgrForMemManage PlayerServer::IsPrepared() = true || isAudioPlayer_ = true
    playerServerMem_->lastOpStatus_ = PlayerStates::PLAYER_PREPARED;
    playerServerMem_->ResetMemmgrForMemManage();

    EXPECT_EQ(playerServerMem_->isReleaseMemByManage_, false);
}
} // namespace Media
} // namespace OHOS