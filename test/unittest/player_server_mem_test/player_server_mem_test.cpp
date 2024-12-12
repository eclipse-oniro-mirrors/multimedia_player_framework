/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "player_server_mem_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void PlayerServerMemTest::SetUpTestCase(void)
{
}

void PlayerServerMemTest::TearDownTestCase(void)
{
}

void PlayerServerMemTest::SetUp(void)
{
    playerServerMem_ = std::make_shared<PlayerServerMem>();
}

void PlayerServerMemTest::TearDown(void)
{
    playerServerMem_ = nullptr;
}

/**
 * @tc.name  : SetPlayerServerConfig
 * @tc.number: SetPlayerServerConfig
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, SetPlayerServerConfig, TestSize.Level1)
{
    playerServerMem_->playerServerConfig_.errorCbOnce = true;
    playerServerMem_->SetPlayerServerConfig();
    EXPECT_EQ(playerServerMem_->errorCbOnce_, true);
}

/**
 * @tc.name  : GetPlayerServerConfig
 * @tc.number: GetPlayerServerConfig
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, GetPlayerServerConfig, TestSize.Level1)
{
    playerServerMem_->errorCbOnce_ = true;
    playerServerMem_->GetPlayerServerConfig();
    EXPECT_EQ(playerServerMem_->playerServerConfig_.errorCbOnce, true);
}

/**
 * @tc.name  : GetVideoHeight
 * @tc.number: GetVideoHeight
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, GetVideoHeight, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = true;
    int32_t height = playerServerMem_->GetVideoHeight();
    EXPECT_EQ(height, MSERR_NO_MEMORY);

    playerServerMem_->isReleaseMemByManage_ = true;
    height = playerServerMem_->GetVideoHeight();
    EXPECT_EQ(height, 0);
}

/**
 * @tc.name  : GetDuration
 * @tc.number: GetDuration
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, GetDuration, TestSize.Level1)
{
    playerServerMem_->isLocalResource_ = true;
    int32_t duration = 0;
    int32_t ret = playerServerMem_->GetDuration(duration);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);

    playerServerMem_->isReleaseMemByManage_ = true;
    ret = playerServerMem_->GetDuration(duration);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : GetPlaybackSpeed
 * @tc.number: GetPlaybackSpeed
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, GetPlaybackSpeed, TestSize.Level1)
{
    PlaybackRateMode speedMode = SPEED_FORWARD_1_00_X;
    int32_t ret = playerServerMem_->GetPlaybackSpeed(speedMode);
    EXPECT_EQ(ret, 0);

    playerServerMem_->isLocalResource_ = true;
    ret = playerServerMem_->GetPlaybackSpeed(speedMode);
    EXPECT_EQ(ret, 0);

    playerServerMem_->isReleaseMemByManage_ = true;
    ret = playerServerMem_->GetPlaybackSpeed(speedMode);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : IsPlaying
 * @tc.number: IsPlaying
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, IsPlaying, TestSize.Level1)
{
    int32_t isPlaying = playerServerMem_->IsPlaying();
    EXPECT_EQ(isPlaying, false);
}

/**
 * @tc.name  : IsLooping
 * @tc.number: IsLooping
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, IsLooping, TestSize.Level1)
{
    int32_t IsLooping = playerServerMem_->IsLooping();
    EXPECT_EQ(IsLooping, false);
}

/**
 * @tc.name  : SaveParameter
 * @tc.number: SaveParameter
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, SaveParameter, TestSize.Level1)
{
    Format param;
    param.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, 0);
    param.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, 0);
    playerServerMem_->SaveParameter(param);
    EXPECT_EQ(playerServerMem_->recoverConfig_.videoScaleType, 0);
    EXPECT_EQ(playerServerMem_->recoverConfig_.interruptMode, 0);
    param.PutIntValue(PlayerKeys::CONTENT_TYPE, 0);
    playerServerMem_->SaveParameter(param);
    EXPECT_EQ(playerServerMem_->recoverConfig_.contentType, -1);
}

/**
 * @tc.name  : GetCurrentTrack
 * @tc.number: GetCurrentTrack
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, GetCurrentTrack, TestSize.Level1)
{
    int32_t trackType = Media::MediaType::MEDIA_TYPE_AUD;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    EXPECT_NE(result, MSERR_OK);
}

/**
 * @tc.name  : DumpInfo
 * @tc.number: DumpInfo
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, DumpInfo, TestSize.Level1)
{
    EXPECT_EQ(playerServerMem_->DumpInfo(-1), MSERR_OK);
    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_EQ(playerServerMem_->DumpInfo(-1), MSERR_OK);
}

/**
 * @tc.name  : HandleCodecBuffers
 * @tc.number: HandleCodecBuffers
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, HandleCodecBuffers, TestSize.Level1)
{
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);
    bool enable = true;
    EXPECT_EQ(playerServerMem_->HandleCodecBuffers(enable), MSERR_INVALID_OPERATION);
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    EXPECT_EQ(playerServerMem_->HandleCodecBuffers(enable), 0);
}

/**
 * @tc.name  : SeekToCurrentTime
 * @tc.number: SeekToCurrentTime
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, SeekToCurrentTime, TestSize.Level1)
{
    PlayerSeekMode mode = SEEK_PREVIOUS_SYNC;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);
    EXPECT_EQ(playerServerMem_->SeekToCurrentTime(0, mode), MSERR_INVALID_OPERATION);
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    playerServerMem_->isLiveStream_ = true;
    EXPECT_EQ(playerServerMem_->SeekToCurrentTime(0, mode), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : OnInfo
 * @tc.number: OnInfo
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, OnInfo, TestSize.Level1)
{
    playerServerMem_->isSeekToCurrentTime_ = true;
    PlayerOnInfoType type = INFO_TYPE_TRACK_NUM_UPDATE;
    Format infoBody;
    int32_t extra = 1;
    playerServerMem_->OnInfo(type, extra, infoBody);
    EXPECT_EQ(playerServerMem_->subtitleTrackNum_, extra);

    type = INFO_TYPE_SEEKDONE;
    playerServerMem_->OnInfo(type, extra, infoBody);
    EXPECT_EQ(playerServerMem_->isSeekToCurrentTime_, false);
}

/**
 * @tc.name  : ReleaseMemByManage
 * @tc.number: ReleaseMemByManage
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, ReleaseMemByManage, TestSize.Level1)
{
    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_EQ(playerServerMem_->ReleaseMemByManage(), MSERR_OK);

    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;
    EXPECT_EQ(playerServerMem_->ReleaseMemByManage(), MSERR_INVALID_OPERATION);

    playerServerMem_->isRecoverMemByUser_ = true;
    EXPECT_EQ(playerServerMem_->ReleaseMemByManage(), MSERR_OK);

    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_EQ(playerServerMem_->ReleaseMemByManage(), MSERR_OK);
}

/**
 * @tc.name  : RecoverMemByUser
 * @tc.number: RecoverMemByUser
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServerMemTest, RecoverMemByUser, TestSize.Level1)
{
    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_NE(playerServerMem_->RecoverMemByUser(), MSERR_OK);

    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;
    playerServerMem_->isRecoverMemByUser_ = true;
    EXPECT_EQ(playerServerMem_->RecoverMemByUser(), MSERR_OK);

    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_EQ(playerServerMem_->RecoverMemByUser(), MSERR_OK);

    playerServerMem_->isRecoverMemByUser_ = false;
    playerServerMem_->Init();
    EXPECT_EQ(playerServerMem_->RecoverMemByUser(), MSERR_INVALID_STATE);
}
}
}