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
}
}
}