/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "gtest/gtest.h"
#include "media_unils_unit_test.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void MediaUtilsUnitTest::SetUpTestCase(void) {}

void MediaUtilsUnitTest::TearDownTestCase(void) {}

void MediaUtilsUnitTest::SetUp(void) {}

void MediaUtilsUnitTest::TearDown(void) {}

HWTEST_F(MediaUtilsUnitTest, TransStatus_001, TestSize.Level0) {
    EXPECT_EQ(TransStatus(Status::ERROR_INVALID_BUFFER_ID), MSERR_UNKNOWN);
}

// Scenario1: Test for PlayerStateId::IDLE
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerIdle_WhenStateIsIdle, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::IDLE;
    PlayerStates expectedState = PLAYER_IDLE;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario2: Test for PlayerStateId::INIT
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerInitialized_WhenStateIsInit, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::INIT;
    PlayerStates expectedState = PLAYER_INITIALIZED;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario3: Test for PlayerStateId::PREPARING
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerPreparing_WhenStateIsPreparing, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::PREPARING;
    PlayerStates expectedState = PLAYER_PREPARING;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario4: Test for PlayerStateId::READY
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerPrepared_WhenStateIsReady, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::READY;
    PlayerStates expectedState = PLAYER_PREPARED;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario5: Test for PlayerStateId::PAUSE
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerPaused_WhenStateIsPause, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::PAUSE;
    PlayerStates expectedState = PLAYER_PAUSED;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario6: Test for PlayerStateId::PLAYING
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerStarted_WhenStateIsPlaying, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::PLAYING;
    PlayerStates expectedState = PLAYER_STARTED;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario7: Test for PlayerStateId::STOPPED
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerStopped_WhenStateIsStopped, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::STOPPED;
    PlayerStates expectedState = PLAYER_STOPPED;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario8: Test for PlayerStateId::EOS
HWTEST_F(MediaUtilsUnitTest,
    TransStateId2PlayerState_ShouldReturnPlayerPlaybackComplete_WhenStateIsEOS, TestSize.Level0)
{
    PlayerStateId state = PlayerStateId::EOS;
    PlayerStates expectedState = PLAYER_PLAYBACK_COMPLETE;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario9: Test for default case
HWTEST_F(MediaUtilsUnitTest, TransStateId2PlayerState_ShouldReturnPlayerError_WhenStateIsInvalid, TestSize.Level0)
{
    PlayerStateId state = static_cast<PlayerStateId>(100); // Assuming 100 is an invalid state
    PlayerStates expectedState = PLAYER_STATE_ERROR;
    EXPECT_EQ(expectedState, TransStateId2PlayerState(state));
}

// Scenario1: Test case for PlayerSeekMode::SEEK_NEXT_SYNC
HWTEST_F(MediaUtilsUnitTest, ShouldReturnSeekNextSync_WhenSeekModeIsNextSync, TestSize.Level0) {
    EXPECT_EQ(Plugins::SeekMode::SEEK_NEXT_SYNC, Transform2SeekMode(PlayerSeekMode::SEEK_NEXT_SYNC));
}

// Scenario2: Test case for PlayerSeekMode::SEEK_PREVIOUS_SYNC
HWTEST_F(MediaUtilsUnitTest, ShouldReturnSeekPreviousSync_WhenSeekModeIsPreviousSync, TestSize.Level0) {
    EXPECT_EQ(Plugins::SeekMode::SEEK_PREVIOUS_SYNC, Transform2SeekMode(PlayerSeekMode::SEEK_PREVIOUS_SYNC));
}

// Scenario3: Test case for PlayerSeekMode::SEEK_CLOSEST_SYNC
HWTEST_F(MediaUtilsUnitTest, ShouldReturnSeekClosestSync_WhenSeekModeIsClosestSync, TestSize.Level0) {
    EXPECT_EQ(Plugins::SeekMode::SEEK_CLOSEST_SYNC, Transform2SeekMode(PlayerSeekMode::SEEK_CLOSEST_SYNC));
}

// Scenario4: Test case for PlayerSeekMode::SEEK_CLOSEST
HWTEST_F(MediaUtilsUnitTest, ShouldReturnSeekClosest_WhenSeekModeIsClosest, TestSize.Level0) {
    EXPECT_EQ(Plugins::SeekMode::SEEK_CLOSEST, Transform2SeekMode(PlayerSeekMode::SEEK_CLOSEST));
}

// Scenario5: Test case for default case
HWTEST_F(MediaUtilsUnitTest, ShouldReturnSeekClosest_WhenSeekModeIsDefault, TestSize.Level0) {
    EXPECT_EQ(Plugins::SeekMode::SEEK_CLOSEST, Transform2SeekMode(static_cast<PlayerSeekMode>(-1)));
}
} // namespace Media
} // namespace OHOS