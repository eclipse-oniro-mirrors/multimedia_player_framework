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

#include "player_server_unittest.h"
#include "player_server_state.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
namespace {
class StatePlaybackRateEngineMock : public PlayerEngineMock {
public:
    int32_t SetPlaybackSpeed(PlaybackRateMode mode) override
    {
        ++speedCalls_;
        speedMode_ = mode;
        return result_;
    }

    int32_t SetPlaybackRate(float rate) override
    {
        ++rateCalls_;
        speedRate_ = rate;
        return result_;
    }

    int32_t result_ = MSERR_OK;
    int32_t speedCalls_ = 0;
    int32_t rateCalls_ = 0;
    PlaybackRateMode speedMode_ = SPEED_FORWARD_1_00_X;
    float speedRate_ = 1.0f;
};
}

/**
 * @tc.name  : IdleRejectsPlaybackOperations
 * @tc.number: PlayerState_IdleRejectsPlaybackOperations_001
 * @tc.desc  : Illegal operations return INVALID_STATE and preserve the idle state.
 */
HWTEST_F(PlayerServerUnitTest, IdleRejectsPlaybackOperations, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    std::shared_ptr<PlayerServer::BaseState> state = server->idleState_;
    ASSERT_NE(state, nullptr);
    EXPECT_EQ(state->Prepare(), MSERR_INVALID_STATE);
    EXPECT_EQ(state->Play(), MSERR_INVALID_STATE);
    EXPECT_EQ(state->Pause(false), MSERR_INVALID_STATE);
    EXPECT_EQ(state->Stop(), MSERR_INVALID_STATE);
    EXPECT_EQ(state->Seek(1000, SEEK_CLOSEST), MSERR_INVALID_STATE);
    EXPECT_EQ(state->SeekContinous(1000, 1), MSERR_INVALID_STATE);
    EXPECT_EQ(state->SetPlaybackSpeed(SPEED_FORWARD_2_00_X), MSERR_INVALID_STATE);
    EXPECT_EQ(state->SetPlaybackRate(2.0f), MSERR_INVALID_STATE);
    EXPECT_EQ(state->SetPlayRangeWithMode(0, 1000, SEEK_CLOSEST), MSERR_INVALID_STATE);
    EXPECT_EQ(state->PauseDemuxer(), MSERR_INVALID_STATE);
    EXPECT_EQ(state->ResumeDemuxer(), MSERR_INVALID_STATE);
    EXPECT_EQ(server->currState_, server->idleState_);
}

/**
 * @tc.name  : SeekDoneSuppressionIsOneShot
 * @tc.number: PlayerState_SeekDoneSuppressionIsOneShot_001
 * @tc.desc  : Consume suppression once, including when a nonzero seek result is delivered.
 */
HWTEST_F(PlayerServerUnitTest, SeekDoneSuppressionIsOneShot, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    std::shared_ptr<PlayerServerState> state = server->preparedState_;
    ASSERT_NE(state, nullptr);
    Format body;
    server->disableNextSeekDone_ = true;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_SEEKDONE, 0, body), MSERR_UNSUPPORT);
    EXPECT_FALSE(server->disableNextSeekDone_);
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_SEEKDONE, 0, body), MSERR_OK);
    server->disableNextSeekDone_ = true;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_SEEKDONE, 1000, body), MSERR_OK);
    EXPECT_FALSE(server->disableNextSeekDone_);
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_SEEKDONE, 0, body), MSERR_OK);
}

/**
 * @tc.name  : StoppedCallbackSuppressionIsOneShot
 * @tc.number: PlayerState_StoppedCallbackSuppressionIsOneShot_001
 * @tc.desc  : Ignore unrelated state messages and suppress only the first stopped callback.
 */
HWTEST_F(PlayerServerUnitTest, StoppedCallbackSuppressionIsOneShot, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    server->ChangeState(server->stoppedState_);
    std::shared_ptr<PlayerServerState> state = server->stoppedState_;
    Format body;
    server->disableStoppedCb_ = true;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, body), MSERR_OK);
    EXPECT_TRUE(server->disableStoppedCb_);
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STOPPED, body), MSERR_UNSUPPORT);
    EXPECT_FALSE(server->disableStoppedCb_);
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STOPPED, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->stoppedState_);
}

/**
 * @tc.name  : PreparingAcceptsOnlyPreparationResult
 * @tc.number: PlayerState_PreparingAcceptsOnlyPreparationResult_001
 * @tc.desc  : Ignore unrelated notifications and transition to prepared on successful preparation.
 */
HWTEST_F(PlayerServerUnitTest, PreparingAcceptsOnlyPreparationResult, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    server->playerEngine_ = std::make_unique<PlayerEngineMock>();
    server->ChangeState(server->preparingState_);
    std::shared_ptr<PlayerServerState> state = server->preparingState_;
    Format body;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_PAUSED, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->preparingState_);
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_PREPARED, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->preparedState_);
}

/**
 * @tc.name  : PreparingErrorReturnsToInitialized
 * @tc.number: PlayerState_PreparingErrorReturnsToInitialized_001
 * @tc.desc  : Preparation failure records error status and permits initialization recovery.
 */
HWTEST_F(PlayerServerUnitTest, PreparingErrorReturnsToInitialized, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    server->playerEngine_ = std::make_unique<PlayerEngineMock>();
    server->ChangeState(server->preparingState_);
    server->lastOpStatus_ = PLAYER_PREPARING;
    std::shared_ptr<PlayerServerState> state = server->preparingState_;
    Format body;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->initializedState_);
    EXPECT_EQ(server->lastOpStatus_, PLAYER_STATE_ERROR);
    server->lastOpStatus_ = PLAYER_IDLE;
}

/**
 * @tc.name  : PreparedErrorReturnsToInitialized
 * @tc.number: PlayerState_PreparedErrorReturnsToInitialized_001
 * @tc.desc  : An engine failure after preparation restores initialized state and records the failure.
 */
HWTEST_F(PlayerServerUnitTest, PreparedErrorReturnsToInitialized, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    server->ChangeState(server->preparedState_);
    server->lastOpStatus_ = PLAYER_PREPARED;
    std::shared_ptr<PlayerServerState> state = server->preparedState_;
    Format body;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->initializedState_);
    EXPECT_EQ(server->lastOpStatus_, PLAYER_STATE_ERROR);
    server->lastOpStatus_ = PLAYER_IDLE;
}

/**
 * @tc.name  : PlaybackCompleteThenStop
 * @tc.number: PlayerState_PlaybackCompleteThenStop_001
 * @tc.desc  : Completion enters completed state; stopping then updates both state and operation status.
 */
HWTEST_F(PlayerServerUnitTest, PlaybackCompleteThenStop, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    server->isBootCompleted_.store(false);
    server->ChangeState(server->playingState_);
    std::shared_ptr<PlayerServerState> state = server->playingState_;
    Format body;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_PLAYBACK_COMPLETE, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->playbackCompletedState_);
    EXPECT_EQ(server->lastOpStatus_, PLAYER_PLAYBACK_COMPLETE);
    state = server->playbackCompletedState_;
    EXPECT_EQ(state->OnMessageReceived(INFO_TYPE_STATE_CHANGE, PLAYER_STOPPED, body), MSERR_OK);
    EXPECT_EQ(server->currState_, server->stoppedState_);
    EXPECT_EQ(server->lastOpStatus_, PLAYER_STOPPED);
    server->lastOpStatus_ = PLAYER_IDLE;
}
/**
 * @tc.name  : PlaybackRateDelegationFailure
 * @tc.number: PlayerState_PlaybackRateDelegationFailure_001
 * @tc.desc  : Every supported state forwards rate arguments and preserves config when the engine fails.
 */
HWTEST_F(PlayerServerUnitTest, PlaybackRateDelegationFailure, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    auto engine = std::make_unique<StatePlaybackRateEngineMock>();
    auto enginePtr = engine.get();
    enginePtr->result_ = MSERR_UNKNOWN;
    server->playerEngine_ = std::move(engine);
    server->isBootCompleted_.store(false);
    const std::vector<std::shared_ptr<PlayerServer::BaseState>> states = {
        server->preparedState_, server->playingState_, server->pausedState_, server->playbackCompletedState_};
    int32_t expectedCalls = 0;
    for (const auto& state : states) {
        SCOPED_TRACE(expectedCalls);
        server->ChangeState(state);
        EXPECT_EQ(state->SetPlaybackSpeed(SPEED_FORWARD_2_00_X), MSERR_INVALID_OPERATION);
        EXPECT_EQ(state->SetPlaybackRate(1.5f), MSERR_INVALID_OPERATION);
        ++expectedCalls;
        EXPECT_EQ(enginePtr->speedCalls_, expectedCalls);
        EXPECT_EQ(enginePtr->rateCalls_, expectedCalls);
        EXPECT_EQ(enginePtr->speedMode_, SPEED_FORWARD_2_00_X);
        EXPECT_FLOAT_EQ(enginePtr->speedRate_, 1.5f);
        EXPECT_EQ(server->config_.speedMode, SPEED_FORWARD_1_00_X);
        EXPECT_FLOAT_EQ(server->config_.speedRate, 1.0f);
        EXPECT_EQ(server->currState_, state);
    }
}

/**
 * @tc.name  : PlaybackRateDelegationSuccess
 * @tc.number: PlayerState_PlaybackRateDelegationSuccess_001
 * @tc.desc  : Each supported state applies the engine-approved speed and rate to playback config.
 */
HWTEST_F(PlayerServerUnitTest, PlaybackRateDelegationSuccess, TestSize.Level0)
{
    auto server = std::static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(server, nullptr);
    auto engine = std::make_unique<StatePlaybackRateEngineMock>();
    auto enginePtr = engine.get();
    server->playerEngine_ = std::move(engine);
    server->isBootCompleted_.store(false);
    const std::vector<std::shared_ptr<PlayerServer::BaseState>> states = {
        server->preparedState_, server->playingState_, server->pausedState_, server->playbackCompletedState_};
    int32_t expectedCalls = 0;
    for (const auto& state : states) {
        SCOPED_TRACE(expectedCalls);
        server->ChangeState(state);
        server->config_.speedMode = SPEED_FORWARD_1_00_X;
        server->config_.speedRate = 1.0f;
        EXPECT_EQ(state->SetPlaybackSpeed(SPEED_FORWARD_2_00_X), MSERR_OK);
        EXPECT_EQ(state->SetPlaybackRate(1.5f), MSERR_OK);
        ++expectedCalls;
        EXPECT_EQ(enginePtr->speedCalls_, expectedCalls);
        EXPECT_EQ(enginePtr->rateCalls_, expectedCalls);
        EXPECT_EQ(server->config_.speedMode, SPEED_FORWARD_2_00_X);
        EXPECT_FLOAT_EQ(server->config_.speedRate, 1.5f);
        EXPECT_EQ(server->currState_, state);
    }
    // Restore defaults so releasing the fixture does not schedule a rate task.
    server->config_.speedMode = SPEED_FORWARD_1_00_X;
    server->config_.speedRate = 1.0f;
}
} // namespace Media
} // namespace OHOS
