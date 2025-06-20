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

#include "player_server_task_mgr_unittest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

const static int32_t TEST_SPEED_MODE = 1;
const static int32_t INVALID_SPEED_MODE = -1;
const static int32_t TEST_SEEK_MODE = 1;
const static int32_t INVALID_SEEK_MODE = -1;
const static int32_t TEST_SEEK_TIME = 1;
const static int32_t INVALID_SEEK_TIME = -1;
const static std::string TASK_NAME = "PlayerServerTaskMgrUnitTest";

namespace OHOS {
namespace Media {
void PlayerServerTaskMgrUnitTest::SetUpTestCase(void)
{
}

void PlayerServerTaskMgrUnitTest::TearDownTestCase(void)
{
}

void PlayerServerTaskMgrUnitTest::SetUp(void)
{
    taskMgr_ = std::make_shared<PlayerServerTaskMgr>();
    task_ = std::make_shared<MockTaskHandler>();
    cancelTask_ = std::make_shared<MockTaskHandler>();
}

void PlayerServerTaskMgrUnitTest::TearDown(void)
{
    taskMgr_ = nullptr;
    task_ = nullptr;
    cancelTask_ = nullptr;
}

/**
 * @tc.name  : Test PlayerServerTaskMgr Init
 * @tc.number: Init_001
 * @tc.desc  : Test Init isInited_ = true
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, Init_001, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    int32_t ret = taskMgr_->Init();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr SpeedTask
 * @tc.number: SpeedTask_001
 * @tc.desc  : Test SpeedTask item.type == PlayerServerTaskType::RATE_CHANGE &&
 *             item.speedMode_ != speedMode
 *             Test SpeedTask item.type != PlayerServerTaskType::RATE_CHANGE &&
 *             item.speedMode_ != speedMode
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, SpeedTask_001, TestSize.Level1)
{
    std::string taskName = TASK_NAME;
    int32_t speedMode = TEST_SPEED_MODE;
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;

    // Test SpeedTask item.type == PlayerServerTaskType::RATE_CHANGE && item.speedMode_ != speedMode
    PlayerServerTaskMgr::TwoPhaseTaskItem item1 {
        .type = PlayerServerTaskType::RATE_CHANGE,
        .speedMode_ = INVALID_SPEED_MODE,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item1);
    int32_t ret = taskMgr_->SpeedTask(task_, cancelTask_, taskName, speedMode);
    EXPECT_EQ(ret, MSERR_OK);

    // Test SpeedTask item.type != PlayerServerTaskType::RATE_CHANGE && item.speedMode_ != speedMode
    taskMgr_->pendingTwoPhaseTasks_.clear();
    PlayerServerTaskMgr::TwoPhaseTaskItem item2 {
        .type = PlayerServerTaskType::STATE_CHANGE,
        .speedMode_ = INVALID_SPEED_MODE,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item2);
    ret = taskMgr_->SpeedTask(task_, cancelTask_, taskName, speedMode);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr SpeedTask
 * @tc.number: SpeedTask_002
 * @tc.desc  : Test SpeedTask item.type == PlayerServerTaskType::RATE_CHANGE &&
 *             item.speedMode_ == speedMode
 *             Test SpeedTask item.type != PlayerServerTaskType::RATE_CHANGE &&
 *             item.speedMode_ == speedMode
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, SpeedTask_002, TestSize.Level1)
{
    std::string taskName = TASK_NAME;
    int32_t speedMode = TEST_SPEED_MODE;
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;

    // Test SpeedTask item.type == PlayerServerTaskType::RATE_CHANGE && item.speedMode_ == speedMode
    PlayerServerTaskMgr::TwoPhaseTaskItem item1 {
        .type = PlayerServerTaskType::RATE_CHANGE,
        .speedMode_ = speedMode,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item1);
    int32_t ret = taskMgr_->SpeedTask(task_, cancelTask_, taskName, speedMode);
    EXPECT_EQ(ret, MSERR_OK);

    // Test SpeedTask item.type != PlayerServerTaskType::RATE_CHANGE && item.speedMode_ == speedMode
    taskMgr_->pendingTwoPhaseTasks_.clear();
    PlayerServerTaskMgr::TwoPhaseTaskItem item2 {
        .type = PlayerServerTaskType::STATE_CHANGE,
        .speedMode_ = speedMode,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item2);
    ret = taskMgr_->SpeedTask(task_, cancelTask_, taskName, speedMode);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr SeekTask
 * @tc.number: SeekTask_001
 * @tc.desc  : Test SeekTask item.type == PlayerServerTaskType::SEEKING
 *             Test SeekTask item.type != PlayerServerTaskType::SEEKING
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, SeekTask_001, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;

    // Test SeekTask item.type == PlayerServerTaskType::SEEKING
    PlayerServerTaskMgr::TwoPhaseTaskItem item1 {
        .type = PlayerServerTaskType::SEEKING,
    };
    // Test SeekTask item.type != PlayerServerTaskType::SEEKING
    PlayerServerTaskMgr::TwoPhaseTaskItem item2 {
        .type = PlayerServerTaskType::STATE_CHANGE,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item1);
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item2);
    int32_t ret = taskMgr_->SeekTask(task_, cancelTask_, TASK_NAME, TEST_SEEK_MODE, TEST_SEEK_TIME);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr SeekTask
 * @tc.number: SeekTask_002
 * @tc.desc  : Test SeekTask currentSeekMode_ == seekMode && currentSeekTime_ == seekTime
 *             Test SeekTask currentSeekMode_ != seekMode && currentSeekTime_ == seekTime
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, SeekTask_002, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;

    // Test SeekTask currentSeekMode_ == seekMode && currentSeekTime_ == seekTime
    int32_t seekMode = INVALID_SEEK_MODE;
    int32_t seekTime = INVALID_SEEK_TIME;
    int32_t ret = taskMgr_->SeekTask(task_, cancelTask_, TASK_NAME, seekMode, seekTime);
    EXPECT_EQ(ret, MSERR_OK);

    // Test SeekTask currentSeekMode_ == seekMode && currentSeekTime_ == seekTime
    seekMode = TEST_SEEK_MODE;
    ret = taskMgr_->SeekTask(task_, cancelTask_, TASK_NAME, seekMode, seekTime);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr SeekTask
 * @tc.number: SeekTask_003
 * @tc.desc  : Test SeekTask currentSeekMode_ == seekMode && currentSeekTime_ != seekTime
 *             Test SeekTask currentSeekMode_ != seekMode && currentSeekTime_ != seekTime
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, SeekTask_003, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;

    // Test SeekTask currentSeekMode_ == seekMode && currentSeekTime_ != seekTime
    int32_t seekMode = INVALID_SEEK_MODE;
    int32_t seekTime = TEST_SEEK_TIME;
    int32_t ret = taskMgr_->SeekTask(task_, cancelTask_, TASK_NAME, seekMode, seekTime);
    EXPECT_EQ(ret, MSERR_OK);

    // Test SeekTask currentSeekMode_ != seekMode && currentSeekTime_ != seekTime
    seekMode = TEST_SEEK_MODE;
    ret = taskMgr_->SeekTask(task_, cancelTask_, TASK_NAME, seekMode, seekTime);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr FreezeTask
 * @tc.number: FreezeTask_001
 * @tc.desc  : Test FreezeTask currTwoPhaseTask_ != nullptr
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, FreezeTask_001, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;
    taskMgr_->FreezeTask(task_, cancelTask_, TASK_NAME);
    EXPECT_EQ(taskMgr_->pendingTwoPhaseTasks_.front().type, PlayerServerTaskType::FREEZE_TASK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr UnFreezeTask
 * @tc.number: UnFreezeTask_001
 * @tc.desc  : Test UnFreezeTask currTwoPhaseTask_ != nullptr
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, UnFreezeTask_001, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;
    taskMgr_->UnFreezeTask(task_, cancelTask_, TASK_NAME);
    EXPECT_EQ(taskMgr_->pendingTwoPhaseTasks_.front().type, PlayerServerTaskType::UNFREEZE_TASK);
}

/**
 * @tc.name  : Test PlayerServerTaskMgr MarkTaskDone
 * @tc.number: MarkTaskDone_001
 * @tc.desc  : Test MarkTaskDone item.type == PlayerServerTaskType::CANCEL_TASK
 */
HWTEST_F(PlayerServerTaskMgrUnitTest, MarkTaskDone_001, TestSize.Level1)
{
    taskMgr_->isInited_ = true;
    taskMgr_->currTwoPhaseTask_ = task_;
    PlayerServerTaskMgr::TwoPhaseTaskItem item {
        .type = PlayerServerTaskType::CANCEL_TASK,
        .task = task_,
        .cancelTask = nullptr,
    };
    taskMgr_->pendingTwoPhaseTasks_.emplace_back(item);
    taskMgr_->MarkTaskDone(TASK_NAME);
    EXPECT_EQ(taskMgr_->currTwoPhaseTask_, nullptr);
}
} // namespace Media
} // namespace OHOS
