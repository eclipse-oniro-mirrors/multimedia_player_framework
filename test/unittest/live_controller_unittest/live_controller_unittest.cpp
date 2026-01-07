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

#include "media_errors.h"
#include "live_controller_unittest.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/autolock.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LiveControllerUnittest::SetUpTestCase(void)
{
}

void LiveControllerUnittest::TearDownTestCase(void)
{
}

void LiveControllerUnittest::SetUp(void)
{
    liveController_ = std::make_unique<LiveController>();
}

void LiveControllerUnittest::TearDown(void)
{
    liveController_ = nullptr;
}

/**
* @tc.name    : Enqueue
* @tc.number  : LCUEnqueue_001
* @tc.desc    : Test Enqueue interface 1.
*/
HWTEST_F(LiveControllerUnittest, LCUEnqueue_001, TestSize.Level0)
{
    ASSERT_NE(liveController_, nullptr);
    std::shared_ptr<LiveController::Event> event = std::make_shared<LiveController::Event>(0, 0, Any());
    event->what = 0;
    auto mockTask = std::make_unique<MockTask>("testName");
    EXPECT_CALL(*mockTask, SubmitJob(_, _, _)).WillRepeatedly(Return());
    liveController_->task_ = std::move(mockTask);
    liveController_->Enqueue(event);
    EXPECT_EQ(event->whenMs, 0);
}

/**
* @tc.name    : LoopOnce
* @tc.number  : LCULoopOnce_001
* @tc.desc    : Test LoopOnce interface 1.
*/
HWTEST_F(LiveControllerUnittest, LCULoopOnce_001, TestSize.Level0)
{
    ASSERT_NE(liveController_, nullptr);
    std::shared_ptr<LiveController::Event> event = std::make_shared<LiveController::Event>(0, 0, Any());
    event->what = 0;
    liveController_->LoopOnce(event);
    EXPECT_EQ(event->what, 0);
    EXPECT_EQ(event->whenMs, 0);
}

/**
* @tc.name    : DoCheckLiveDelayTime
* @tc.number  : LCUDoCheckLiveDelayTime_001
* @tc.desc    : Test DoCheckLiveDelayTime interface 1.
*/
HWTEST_F(LiveControllerUnittest, LCUDoCheckLiveDelayTime_001, TestSize.Level0)
{
    ASSERT_NE(liveController_, nullptr);
    liveController_->isCheckLiveDelayTimeSet_ = false;
    liveController_->DoCheckLiveDelayTime();
    EXPECT_NE(liveController_->isCheckLiveDelayTimeSet_, true);
}

/**
* @tc.name    : OnError&&OnInfo&&OnSystemOperation
* @tc.number  : LCUOtherFunction_001
* @tc.desc    : Test DoCheckLiveDelayTime interface 3.
*/
HWTEST_F(LiveControllerUnittest, LCUOtherFunction_001, TestSize.Level0)
{
    ASSERT_NE(liveController_, nullptr);
    PlayerErrorType errorType = PlayerErrorType::PLAYER_ERROR;
    int32_t errorCode = 0;
    liveController_->OnError(errorType, errorCode, "");
    PlayerOnInfoType typeInfo = PlayerOnInfoType::INFO_TYPE_ERROR_MSG;
    int32_t extra = 0;
    Format infoBody;
    liveController_->OnInfo(typeInfo, extra, infoBody);
    PlayerOnSystemOperationType typeSystem = PlayerOnSystemOperationType::OPERATION_TYPE_PLAY;
    PlayerOperationReason reason = PlayerOperationReason::OPERATION_REASON_AUDIO_INTERRUPT;
    liveController_->OnSystemOperation(typeSystem, reason);
    EXPECT_EQ(liveController_->isCheckLiveDelayTimeSet_, false);
    EXPECT_EQ(liveController_->task_, nullptr);
}
} // Media
} // OHOS
