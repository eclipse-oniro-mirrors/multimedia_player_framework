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
#include "live_controller_unit_test.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/autolock.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
namespace {
constexpr int32_t WHAT_LIVE_DELAY_TIME = 1;
constexpr int32_t UPDATE_INTERVAL_MS = 200;
}

void LiveControllerUnitTest::SetUpTestCase(void)
{
}

void LiveControllerUnitTest::TearDownTestCase(void)
{
}

void LiveControllerUnitTest::SetUp(void)
{
    liveController_ = std::make_unique<LiveController>();
    testObs_ = std::make_shared<MockIPlayerEngineObs>();
    liveController_->task_ = std::make_unique<Task>("checkliveDelayThread");
}

void LiveControllerUnitTest::TearDown(void)
{
    if (testObs_) {
        testObs_ = nullptr;
    }
    liveController_ = nullptr;
}

/**
* @tc.name    : Test flv smart play
* @tc.number  : StartWithPlayerEngineObs_001
* @tc.desc    : Test create flv live scheduled check task
* @tc.require :
*/
HWTEST_F(LiveControllerUnitTest, StartWithPlayerEngineObs_001, TestSize.Level0)
{
    liveController_->taskStarted_ = false;
    liveController_->StartWithPlayerEngineObs(testObs_);
    EXPECT_TRUE(liveController_->taskStarted_);
}

/**
* @tc.name    : Test flv smart play
* @tc.number  : StartAndStopTask_001
* @tc.desc    : Test start and stop flv live scheduled check task
* @tc.require :
*/
HWTEST_F(LiveControllerUnitTest, StartAndStopTask_001, TestSize.Level0)
{
    liveController_->isCheckLiveDelayTimeSet_.store(true);
    liveController_->StartCheckLiveDelayTime(UPDATE_INTERVAL_MS);
    EXPECT_EQ(liveController_->checkLiveDelayTimeIntervalMs_, UPDATE_INTERVAL_MS);
    liveController_->isCheckLiveDelayTimeSet_.store(false);
    liveController_->StartCheckLiveDelayTime(UPDATE_INTERVAL_MS);
    EXPECT_TRUE(liveController_->isCheckLiveDelayTimeSet_.load());

    liveController_->StopCheckLiveDelayTime();
    EXPECT_FALSE(liveController_->isCheckLiveDelayTimeSet_.load());
}

/**
 * @tc.name  : Test Enqueue
 * @tc.number: Enqueue_001
 * @tc.desc  : Test Enqueue
 */
HWTEST_F(LiveControllerUnitTest, Enqueue_001, TestSize.Level0)
{
    liveController_->StartWithPlayerEngineObs(testObs_);
    liveController_->isCheckLiveDelayTimeSet_.store(true);
    std::shared_ptr<LiveController::Event> event =
        std::make_shared<LiveController::Event>(WHAT_LIVE_DELAY_TIME,
        SteadyClock::GetCurrentTimeMs(), Any());
    liveController_->LoopOnce(event);
    EXPECT_TRUE(testObs_->onSystemOperationFlag);
    liveController_->StopCheckLiveDelayTime();
}
}
}