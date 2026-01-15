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
#include "hiplayer_callback_looper_unit_test.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/autolock.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr int32_t WHAT_NONE = 0;
    constexpr int32_t WHAT_MEDIA_PROGRESS = 1;
    constexpr int32_t WHAT_INFO = 2;
}
using namespace std;
using namespace testing::ext;

void HiplayerCallbackLooperUnitTest::SetUpTestCase(void)
{
}

void HiplayerCallbackLooperUnitTest::TearDownTestCase(void)
{
}

void HiplayerCallbackLooperUnitTest::SetUp(void)
{
    callback_ = std::make_unique<HiPlayerCallbackLooper>();
    mockIPlayerEngine_ = new MockIPlayerEngine();
    callback_->playerEngine_ = mockIPlayerEngine_;
    testObs_ = std::make_shared<MockIPlayerEngineObs>();
    callback_->task_ = std::make_unique<Task>("callbackTestThread");
    callback_->StartWithPlayerEngineObs(testObs_);
}

void HiplayerCallbackLooperUnitTest::TearDown(void)
{
    if (mockIPlayerEngine_) {
        delete mockIPlayerEngine_;
        mockIPlayerEngine_ = nullptr;
    }
    if (testObs_) {
        testObs_ = nullptr;
    }
    callback_ = nullptr;
}

/**
 * @tc.name  : Test DoReportMediaProgress
 * @tc.number: DoReportMediaProgress_001
 * @tc.desc  : Test DoReportMediaProgress
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, DoReportMediaProgress_001, TestSize.Level0)
{
    callback_->reportMediaProgress_ = true;
    testObs_ = nullptr;
    callback_->DoReportMediaProgress();
    EXPECT_FALSE(callback_->isDropMediaProgress_);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test DoReportMediaProgress
 * @tc.number: DoReportMediaProgress_002
 * @tc.desc  : Test DoReportMediaProgress
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, DoReportMediaProgress_002, TestSize.Level0)
{
    callback_->reportMediaProgress_ = false;
    callback_->isDropMediaProgress_ = true;
    callback_->DoReportMediaProgress();
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = true;
    callback_->isDropMediaProgress_ = true;
    callback_->DoReportMediaProgress();
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test StartReportMediaProgress
 * @tc.number: StartReportMediaProgress_001
 * @tc.desc  : Test StartReportMediaProgress
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, StartReportMediaProgress_001, TestSize.Level0)
{
    int32_t updateIntervalMs = 0;
    callback_->reportMediaProgress_ = true;
    callback_->StartReportMediaProgress(updateIntervalMs);
    EXPECT_EQ(callback_->reportMediaProgress_, true);
}

/**
 * @tc.name  : Test StartReportMediaProgress
 * @tc.number: StartReportMediaProgress_002
 * @tc.desc  : Test StartReportMediaProgress
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, StartReportMediaProgress_002, TestSize.Level0)
{
    int32_t updateIntervalMs = 0;
    callback_->reportMediaProgress_ = false;
    callback_->StartReportMediaProgress(updateIntervalMs);
    EXPECT_EQ(callback_->reportMediaProgress_, true);
}

/**
 * @tc.name  : Test StartCollectMaxAmplitude
 * @tc.number: StartCollectMaxAmplitude_001
 * @tc.desc  : Test StartCollectMaxAmplitude
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, StartCollectMaxAmplitude_001, TestSize.Level0)
{
    int32_t updateIntervalMs = 0;
    callback_->collectMaxAmplitude_ = true;
    callback_->StartCollectMaxAmplitude(updateIntervalMs);
    EXPECT_EQ(callback_->collectMaxAmplitudeIntervalMs_, updateIntervalMs);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test StartCollectMaxAmplitude
 * @tc.number: StartCollectMaxAmplitude_002
 * @tc.desc  : Test StartCollectMaxAmplitude
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, StartCollectMaxAmplitude_002, TestSize.Level0)
{
    int32_t updateIntervalMs = 0;
    callback_->collectMaxAmplitude_ = false;
    callback_->StartCollectMaxAmplitude(updateIntervalMs);
    EXPECT_EQ(callback_->collectMaxAmplitude_, true);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test Enqueue
 * @tc.number: Enqueue_001
 * @tc.desc  : Test Enqueue
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, Enqueue_001, TestSize.Level0)
{
    std::shared_ptr<HiPlayerCallbackLooper::Event> event =
        std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_NONE,
        SteadyClock::GetCurrentTimeMs(), Any());
    callback_->Enqueue(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test Enqueue
 * @tc.number: Enqueue_002
 * @tc.desc  : Test Enqueue
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, Enqueue_002, TestSize.Level0)
{
    std::shared_ptr<HiPlayerCallbackLooper::Event> event =
        std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_MEDIA_PROGRESS,
        SteadyClock::GetCurrentTimeMs(), Any());
    callback_->Enqueue(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name  : Test LoopOnce
 * @tc.number: LoopOnce_001
 * @tc.desc  : Test LoopOnce
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, LoopOnce_001, TestSize.Level0)
{
    std::shared_ptr<HiPlayerCallbackLooper::Event> event =
        std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_INFO,
        SteadyClock::GetCurrentTimeMs() + 100, Any());
    callback_->LoopOnce(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
}

/**
 * @tc.name  : Test LoopOnce
 * @tc.number: LoopOnce_002
 * @tc.desc  : Test LoopOnce
 */
HWTEST_F(HiplayerCallbackLooperUnitTest, LoopOnce_002, TestSize.Level0)
{
    std::shared_ptr<HiPlayerCallbackLooper::Event> event =
        std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_NONE,
        SteadyClock::GetCurrentTimeMs() + 100, Any());
    callback_->LoopOnce(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
}
} // namespace Media
} // namespace OHOS