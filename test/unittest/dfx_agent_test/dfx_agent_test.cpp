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

#include <future>
#include <thread>
#include "dfx_agent_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

static const int32_t NUM_1200 = 1200;
static const int32_t NUM_1100 = 1100;
static const int32_t NUM_1000 = 1000;
static const int32_t NUM_100 = 100;
static const int32_t NUM_10 = 10;
static const int32_t NUM_1 = 1;
static const int32_t NUM_0 = 0;
static const int32_t NUM_500 = 500;
static const int32_t NUM_900 = 900;
static const int32_t ASYNC_WAIT_MS = 300;

void DfxAgentUnitTest::SetUpTestCase(void) {}

void DfxAgentUnitTest::TearDownTestCase(void) {}

void DfxAgentUnitTest::SetUp(void)
{
    std::string groupId = "test_group";
    std::string appName = "test_app";
    agent_ = std::make_shared<DfxAgent>(groupId, appName);
    agent_->SetInstanceId("42");
}

void DfxAgentUnitTest::TearDown(void)
{
    agent_ = nullptr;
}

/**
 * @tc.name  : Test SetMetricsCallback
 * @tc.number: SetMetricsCallback_001
 * @tc.desc  : Test SetMetricsCallback can set and trigger callback
 */
HWTEST_F(DfxAgentUnitTest, SetMetricsCallback_001, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1000,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_100,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_500,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_0,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->ReportMetricsEvent(event);

    auto status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);

    int64_t stallDuration = NUM_0;
    agent_->GetTotalStallingDuration(&stallDuration);
    int64_t expectedDelay = NUM_500 - (NUM_100 + NUM_10);
    EXPECT_EQ(stallDuration, expectedDelay);
}

/**
 * @tc.name  : ReportMetricsEvent_001
 * @tc.number: ReportMetricsEvent_001
 * @tc.desc  : Test ReportMetricsEvent when a stall occurs
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_001, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;
    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1000,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_100,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_500,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_0,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;

    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);

    int64_t stallDuration = NUM_0;
    agent_->GetTotalStallingDuration(&stallDuration);
    int64_t expectedDelay = NUM_500 - (NUM_100 + NUM_10);
    EXPECT_EQ(stallDuration, expectedDelay);
}

/**
 * @tc.name  : ReportMetricsEvent_002
 * @tc.number: ReportMetricsEvent_002
 * @tc.desc  : Test ReportMetricsEvent when no stall occurs
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_002, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;
    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1100,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_1000,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_500,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_0,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::seconds(1));
    EXPECT_NE(status, std::future_status::ready);
}

/**
 * @tc.name  : ReportMetricsEvent_003
 * @tc.number: ReportMetricsEvent_003
 * @tc.desc  : Test ReportMetricsEvent to trigger loader stage log
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_003, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;

    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1200,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_500,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_1000,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_1000,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::milliseconds(ASYNC_WAIT_MS * 2));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);
}

/**
 * @tc.name  : ReportMetricsEvent_004
 * @tc.number: ReportMetricsEvent_004
 * @tc.desc  : Test ReportMetricsEvent to trigger demuxer stage log
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_004, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;

    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1200,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_900,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_1000,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_500,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::milliseconds(ASYNC_WAIT_MS * 2));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);
}

/**
 * @tc.name  : ReportMetricsEvent_005
 * @tc.number: ReportMetricsEvent_005
 * @tc.desc  : Test ReportMetricsEvent to trigger decoder stage log
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_005, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;

    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1200,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_1000,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_1200,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_900,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_0,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::milliseconds(ASYNC_WAIT_MS * 2));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);
}

/**
 * @tc.name  : ReportMetricsEvent_006
 * @tc.number: ReportMetricsEvent_006
 * @tc.desc  : Test ReportMetricsEvent to trigger AVSync stage log
 */
HWTEST_F(DfxAgentUnitTest, ReportMetricsEvent_006, TestSize.Level0)
{
    ASSERT_NE(agent_, nullptr);
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    DfxEventHandleFunc cb = [&promise](std::weak_ptr<DfxAgent> agent, const DfxEvent& event) {
        promise.set_value();
    };
    agent_->SetMetricsCallback(cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_WAIT_MS));

    DfxEvent event;
    event.type = DfxEventType::DFX_EVENT_STALLING;
    std::vector<int64_t> timeStampList = {
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_PTS), NUM_1200,
        static_cast<int64_t>(StallingStage::CUSTOM_PRE_RENDER), NUM_1000,
        static_cast<int64_t>(StallingStage::CUSTOM_FRAME_INTERVAL), NUM_10,
        static_cast<int64_t>(StallingStage::RENDERER_START), NUM_1200,
        static_cast<int64_t>(StallingStage::AVSYNC_START), NUM_900,
        static_cast<int64_t>(StallingStage::DEMUXER_START), NUM_0,
        static_cast<int64_t>(StallingStage::DECODER_START), NUM_0,
    };
    event.param = timeStampList;
    agent_->OnDfxEvent(event);
    auto status = future.wait_for(std::chrono::milliseconds(ASYNC_WAIT_MS * 2));
    EXPECT_EQ(status, std::future_status::ready);

    int64_t stallTimes = NUM_0;
    agent_->GetTotalStallingTimes(&stallTimes);
    EXPECT_EQ(stallTimes, NUM_1);
}
} // namespace Media
} // namespace OHOS
