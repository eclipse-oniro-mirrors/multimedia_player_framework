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

#include <gtest/gtest.h>
#include <vector>
#include "lpp_video_callback_looper_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppVideoCallbackLooperUnitTest::SetUpTestCase(void)
{
}

void LppVideoCallbackLooperUnitTest::TearDownTestCase(void)
{
}

void LppVideoCallbackLooperUnitTest::SetUp(void)
{
    callbackLooper_ = std::make_shared<LppVideoCallbackLooper>(streamerId_);
    engineObs_ = std::make_shared<MockLppVideoStreamerEngineObs>();
}

void LppVideoCallbackLooperUnitTest::TearDown(void)
{
    engineObs_ = nullptr;
    callbackLooper_ = nullptr;
}

/**
* @tc.name    : Test StartWithLppVideoStreamerEngineObs API
* @tc.number  : StartWithLppVideoStreamerEngineObs_001
* @tc.desc    : Test StartWithLppVideoStreamerEngineObs interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, StartWithLppVideoStreamerEngineObs_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->taskStarted_ = true;
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_NE(callbackLooper_->obs_.lock(), nullptr);
}

/**
* @tc.name    : Test StartWithLppVideoStreamerEngineObs API
* @tc.number  : StartWithLppVideoStreamerEngineObs_002
* @tc.desc    : Test StartWithLppVideoStreamerEngineObs interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, StartWithLppVideoStreamerEngineObs_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->taskStarted_ = false;
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_NE(callbackLooper_->obs_.lock(), nullptr);
    EXPECT_EQ(callbackLooper_->taskStarted_, true);
}

/**
* @tc.name    : Test OnDataNeeded API
* @tc.number  : OnDataNeeded_001
* @tc.desc    : Test OnDataNeeded interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, OnDataNeeded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    EXPECT_CALL(*engineObs_, OnDataNeeded(_, _)).WillOnce(Return());
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_NE(callbackLooper_->obs_.lock(), nullptr);
    callbackLooper_->OnDataNeeded(10, 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    EXPECT_EQ(callbackLooper_->taskStarted_, true);
}

/**
* @tc.name    : Test OnDataNeeded API
* @tc.number  : OnDataNeeded_002
* @tc.desc    : Test OnDataNeeded interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, OnDataNeeded_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    EXPECT_EQ(callbackLooper_->obs_.lock(), nullptr);
    callbackLooper_->OnDataNeeded(10, 10);
    EXPECT_EQ(callbackLooper_->taskStarted_, false);
}

/**
* @tc.name    : Test OnTargetArrived API
* @tc.number  : OnTargetArrived_001
* @tc.desc    : Test OnTargetArrived interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, OnTargetArrived_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    EXPECT_CALL(*engineObs_, OnTargetArrived(_, _)).WillOnce(Return());
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_NE(callbackLooper_->obs_.lock(), nullptr);
    callbackLooper_->OnTargetArrived(10, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    EXPECT_EQ(callbackLooper_->taskStarted_, true);
}

/**
* @tc.name    : Test OnTargetArrived API
* @tc.number  : OnTargetArrived_002
* @tc.desc    : Test OnTargetArrived interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, OnTargetArrived_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    EXPECT_EQ(callbackLooper_->obs_.lock(), nullptr);
    callbackLooper_->OnTargetArrived(10, true);
    EXPECT_EQ(callbackLooper_->taskStarted_, false);
}

/**
* @tc.name    : Test Stop API
* @tc.number  : Stop_001
* @tc.desc    : Test Stop interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, Stop_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_EQ(callbackLooper_->taskStarted_, true);
    callbackLooper_->Stop();
    EXPECT_EQ(callbackLooper_->taskStarted_, false);
}

/**
* @tc.name    : Test Stop API
* @tc.number  : Stop_002
* @tc.desc    : Test Stop interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoCallbackLooperUnitTest, Stop_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    EXPECT_EQ(callbackLooper_->taskStarted_, false);
    callbackLooper_->Stop();
    EXPECT_EQ(callbackLooper_->taskStarted_, false);
}

/**
 * @tc.name    : Test OnError API
 * @tc.number  : OnError_001
 * @tc.desc    : Test OnError interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnError_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);

    MediaServiceErrCode errCode = MediaServiceErrCode::MSERR_UNKNOWN;
    std::string errMsg = "Test MSERR_UNKNOWN";

    EXPECT_CALL(*engineObs_, OnError(errCode, errMsg)).Times(1);
    callbackLooper_->OnError(errCode, errMsg);
}

/**
 * @tc.name    : Test OnAnchorUpdateNeeded API
 * @tc.number  : OnAnchorUpdateNeeded_001
 * @tc.desc    : Test OnAnchorUpdateNeeded interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnAnchorUpdateNeeded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);

    int64_t anchorPts = 0;
    int64_t anchorClk = 0;

    bool result = callbackLooper_->OnAnchorUpdateNeeded(anchorPts, anchorClk);
    EXPECT_TRUE(result);
}

/**
 * @tc.name    : Test OnEos API
 * @tc.number  : OnEos_001
 * @tc.desc    : Test OnEos interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnEos_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_CALL(*engineObs_, OnEos()).Times(1);

    callbackLooper_->OnEos();
}

/**
 * @tc.name    : Test OnRenderStarted API
 * @tc.number  : OnRenderStarted_001
 * @tc.desc    : Test OnRenderStarted interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnRenderStarted_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_CALL(*engineObs_, OnRenderStarted()).Times(1);

    callbackLooper_->OnRenderStarted();
}

/**
 * @tc.name    : Test OnFirstFrameReady API
 * @tc.number  : OnFirstFrameReady_001
 * @tc.desc    : Test OnFirstFrameReady interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnFirstFrameReady_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_CALL(*engineObs_, OnFirstFrameReady()).Times(1);

    callbackLooper_->OnFirstFrameReady();
}

/**
 * @tc.name    : Test OnStreamChanged API
 * @tc.number  : OnStreamChanged_001
 * @tc.desc    : Test OnStreamChanged interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, OnStreamChanged_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);
    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);

    Format format;
    EXPECT_CALL(*engineObs_, OnStreamChanged(_)).Times(1);

    callbackLooper_->OnStreamChanged(format);
}

/**
 * @tc.name    : Test Reset API
 * @tc.number  : Reset_001
 * @tc.desc    : Test Reset interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoCallbackLooperUnitTest, Reset_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, callbackLooper_);
    ASSERT_NE(nullptr, engineObs_);

    callbackLooper_->StartWithLppVideoStreamerEngineObs(engineObs_);
    EXPECT_TRUE(callbackLooper_->taskStarted_);

    callbackLooper_->Reset();
    EXPECT_FALSE(callbackLooper_->taskStarted_);
}
} // namespace Media
} // namespace OHOS
