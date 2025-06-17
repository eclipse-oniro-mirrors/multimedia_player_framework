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
#include "hiplayer_callback_looper_unittest.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/autolock.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void HiplayerCallbackLooperUnittest::SetUpTestCase(void)
{
}

void HiplayerCallbackLooperUnittest::TearDownTestCase(void)
{
}

void HiplayerCallbackLooperUnittest::SetUp(void)
{
    callback_ = std::make_unique<HiPlayerCallbackLooper>();
    mockIPlayerEngine_ = new MockIPlayerEngine();
    callback_->playerEngine_ = mockIPlayerEngine_;
    testObs_ = std::make_shared<MockIPlayerEngineObs>();
    callback_->task_ = std::make_unique<Task>("callbackTestThread");
    callback_->StartWithPlayerEngineObs(testObs_);
}

void HiplayerCallbackLooperUnittest::TearDown(void)
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
 * @tc.name  : Test DoReportCompletedTime
 * @tc.number: DoReportCompletedTime_001
 * @tc.desc  : Test DoReportCompletedTime
 */
HWTEST_F(HiplayerCallbackLooperUnittest, DoReportCompletedTime_001, TestSize.Level0)
{
    ASSERT_NE(callback_, nullptr);
    EXPECT_CALL(*mockIPlayerEngine_, GetPlayRangeEndTime()).WillRepeatedly(Return(-1));
    EXPECT_CALL(*mockIPlayerEngine_, GetDuration(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*testObs_, OnInfo(_, _, _)).WillRepeatedly(Return());
    callback_->DoReportCompletedTime();
    EXPECT_EQ(mockIPlayerEngine_->GetPlayRangeEndTime(), -1);
}

/**
 * @tc.name  : Test DoReportCompletedTime
 * @tc.number: DoReportCompletedTime_002
 * @tc.desc  : Test DoReportCompletedTime
 */
HWTEST_F(HiplayerCallbackLooperUnittest, DoReportCompletedTime_002, TestSize.Level0)
{
    ASSERT_NE(callback_, nullptr);
    EXPECT_CALL(*mockIPlayerEngine_, GetPlayRangeEndTime()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockIPlayerEngine_, GetDuration(_)).WillRepeatedly(Return(1));
    EXPECT_CALL(*testObs_, OnInfo(_, _, _)).WillRepeatedly(Return());
    callback_->DoReportCompletedTime();
    EXPECT_EQ(mockIPlayerEngine_->GetPlayRangeEndTime(), 1);
}
} // namespace Media
} // namespace OHOS