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
#include "player_xcollie_unittest.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing;
using namespace testing::ext;

const static int32_t TEST_SUCCESS = 0;
static constexpr uint32_t TEST_THRESHOLD_ID_MIN = 0;
static constexpr uint32_t TEST_TIMEOUT = 1000;

namespace OHOS {
namespace Media {
void PlayerXcollieUnitTest::SetUpTestCase(void) {}

void PlayerXcollieUnitTest::TearDownTestCase(void) {}

void PlayerXcollieUnitTest::SetUp(void) {}

void PlayerXcollieUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test SetTimer
 * @tc.number: SetTimer_001
 * @tc.desc  : Test SetTimer recovery = true
 *             Test TimerCallback threadDeadlockCount_ < threshold
 */
HWTEST_F(PlayerXcollieUnitTest, SetTimer_001, TestSize.Level1)
{
    // Test TimerCallback threadDeadlockCount_ < threshold
    auto data = std::function<void (void *)>();
    PlayerXCollie::GetInstance().threadDeadlockCount_ = TEST_THRESHOLD_ID_MIN;
    PlayerXCollie::GetInstance().TimerCallback(&data);

    // Test SetTimer recovery = true
    const std::string name = "test_timer";
    bool recovery = true;
    EXPECT_CALL(HiviewDFX::XCollie::GetInstance(), SetTimer(_, _, _, _, _))
        .WillOnce(Return(TEST_SUCCESS));
    PlayerXCollie::GetInstance().SetTimer(name, recovery, TEST_TIMEOUT);
}

/**
 * @tc.name  : Test SetTimerByLog
 * @tc.number: SetTimerByLog_001
 * @tc.desc  : Test SetTimerByLog id != HiviewDFX::INVALID_ID
 */
HWTEST_F(PlayerXcollieUnitTest, SetTimerByLog_001, TestSize.Level1)
{
    const std::string name = "test_timer";
    EXPECT_CALL(HiviewDFX::XCollie::GetInstance(), SetTimer(_, _, _, _, _))
        .WillOnce(Return(TEST_SUCCESS));
    PlayerXCollie::GetInstance().SetTimerByLog(name, TEST_TIMEOUT);
}

/**
 * @tc.name  : Test SetTimerByLog
 * @tc.number: SetTimerByLog_002
 * @tc.desc  : Test SetTimerByLog id == HiviewDFX::INVALID_ID
 */
HWTEST_F(PlayerXcollieUnitTest, SetTimerByLog_002, TestSize.Level1)
{
    const std::string name = "test_timer";
    EXPECT_CALL(HiviewDFX::XCollie::GetInstance(), SetTimer(_, _, _, _, _))
        .WillOnce(Return(HiviewDFX::INVALID_ID));
    PlayerXCollie::GetInstance().SetTimerByLog(name, TEST_TIMEOUT);
}

/**
 * @tc.name  : Test CancelTimer
 * @tc.number: CancelTimer_001
 * @tc.desc  : Test CancelTimer id == HiviewDFX::INVALID_ID
 *             Test CancelTimer dfxDumper_.size() == 0
 */
HWTEST_F(PlayerXcollieUnitTest, CancelTimer_001, TestSize.Level1)
{
    PlayerXCollie::GetInstance().dfxDumper_.clear();

    // Test CancelTimer id == HiviewDFX::INVALID_ID
    int32_t id = HiviewDFX::INVALID_ID;
    PlayerXCollie::GetInstance().CancelTimer(id);

    // Test CancelTimer dfxDumper_.size() == 0
    id = TEST_SUCCESS;
    PlayerXCollie::GetInstance().CancelTimer(id);
    EXPECT_EQ(PlayerXCollie::GetInstance().dfxDumper_.size(), 0);
}
} // namespace Media
} // namespace OHOS