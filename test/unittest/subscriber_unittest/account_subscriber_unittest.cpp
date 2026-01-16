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

#include "account_subscriber_unittest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media;

const static int32_t TIME_ONE = 1;
const static int32_t TEST_USER_ID = 1;
const static int32_t TEST_INV_USER_ID = -1;
const static std::string TEST_ACTION = "test_action";

namespace OHOS {
namespace Media {
void AccountSubscriberUnitTest::SetUpTestCase(void) {}

void AccountSubscriberUnitTest::TearDownTestCase(void) {}

void AccountSubscriberUnitTest::SetUp(void)
{
    accountSubscriber_ = AccountSubscriber::GetInstance();
}

void AccountSubscriberUnitTest::TearDown(void)
{
    accountSubscriber_ = nullptr;
}

/**
 * @tc.name  : Test DispatchEvent
 * @tc.number: DispatchEvent_001
 * @tc.desc  : Test DispatchEvent mapIt == userMap_.end()
 *             Test DispatchEvent mapIt != userMap_.end()
 */
HWTEST_F(AccountSubscriberUnitTest, DispatchEvent_001, TestSize.Level1)
{
    int32_t userId = TEST_USER_ID;
    std::string expectedAction = TEST_ACTION;

    // Test DispatchEvent mapIt == userMap_.end()
    accountSubscriber_->userMap_.clear();
    accountSubscriber_->DispatchEvent(userId, expectedAction);

    // Test DispatchEvent mapIt != userMap_.end()
    accountSubscriber_->userMap_[TEST_USER_ID] = { std::make_shared<MockCommonEventReceiver>() };
    EXPECT_CALL(*std::static_pointer_cast<MockCommonEventReceiver>(accountSubscriber_->userMap_[TEST_USER_ID][0]),
                OnCommonEventReceived(_))
        .Times(TIME_ONE);
    accountSubscriber_->DispatchEvent(userId, expectedAction);
}

/**
 * @tc.name  : Test DispatchEvent
 * @tc.number: DispatchEvent_002
 * @tc.desc  : Test DispatchEvent receiver == nullptr
 *             Test DispatchEvent receiver != nullptr
 */
HWTEST_F(AccountSubscriberUnitTest, DispatchEvent_002, TestSize.Level1)
{
    int32_t userId = TEST_USER_ID;
    std::string expectedAction = TEST_ACTION;

    // Test DispatchEvent receiver == nullptr
    accountSubscriber_->userMap_[TEST_USER_ID] = { nullptr };
    accountSubscriber_->DispatchEvent(userId, expectedAction);

    // Test DispatchEvent receiver != nullptr
    accountSubscriber_->userMap_[TEST_USER_ID] = { std::make_shared<MockCommonEventReceiver>() };
    EXPECT_CALL(*std::static_pointer_cast<MockCommonEventReceiver>(accountSubscriber_->userMap_[TEST_USER_ID][0]),
                OnCommonEventReceived(_))
        .Times(TIME_ONE);
    accountSubscriber_->DispatchEvent(userId, expectedAction);
}

/**
 * @tc.name  : Test RegisterCommonEventReceiver
 * @tc.number: RegisterCommonEventReceiver_001
 * @tc.desc  : Test RegisterCommonEventReceiver receiver == nullptr
 *             Test RegisterCommonEventReceiver userId < 0
 *             Test RegisterCommonEventReceiver userMap_.empty() == false
 *             Test RegisterCommonEventReceiver mapIt != userMap_.end()
 */
HWTEST_F(AccountSubscriberUnitTest, RegisterCommonEventReceiver_001, TestSize.Level1)
{
    // Test RegisterCommonEventReceiver receiver == nullptr
    int32_t userId = TEST_USER_ID;
    std::shared_ptr<CommonEventReceiver> receiver = nullptr;
    accountSubscriber_->RegisterCommonEventReceiver(userId, receiver);

    // Test RegisterCommonEventReceiver userId < 0
    userId = TEST_INV_USER_ID;
    receiver = std::make_shared<MockCommonEventReceiver>();
    accountSubscriber_->RegisterCommonEventReceiver(userId, receiver);

    // Test RegisterCommonEventReceiver userMap_.empty() == false
    // Test RegisterCommonEventReceiver mapIt != userMap_.end()
    userId = TEST_USER_ID;
    accountSubscriber_->userMap_.insert({TEST_USER_ID, { receiver }});
    accountSubscriber_->RegisterCommonEventReceiver(userId, receiver);
    EXPECT_EQ(accountSubscriber_->userMap_.size(), 1);
}

/**
 * @tc.name  : Test RegisterCommonEventReceiver
 * @tc.number: RegisterCommonEventReceiver_002
 * @tc.desc  : Test RegisterCommonEventReceiver receiverIt == mapIt->second.end()
 *             Test RegisterCommonEventReceiver receiverIt != mapIt->second.end()
 */
HWTEST_F(AccountSubscriberUnitTest, RegisterCommonEventReceiver_002, TestSize.Level1)
{
    int32_t userId = TEST_USER_ID;
    auto receiver1 = std::make_shared<MockCommonEventReceiver>();
    auto receiver2 = std::make_shared<MockCommonEventReceiver>();
    accountSubscriber_->userMap_.insert({TEST_USER_ID, { receiver1 }});

    // Test RegisterCommonEventReceiver receiverIt != mapIt->second.end()
    accountSubscriber_->RegisterCommonEventReceiver(userId, receiver1);

    // Test RegisterCommonEventReceiver receiver == nullptr
    accountSubscriber_->RegisterCommonEventReceiver(userId, receiver2);
    EXPECT_TRUE(!accountSubscriber_->userMap_[TEST_USER_ID].empty());
}

/**
 * @tc.name  : Test UnregisterCommonEventReceiver
 * @tc.number: UnregisterCommonEventReceiver_001
 * @tc.desc  : Test UnregisterCommonEventReceiver receiver == nullptr
 *             Test UnregisterCommonEventReceiver mapIt == userMap_.end()
 */
HWTEST_F(AccountSubscriberUnitTest, UnregisterCommonEventReceiver_001, TestSize.Level1)
{
    // Test UnregisterCommonEventReceiver receiver == nullptr
    int32_t userId = TEST_USER_ID;
    std::shared_ptr<CommonEventReceiver> receiver = nullptr;
    accountSubscriber_->UnregisterCommonEventReceiver(userId, receiver);

    // Test UnregisterCommonEventReceiver mapIt == userMap_.end()
    userId = TEST_USER_ID;
    receiver = std::make_shared<MockCommonEventReceiver>();
    accountSubscriber_->userMap_.clear();
    accountSubscriber_->UnregisterCommonEventReceiver(userId, receiver);
    EXPECT_TRUE(accountSubscriber_->userMap_.empty());
}

/**
 * @tc.name  : Test UnregisterCommonEventReceiver
 * @tc.number: UnregisterCommonEventReceiver_002
 * @tc.desc  : Test UnregisterCommonEventReceiver receiverIt == mapIt->second.end()
 */
HWTEST_F(AccountSubscriberUnitTest, UnregisterCommonEventReceiver_002, TestSize.Level1)
{
    int32_t userId = TEST_USER_ID;
    auto receiver1 = std::make_shared<MockCommonEventReceiver>();
    auto receiver2 = std::make_shared<MockCommonEventReceiver>();
    accountSubscriber_->userMap_[TEST_USER_ID] = { receiver1 };
    accountSubscriber_->UnregisterCommonEventReceiver(userId, receiver2);
    EXPECT_EQ(accountSubscriber_->userMap_[TEST_USER_ID].size(), 1);
}

/**
 * @tc.name  : Test UnregisterCommonEventReceiver
 * @tc.number: UnregisterCommonEventReceiver_003
 * @tc.desc  : Test UnregisterCommonEventReceiver mapIt->second.empty() == false
 * @tc.desc  : Test UnregisterCommonEventReceiver userMap_.empty() == false
 */
HWTEST_F(AccountSubscriberUnitTest, UnregisterCommonEventReceiver_003, TestSize.Level1)
{
    int32_t userId = TEST_USER_ID;
    auto receiver1 = std::make_shared<MockCommonEventReceiver>();
    auto receiver2 = std::make_shared<MockCommonEventReceiver>();
    accountSubscriber_->userMap_[TEST_USER_ID] = { receiver1, receiver2 };
    accountSubscriber_->UnregisterCommonEventReceiver(userId, receiver2);
    EXPECT_TRUE(!accountSubscriber_->userMap_.empty());
}
} // namespace Media
} // namespace OHOS
