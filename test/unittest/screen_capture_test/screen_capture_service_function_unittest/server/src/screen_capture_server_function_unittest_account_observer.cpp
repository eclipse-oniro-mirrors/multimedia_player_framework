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

#include "account_observer.h"
#include "account_observer_callback.h"
#include "media_errors.h"
#include "screen_capture_server_function_unittest.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>

using namespace testing::ext;
using namespace OHOS::Media;
using testing::Return;

namespace OHOS {
namespace Media {

class MockAccountObserverCallBack : public AccountObserverCallBack {
public:
    MOCK_METHOD(bool, OnAccountsSwitch, (), (override));
};

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_RegisterNullCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    std::weak_ptr<AccountObserverCallBack> nullCb;
    EXPECT_FALSE(observer.RegisterAccountObserverCallBack(nullCb));
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_RegisterValidCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb = std::make_shared<MockAccountObserverCallBack>();
    EXPECT_TRUE(observer.RegisterAccountObserverCallBack(cb));
    observer.UnregisterAccountObserverCallBack(cb);
    EXPECT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_UnregisterNullCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    std::weak_ptr<AccountObserverCallBack> nullCb;
    observer.UnregisterAccountObserverCallBack(nullCb);
    ASSERT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_UnregisterMatchAndExpired_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb1 = std::make_shared<MockAccountObserverCallBack>();
    auto cb2 = std::make_shared<MockAccountObserverCallBack>();
    observer.RegisterAccountObserverCallBack(cb1);
    observer.RegisterAccountObserverCallBack(cb2);
    cb2.reset();
    observer.UnregisterAccountObserverCallBack(cb1);
    // Also unregister expired cb2 -> exercises nullptr erase path again
    std::weak_ptr<AccountObserverCallBack> expiredCb;
    observer.UnregisterAccountObserverCallBack(expiredCb);
    EXPECT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_OnAccountsSwitch_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb = std::make_shared<MockAccountObserverCallBack>();
    EXPECT_CALL(*cb, OnAccountsSwitch()).WillOnce(Return(true));
    observer.RegisterAccountObserverCallBack(cb);
    std::weak_ptr<AccountObserverCallBack> expired;
    observer.accountObserverCallBacks_.push_back(expired);
    bool ret = observer.OnAccountsSwitch();
    observer.UnregisterAccountObserverCallBack(cb);
    EXPECT_TRUE(ret);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_OnAccountsSwitch_Empty_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    observer.accountObserverCallBacks_.clear();
    bool ret = observer.OnAccountsSwitch();
    EXPECT_TRUE(ret);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_OnAccountsSwitch_False_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb = std::make_shared<MockAccountObserverCallBack>();
    EXPECT_CALL(*cb, OnAccountsSwitch()).WillOnce(Return(false));
    observer.RegisterAccountObserverCallBack(cb);
    bool ret = observer.OnAccountsSwitch();
    observer.UnregisterAccountObserverCallBack(cb);
    EXPECT_FALSE(ret);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_Init_NotDied_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    observer.isAccountListenerDied_.store(false);
    bool ret = observer.Init();
    observer.isAccountListenerDied_.store(true);
    EXPECT_TRUE(ret);
}

} // namespace Media
} // namespace OHOS

