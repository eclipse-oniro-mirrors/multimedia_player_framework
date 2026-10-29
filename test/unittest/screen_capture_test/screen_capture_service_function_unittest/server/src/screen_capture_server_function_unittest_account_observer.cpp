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

// L51 branch 1: callback.lock() returns nullptr -> return false
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_RegisterNullCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    std::weak_ptr<AccountObserverCallBack> nullCb;
    EXPECT_FALSE(observer.RegisterAccountObserverCallBack(nullCb));
}

// L51 branch 0: valid callback -> push_back -> return true
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_RegisterValidCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb = std::make_shared<MockAccountObserverCallBack>();
    EXPECT_TRUE(observer.RegisterAccountObserverCallBack(cb));
    observer.UnregisterAccountObserverCallBack(cb);
    EXPECT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

// L66 branch 1: unregisterCallBack == nullptr -> CHECK_AND_RETURN
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_UnregisterNullCallback_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    std::weak_ptr<AccountObserverCallBack> nullCb;
    observer.UnregisterAccountObserverCallBack(nullCb);
    ASSERT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

// L69: unregister a callback that matches (branch 0) + erase expired callbacks (nullptr, branch 2/3)
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_UnregisterMatchAndExpired_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb1 = std::make_shared<MockAccountObserverCallBack>();
    auto cb2 = std::make_shared<MockAccountObserverCallBack>();
    observer.RegisterAccountObserverCallBack(cb1);
    observer.RegisterAccountObserverCallBack(cb2);
    // Release cb2 so its weak_ptr expires -> L69 iterCallback == nullptr branch
    cb2.reset();
    // Unregister cb1 -> L69 iterCallback == unregisterCallBack branch
    observer.UnregisterAccountObserverCallBack(cb1);
    // Also unregister expired cb2 -> exercises nullptr erase path again
    std::weak_ptr<AccountObserverCallBack> expiredCb;
    observer.UnregisterAccountObserverCallBack(expiredCb);
    EXPECT_EQ(observer.accountObserverCallBacks_.size(), 0u);
}

// L85/L88/L89: OnAccountsSwitch with callbacks (branch 0) + null callback in list (branch 1)
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_OnAccountsSwitch_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    auto cb = std::make_shared<MockAccountObserverCallBack>();
    EXPECT_CALL(*cb, OnAccountsSwitch()).WillOnce(Return(true));
    observer.RegisterAccountObserverCallBack(cb);
    // Also register an expired callback to cover L88 branch 1 (callbackPtr null)
    std::weak_ptr<AccountObserverCallBack> expired;
    observer.accountObserverCallBacks_.push_back(expired);
    bool ret = observer.OnAccountsSwitch();
    observer.UnregisterAccountObserverCallBack(cb);
    EXPECT_TRUE(ret);
}

// L85 loop empty: OnAccountsSwitch with no callbacks
HWTEST_F(ScreenCaptureServerFunctionTest, AccountObserver_OnAccountsSwitch_Empty_001, TestSize.Level2)
{
    auto &observer = AccountObserver::GetInstance();
    observer.accountObserverCallBacks_.clear();
    bool ret = observer.OnAccountsSwitch();
    EXPECT_TRUE(ret);
}

// L88/L89: OnAccountsSwitch where callback returns false
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

// L101 branch 1: Init when isAccountListenerDied_ is false -> skip RegisterObserver
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
