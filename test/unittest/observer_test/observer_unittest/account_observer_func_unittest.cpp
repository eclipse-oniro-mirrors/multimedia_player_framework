/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <string>
#include "account_observer.h"
#include <cstdlib>
#include "account_listener.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace AccountObserverFuncUT {

class AccountObserverTestCallBack : public AccountObserverCallBack {
public:
    AccountObserverTestCallBack() {}
    ~AccountObserverTestCallBack() {}
    bool StopAndRelease(AVScreenCaptureStateCode state)
    {
        return true;
    }
};

class AccountObserverTestFalseCallBack : public AccountObserverCallBack {
public:
    AccountObserverTestFalseCallBack() {}
    ~AccountObserverTestFalseCallBack() {}
    bool StopAndRelease(AVScreenCaptureStateCode state)
    {
        return false;
    }
};

class AccountObserverInnerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp(void);

    void TearDown(void);
};

void AccountObserverInnerUnitTest::SetUpTestCase(void) {}

void AccountObserverInnerUnitTest::TearDownTestCase(void) {}

void AccountObserverInnerUnitTest::SetUp(void)
{
    std::cout << "[SetUp]: SetUp!!!, test: "<< std::endl;
}

void AccountObserverInnerUnitTest::TearDown(void)
{
    std::cout << "[TearDown]: over!!!" << std::endl;
}

/**
 * @tc.name: RegisterObserver_01
 * @tc.desc: RegisterObserver_01
 * @tc.type: FUNC
 */
HWTEST_F(AccountObserverInnerUnitTest, RegisterObserver_01, TestSize.Level1)
{
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterObserver());
    AccountObserver::GetInstance().UnregisterObserver();
}

/**
 * @tc.name: RegisterAccountObserverCallBack_01
 * @tc.desc: RegisterAccountObserverCallBack_01
 * @tc.type: FUNC
 */
HWTEST_F(AccountObserverInnerUnitTest, RegisterAccountObserverCallBack_01, TestSize.Level1)
{
    auto accountObserverCallBack = std::make_shared<AccountObserverTestCallBack>();
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterAccountObserverCallBack(accountObserverCallBack));
    AccountObserver::GetInstance().UnregisterAccountObserverCallBack(accountObserverCallBack);
    ASSERT_TRUE(accountObserverCallBack->StopAndRelease(
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER_SWITCHES));
}

/**
 * @tc.name: AccountCallBackReturn_01
 * @tc.desc: AccountCallBackReturn_01
 * @tc.type: FUNC
 */
HWTEST_F(AccountObserverInnerUnitTest, AccountCallBackReturn_01, TestSize.Level1)
{
    AccountObserver::GetInstance().UnregisterObserver();
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterObserver());
    auto accountObserverCallBack = std::make_shared<AccountObserverTestCallBack>();
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterAccountObserverCallBack(accountObserverCallBack));
    ASSERT_TRUE(AccountObserver::GetInstance().OnAccountsSwitch());
    AccountObserver::GetInstance().UnregisterObserver();
}
} // namespace AccountObserverFuncUT
} // namespace Media
} // namespace OHOS
