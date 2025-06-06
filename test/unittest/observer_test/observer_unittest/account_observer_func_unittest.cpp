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
    bool NotifyStopAndRelease(AVScreenCaptureStateCode state)
    {
        return true;
    }
    void Release() {}
};

class AccountObserverTestFalseCallBack : public AccountObserverCallBack {
public:
    AccountObserverTestFalseCallBack() {}
    ~AccountObserverTestFalseCallBack() {}
    bool StopAndRelease(AVScreenCaptureStateCode state)
    {
        return false;
    }
    bool NotifyStopAndRelease(AVScreenCaptureStateCode state)
    {
        return false;
    }
    void Release() {}
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
 * @tc.name: RegisterAccountObserverCallBack_01
 * @tc.desc: StopAndRelease
 * @tc.type: FUNC
 */
HWTEST_F(AccountObserverInnerUnitTest, RegisterAccountObserverCallBack_01, TestSize.Level1)
{
    auto accountObserverCallBack = std::make_shared<AccountObserverTestCallBack>();
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterAccountObserverCallBack(accountObserverCallBack));
    ASSERT_TRUE(accountObserverCallBack->StopAndRelease(
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER_SWITCHES));
    AccountObserver::GetInstance().UnregisterAccountObserverCallBack(accountObserverCallBack);
}

/**
 * @tc.name: RegisterAccountObserverCallBack_02
 * @tc.desc: OnAccountsSwitch
 * @tc.type: FUNC
 */
HWTEST_F(AccountObserverInnerUnitTest, RegisterAccountObserverCallBack_02, TestSize.Level1)
{
    auto accountObserverCallBack = std::make_shared<AccountObserverTestCallBack>();
    ASSERT_TRUE(AccountObserver::GetInstance().RegisterAccountObserverCallBack(accountObserverCallBack));
    ASSERT_TRUE(AccountObserver::GetInstance().OnAccountsSwitch());
    AccountObserver::GetInstance().UnregisterAccountObserverCallBack(accountObserverCallBack);
}
} // namespace AccountObserverFuncUT
} // namespace Media
} // namespace OHOS
