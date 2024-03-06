/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "incall_observer.h"
#include <cstdlib>
#include <string>

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace InCallObserverFuncUT {

class InCallObserverTestCallBack : public InCallObserverCallBack {
public:
    InCallObserverTestCallBack(){}
    ~InCallObserverTestCallBack() = default;
    bool StopAndReleaseCallBack()
    {
        return true;
    }
};

class InCallObserverInnerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp(void);

    void TearDown(void);
};

void InCallObserverInnerUnitTest::SetUpTestCase(void) {}

void InCallObserverInnerUnitTest::TearDownTestCase(void) {}

void InCallObserverInnerUnitTest::SetUp(void)
{
    std::cout << "[SetUp]: SetUp!!!, test: ";
    const ::testing::TestInfo *testInfo_ = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string testName = testInfo_->name();
    std::cout << testName << std::endl;
}

void InCallObserverInnerUnitTest::TearDown(void)
{
    std::cout << "[TearDown]: over!!!" << std::endl;
}

/**
 * @tc.name: RegisterObserver_01
 * @tc.desc: RegisterObserver_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, RegisterObserver_01, TestSize.Level1)
{
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterObserver());
    InCallObserver::GetInstance().UnRegisterObserver();

}

/**
 * @tc.name: OnCallStateUpdated_01
 * @tc.desc: OnCallStateUpdated_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, OnCallStateUpdated_01, TestSize.Level1)
{
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall());
    InCallObserver::GetInstance().OnCallStateUpdated(true);
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall());
}

/**
 * @tc.name: RegisterInCallObserverCallBack_01
 * @tc.desc: RegisterInCallObserverCallBack_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, RegisterInCallObserverCallBack_01, TestSize.Level1)
{
    InCallObserverCallBack inCallObserverCallBack = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverCallBack));
    InCallObserver::GetInstance().UnRegisterInCallObserverCallBack(inCallObserverCallBack);
    ASSERT_TRUE(inCallObserverCallBack->StopAndReleaseCallBack());
}
} // namespace MetaFuncUT
} // namespace Media
} // namespace OHOS
