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

#include "thermal_observer.h"
#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace ThermalObserverFuncUT {

class ThermalObserverTestCallBack : public ThermalObserverCallBack {
public:
    ThermalObserverTestCallBack() {}
    ~ThermalObserverTestCallBack() {}
    void OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level) override
    {
        lastLevel_ = level;
        callCount_++;
    }
    OHOS::PowerMgr::ThermalLevel lastLevel_ = OHOS::PowerMgr::ThermalLevel::COOL;
    int32_t callCount_ = 0;
};

class ThermalObserverInnerUnitTest : public testing::Test {};

HWTEST_F(ThermalObserverInnerUnitTest, RegisterThermalObserverCallBack_001, TestSize.Level1)
{
    auto cb = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb));
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb);
}

HWTEST_F(ThermalObserverInnerUnitTest, RegisterThermalObserverCallBack_002, TestSize.Level1)
{
    std::weak_ptr<ThermalObserverCallBack> cb;
    ASSERT_FALSE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb));
}

HWTEST_F(ThermalObserverInnerUnitTest, OnThermalLevelChanged_001, TestSize.Level1)
{
    auto cb = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb));
    ASSERT_TRUE(ThermalObserver::GetInstance().OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel::HOT));
    ASSERT_EQ(cb->callCount_, 1);
    ASSERT_EQ(cb->lastLevel_, OHOS::PowerMgr::ThermalLevel::HOT);
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb);
}

HWTEST_F(ThermalObserverInnerUnitTest, OnThermalLevelChanged_002, TestSize.Level1)
{
    auto cb1 = std::make_shared<ThermalObserverTestCallBack>();
    auto cb2 = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb1));
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb2));
    ASSERT_TRUE(ThermalObserver::GetInstance().OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel::WARM));
    ASSERT_EQ(cb1->callCount_, 1);
    ASSERT_EQ(cb2->callCount_, 1);
    ASSERT_EQ(cb1->lastLevel_, OHOS::PowerMgr::ThermalLevel::WARM);
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb1);
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb2);
}

HWTEST_F(ThermalObserverInnerUnitTest, UnregisterThermalObserverCallBack_001, TestSize.Level1)
{
    auto cb = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb));
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb);
    ASSERT_TRUE(ThermalObserver::GetInstance().OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel::HOT));
    ASSERT_EQ(cb->callCount_, 0);
}

HWTEST_F(ThermalObserverInnerUnitTest, UnregisterThermalObserverCallBack_002, TestSize.Level1)
{
    auto cb = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cb));
    auto cbExpired = std::make_shared<ThermalObserverTestCallBack>();
    ASSERT_TRUE(ThermalObserver::GetInstance().RegisterThermalObserverCallBack(cbExpired));
    cbExpired.reset();
    ThermalObserver::GetInstance().UnregisterThermalObserverCallBack(cb);
    ASSERT_TRUE(ThermalObserver::GetInstance().OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel::HOT));
    ASSERT_EQ(cb->callCount_, 0);
}
} // namespace ThermalObserverFuncUT
} // namespace Media
} // namespace OHOS
