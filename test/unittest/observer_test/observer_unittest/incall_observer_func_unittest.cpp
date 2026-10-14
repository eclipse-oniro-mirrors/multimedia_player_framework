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
#include "incall_observer.h"
#include <cstdlib>
#include "media_telephony_listener.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace InCallObserverFuncUT {

class InCallObserverTestCallBack : public InCallObserverCallBack {
public:
    InCallObserverTestCallBack() {}
    ~InCallObserverTestCallBack() {}
    bool OnTelCallStateUpdated(bool isInCall) override
    {
        return true;
    }
};

class InCallObserverTestFalseCallBack : public InCallObserverCallBack {
public:
    InCallObserverTestFalseCallBack() {}
    ~InCallObserverTestFalseCallBack() {}
    bool OnTelCallStateUpdated(bool isInCall) override
    {
        return false;
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
    std::cout << "[SetUp]: SetUp!!!, test: "<< std::endl;
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
 * @tc.name: RegisterInCallObserverCallBack_01
 * @tc.desc: RegisterInCallObserverCallBack_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, RegisterInCallObserverCallBack_01, TestSize.Level1)
{
    auto inCallObserverCallBack = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverCallBack));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(inCallObserverCallBack);
}

/**
 * @tc.name: InCallCallBackReturn_01
 * @tc.desc: InCallCallBackReturn_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, InCallCallBackReturn_01, TestSize.Level1)
{
    InCallObserver::GetInstance().UnRegisterObserver();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterObserver());
    auto inCallObserverCallBack = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverCallBack));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().UnRegisterObserver();
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: InCallCallBackReturn_02
 * @tc.desc: InCallCallBackReturn_02
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, InCallCallBackReturn_02, TestSize.Level1)
{
    InCallObserver::GetInstance().UnRegisterObserver();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterObserver());
    auto inCallObserverCallBack = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverCallBack));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(false));
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
    sleep(3); // 3 second
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(inCallObserverCallBack);
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().UnRegisterObserver();
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: InCallCallBackReturn_03
 * @tc.desc: InCallCallBackReturn_03
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, InCallCallBackReturn_03, TestSize.Level1)
{
    InCallObserver::GetInstance().UnRegisterObserver();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterObserver());
    auto inCallObserverTestFalseCallBack = std::make_shared<InCallObserverTestFalseCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverTestFalseCallBack));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(false));
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
    sleep(3); // 3 second
    ASSERT_FALSE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(inCallObserverTestFalseCallBack);
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().UnRegisterObserver();
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: InCallCallBackReturn_04
 * @tc.desc: InCallCallBackReturn_04
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, InCallCallBackReturn_04, TestSize.Level1)
{
    InCallObserver::GetInstance().UnRegisterObserver();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterObserver());
    std::weak_ptr<InCallObserverCallBack> inCallObserverTestFalseCallBack =
        std::make_shared<InCallObserverTestFalseCallBack>();
    inCallObserverTestFalseCallBack.reset();
    ASSERT_FALSE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(inCallObserverTestFalseCallBack));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(false));
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(inCallObserverTestFalseCallBack);
    InCallObserver::GetInstance().UnRegisterObserver();
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: InCallCallBackReturn_05
 * @tc.desc: InCallCallBackReturn_05
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, InCallCallBackReturn_05, TestSize.Level1)
{
    auto telephonyObserver = std::make_unique<MediaTelephonyListener>().release();
    std::u16string phoneNumber = u"";
    telephonyObserver->OnCallStateUpdated(3, 1, phoneNumber); // 3 invalid slot id
    int32_t slotId = -1; // -1 all slot id
    for (int i = -1; i <= 9; i++) { // -1 9 foreach all state
        telephonyObserver->OnCallStateUpdated(slotId, i, phoneNumber);
    }
    const std::vector<sptr<OHOS::Telephony::SignalInformation>> vecSigInfo{};
    telephonyObserver->OnSignalInfoUpdated(slotId, vecSigInfo);
    telephonyObserver->OnNetworkStateUpdated(slotId, nullptr);
    const std::vector<sptr<OHOS::Telephony::CellInformation>> vecCellInfo{};
    telephonyObserver->OnCellInfoUpdated(slotId, vecCellInfo);
    telephonyObserver->OnSimStateUpdated(slotId, OHOS::Telephony::CardType::UNKNOWN_CARD,
        OHOS::Telephony::SimState::SIM_STATE_UNKNOWN, OHOS::Telephony::LockReason::SIM_NONE);
    telephonyObserver->OnCellularDataConnectStateUpdated(slotId, 0, 0);
    telephonyObserver->OnCellularDataFlowUpdated(slotId, 0);
    telephonyObserver->OnCfuIndicatorUpdated(slotId, false);
    telephonyObserver->OnVoiceMailMsgIndicatorUpdated(slotId, false);
    telephonyObserver->OnIccAccountUpdated();
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    telephonyObserver->OnCallStateUpdated(slotId, 6, phoneNumber); // CALL_STATUS_DISCONNECTED
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
}

/**
 * @tc.name: OnCallStateUpdated_01
 * @tc.desc: OnCallStateUpdated_01
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, OnCallStateUpdated_01, TestSize.Level1)
{
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().OnCallStateUpdated(true);
    ASSERT_TRUE(InCallObserver::GetInstance().IsInCall(false));
    InCallObserver::GetInstance().OnCallStateUpdated(false);
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(true));
}

/**
 * @tc.name: IsInCall_RefreshFalse_001
 * @tc.desc: IsInCall with refreshState=false covers L58 false branch
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, IsInCall_RefreshFalse_001, TestSize.Level1)
{
    InCallObserver::GetInstance().OnCallStateUpdated(false);
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
}

/**
 * @tc.name: OnCallStateUpdated_SameState_001
 * @tc.desc: OnCallStateUpdated with same state returns true (L104 true branch)
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, OnCallStateUpdated_SameState_001, TestSize.Level1)
{
    InCallObserver::GetInstance().OnCallStateUpdated(true);
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    InCallObserver::GetInstance().OnCallStateUpdated(false);
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(false));
}

/**
 * @tc.name: UnregisterCallBack_ExpiredInList_001
 * @tc.desc: Unregister with expired callback in list covers L89 nullptr path
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, UnregisterCallBack_ExpiredInList_001, TestSize.Level1)
{
    std::weak_ptr<InCallObserverCallBack> expiredCb =
        std::make_shared<InCallObserverTestCallBack>();
    expiredCb.reset();
    ASSERT_FALSE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(expiredCb));
    auto validCb = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(validCb));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(expiredCb);
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(validCb);
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: UnregisterCallBack_DifferentCallback_001
 * @tc.desc: Unregister with different callback covers L89 iter++ path
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, UnregisterCallBack_DifferentCallback_001, TestSize.Level1)
{
    auto cb1 = std::make_shared<InCallObserverTestCallBack>();
    auto cb2 = std::make_shared<InCallObserverTestCallBack>();
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(cb1));
    ASSERT_TRUE(InCallObserver::GetInstance().RegisterInCallObserverCallBack(cb2));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(cb1);
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(true));
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(cb2);
    InCallObserver::GetInstance().OnCallStateUpdated(false);
}

/**
 * @tc.name: MediaTelephonyListener_AllCallbacks_001
 * @tc.desc: Call all MediaTelephonyListener callback methods
 * @tc.type: FUNC
 */
HWTEST_F(InCallObserverInnerUnitTest, MediaTelephonyListener_AllCallbacks_001, TestSize.Level1)
{
    auto listener = std::make_unique<MediaTelephonyListener>().release();
    int32_t slotId = -1;
    std::u16string phoneNumber = u"";
    listener->OnCallStateUpdated(slotId, 0, phoneNumber);
    listener->OnCallStateUpdated(slotId, 1, phoneNumber);
    listener->OnCallStateUpdated(slotId, 2, phoneNumber);
    listener->OnCallStateUpdated(slotId, 3, phoneNumber);
    listener->OnCallStateUpdated(slotId, 4, phoneNumber);
    listener->OnCallStateUpdated(slotId, 5, phoneNumber);
    listener->OnCallStateUpdated(slotId, 7, phoneNumber);
    listener->OnCallStateUpdated(slotId, 8, phoneNumber);
    listener->OnCallStateUpdated(slotId, 9, phoneNumber);
    const std::vector<sptr<OHOS::Telephony::SignalInformation>> vecSigInfo{};
    listener->OnSignalInfoUpdated(slotId, vecSigInfo);
    listener->OnNetworkStateUpdated(slotId, nullptr);
    const std::vector<sptr<OHOS::Telephony::CellInformation>> vecCellInfo{};
    listener->OnCellInfoUpdated(slotId, vecCellInfo);
    listener->OnSimStateUpdated(slotId, OHOS::Telephony::CardType::UNKNOWN_CARD,
        OHOS::Telephony::SimState::SIM_STATE_UNKNOWN, OHOS::Telephony::LockReason::SIM_NONE);
    listener->OnCellularDataConnectStateUpdated(slotId, 0, 0);
    listener->OnCellularDataFlowUpdated(slotId, 0);
    listener->OnCfuIndicatorUpdated(slotId, true);
    listener->OnVoiceMailMsgIndicatorUpdated(slotId, true);
    listener->OnIccAccountUpdated();
    InCallObserver::GetInstance().OnCallStateUpdated(true);
    listener->OnCallStateUpdated(slotId, 6, phoneNumber);
    ASSERT_FALSE(InCallObserver::GetInstance().IsInCall(false));
}

} // namespace InCallObserverFuncUT
} // namespace Media
} // namespace OHOS
