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
    bool StopAndRelease(AVScreenCaptureStateCode state)
    {
        return true;
    }
    bool NotifyStopAndRelease(AVScreenCaptureStateCode state)
    {
        return true;
    }
    void Release() {}
    bool TelCallStateUpdated(bool isInCall)
    {
        return true;
    }
    bool NotifyTelCallStateUpdated(bool isInCall)
    {
        return true;
    }
};

class InCallObserverTestFalseCallBack : public InCallObserverCallBack {
public:
    InCallObserverTestFalseCallBack() {}
    ~InCallObserverTestFalseCallBack() {}
    bool StopAndRelease(AVScreenCaptureStateCode state)
    {
        return false;
    }
    bool NotifyStopAndRelease(AVScreenCaptureStateCode state)
    {
        return false;
    }
    void Release() {}
    bool TelCallStateUpdated(bool isInCall)
    {
        return false;
    }
    bool NotifyTelCallStateUpdated(bool isInCall)
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
    ASSERT_TRUE(inCallObserverCallBack->StopAndRelease(
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL));
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
    telephonyObserver->OnCallStateUpdated(slotId, 6, phoneNumber); // CALL_STATUS_DISCONNECTED
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
    InCallObserver::GetInstance().IsInCall(false);
    ASSERT_TRUE(InCallObserver::GetInstance().OnCallStateUpdated(false));
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
} // namespace InCallObserverFuncUT
} // namespace Media
} // namespace OHOS
