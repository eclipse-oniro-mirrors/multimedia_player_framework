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

#include "screen_capture_controller_proxy_unittest.h"
#include "media_errors.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void ScreenCaptureControllerProxyTest::SetUp(void)
{
    mockRemote_ = new MockRemoteObject();
    ASSERT_NE(mockRemote_, nullptr);
    proxy_ = new ScreenCaptureControllerProxy(mockRemote_);
    ASSERT_NE(proxy_, nullptr);
}

void ScreenCaptureControllerProxyTest::TearDown(void)
{
    proxy_ = nullptr;
    mockRemote_ = nullptr;
}

/**
 * @tc.name    : DestroyStub_001
 * @tc.number  : DestroyStub_001
 * @tc.desc    : Test DestroyStub with successful SendRequest
 */
HWTEST_F(ScreenCaptureControllerProxyTest, DestroyStub_001, TestSize.Level1)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::DESTROY, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->DestroyStub();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : DestroyStub_002
 * @tc.number  : DestroyStub_002
 * @tc.desc    : Test DestroyStub when SendRequest fails
 */
HWTEST_F(ScreenCaptureControllerProxyTest, DestroyStub_002, TestSize.Level1)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::DESTROY, _, _, _)).WillOnce(Return(-1));
    int32_t ret = proxy_->DestroyStub();
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : DestroyStub_003
 * @tc.number  : DestroyStub_003
 * @tc.desc    : Test DestroyStub when reply contains error code
 */
HWTEST_F(ScreenCaptureControllerProxyTest, DestroyStub_003, TestSize.Level1)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::DESTROY, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
            reply.WriteInt32(MSERR_UNKNOWN);
            return 0;
        }));
    int32_t ret = proxy_->DestroyStub();
    EXPECT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name    : ReportAVScreenCaptureUserChoice_001
 * @tc.number  : ReportAVScreenCaptureUserChoice_001
 * @tc.desc    : Test ReportAVScreenCaptureUserChoice with valid params and success
 */
HWTEST_F(ScreenCaptureControllerProxyTest, ReportAVScreenCaptureUserChoice_001, TestSize.Level1)
{
    int32_t sessionId = 100;
    std::string choice = "MIC";
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::REPORT_USER_CHOICE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->ReportAVScreenCaptureUserChoice(sessionId, choice);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : ReportAVScreenCaptureUserChoice_002
 * @tc.number  : ReportAVScreenCaptureUserChoice_002
 * @tc.desc    : Test ReportAVScreenCaptureUserChoice when SendRequest fails
 */
HWTEST_F(ScreenCaptureControllerProxyTest, ReportAVScreenCaptureUserChoice_002, TestSize.Level1)
{
    int32_t sessionId = 200;
    std::string choice = "SPEAKER";
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::REPORT_USER_CHOICE, _, _, _))
        .WillOnce(Return(-1));
    int32_t ret = proxy_->ReportAVScreenCaptureUserChoice(sessionId, choice);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : ReportAVScreenCaptureUserChoice_003
 * @tc.number  : ReportAVScreenCaptureUserChoice_003
 * @tc.desc    : Test ReportAVScreenCaptureUserChoice when reply contains error
 */
HWTEST_F(ScreenCaptureControllerProxyTest, ReportAVScreenCaptureUserChoice_003, TestSize.Level1)
{
    int32_t sessionId = 300;
    std::string choice = "ALL_PLAYBACK";
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::REPORT_USER_CHOICE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
            reply.WriteInt32(MSERR_INVALID_VAL);
            return 0;
        }));
    int32_t ret = proxy_->ReportAVScreenCaptureUserChoice(sessionId, choice);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name    : GetAVScreenCaptureConfigurableParameters_001
 * @tc.number  : GetAVScreenCaptureConfigurableParameters_001
 * @tc.desc    : Test GetAVScreenCaptureConfigurableParameters with success and result string
 */
HWTEST_F(ScreenCaptureControllerProxyTest, GetAVScreenCaptureConfigurableParameters_001, TestSize.Level1)
{
    int32_t sessionId = 1;
    std::string expectedStr = "{\"width\":1080,\"height\":1920}";
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::GET_CONFIG_PARAM, _, _, _))
        .WillOnce(Invoke(
            [&expectedStr](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
                reply.WriteInt32(MSERR_OK);
                reply.WriteString(expectedStr);
                return 0;
            }));
    std::string resultStr;
    int32_t ret = proxy_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(resultStr, expectedStr);
}

/**
 * @tc.name    : GetAVScreenCaptureConfigurableParameters_002
 * @tc.number  : GetAVScreenCaptureConfigurableParameters_002
 * @tc.desc    : Test GetAVScreenCaptureConfigurableParameters when SendRequest fails
 */
HWTEST_F(ScreenCaptureControllerProxyTest, GetAVScreenCaptureConfigurableParameters_002, TestSize.Level1)
{
    int32_t sessionId = 2;
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::GET_CONFIG_PARAM, _, _, _))
        .WillOnce(Return(-1));
    std::string resultStr = "initial";
    int32_t ret = proxy_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : GetAVScreenCaptureConfigurableParameters_003
 * @tc.number  : GetAVScreenCaptureConfigurableParameters_003
 * @tc.desc    : Test GetAVScreenCaptureConfigurableParameters when server returns error
 */
HWTEST_F(ScreenCaptureControllerProxyTest, GetAVScreenCaptureConfigurableParameters_003, TestSize.Level1)
{
    int32_t sessionId = 3;
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardScreenCaptureController::GET_CONFIG_PARAM, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) -> int {
            reply.WriteInt32(MSERR_INVALID_OPERATION);
            reply.WriteString("");
            return 0;
        }));
    std::string resultStr;
    int32_t ret = proxy_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

} // namespace Media
} // namespace OHOS
