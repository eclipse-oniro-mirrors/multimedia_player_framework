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

#include "media_errors.h"
#include "mock/mock_remote_object.h"
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace testing::ext;
using namespace OHOS::Media;
using testing::Invoke;
using testing::Return;

namespace OHOS {
namespace Media {

// L34 status_ != UNKNOWN -> return (branch 1)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_StatusNotUnknown_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::STARTED;
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, nullptr, 0);
    EXPECT_EQ(conn->status_.load(), ConnectStatus::STARTED);
}

// L34 status_ == UNKNOWN + L35 remoteObject == nullptr -> return (L35 branch 1)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_NullRemote_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, nullptr, 0);
    EXPECT_EQ(conn->status_.load(), ConnectStatus::UNKNOWN);
}

// L35 branch 0 (non-null remote) + L52 branch 0 (SendRequest OK) + L53 branch 0 (STARTING -> STARTED)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_Success_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _)).WillOnce(Return(0));
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, mockObj, 0);
    ASSERT_EQ(conn->status_.load(), ConnectStatus::STARTED);
}

// L52 branch 1 (SendRequest fails -> early return)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_SendRequestFail_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _)).WillOnce(Return(-1));
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, mockObj, 0);
    ASSERT_EQ(conn->status_.load(), ConnectStatus::STARTING);
}

// L53 branch 1 + L55 branch 0: status_ changed to CLOSING during SendRequest -> CloseDialog called
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_StatusCLOSING_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _))
        .WillOnce(Invoke([&conn](uint32_t, MessageParcel &, MessageParcel &, MessageOption &) {
            conn->status_ = ConnectStatus::CLOSING;
            return 0;
        }))
        .WillOnce(Return(0));
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, mockObj, 0);
    ASSERT_EQ(conn->status_.load(), ConnectStatus::CLOSED);
}

// L55 branch 1: status_ changed to CLOSED (not STARTING, not CLOSING) during SendRequest -> no action
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnConnectDone_StatusOther_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _))
        .WillOnce(Invoke([&conn](uint32_t, MessageParcel &, MessageParcel &, MessageOption &) {
            conn->status_ = ConnectStatus::CLOSED;
            return 0;
        }));
    AppExecFwk::ElementName element;
    conn->OnAbilityConnectDone(element, mockObj, 0);
    ASSERT_EQ(conn->status_.load(), ConnectStatus::CLOSED);
}

// L70 branch 1 (status_ != STARTED -> return true)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_CloseDialog_StatusNotStarted_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::UNKNOWN;
    EXPECT_TRUE(conn->CloseDialog());
    EXPECT_EQ(conn->status_.load(), ConnectStatus::CLOSING);
}

// L70 branch 0 + L79 branch 1: status_ == STARTED + remoteObject_ == nullptr -> return true
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_CloseDialog_StartedNullRemote_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::STARTED;
    conn->remoteObject_ = nullptr;
    EXPECT_TRUE(conn->CloseDialog());
    EXPECT_EQ(conn->status_.load(), ConnectStatus::CLOSING);
}

// L79 branch 0 + L83 branch 0: CloseDialog with non-null remoteObject_, SendRequest OK
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_CloseDialog_Success_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::STARTED;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    conn->remoteObject_ = mockObj;
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(conn->CloseDialog());
    ASSERT_EQ(conn->status_.load(), ConnectStatus::CLOSED);
}

// L83 branch 1: CloseDialog with non-null remoteObject_, SendRequest fails -> return false
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_CloseDialog_SendRequestFail_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    conn->status_ = ConnectStatus::STARTED;
    auto mockObj = sptr<MockRemoteObject>::MakeSptr();
    conn->remoteObject_ = mockObj;
    EXPECT_CALL(*mockObj, SendRequest(_, _, _, _)).WillOnce(Return(-1));
    EXPECT_FALSE(conn->CloseDialog());
    ASSERT_EQ(conn->status_.load(), ConnectStatus::CLOSED);
}

// OnAbilityDisconnectDone — covers the function (no branches, line coverage)
HWTEST_F(ScreenCaptureServerFunctionTest, UIExtConn_OnDisconnectDone_001, TestSize.Level2)
{
    auto conn = sptr<UIExtensionAbilityConnection>(new UIExtensionAbilityConnection("test"));
    AppExecFwk::ElementName element;
    conn->OnAbilityDisconnectDone(element, 0);
    ASSERT_EQ(conn->status_.load(), ConnectStatus::UNKNOWN);
}

} // namespace Media
} // namespace OHOS
