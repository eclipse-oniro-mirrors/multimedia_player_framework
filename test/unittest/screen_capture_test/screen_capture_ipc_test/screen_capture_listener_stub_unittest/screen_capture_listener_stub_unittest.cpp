/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "screen_capture_listener_stub_unittest.h"

#include <unistd.h>
#include <sys/stat.h>
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"
#include "screen_capture_client.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureListenerStubTest"};
}

namespace OHOS {
namespace Media {
void ScreenCaptureListenerStubTest::SetUpTestCase(void)
{
}

void ScreenCaptureListenerStubTest::TearDownTestCase(void)
{
}

void ScreenCaptureListenerStubTest::SetUp(void)
{
    SetHapPermission();
}

void ScreenCaptureListenerStubTest::TearDown(void)
{
}

void ScreenCaptureListenerStubTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info_, policy_);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

/**
 * @tc.name  : ~ScreenCaptureListenerStub
 * @tc.number: ~ScreenCaptureListenerStub
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, CreateReleaseStubObject_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : errorCode_001
 * @tc.number: errorCode_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, errorCode_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = screenCaptureListenerStub->OnRemoteRequest(-1, data, reply, option);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : OnCaptureContentChanged_001
 * @tc.number: OnCaptureContentChanged_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnCaptureContentChanged_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureListenerStub->GetDescriptor());
    ASSERT_EQ(token, true);
    bool isAreaExist = true;
    data.WriteBool(isAreaExist);
    AVScreenCaptureContentChangedEvent event = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    data.WriteInt32(event);
    ScreenCaptureRect area = {0, 0, 0, 0};
    area.x = 1;
    area.y = 1;
    area.width = 5;
    area.height = 5;
    data.WriteInt32(area.x);
    data.WriteInt32(area.y);
    data.WriteInt32(area.width);
    data.WriteInt32(area.height);
    int ret = screenCaptureListenerStub->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_CONTENT_CHANGED, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : OnCaptureContentChanged_002
 * @tc.number: OnCaptureContentChanged_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnCaptureContentChanged_002, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureListenerStub->GetDescriptor());
    ASSERT_EQ(token, true);
    bool isAreaExist = true;
    data.WriteBool(isAreaExist);
    AVScreenCaptureContentChangedEvent event = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    data.WriteInt32(event);
    ScreenCaptureRect area = {0, 0, 0, 0};
    area.x = 1;
    area.y = 1;
    area.width = 5;
    area.height = 5;
    data.WriteInt32(area.x);
    data.WriteInt32(area.y);
    data.WriteInt32(area.width);
    data.WriteInt32(area.height);
    screenCaptureListenerStub->callback_ = nullptr;
    int ret = screenCaptureListenerStub->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_CONTENT_CHANGED, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : OnError_001
 * @tc.number: OnError_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnError_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureListenerStub->GetDescriptor());
    ASSERT_EQ(token, true);
    ScreenCaptureErrorType errorType;
    int32_t errorCode = 0;
    errorType = ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL;
    data.WriteInt32(errorType);
    data.WriteInt32(errorCode);
    int ret = screenCaptureListenerStub->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_ERROR, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : OnError_002
 * @tc.number: OnError_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnError_002, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> serviceStub = ScreenCaptureServiceStub::Create();
    std::shared_ptr<ScreenCaptureClient> screenCaptureClient = ScreenCaptureClient::Create(serviceStub);
    ASSERT_NE(screenCaptureClient->listenerStub_, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureClient->listenerStub_->GetDescriptor());
    ASSERT_EQ(token, true);
    ScreenCaptureErrorType errorType;
    int32_t errorCode = 0;
    errorType = ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL;
    data.WriteInt32(errorType);
    data.WriteInt32(errorCode);
    screenCaptureClient->listenerStub_->callback_ = nullptr;
    int ret = screenCaptureClient->listenerStub_->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_ERROR, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureClient->listenerStub_ = nullptr;
}

/**
 * @tc.name  : OnUserSelected_001
 * @tc.number: OnUserSelected_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnUserSelected_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> serviceStub = ScreenCaptureServiceStub::Create();
    std::shared_ptr<ScreenCaptureClient> screenCaptureClient = ScreenCaptureClient::Create(serviceStub);
    ASSERT_NE(screenCaptureClient->listenerStub_, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureClient->listenerStub_->GetDescriptor());
    ASSERT_EQ(token, true);
    ScreenCaptureUserSelectionInfo selectionInfo;
    selectionInfo.selectType = 1;
    selectionInfo.displayIds = {100};
    token = data.WriteInt32(selectionInfo.selectType);
    ASSERT_EQ(token, true);
    token = data.WriteUInt64Vector(selectionInfo.displayIds);
    ASSERT_EQ(token, true);
    int ret = screenCaptureClient->listenerStub_->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_USER_SELECTED, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureClient->listenerStub_ = nullptr;
}

/**
 * @tc.name  : OnUserSelected_002
 * @tc.number: OnUserSelected_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnUserSelected_002, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureListenerStub->GetDescriptor());
    ASSERT_EQ(token, true);
    ScreenCaptureUserSelectionInfo selectionInfo;
    selectionInfo.selectType = 1;
    selectionInfo.displayIds = {100};
    token = data.WriteInt32(selectionInfo.selectType);
    ASSERT_EQ(token, true);
    token = data.WriteUInt64Vector(selectionInfo.displayIds);
    ASSERT_EQ(token, true);
    screenCaptureListenerStub->callback_ = nullptr;
    int ret = screenCaptureListenerStub->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_USER_SELECTED, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureListenerStub = nullptr;
}

/**
 * @tc.name  : OnPrivacyProtect_001
 * @tc.number: OnPrivacyProtect_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnPrivacyProtect_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> serviceStub = ScreenCaptureServiceStub::Create();
    std::shared_ptr<ScreenCaptureClient> screenCaptureClient = ScreenCaptureClient::Create(serviceStub);
    ASSERT_NE(screenCaptureClient->listenerStub_, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureClient->listenerStub_->GetDescriptor());
    ASSERT_EQ(token, true);
    AVScreenCapturePrivacyProtect privacyProtect;
    privacyProtect.appPrivacyProtection = true;
    privacyProtect.systemPrivacyProtection = true;
    data.WriteBool(privacyProtect.systemPrivacyProtection);
    data.WriteBool(privacyProtect.appPrivacyProtection);
    int ret = screenCaptureClient->listenerStub_->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_PRIVACY_PROTECT, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureClient->listenerStub_ = nullptr;
}

/**
 * @tc.name  : OnPrivacyProtect_002
 * @tc.number: OnPrivacyProtect_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerStubTest, OnPrivacyProtect_002, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureListenerStub->GetDescriptor());
    ASSERT_EQ(token, true);
    AVScreenCapturePrivacyProtect privacyProtect;
    privacyProtect.appPrivacyProtection = true;
    privacyProtect.systemPrivacyProtection = true;
    data.WriteBool(privacyProtect.systemPrivacyProtection);
    data.WriteBool(privacyProtect.appPrivacyProtection);
    screenCaptureListenerStub->callback_ = nullptr;
    int ret = screenCaptureListenerStub->OnRemoteRequest(
            IStandardScreenCaptureListener::ON_PRIVACY_PROTECT, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureListenerStub = nullptr;
}
} // Media
} // OHOS