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

#include "screen_capture_listener_proxy_unittest.h"

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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureListenerProxyTest"};
}

namespace OHOS {
namespace Media {
namespace {
// Records the callback invocations dispatched by ScreenCaptureListenerStub so the proxy IPC
// serialization can be verified.
class ProxyTestCallback : public ScreenCaptureCallBack {
public:
    int32_t errorCallCount = 0;
    ScreenCaptureErrorType lastErrorType = ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL;
    int32_t lastErrorCode = -1;
    int32_t stateChangeCount = 0;
    AVScreenCaptureStateCode lastStateCode = AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED;
    int32_t audioBufferCount = 0;
    bool lastAudioReady = false;
    AudioCaptureSourceType lastAudioType = AudioCaptureSourceType::SOURCE_DEFAULT;
    int32_t displaySelectedCount = 0;
    uint64_t lastDisplayId = 0;
    int32_t contentChangedCount = 0;
    AVScreenCaptureContentChangedEvent lastEvent =
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    bool lastAreaExist = false;
    ScreenCaptureRect lastArea = {0, 0, 0, 0};
    int32_t userSelectedCount = 0;
    ScreenCaptureUserSelectionInfo lastSelectionInfo;
    int32_t privacyProtectCount = 0;
    AVScreenCapturePrivacyProtect lastPrivacyProtect;

    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override
    {
        errorCallCount++;
        lastErrorType = errorType;
        lastErrorCode = errorCode;
    }

    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override
    {
        audioBufferCount++;
        lastAudioReady = isReady;
        lastAudioType = type;
    }

    void OnDisplaySelected(uint64_t displayId) override
    {
        displaySelectedCount++;
        lastDisplayId = displayId;
    }

    void OnVideoBufferAvailable(bool isReady) override
    {
        (void)isReady;
    }

    void OnStateChange(AVScreenCaptureStateCode stateCode) override
    {
        stateChangeCount++;
        lastStateCode = stateCode;
    }

    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area) override
    {
        contentChangedCount++;
        lastEvent = event;
        lastAreaExist = (area != nullptr);
        if (area != nullptr) {
            lastArea = *area;
        }
    }

    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override
    {
        userSelectedCount++;
        lastSelectionInfo = selectionInfo;
    }

    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) override
    {
        privacyProtectCount++;
        lastPrivacyProtect = privacyProtect;
    }
};
} // namespace

void ScreenCaptureListenerProxyTest::SetUpTestCase(void)
{
}

void ScreenCaptureListenerProxyTest::TearDownTestCase(void)
{
}

void ScreenCaptureListenerProxyTest::SetUp(void)
{
    SetHapPermission();
}

void ScreenCaptureListenerProxyTest::TearDown(void)
{
}

void ScreenCaptureListenerProxyTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info_, policy_);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

/**
 * @tc.name  : ScreenCaptureListenerStub
 * @tc.number: ScreenCaptureListenerStub
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, CreateReleaseStubObject_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);
    AVScreenCaptureStateCode stateCode = AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED;
    proxy->OnStateChange(stateCode);
    EXPECT_EQ(callback->stateChangeCount, 1);
    EXPECT_EQ(callback->lastStateCode, stateCode);
    proxy = nullptr;
}

/**
 * @tc.name  : OnCaptureContentChanged_001
 * @tc.number: OnCaptureContentChanged_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnCaptureContentChanged_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    AVScreenCaptureContentChangedEvent event = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    ScreenCaptureRect area = {0, 0, 5, 5};
    proxy->OnCaptureContentChanged(event, &area);
    EXPECT_EQ(callback->contentChangedCount, 1);
    EXPECT_EQ(callback->lastEvent, event);
    EXPECT_TRUE(callback->lastAreaExist);
    EXPECT_EQ(callback->lastArea.width, 5);
    EXPECT_EQ(callback->lastArea.height, 5);
    proxy = nullptr;
}

/**
 * @tc.name  : OnCaptureContentChanged_002
 * @tc.number: OnCaptureContentChanged_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnCaptureContentChanged_002, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    AVScreenCaptureContentChangedEvent event = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    proxy->OnCaptureContentChanged(event, nullptr);
    EXPECT_EQ(callback->contentChangedCount, 1);
    EXPECT_EQ(callback->lastEvent, event);
    EXPECT_FALSE(callback->lastAreaExist);
    proxy = nullptr;
}

/**
 * @tc.name  : OnError_001
 * @tc.number: OnError_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnError_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    ScreenCaptureErrorType errorType;
    int32_t errorCode = 0;
    errorType = ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL;
    proxy->OnError(errorType, errorCode);
    EXPECT_EQ(callback->errorCallCount, 1);
    EXPECT_EQ(callback->lastErrorType, errorType);
    EXPECT_EQ(callback->lastErrorCode, errorCode);
    proxy = nullptr;
}

/**
 * @tc.name  : OnUserSelected_001
 * @tc.number: OnUserSelected_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnUserSelected_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    ScreenCaptureUserSelectionInfo selectionInfo;
    selectionInfo.selectType = 1;
    selectionInfo.displayIds = {100};
    proxy->OnUserSelected(selectionInfo);
    EXPECT_EQ(callback->userSelectedCount, 1);
    EXPECT_EQ(callback->lastSelectionInfo.selectType, 1);
    EXPECT_EQ(callback->lastSelectionInfo.displayIds, std::vector<uint64_t>({100}));
    proxy = nullptr;
}

/**
 * @tc.name  : OnPrivacyProtect_001
 * @tc.number: OnPrivacyProtect_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnPrivacyProtect_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    AVScreenCapturePrivacyProtect privacyProtect;
    privacyProtect.appPrivacyProtection = true;
    privacyProtect.systemPrivacyProtection = true;
    proxy->OnPrivacyProtect(privacyProtect);
    EXPECT_EQ(callback->privacyProtectCount, 1);
    EXPECT_TRUE(callback->lastPrivacyProtect.appPrivacyProtection);
    EXPECT_TRUE(callback->lastPrivacyProtect.systemPrivacyProtection);
    proxy = nullptr;
}
/**
 * @tc.name  : OnAudioBufferAvailable_001
 * @tc.number: OnAudioBufferAvailable_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnAudioBufferAvailable_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    proxy->OnAudioBufferAvailable(true, AudioCaptureSourceType::ALL_PLAYBACK);
    EXPECT_EQ(callback->audioBufferCount, 1);
    EXPECT_TRUE(callback->lastAudioReady);
    EXPECT_EQ(callback->lastAudioType, AudioCaptureSourceType::ALL_PLAYBACK);
    proxy = nullptr;
}

/**
 * @tc.name  : OnDisplaySelected_001
 * @tc.number: OnDisplaySelected_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureListenerProxyTest, OnDisplaySelected_001, TestSize.Level1)
{
    sptr<ScreenCaptureListenerStub> screenCaptureListenerStub =
        new(std::nothrow) ScreenCaptureListenerStub();
    ASSERT_NE(screenCaptureListenerStub, nullptr);
    sptr<IRemoteObject> remoteObject = screenCaptureListenerStub->AsObject();
    ASSERT_NE(remoteObject, nullptr);
    sptr<ScreenCaptureListenerProxy> proxy = new(std::nothrow) ScreenCaptureListenerProxy(remoteObject);
    ASSERT_NE(proxy, nullptr);
    auto callback = std::make_shared<ProxyTestCallback>();
    screenCaptureListenerStub->SetScreenCaptureCallback(callback);

    proxy->OnDisplaySelected(12345);
    EXPECT_EQ(callback->displaySelectedCount, 1);
    EXPECT_EQ(callback->lastDisplayId, 12345u);
    proxy = nullptr;
}
} // Media
} // OHOS