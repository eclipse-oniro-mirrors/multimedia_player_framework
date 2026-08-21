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

#include "screen_capture_callback_proxy.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <memory>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class MockScreenCaptureCallBack : public ScreenCaptureCallBack {
public:
    MOCK_METHOD(void, OnError, (ScreenCaptureErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnAudioBufferAvailable, (bool isReady, AudioCaptureSourceType type), (override));
    MOCK_METHOD(void, OnVideoBufferAvailable, (bool isReady), (override));
    MOCK_METHOD(void, OnStateChange, (AVScreenCaptureStateCode stateCode), (override));
    MOCK_METHOD(void, OnDisplaySelected, (uint64_t displayId), (override));
    MOCK_METHOD(void, OnCaptureContentChanged, (AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area),
        (override));
    MOCK_METHOD(void, OnUserSelected, (ScreenCaptureUserSelectionInfo selectionInfo), (override));
    MOCK_METHOD(void, OnPrivacyProtect, (AVScreenCapturePrivacyProtect privacyProtect), (override));
};

class ScreenCaptureCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        proxy_ = std::make_shared<ScreenCaptureCallbackProxy>();
        ASSERT_NE(proxy_, nullptr);
    }
    void TearDown(void) override
    {
        proxy_ = nullptr;
    }

protected:
    std::shared_ptr<ScreenCaptureCallbackProxy> proxy_;
    std::shared_ptr<MockScreenCaptureCallBack> mockCb_ = std::make_shared<MockScreenCaptureCallBack>();
};

/**
 * @tc.name    : OnError_NullCb_001
 * @tc.number  : OnError_NullCb_001
 * @tc.desc    : Test OnError when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnError_NullCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnError(_, _)).Times(0);
    proxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnError(_, _)).Times(1);
    proxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
}

/**
 * @tc.name    : OnAudioBufferAvailable_NullCb_001
 * @tc.number  : OnAudioBufferAvailable_NullCb_001
 * @tc.desc    : Test OnAudioBufferAvailable when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnAudioBufferAvailable_NullCb_001, TestSize.Level1)
{
    proxy_->SetBufferActive(true);
    EXPECT_CALL(*mockCb_, OnAudioBufferAvailable(_, _)).Times(0);
    proxy_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT)).Times(1);
    proxy_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
}

/**
 * @tc.name    : OnVideoBufferAvailable_NullCb_001
 * @tc.number  : OnVideoBufferAvailable_NullCb_001
 * @tc.desc    : Test OnVideoBufferAvailable when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnVideoBufferAvailable_NullCb_001, TestSize.Level1)
{
    proxy_->SetBufferActive(true);
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    proxy_->OnVideoBufferAvailable(true);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(true)).Times(1);
    proxy_->OnVideoBufferAvailable(true);
}

/**
 * @tc.name    : OnStateChange_NullCb_001
 * @tc.number  : OnStateChange_NullCb_001
 * @tc.desc    : Test OnStateChange when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnStateChange_NullCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnStateChange(_)).Times(0);
    proxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED)).Times(1);
    proxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
}

/**
 * @tc.name    : OnDisplaySelected_NullCb_001
 * @tc.number  : OnDisplaySelected_NullCb_001
 * @tc.desc    : Test OnDisplaySelected when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnDisplaySelected_NullCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnDisplaySelected(_)).Times(0);
    proxy_->OnDisplaySelected(1);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnDisplaySelected(1)).Times(1);
    proxy_->OnDisplaySelected(1);
}

/**
 * @tc.name    : OnCaptureContentChanged_NullCb_001
 * @tc.number  : OnCaptureContentChanged_NullCb_001
 * @tc.desc    : Test OnCaptureContentChanged when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnCaptureContentChanged_NullCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnCaptureContentChanged(_, _)).Times(0);
    proxy_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnCaptureContentChanged(_, _)).Times(1);
    proxy_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
}

/**
 * @tc.name    : OnUserSelected_NullCb_001
 * @tc.number  : OnUserSelected_NullCb_001
 * @tc.desc    : Test OnUserSelected when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnUserSelected_NullCb_001, TestSize.Level1)
{
    ScreenCaptureUserSelectionInfo info;
    info.selectType = 1;
    EXPECT_CALL(*mockCb_, OnUserSelected(_)).Times(0);
    proxy_->OnUserSelected(info);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnUserSelected(_)).Times(1);
    proxy_->OnUserSelected(info);
}

/**
 * @tc.name    : OnPrivacyProtect_NullCb_001
 * @tc.number  : OnPrivacyProtect_NullCb_001
 * @tc.desc    : Test OnPrivacyProtect when screenCaptureCb_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnPrivacyProtect_NullCb_001, TestSize.Level1)
{
    AVScreenCapturePrivacyProtect privacy{};
    EXPECT_CALL(*mockCb_, OnPrivacyProtect(_)).Times(0);
    proxy_->OnPrivacyProtect(privacy);
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnPrivacyProtect(_)).Times(1);
    proxy_->OnPrivacyProtect(privacy);
}

/**
 * @tc.name    : OnAudioBufferAvailable_BufferInactive_001
 * @tc.number  : OnAudioBufferAvailable_BufferInactive_001
 * @tc.desc    : Test OnAudioBufferAvailable when bufferActive_ is false (early return branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnAudioBufferAvailable_BufferInactive_001, TestSize.Level1)
{
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnAudioBufferAvailable(_, _)).Times(0);
    proxy_->SetBufferActive(false);
    proxy_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
}

/**
 * @tc.name    : OnVideoBufferAvailable_BufferInactive_001
 * @tc.number  : OnVideoBufferAvailable_BufferInactive_001
 * @tc.desc    : Test OnVideoBufferAvailable when bufferActive_ is false (early return branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnVideoBufferAvailable_BufferInactive_001, TestSize.Level1)
{
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    proxy_->SetBufferActive(false);
    proxy_->OnVideoBufferAvailable(true);
}

/**
 * @tc.name    : OnStateChange_InvalidState_001
 * @tc.number  : OnStateChange_InvalidState_001
 * @tc.desc    : Test OnStateChange with SCREEN_CAPTURE_STATE_INVALID (early return branch)
 */
HWTEST_F(ScreenCaptureCallbackProxyTest, OnStateChange_InvalidState_001, TestSize.Level1)
{
    proxy_->SetCallback(mockCb_);
    EXPECT_CALL(*mockCb_, OnStateChange(_)).Times(0);
    proxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
}

} // namespace Media
} // namespace OHOS
