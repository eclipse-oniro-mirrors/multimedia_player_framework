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

#include <gmock/gmock.h>
#include <memory>
#include "screen_capture_listener_callback.h"
#include "i_standard_screen_capture_listener.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class MockScreenCaptureListener : public IStandardScreenCaptureListener {
public:
    MOCK_METHOD(void, OnError, (ScreenCaptureErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnAudioBufferAvailable, (bool isReady, AudioCaptureSourceType type), (override));
    MOCK_METHOD(void, OnVideoBufferAvailable, (bool isReady), (override));
    MOCK_METHOD(void, OnStateChange, (AVScreenCaptureStateCode stateCode), (override));
    MOCK_METHOD(void, OnDisplaySelected, (uint64_t displayId), (override));
    MOCK_METHOD(void, OnCaptureContentChanged,
        (AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area), (override));
    MOCK_METHOD(void, OnUserSelected, (ScreenCaptureUserSelectionInfo selectionInfo), (override));
    MOCK_METHOD(void, OnPrivacyProtect, (AVScreenCapturePrivacyProtect privacyProtect), (override));
    sptr<IRemoteObject> AsObject() override { return nullptr; }
};

class ScreenCaptureListenerCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        nullCb_ = std::make_shared<ScreenCaptureListenerCallback>(nullptr);
        ASSERT_NE(nullCb_, nullptr);
        mockListener_ = new MockScreenCaptureListener();
        validCb_ = std::make_shared<ScreenCaptureListenerCallback>(mockListener_);
        ASSERT_NE(validCb_, nullptr);
    }
    void TearDown(void) override
    {
        nullCb_ = nullptr;
        validCb_ = nullptr;
        mockListener_ = nullptr;
    }

protected:
    std::shared_ptr<ScreenCaptureListenerCallback> nullCb_;
    std::shared_ptr<ScreenCaptureListenerCallback> validCb_;
    sptr<MockScreenCaptureListener> mockListener_;
};

/**
 * @tc.name    : OnError_NullListener_001
 * @tc.number  : OnError_NullListener_001
 * @tc.desc    : Test OnError when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnError_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnError(_, _)).Times(0);
    nullCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
    EXPECT_CALL(*mockListener_, OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100)).Times(1);
    validCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
}

/**
 * @tc.name    : OnAudioBufferAvailable_NullListener_001
 * @tc.number  : OnAudioBufferAvailable_NullListener_001
 * @tc.desc    : Test OnAudioBufferAvailable when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnAudioBufferAvailable_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnAudioBufferAvailable(_, _)).Times(0);
    nullCb_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
    EXPECT_CALL(*mockListener_, OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT)).Times(1);
    validCb_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
}

/**
 * @tc.name    : OnVideoBufferAvailable_NullListener_001
 * @tc.number  : OnVideoBufferAvailable_NullListener_001
 * @tc.desc    : Test OnVideoBufferAvailable when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnVideoBufferAvailable_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnVideoBufferAvailable(_)).Times(0);
    nullCb_->OnVideoBufferAvailable(true);
    EXPECT_CALL(*mockListener_, OnVideoBufferAvailable(true)).Times(1);
    validCb_->OnVideoBufferAvailable(true);
}

/**
 * @tc.name    : OnStateChange_NullListener_001
 * @tc.number  : OnStateChange_NullListener_001
 * @tc.desc    : Test OnStateChange when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnStateChange_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnStateChange(_)).Times(0);
    nullCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    EXPECT_CALL(*mockListener_, OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED)).Times(1);
    validCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
}

/**
 * @tc.name    : OnDisplaySelected_NullListener_001
 * @tc.number  : OnDisplaySelected_NullListener_001
 * @tc.desc    : Test OnDisplaySelected when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnDisplaySelected_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnDisplaySelected(_)).Times(0);
    nullCb_->OnDisplaySelected(1);
    EXPECT_CALL(*mockListener_, OnDisplaySelected(1)).Times(1);
    validCb_->OnDisplaySelected(1);
}

/**
 * @tc.name    : OnCaptureContentChanged_NullListener_001
 * @tc.number  : OnCaptureContentChanged_NullListener_001
 * @tc.desc    : Test OnCaptureContentChanged when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnCaptureContentChanged_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnCaptureContentChanged(_, _)).Times(0);
    nullCb_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    EXPECT_CALL(*mockListener_, OnCaptureContentChanged(_, _)).Times(1);
    validCb_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
}

/**
 * @tc.name    : OnUserSelected_NullListener_001
 * @tc.number  : OnUserSelected_NullListener_001
 * @tc.desc    : Test OnUserSelected when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnUserSelected_NullListener_001, TestSize.Level1)
{
    ScreenCaptureUserSelectionInfo info;
    info.selectType = 1;
    EXPECT_CALL(*mockListener_, OnUserSelected(_)).Times(0);
    nullCb_->OnUserSelected(info);
    EXPECT_CALL(*mockListener_, OnUserSelected(_)).Times(1);
    validCb_->OnUserSelected(info);
}

/**
 * @tc.name    : OnPrivacyProtect_NullListener_001
 * @tc.number  : OnPrivacyProtect_NullListener_001
 * @tc.desc    : Test OnPrivacyProtect when listener_ is nullptr (null branch)
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnPrivacyProtect_NullListener_001, TestSize.Level1)
{
    AVScreenCapturePrivacyProtect privacy{};
    EXPECT_CALL(*mockListener_, OnPrivacyProtect(_)).Times(0);
    nullCb_->OnPrivacyProtect(privacy);
    EXPECT_CALL(*mockListener_, OnPrivacyProtect(_)).Times(1);
    validCb_->OnPrivacyProtect(privacy);
}

} // namespace Media
} // namespace OHOS
