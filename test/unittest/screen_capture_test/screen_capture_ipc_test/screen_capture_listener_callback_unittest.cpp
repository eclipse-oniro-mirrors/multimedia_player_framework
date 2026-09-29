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

#include "i_standard_screen_capture_listener.h"
#include "screen_capture_listener_callback.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <memory>

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
    MOCK_METHOD(void, OnCaptureContentChanged, (AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area),
        (override));
    MOCK_METHOD(void, OnUserSelected, (ScreenCaptureUserSelectionInfo selectionInfo), (override));
    MOCK_METHOD(void, OnPrivacyProtect, (AVScreenCapturePrivacyProtect privacyProtect), (override));
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
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
 * @tc.desc    : OnError with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnError_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnError(_, _)).Times(0);
    nullCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnError_ValidListener_001
 * @tc.desc    : OnError with valid listener should forward with correct args
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnError_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100)).Times(1);
    validCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, 100);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnAudioBufferAvailable_NullListener_001
 * @tc.desc    : OnAudioBufferAvailable with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnAudioBufferAvailable_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnAudioBufferAvailable(_, _)).Times(0);
    nullCb_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnAudioBufferAvailable_ValidListener_001
 * @tc.desc    : OnAudioBufferAvailable with valid listener should forward with correct args
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnAudioBufferAvailable_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT)).Times(1);
    validCb_->OnAudioBufferAvailable(true, AudioCaptureSourceType::SOURCE_DEFAULT);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnVideoBufferAvailable_NullListener_001
 * @tc.desc    : OnVideoBufferAvailable with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnVideoBufferAvailable_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnVideoBufferAvailable(_)).Times(0);
    nullCb_->OnVideoBufferAvailable(true);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnVideoBufferAvailable_ValidListener_001
 * @tc.desc    : OnVideoBufferAvailable with valid listener should forward with correct args
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnVideoBufferAvailable_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnVideoBufferAvailable(true)).Times(1);
    validCb_->OnVideoBufferAvailable(true);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnStateChange_NullListener_001
 * @tc.desc    : OnStateChange with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnStateChange_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnStateChange(_)).Times(0);
    nullCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnStateChange_ValidListener_001
 * @tc.desc    : OnStateChange with valid listener should forward with correct args
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnStateChange_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED)).Times(1);
    validCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnDisplaySelected_NullListener_001
 * @tc.desc    : OnDisplaySelected with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnDisplaySelected_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnDisplaySelected(_)).Times(0);
    nullCb_->OnDisplaySelected(1);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnDisplaySelected_ValidListener_001
 * @tc.desc    : OnDisplaySelected with valid listener should forward with correct args
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnDisplaySelected_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnDisplaySelected(1)).Times(1);
    validCb_->OnDisplaySelected(1);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnCaptureContentChanged_NullListener_001
 * @tc.desc    : OnCaptureContentChanged with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnCaptureContentChanged_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnCaptureContentChanged(_, _)).Times(0);
    nullCb_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnCaptureContentChanged_ValidListener_001
 * @tc.desc    : OnCaptureContentChanged with valid listener should forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnCaptureContentChanged_ValidListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_,
        OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr))
        .Times(1);
    validCb_->OnCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnUserSelected_NullListener_001
 * @tc.desc    : OnUserSelected with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnUserSelected_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnUserSelected(_)).Times(0);
    ScreenCaptureUserSelectionInfo info;
    info.selectType = 1;
    nullCb_->OnUserSelected(info);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnUserSelected_ValidListener_001
 * @tc.desc    : OnUserSelected with valid listener should forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnUserSelected_ValidListener_001, TestSize.Level1)
{
    ScreenCaptureUserSelectionInfo info;
    info.selectType = 1;
    EXPECT_CALL(*mockListener_, OnUserSelected(_)).Times(1);
    validCb_->OnUserSelected(info);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnPrivacyProtect_NullListener_001
 * @tc.desc    : OnPrivacyProtect with null listener should not forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnPrivacyProtect_NullListener_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnPrivacyProtect(_)).Times(0);
    AVScreenCapturePrivacyProtect privacy{};
    nullCb_->OnPrivacyProtect(privacy);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

/**
 * @tc.name    : OnPrivacyProtect_ValidListener_001
 * @tc.desc    : OnPrivacyProtect with valid listener should forward
 */
HWTEST_F(ScreenCaptureListenerCallbackTest, OnPrivacyProtect_ValidListener_001, TestSize.Level1)
{
    AVScreenCapturePrivacyProtect privacy{};
    EXPECT_CALL(*mockListener_, OnPrivacyProtect(_)).Times(1);
    validCb_->OnPrivacyProtect(privacy);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockListener_.GetRefPtr()));
}

} // namespace Media
} // namespace OHOS
