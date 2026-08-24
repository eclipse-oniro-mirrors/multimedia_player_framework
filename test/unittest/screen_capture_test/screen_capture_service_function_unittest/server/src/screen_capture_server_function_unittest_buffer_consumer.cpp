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

#include "screen_cap_buffer_consumer_listener.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <memory>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class MockScreenCaptureCallBackForBuffer : public ScreenCaptureCallBack {
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

class ScreenCapBufferConsumerListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockCb_ = std::make_shared<MockScreenCaptureCallBackForBuffer>();
        listener_ = std::make_shared<ScreenCapBufferConsumerListener>(nullptr, mockCb_);
        ASSERT_NE(listener_, nullptr);
    }
    void TearDown(void) override
    {
        listener_ = nullptr;
        mockCb_ = nullptr;
    }

protected:
    std::shared_ptr<ScreenCapBufferConsumerListener> listener_;
    std::shared_ptr<MockScreenCaptureCallBackForBuffer> mockCb_;
};

HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailable_001, TestSize.Level1)
{
    listener_->OnBufferAvailable();
    EXPECT_FALSE(listener_->messageQueueSCB_.empty());
    EXPECT_EQ(listener_->messageQueueSCB_.front().type, SCBufferMessageType::GET_BUFFER);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ProcessVideoBufferCallBack_NullCb_001, TestSize.Level1)
{
    auto nullListener = std::make_shared<ScreenCapBufferConsumerListener>(nullptr, nullptr);
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    nullListener->ProcessVideoBufferCallBack();
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ProcessVideoBufferCallBack_WithCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(true)).Times(1);
    listener_->ProcessVideoBufferCallBack();
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseVideoBuffer_EmptyQueue_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->ReleaseVideoBuffer(), MSERR_OK);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, Release_EmptyQueue_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->Release(), MSERR_OK);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_EmptyQueue_001, TestSize.Level1)
{
    sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp = 0;
    OHOS::Rect damage{0, 0, 0, 0};
    EXPECT_EQ(listener_->AcquireVideoBuffer(buffer, fence, timestamp, damage), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, StopBufferThread_001, TestSize.Level1)
{
    listener_->StopBufferThread();
    EXPECT_FALSE(listener_->messageQueueSCB_.empty());
    EXPECT_EQ(listener_->messageQueueSCB_.back().type, SCBufferMessageType::EXIT);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, StartBufferThread_001, TestSize.Level1)
{
    EXPECT_TRUE(listener_->isSurfaceCbInThreadStopped_.load());
    EXPECT_EQ(listener_->StartBufferThread(), MSERR_OK);
    EXPECT_FALSE(listener_->isSurfaceCbInThreadStopped_.load());
    listener_->StopBufferThread();
    if (listener_->surfaceCbInThread_ && listener_->surfaceCbInThread_->joinable()) {
        listener_->surfaceCbInThread_->join();
    }
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, StartBufferThread_AlreadyRunning_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->StartBufferThread(), MSERR_OK);
    EXPECT_FALSE(listener_->isSurfaceCbInThreadStopped_.load());
    EXPECT_EQ(listener_->StartBufferThread(), MSERR_OK);
    listener_->StopBufferThread();
    if (listener_->surfaceCbInThread_ && listener_->surfaceCbInThread_->joinable()) {
        listener_->surfaceCbInThread_->join();
    }
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailableAction_NullConsumer_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    listener_->OnBufferAvailableAction();
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseBuffer_EmptyQueue_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->ReleaseBuffer(), MSERR_OK);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, Destructor_NullThread_001, TestSize.Level1)
{
    auto localListener = std::make_shared<ScreenCapBufferConsumerListener>(nullptr, nullptr);
    EXPECT_EQ(localListener->surfaceCbInThread_, nullptr);
    localListener.reset();
    SUCCEED();
}

} // namespace Media
} // namespace OHOS
