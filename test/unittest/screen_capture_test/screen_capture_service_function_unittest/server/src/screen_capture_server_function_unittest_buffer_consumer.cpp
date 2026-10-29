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
#include "surface.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <chrono>
#include <memory>
#include <thread>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

constexpr int32_t TEST_BUFFER_WIDTH = 64;
constexpr int32_t TEST_BUFFER_HEIGHT = 64;

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
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ProcessVideoBufferCallBack_WithCb_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(true)).Times(1);
    listener_->ProcessVideoBufferCallBack();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
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
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, StartBufferThread_AlreadyRunning_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->StartBufferThread(), MSERR_OK);
    EXPECT_FALSE(listener_->isSurfaceCbInThreadStopped_.load());
    EXPECT_EQ(listener_->StartBufferThread(), MSERR_OK);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailableAction_NullConsumer_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    listener_->OnBufferAvailableAction();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseBuffer_EmptyQueue_001, TestSize.Level1)
{
    EXPECT_EQ(listener_->ReleaseBuffer(), MSERR_OK);
}

// Push a (null-buffer) entry so we exercise the non-empty control-flow paths
// without depending on a real producer->consumer buffer flow.
static void PushNullEntry(ScreenCapBufferConsumerListener &l, int32_t fence = -1)
{
    sptr<OHOS::SurfaceBuffer> nullBuf = nullptr;
    OHOS::Rect damage{0, 0, 0, 0};
    l.availBuffers_.push(std::make_unique<SurfaceBufferEntry>(nullBuf, fence, 0, damage));
}

// Create a consumer Surface with one real buffer queued (registers a listener, then producer
// RequestBuffer + FlushBuffer). usage includes BUFFER_USAGE_MEM_MMZ_CACHE so OnBufferAvailableAction's
static sptr<OHOS::Surface> MakeConsumerWithQueuedBuffer(sptr<OHOS::SurfaceBuffer> &outBuf,
    const std::shared_ptr<ScreenCaptureCallBack> &cb,
    sptr<ScreenCapBufferConsumerListener> &outRegListener)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer("sc_cov_test");
    if (consumer == nullptr) {
        return nullptr;
    }
    auto regListener = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(consumer, cb);
    if (regListener == nullptr) {
        return nullptr;
    }
    sptr<OHOS::IBufferConsumerListener> listenerObj = regListener;
    consumer->RegisterConsumerListener(listenerObj); // required before RequestBuffer (else error 412)
    sptr<OHOS::IBufferProducer> producerObj = consumer->GetProducer();
    auto producer = OHOS::Surface::CreateSurfaceAsProducer(producerObj);
    if (producer == nullptr) {
        return nullptr;
    }
    sptr<OHOS::SurfaceBuffer> buf = nullptr;
    int32_t fence = -1;
    OHOS::BufferRequestConfig config;
    config.width = TEST_BUFFER_WIDTH;
    config.height = TEST_BUFFER_HEIGHT;
    config.format = GRAPHIC_PIXEL_FMT_RGBA_8888;
    config.usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE;
    config.timeout = 0;
    if (producer->RequestBuffer(buf, fence, config) != GSERROR_OK) {
        return nullptr;
    }
    OHOS::BufferFlushConfig flushConfig {};
    if (producer->FlushBuffer(buf, fence, flushConfig) != GSERROR_OK) {
        return nullptr;
    }
    outBuf = buf;
    outRegListener = regListener; // keep alive; caller MUST UnregisterConsumerListener() before it goes out of scope
    return consumer;
}

// consumer_ with a queued real buffer -> OnBufferAvailableAction
HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailableAction_WithBuffer_001, TestSize.Level1)
{
    sptr<OHOS::SurfaceBuffer> buf = nullptr;
    sptr<ScreenCapBufferConsumerListener> regListener;
    auto consumer = MakeConsumerWithQueuedBuffer(buf, mockCb_, regListener);
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0);
    listener_->OnBufferAvailableAction();
    consumer->UnregisterConsumerListener();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
    EXPECT_EQ(listener_->availBuffers_.size(), 0u);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailableAction_QueueFull_001, TestSize.Level1)
{
    sptr<OHOS::SurfaceBuffer> buf = nullptr;
    sptr<ScreenCapBufferConsumerListener> regListener;
    auto consumer = MakeConsumerWithQueuedBuffer(buf, mockCb_, regListener);
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    for (int i = 0; i < 4; ++i) {
        PushNullEntry(*listener_);
    }
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0); // drop -> no callback
    listener_->OnBufferAvailableAction();
    consumer->UnregisterConsumerListener();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, SurfaceBufferThreadRun_QueueOverflowExit_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    for (int i = 0; i < 6; ++i) {
        listener_->messageQueueSCB_.push({SCBufferMessageType::EXIT, ""});
    }
    ASSERT_EQ(listener_->StartBufferThread(), MSERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(listener_->isSurfaceCbInThreadStopped_.load());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_HasEntry_001, TestSize.Level1)
{
    PushNullEntry(*listener_);
    sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    int32_t fence = -2;
    int64_t timestamp = -1;
    OHOS::Rect damage{1, 2, 3, 4};
    EXPECT_EQ(listener_->AcquireVideoBuffer(buffer, fence, timestamp, damage), MSERR_OK);
    EXPECT_EQ(buffer, nullptr);
    EXPECT_EQ(fence, -1);
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseVideoBuffer_HasEntry_NullConsumer_001, TestSize.Level1)
{
    PushNullEntry(*listener_);
    EXPECT_EQ(listener_->ReleaseVideoBuffer(), MSERR_OK);
    EXPECT_TRUE(listener_->availBuffers_.empty());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, Release_HasEntry_NullConsumer_001, TestSize.Level1)
{
    PushNullEntry(*listener_);
    PushNullEntry(*listener_);
    EXPECT_EQ(listener_->Release(), MSERR_OK);
    EXPECT_TRUE(listener_->availBuffers_.empty());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseBuffer_HasEntry_NullConsumer_001, TestSize.Level1)
{
    PushNullEntry(*listener_);
    EXPECT_EQ(listener_->ReleaseBuffer(), MSERR_OK);
    EXPECT_TRUE(listener_->availBuffers_.empty());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, Destructor_RunningThread_001, TestSize.Level1)
{
    auto localListener = std::make_shared<ScreenCapBufferConsumerListener>(nullptr, nullptr);
    ASSERT_EQ(localListener->StartBufferThread(), MSERR_OK);
    EXPECT_FALSE(localListener->isSurfaceCbInThreadStopped_.load());
    localListener->StopBufferThread();
    for (int i = 0; i < 50 && !localListener->isSurfaceCbInThreadStopped_.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(localListener->isSurfaceCbInThreadStopped_.load());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailableAction_NonNullConsumer_NoBuffer_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_)).Times(0); // no buffer -> no callback
    listener_->OnBufferAvailableAction();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, SurfaceBufferThreadRun_ProcessMessages_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    ASSERT_EQ(listener_->StartBufferThread(), MSERR_OK);
    listener_->OnBufferAvailable(); // push GET_BUFFER
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    listener_->StopBufferThread(); // push EXIT
    for (int i = 0; i < 50 && !listener_->isSurfaceCbInThreadStopped_.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(listener_->isSurfaceCbInThreadStopped_.load());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, SurfaceBufferThreadRun_QueueOverflow_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    for (int i = 0; i < 6; ++i) {
        listener_->messageQueueSCB_.push({SCBufferMessageType::GET_BUFFER, "overflow"});
    }
    ASSERT_EQ(listener_->StartBufferThread(), MSERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    listener_->StopBufferThread();
    for (int i = 0; i < 50 && !listener_->isSurfaceCbInThreadStopped_.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(listener_->isSurfaceCbInThreadStopped_.load());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseVideoBuffer_NonNullConsumer_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    PushNullEntry(*listener_);
    EXPECT_EQ(listener_->ReleaseVideoBuffer(), MSERR_OK);
    EXPECT_TRUE(listener_->availBuffers_.empty());
}

HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseBuffer_NonNullConsumer_001, TestSize.Level1)
{
    auto consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    listener_->consumer_ = consumer;
    PushNullEntry(*listener_);
    PushNullEntry(*listener_);
    EXPECT_EQ(listener_->ReleaseBuffer(), MSERR_OK);
    EXPECT_TRUE(listener_->availBuffers_.empty());
}

} // namespace Media
} // namespace OHOS

