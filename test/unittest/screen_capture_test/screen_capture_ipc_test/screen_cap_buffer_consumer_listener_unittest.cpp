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
#include "screen_capture.h"
#include "gtest/gtest.h"
#include <future>
#include <gmock/gmock.h>
#include <memory>
#include <surface.h>
#include <surface_type.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

namespace {
constexpr int32_t TEST_BUFFER_WIDTH = 64;
constexpr int32_t TEST_BUFFER_HEIGHT = 64;
constexpr int32_t TEST_BUFFER_STRIDE = 4;
} // namespace

class MockScreenCaptureCallBack : public ScreenCaptureCallBack {
public:
    MOCK_METHOD(void, OnError, (ScreenCaptureErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnAudioBufferAvailable, (bool isReady, AudioCaptureSourceType type), (override));
    MOCK_METHOD(void, OnVideoBufferAvailable, (bool isReady), (override));
};

class ScreenCapBufferConsumerListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockCb_ = std::make_shared<NiceMock<MockScreenCaptureCallBack>>();
        listener_ = new ScreenCapBufferConsumerListener(nullptr, mockCb_);
        ASSERT_NE(listener_, nullptr);
    }
    void TearDown(void) override
    {
        listener_ = nullptr;
        mockCb_ = nullptr;
    }

protected:
    struct RealSurfaceEnv {
        sptr<Surface> consumer;
        sptr<Surface> producerSurface;
        sptr<ScreenCapBufferConsumerListener> listener;
    };
    RealSurfaceEnv CreateRealSurfaceEnv()
    {
        RealSurfaceEnv env;
        env.consumer = Surface::CreateSurfaceAsConsumer();
        if (env.consumer == nullptr) {
            return env;
        }
        env.consumer->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE);
        env.consumer->SetDefaultWidthAndHeight(TEST_BUFFER_WIDTH, TEST_BUFFER_HEIGHT);
        env.listener = new ScreenCapBufferConsumerListener(env.consumer, mockCb_);
        if (env.listener == nullptr) {
            return env;
        }
        sptr<IBufferConsumerListener> ibl = env.listener;
        env.consumer->RegisterConsumerListener(ibl);
        auto producer = env.consumer->GetProducer();
        env.producerSurface = Surface::CreateSurfaceAsProducer(producer);
        return env;
    }
    void FlushOneBuffer(const sptr<Surface> &producer)
    {
        if (producer == nullptr) {
            return;
        }
        BufferRequestConfig config;
        config.width = TEST_BUFFER_WIDTH;
        config.height = TEST_BUFFER_HEIGHT;
        config.strideAlignment = TEST_BUFFER_STRIDE;
        config.format = GRAPHIC_PIXEL_FMT_RGBA_8888;
        config.usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_MMZ_CACHE;
        config.timeout = 0;
        sptr<SurfaceBuffer> buf;
        int32_t fence = -1;
        GSError err = producer->RequestBuffer(buf, fence, config);
        if (err != GSERROR_OK) {
            return;
        }
        BufferFlushConfig flushConfig;
        flushConfig.damage = {0, 0, 64, 64};
        producer->FlushBuffer(buf, fence, flushConfig);
    }
    std::shared_ptr<MockScreenCaptureCallBack> mockCb_;
    sptr<ScreenCapBufferConsumerListener> listener_;
};

/**
 * @tc.name    : AcquireVideoBuffer_NullConsumer_001
 * @tc.desc    : AcquireVideoBuffer with null consumer returns MSERR_INVALID_OPERATION
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_NullConsumer_001, TestSize.Level2)
{
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    int32_t ret = listener_->AcquireVideoBuffer(buf, fence, timestamp, damage);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : ReleaseVideoBuffer_NoBuffer_001
 * @tc.desc    : ReleaseVideoBuffer with no acquired buffer returns MSERR_INVALID_OPERATION
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseVideoBuffer_NoBuffer_001, TestSize.Level2)
{
    int32_t ret = listener_->ReleaseVideoBuffer();
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : OnBufferAvailable_TriggersNotify_001
 * @tc.desc    : OnBufferAvailable triggers notify thread to call OnVideoBufferAvailable on callback
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailable_TriggersNotify_001, TestSize.Level2)
{
    listener_->StartBufferThread();
    std::promise<void> promise;
    auto future = promise.get_future();
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(true)).WillOnce(::testing::InvokeWithoutArgs([&promise]() {
        promise.set_value();
    }));
    listener_->OnBufferAvailable();
    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

/**
 * @tc.name    : SetCallback_SwitchCallback_001
 * @tc.desc    : SetCallback switches callback; new callback receives OnVideoBufferAvailable
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, SetCallback_SwitchCallback_001, TestSize.Level2)
{
    listener_->StartBufferThread();
    auto newCb = std::make_shared<NiceMock<MockScreenCaptureCallBack>>();
    listener_->SetCallback(newCb);
    ASSERT_EQ(listener_->screenCaptureCb_.get(), newCb.get());
    std::promise<void> promise;
    auto future = promise.get_future();
    EXPECT_CALL(*newCb, OnVideoBufferAvailable(true)).WillOnce(::testing::InvokeWithoutArgs([&promise]() {
        promise.set_value();
    }));
    listener_->OnBufferAvailable();
    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(newCb.get()));
}

/**
 * @tc.name    : StopBufferThread_001
 * @tc.desc    : After StopBufferThread, OnBufferAvailable does not invoke callback
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, StopBufferThread_001, TestSize.Level2)
{
    listener_->StartBufferThread();
    std::promise<void> promise;
    auto future = promise.get_future();
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_))
        .Times(AtMost(1))
        .WillOnce(::testing::InvokeWithoutArgs([&promise]() { promise.set_value(); }));
    listener_->StopBufferThread();
    listener_->OnBufferAvailable();
    ASSERT_EQ(future.wait_for(std::chrono::milliseconds(500)), std::future_status::timeout);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

/**
 * @tc.name    : OnBufferAvailable_QueueFull_001
 * @tc.desc    : OnBufferAvailable skips push when message queue exceeds MAX_MESSAGE_QUEUE_SIZE
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, OnBufferAvailable_QueueFull_001, TestSize.Level2)
{
    for (int i = 0; i < 10; i++) {
        listener_->OnBufferAvailable();
    }
    ASSERT_EQ(listener_->messageQueue_.size(), static_cast<size_t>(6));
}

/**
 * @tc.name    : NotifyThreadRun_NullCallback_001
 * @tc.desc    : Notify thread does not invoke callback when screenCaptureCb_ is null
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, NotifyThreadRun_NullCallback_001, TestSize.Level2)
{
    listener_->SetCallback(nullptr);
    ASSERT_EQ(listener_->screenCaptureCb_, nullptr);
    listener_->StartBufferThread();
    std::promise<void> promise;
    auto future = promise.get_future();
    EXPECT_CALL(*mockCb_, OnVideoBufferAvailable(_))
        .Times(AtMost(1))
        .WillOnce(::testing::InvokeWithoutArgs([&promise]() { promise.set_value(); }));
    listener_->OnBufferAvailable();
    ASSERT_EQ(future.wait_for(std::chrono::milliseconds(500)), std::future_status::timeout);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(mockCb_.get()));
}

/**
 * @tc.name    : AcquireVideoBuffer_SuccessPath_001
 * @tc.desc    : AcquireVideoBuffer succeeds with real consumer and producer buffer
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_SuccessPath_001, TestSize.Level2)
{
    auto env = CreateRealSurfaceEnv();
    ASSERT_NE(env.listener, nullptr);
    ASSERT_NE(env.producerSurface, nullptr);
    FlushOneBuffer(env.producerSurface);
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    int32_t ret = env.listener->AcquireVideoBuffer(buf, fence, timestamp, damage);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_NE(buf, nullptr);
}

/**
 * @tc.name    : ReleaseVideoBuffer_SuccessPath_001
 * @tc.desc    : ReleaseVideoBuffer succeeds after AcquireVideoBuffer
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, ReleaseVideoBuffer_SuccessPath_001, TestSize.Level2)
{
    auto env = CreateRealSurfaceEnv();
    ASSERT_NE(env.listener, nullptr);
    ASSERT_NE(env.producerSurface, nullptr);
    FlushOneBuffer(env.producerSurface);
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    int32_t ret = env.listener->AcquireVideoBuffer(buf, fence, timestamp, damage);
    ASSERT_EQ(ret, MSERR_OK);
    ret = env.listener->ReleaseVideoBuffer();
    ASSERT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : AcquireVideoBuffer_AutoReleaseOld_001
 * @tc.desc    : AcquireVideoBuffer auto-releases previous currentBuffer_ before acquiring new
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_AutoReleaseOld_001, TestSize.Level2)
{
    auto env = CreateRealSurfaceEnv();
    ASSERT_NE(env.listener, nullptr);
    ASSERT_NE(env.producerSurface, nullptr);
    FlushOneBuffer(env.producerSurface);
    sptr<SurfaceBuffer> buf1;
    int32_t fence1 = 0;
    int64_t ts1 = 0;
    OHOS::Rect damage1;
    int32_t ret = env.listener->AcquireVideoBuffer(buf1, fence1, ts1, damage1);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_NE(buf1, nullptr);
    FlushOneBuffer(env.producerSurface);
    sptr<SurfaceBuffer> buf2;
    int32_t fence2 = 0;
    int64_t ts2 = 0;
    OHOS::Rect damage2;
    ret = env.listener->AcquireVideoBuffer(buf2, fence2, ts2, damage2);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_NE(buf2, nullptr);
    ASSERT_EQ(env.listener->currentBuffer_, buf2);
}

/**
 * @tc.name    : StartBufferThread_RepeatCall_001
 * @tc.desc    : StartBufferThread returns OK on repeat call when thread already running
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, StartBufferThread_RepeatCall_001, TestSize.Level2)
{
    ASSERT_EQ(listener_->StartBufferThread(), MSERR_OK);
    ASSERT_EQ(listener_->StartBufferThread(), MSERR_OK);
}

/**
 * @tc.name    : AcquireVideoBuffer_NoBuffer_001
 * @tc.desc    : AcquireVideoBuffer returns MSERR_UNKNOWN when consumer has no buffer to acquire
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_NoBuffer_001, TestSize.Level2)
{
    auto env = CreateRealSurfaceEnv();
    ASSERT_NE(env.listener, nullptr);
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    int32_t ret = env.listener->AcquireVideoBuffer(buf, fence, timestamp, damage);
    ASSERT_EQ(ret, MSERR_UNKNOWN);
}

/**
 * @tc.name    : Destructor_WithCurrentBuffer_001
 * @tc.desc    : Destructor releases currentBuffer_ to consumer; consumer stays usable
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, Destructor_WithCurrentBuffer_001, TestSize.Level2)
{
    auto env = CreateRealSurfaceEnv();
    ASSERT_NE(env.listener, nullptr);
    ASSERT_NE(env.producerSurface, nullptr);
    FlushOneBuffer(env.producerSurface);
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    ASSERT_EQ(env.listener->AcquireVideoBuffer(buf, fence, timestamp, damage), MSERR_OK);
    ASSERT_NE(buf, nullptr);
    env.listener = nullptr;
    FlushOneBuffer(env.producerSurface);
    sptr<ScreenCapBufferConsumerListener> listener2 = new ScreenCapBufferConsumerListener(env.consumer, mockCb_);
    sptr<SurfaceBuffer> buf2;
    ASSERT_EQ(listener2->AcquireVideoBuffer(buf2, fence, timestamp, damage), MSERR_OK);
    ASSERT_NE(buf2, nullptr);
}

/**
 * @tc.name    : AcquireVideoBuffer_NoMmzCache_001
 * @tc.desc    : AcquireVideoBuffer skips InvalidateCache when buffer usage has no MMZ_CACHE
 */
HWTEST_F(ScreenCapBufferConsumerListenerTest, AcquireVideoBuffer_NoMmzCache_001, TestSize.Level2)
{
    auto consumer = Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    consumer->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE);
    consumer->SetDefaultWidthAndHeight(TEST_BUFFER_WIDTH, TEST_BUFFER_HEIGHT);
    auto listener = new ScreenCapBufferConsumerListener(consumer, mockCb_);
    sptr<IBufferConsumerListener> ibl = listener;
    consumer->RegisterConsumerListener(ibl);
    auto producer = consumer->GetProducer();
    auto producerSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(producerSurface, nullptr);

    BufferRequestConfig config;
    config.width = 64;
    config.height = 64;
    config.strideAlignment = 4;
    config.format = GRAPHIC_PIXEL_FMT_RGBA_8888;
    config.usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE;
    config.timeout = 0;
    sptr<SurfaceBuffer> buf;
    int32_t fence = -1;
    ASSERT_EQ(producerSurface->RequestBuffer(buf, fence, config), GSERROR_OK);
    BufferFlushConfig flushConfig;
    flushConfig.damage = {0, 0, 64, 64};
    ASSERT_EQ(producerSurface->FlushBuffer(buf, fence, flushConfig), GSERROR_OK);

    sptr<SurfaceBuffer> acqBuf;
    int32_t acqFence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    ASSERT_EQ(listener->AcquireVideoBuffer(acqBuf, acqFence, timestamp, damage), MSERR_OK);
    ASSERT_NE(acqBuf, nullptr);
}
} // namespace Media
} // namespace OHOS
