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

#include "screen_capture.h"
#include "screen_capture_local_surface.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <memory>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
class MockSCCallBack : public ScreenCaptureCallBack {
public:
    MOCK_METHOD(void, OnError, (ScreenCaptureErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnAudioBufferAvailable, (bool isReady, AudioCaptureSourceType type), (override));
    MOCK_METHOD(void, OnVideoBufferAvailable, (bool isReady), (override));
};
} // namespace

class ScreenCaptureLocalSurfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockCb_ = std::make_shared<NiceMock<MockSCCallBack>>();
        localSurface_ = std::make_shared<ScreenCaptureLocalSurface>();
        ASSERT_NE(localSurface_, nullptr);
    }
    void TearDown(void) override
    {
        localSurface_ = nullptr;
        mockCb_ = nullptr;
    }

protected:
    std::shared_ptr<MockSCCallBack> mockCb_;
    std::shared_ptr<ScreenCaptureLocalSurface> localSurface_;
};

HWTEST_F(ScreenCaptureLocalSurfaceTest, GetProducerSurface_BeforeInit_001, TestSize.Level2)
{
    sptr<Surface> before = localSurface_->GetProducerSurface();
    ASSERT_EQ(before, nullptr);
    int32_t ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, AcquireVideoBuffer_NotInit_001, TestSize.Level2)
{
    sptr<SurfaceBuffer> buf;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    int32_t ret = localSurface_->AcquireVideoBuffer(buf, fence, timestamp, damage);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, ReleaseVideoBuffer_NotInit_001, TestSize.Level2)
{
    int32_t ret = localSurface_->ReleaseVideoBuffer();
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, Init_Valid_001, TestSize.Level2)
{
    int32_t ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, Init_Duplicate_001, TestSize.Level2)
{
    int32_t ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_OK);
    ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, Reinit_AfterDestruct_001, TestSize.Level2)
{
    int32_t ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_OK);
    localSurface_ = nullptr;
    localSurface_ = std::make_shared<ScreenCaptureLocalSurface>();
    ret = localSurface_->Init(mockCb_);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureLocalSurfaceTest, SetCallback_ForwardsToListener_001, TestSize.Level2)
{
    int32_t ret = localSurface_->Init(nullptr);
    ASSERT_EQ(ret, MSERR_OK);
    ASSERT_EQ(localSurface_->surfaceCb_->screenCaptureCb_.get(), nullptr);
    localSurface_->SetCallback(mockCb_);
    ASSERT_EQ(localSurface_->surfaceCb_->screenCaptureCb_.get(), mockCb_.get());
}

} // namespace Media
} // namespace OHOS
