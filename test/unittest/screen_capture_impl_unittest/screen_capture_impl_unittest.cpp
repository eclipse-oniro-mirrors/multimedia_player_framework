/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "screen_capture_impl_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

static const int32_t NUM_0 = 0;
static const int32_t NUM_1 = 1;

void ScreenCaptureImplUnitTest::SetUpTestCase(void) {}

void ScreenCaptureImplUnitTest::TearDownTestCase(void) {}

void ScreenCaptureImplUnitTest::SetUp(void)
{
    screenCaptureImpl_ = std::make_shared<ScreenCaptureImpl>();
}

void ScreenCaptureImplUnitTest::TearDown(void)
{
    screenCaptureImpl_ = nullptr;
}

/**
 * @tc.name  : Test Init
 * @tc.number: Init_001
 * @tc.desc  : Test case ENCODED_STREAM
 */
HWTEST_F(ScreenCaptureImplUnitTest, Init_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    AVScreenCaptureConfig config;
    EXPECT_CALL(*mockService, SetCaptureMode(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockService, SetDataType(_)).WillOnce(Return(MSERR_OK));
    config.dataType = DataType::ENCODED_STREAM;
    auto ret = screenCaptureImpl_->Init(config);
    EXPECT_EQ(ret, MSERR_UNSUPPORT);
}

/**
 * @tc.name  : Test Init
 * @tc.number: Init_002
 * @tc.desc  : Test default case
 */
HWTEST_F(ScreenCaptureImplUnitTest, Init_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    AVScreenCaptureConfig config;
    EXPECT_CALL(*mockService, SetCaptureMode(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockService, SetDataType(_)).WillOnce(Return(MSERR_OK));
    config.dataType = DataType::INVAILD;
    auto ret = screenCaptureImpl_->Init(config);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test InitOriginalStream
 * @tc.number: InitOriginalStream_001
 * @tc.desc  : Test config.strategy.setByUser == true
 */
HWTEST_F(ScreenCaptureImplUnitTest, InitOriginalStream_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    AVScreenCaptureConfig config;
    config.audioInfo.innerCapInfo.audioChannels = NUM_0;
    config.audioInfo.innerCapInfo.audioSampleRate = NUM_1;
    config.videoInfo.videoCapInfo.videoFrameWidth = NUM_0;
    config.videoInfo.videoCapInfo.videoFrameHeight = NUM_0;
    config.strategy.setByUser = true;
    EXPECT_CALL(*mockService, SetScreenCaptureStrategy(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->InitOriginalStream(config);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test InitCaptureFile
 * @tc.number: InitCaptureFile_001
 * @tc.desc  : Test config.strategy.setByUser == true
 */
HWTEST_F(ScreenCaptureImplUnitTest, InitCaptureFile_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    AVScreenCaptureConfig config;
    EXPECT_CALL(*mockService, SetRecorderInfo(_)).WillOnce(Return(MSERR_OK));
    config.recorderInfo.url = "fd://1";
    EXPECT_CALL(*mockService, SetOutputFile(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockService, InitAudioEncInfo(_)).WillOnce(Return(MSERR_OK));
    config.audioInfo.innerCapInfo.audioChannels = NUM_0;
    config.audioInfo.innerCapInfo.audioSampleRate = NUM_1;
    config.audioInfo.micCapInfo.audioChannels = NUM_0;
    config.audioInfo.micCapInfo.audioSampleRate = NUM_0;
    EXPECT_CALL(*mockService, InitAudioCap(_)).WillOnce(Return(MSERR_OK));
    config.videoInfo.videoCapInfo.videoFrameWidth = NUM_0;
    config.videoInfo.videoCapInfo.videoFrameHeight = NUM_0;
    config.strategy.setByUser = true;
    EXPECT_CALL(*mockService, SetScreenCaptureStrategy(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->InitCaptureFile(config);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test StartScreenCaptureWithSurface
 * @tc.number: StartScreenCaptureWithSurface_001
 * @tc.desc  : Test dataType_ != ORIGINAL_STREAM
 */
HWTEST_F(ScreenCaptureImplUnitTest, StartScreenCaptureWithSurface_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    screenCaptureImpl_->dataType_ = DataType::INVAILD;
    sptr<Surface> surface = new MockSurface();
    auto ret = screenCaptureImpl_->StartScreenCaptureWithSurface(surface);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AcquireVideoBuffer
 * @tc.number: AcquireVideoBuffer_001
 * @tc.desc  : Test ret != MSERR_OK
 */
HWTEST_F(ScreenCaptureImplUnitTest, AcquireVideoBuffer_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    EXPECT_CALL(*mockService, AcquireVideoBuffer(_, _, _, _)).WillOnce(Return(MSERR_NO_MEMORY));
    int32_t fence = NUM_0;
    int64_t timestamp = NUM_0;
    OHOS::Rect damage;
    auto ret = screenCaptureImpl_->AcquireVideoBuffer(fence, timestamp, damage);
    EXPECT_EQ(ret, nullptr);
}
} // namespace Media
} // namespace OHOS