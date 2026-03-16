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

/**
 * @tc.name  : Test AcquireAudioBuffer
 * @tc.number: AcquireAudioBuffer_001
 * @tc.desc  : Test AcquireAudioBuffer with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, AcquireAudioBuffer_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::shared_ptr<AudioBuffer> audioBuffer = nullptr;
    EXPECT_CALL(*mockService, AcquireAudioBuffer(_, _)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AcquireAudioBuffer
 * @tc.number: AcquireAudioBuffer_002
 * @tc.desc  : Test AcquireAudioBuffer with service error
 */
HWTEST_F(ScreenCaptureImplUnitTest, AcquireAudioBuffer_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::shared_ptr<AudioBuffer> audioBuffer = nullptr;
    EXPECT_CALL(*mockService, AcquireAudioBuffer(_, _)).WillOnce(Return(MSERR_NO_MEMORY));
    auto ret = screenCaptureImpl_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::APP_PLAYBACK);
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/**
 * @tc.name  : Test AddWhiteListWindows
 * @tc.number: AddWhiteListWindows_001
 * @tc.desc  : Test AddWhiteListWindows with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, AddWhiteListWindows_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::vector<uint64_t> windowIDsVec = {1, 2, 3};
    EXPECT_CALL(*mockService, AddWhiteListWindows(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->AddWhiteListWindows(windowIDsVec);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AddWhiteListWindows
 * @tc.number: AddWhiteListWindows_002
 * @tc.desc  : Test AddWhiteListWindows with empty window list
 */
HWTEST_F(ScreenCaptureImplUnitTest, AddWhiteListWindows_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::vector<uint64_t> windowIDsVec;
    EXPECT_CALL(*mockService, AddWhiteListWindows(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->AddWhiteListWindows(windowIDsVec);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ExcludeContent
 * @tc.number: ExcludeContent_001
 * @tc.desc  : Test ExcludeContent with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, ExcludeContent_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    ScreenCaptureContentFilter contentFilter;
    contentFilter.filteredAudioContents.insert(AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO);
    contentFilter.windowIDsVec = {1, 2};
    EXPECT_CALL(*mockService, ExcludeContent(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->ExcludeContent(contentFilter);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ReleaseAudioBuffer
 * @tc.number: ReleaseAudioBuffer_001
 * @tc.desc  : Test ReleaseAudioBuffer with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, ReleaseAudioBuffer_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    EXPECT_CALL(*mockService, ReleaseAudioBuffer(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->ReleaseAudioBuffer(AudioCaptureSourceType::MIC);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ReleaseAudioBuffer
 * @tc.number: ReleaseAudioBuffer_002
 * @tc.desc  : Test ReleaseAudioBuffer with different audio source
 */
HWTEST_F(ScreenCaptureImplUnitTest, ReleaseAudioBuffer_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    EXPECT_CALL(*mockService, ReleaseAudioBuffer(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test RemoveWhiteListWindows
 * @tc.number: RemoveWhiteListWindows_001
 * @tc.desc  : Test RemoveWhiteListWindows with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, RemoveWhiteListWindows_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::vector<uint64_t> windowIDsVec = {1, 2, 3};
    EXPECT_CALL(*mockService, RemoveWhiteListWindows(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->RemoveWhiteListWindows(windowIDsVec);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test RemoveWhiteListWindows
 * @tc.number: RemoveWhiteListWindows_002
 * @tc.desc  : Test RemoveWhiteListWindows with empty window list
 */
HWTEST_F(ScreenCaptureImplUnitTest, RemoveWhiteListWindows_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    std::vector<uint64_t> windowIDsVec;
    EXPECT_CALL(*mockService, RemoveWhiteListWindows(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->RemoveWhiteListWindows(windowIDsVec);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetCaptureArea
 * @tc.number: SetCaptureArea_001
 * @tc.desc  : Test SetCaptureArea with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, SetCaptureArea_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    uint64_t displayId = 1;
    OHOS::Rect area = {0, 0, 1920, 1080};
    EXPECT_CALL(*mockService, SetCaptureArea(_, _)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->SetCaptureArea(displayId, area);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetCaptureArea
 * @tc.number: SetCaptureArea_002
 * @tc.desc  : Test SetCaptureArea with different displayId
 */
HWTEST_F(ScreenCaptureImplUnitTest, SetCaptureArea_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    uint64_t displayId = 2;
    OHOS::Rect area = {100, 100, 800, 600};
    EXPECT_CALL(*mockService, SetCaptureArea(_, _)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->SetCaptureArea(displayId, area);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetPrivacyAuthorityEnabled
 * @tc.number: SetPrivacyAuthorityEnabled_001
 * @tc.desc  : Test SetPrivacyAuthorityEnabled with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, SetPrivacyAuthorityEnabled_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    auto ret = screenCaptureImpl_->SetPrivacyAuthorityEnabled();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetScreenCaptureStrategy
 * @tc.number: SetScreenCaptureStrategy_001
 * @tc.desc  : Test SetScreenCaptureStrategy with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, SetScreenCaptureStrategy_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    ScreenCaptureStrategy strategy;
    strategy.enableDeviceLevelCapture = true;
    strategy.keepCaptureDuringCall = false;
    strategy.strategyForPrivacyMaskMode = 1;
    EXPECT_CALL(*mockService, SetScreenCaptureStrategy(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->SetScreenCaptureStrategy(strategy);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetScreenCaptureStrategy
 * @tc.number: SetScreenCaptureStrategy_002
 * @tc.desc  : Test SetScreenCaptureStrategy with different strategy
 */
HWTEST_F(ScreenCaptureImplUnitTest, SetScreenCaptureStrategy_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    ScreenCaptureStrategy strategy;
    strategy.enableDeviceLevelCapture = false;
    strategy.keepCaptureDuringCall = true;
    strategy.strategyForPrivacyMaskMode = 2;
    EXPECT_CALL(*mockService, SetScreenCaptureStrategy(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->SetScreenCaptureStrategy(strategy);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ShowCursor
 * @tc.number: ShowCursor_001
 * @tc.desc  : Test ShowCursor with valid service
 */
HWTEST_F(ScreenCaptureImplUnitTest, ShowCursor_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    EXPECT_CALL(*mockService, ShowCursor(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->ShowCursor(true);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ShowCursor
 * @tc.number: ShowCursor_002
 * @tc.desc  : Test ShowCursor with false parameter
 */
HWTEST_F(ScreenCaptureImplUnitTest, ShowCursor_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    EXPECT_CALL(*mockService, ShowCursor(_)).WillOnce(Return(MSERR_OK));
    auto ret = screenCaptureImpl_->ShowCursor(false);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test boundary conditions
 * @tc.number: BoundaryConditions_001
 * @tc.desc  : Test with invalid service pointer
 */
HWTEST_F(ScreenCaptureImplUnitTest, BoundaryConditions_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    screenCaptureImpl_->screenCaptureService_ = nullptr;
    
    std::vector<uint64_t> windowIDsVec = {1, 2};
    EXPECT_NE(screenCaptureImpl_->AddWhiteListWindows(windowIDsVec), MSERR_OK);
    EXPECT_NE(screenCaptureImpl_->RemoveWhiteListWindows(windowIDsVec), MSERR_OK);
    
    ScreenCaptureContentFilter contentFilter;
    EXPECT_NE(screenCaptureImpl_->ExcludeContent(contentFilter), MSERR_OK);
    
    EXPECT_NE(screenCaptureImpl_->ReleaseAudioBuffer(AudioCaptureSourceType::MIC), MSERR_OK);
    
    uint64_t displayId = 1;
    OHOS::Rect area = {0, 0, 1920, 1080};
    EXPECT_NE(screenCaptureImpl_->SetCaptureArea(displayId, area), MSERR_OK);
}

/**
 * @tc.name  : Test boundary conditions
 * @tc.number: BoundaryConditions_002
 * @tc.desc  : Test with service returning errors
 */
HWTEST_F(ScreenCaptureImplUnitTest, BoundaryConditions_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    
    std::vector<uint64_t> windowIDsVec = {1, 2};
    EXPECT_CALL(*mockService, AddWhiteListWindows(_)).WillOnce(Return(MSERR_INVALID_VAL));
    EXPECT_NE(screenCaptureImpl_->AddWhiteListWindows(windowIDsVec), MSERR_OK);
    
    EXPECT_CALL(*mockService, RemoveWhiteListWindows(_)).WillOnce(Return(MSERR_INVALID_OPERATION));
    EXPECT_NE(screenCaptureImpl_->RemoveWhiteListWindows(windowIDsVec), MSERR_OK);
    
    ScreenCaptureContentFilter contentFilter;
    EXPECT_CALL(*mockService, ExcludeContent(_)).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_NE(screenCaptureImpl_->ExcludeContent(contentFilter), MSERR_OK);
}

/**
 * @tc.name  : Test exception scenarios
 * @tc.number: ExceptionScenarios_001
 * @tc.desc  : Test with various error codes
 */
HWTEST_F(ScreenCaptureImplUnitTest, ExceptionScenarios_001, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    
    EXPECT_CALL(*mockService, AcquireAudioBuffer(_, _)).WillOnce(Return(MSERR_NO_MEMORY));
    std::shared_ptr<AudioBuffer> audioBuffer = nullptr;
    EXPECT_NE(screenCaptureImpl_->AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC), MSERR_OK);
    
    EXPECT_CALL(*mockService, ReleaseAudioBuffer(_)).WillOnce(Return(MSERR_INVALID_OPERATION));
    EXPECT_NE(screenCaptureImpl_->ReleaseAudioBuffer(AudioCaptureSourceType::APP_PLAYBACK), MSERR_OK);
    
    EXPECT_CALL(*mockService, ShowCursor(_)).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_NE(screenCaptureImpl_->ShowCursor(true), MSERR_OK);
}

/**
 * @tc.name  : Test exception scenarios
 * @tc.number: ExceptionScenarios_002
 * @tc.desc  : Test with timeout and service died errors
 */
HWTEST_F(ScreenCaptureImplUnitTest, ExceptionScenarios_002, TestSize.Level0)
{
    ASSERT_NE(screenCaptureImpl_, nullptr);
    auto mockService = std::make_shared<MockScreenCaptureService>();
    screenCaptureImpl_->screenCaptureService_ = mockService;
    
    ScreenCaptureStrategy strategy;
    EXPECT_CALL(*mockService, SetScreenCaptureStrategy(_)).WillOnce(Return(MSERR_TIMEOUT));
    EXPECT_NE(screenCaptureImpl_->SetScreenCaptureStrategy(strategy), MSERR_OK);
    
    uint64_t displayId = 1;
    OHOS::Rect area = {0, 0, 1920, 1080};
    EXPECT_CALL(*mockService, SetCaptureArea(_, _)).WillOnce(Return(MSERR_SERVICE_DIED));
    EXPECT_NE(screenCaptureImpl_->SetCaptureArea(displayId, area), MSERR_OK);
}

} // namespace Media
} // namespace OHOS