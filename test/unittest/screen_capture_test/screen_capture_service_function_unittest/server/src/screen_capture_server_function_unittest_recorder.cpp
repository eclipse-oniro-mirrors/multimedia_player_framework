/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "image_source.h"
#include "image_type.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "mock_recorder_service.h"
#include "pixel_map.h"
#include "scope_guard.h"
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "uri_helper.h"
#include <sys/stat.h>
#include <unistd.h>

using ::testing::_;
using ::testing::Return;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
static void SetupRecorderDefaults(MockRecorderService &m)
{
    ON_CALL(m, SetVideoSource(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetOutputFormat(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioEncoder(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioSampleRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioChannels(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioEncodingBitRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEncoder(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoSize(_, _, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoFrameRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEncodingBitRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEnableBFrame(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetOutputFile(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetStabilizationMode(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Prepare()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, GetSurface(_)).WillByDefault(Return(nullptr));
    ON_CALL(m, SetAudioDataSource(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Start()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Stop(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Release()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Pause()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Resume()).WillByDefault(Return(MSERR_OK));
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureRecorder_001, TestSize.Level2)
{
    auto screenCaptureServerInner = MakeScreenCaptureServer();
    SetMockBuilder(screenCaptureServerInner.get());
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_recorder_001.mp4", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetValidConfigFile(recorderInfo);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->SetRecorderInfo(config_.recorderInfo);
    screenCaptureServerInner->SetOutputFile(outputFd);
    screenCaptureServerInner->InitAudioEncInfo(config_.audioInfo.audioEncInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoEncInfo(config_.videoInfo.videoEncInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
    close(outputFd);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureRecorder_002, TestSize.Level2)
{
    auto screenCaptureServerInner = MakeScreenCaptureServer();
    SetMockBuilder(screenCaptureServerInner.get());
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_recorder_002.mp4", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetValidConfigFile(recorderInfo);
    screenCaptureServerInner->SetScreenCaptureCallback(nullptr);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->SetRecorderInfo(config_.recorderInfo);
    screenCaptureServerInner->SetOutputFile(outputFd);
    screenCaptureServerInner->InitAudioEncInfo(config_.audioInfo.audioEncInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoEncInfo(config_.videoInfo.videoEncInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
    close(outputFd);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureRecorder_003, TestSize.Level2)
{
    auto screenCaptureServerInner = MakeScreenCaptureServer();
    SetMockBuilder(screenCaptureServerInner.get());
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_recorder_003.mp4", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "mp4";
    SetValidConfigFile(recorderInfo);
    screenCaptureServerInner->SetScreenCaptureCallback(nullptr);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->SetRecorderInfo(config_.recorderInfo);
    screenCaptureServerInner->SetOutputFile(outputFd);
    screenCaptureServerInner->InitAudioEncInfo(config_.audioInfo.audioEncInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoEncInfo(config_.videoInfo.videoEncInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(true);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
    close(outputFd);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureRecorder_004, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_recorder_004.m4a", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "m4a";
    int32_t ret = screenCaptureServer_->SetRecorderInfo(recorderInfo);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureRecorder_005, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    int outputFd = open("/data/test/media/screen_capture_recorder_004.abcdefg", O_RDWR);
    recorderInfo.url = "fd://" + std::to_string(outputFd);
    recorderInfo.fileFormat = "abcdefg";
    int32_t ret = screenCaptureServer_->SetRecorderInfo(recorderInfo);
    ASSERT_NE(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenCaptureStream_001, TestSize.Level2)
{
    auto screenCaptureServerInner = MakeScreenCaptureServer();
    SetMockBuilder(screenCaptureServerInner.get());
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_PauseRecorder_Success_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->PauseRecorder(), MSERR_OK);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_PauseRecorder_Failed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Pause()).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_EQ(screenCaptureServer_->PauseRecorder(), MSERR_UNKNOWN_RECORDER_PAUSE);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_ResumeRecorder_Success_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Resume()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->ResumeRecorder(), MSERR_OK);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_ResumeRecorder_Failed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Resume()).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_EQ(screenCaptureServer_->ResumeRecorder(), MSERR_UNKNOWN_RECORDER_RESUME);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_StopScreenCaptureRecorder_Success_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Stop(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->StopScreenCaptureRecorder(), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->recorder_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_StopScreenCaptureRecorder_StopFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    EXPECT_CALL(*mock, Stop(_)).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->StopScreenCaptureRecorder(), MSERR_UNKNOWN_RECORDER_STOP);
    EXPECT_EQ(screenCaptureServer_->recorder_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_AllSuccess_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    AudioCaptureInfo audioInfo = {.audioSampleRate = 16000, .audioChannels = 2};
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_OK);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_VideoIgnore_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_OK);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetVideoSourceFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_CALL(*mock, SetVideoSource(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetOutputFormatFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_CALL(*mock, SetOutputFormat(_)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetAudioEncoderFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_CALL(*mock, SetAudioEncoder(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetAudioSampleRateFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_CALL(*mock, SetAudioSampleRate(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetAudioChannelsFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_CALL(*mock, SetAudioChannels(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetAudioBitRateFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_CALL(*mock, SetAudioEncodingBitRate(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetVideoEncoderFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_CALL(*mock, SetVideoEncoder(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetVideoSizeFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_CALL(*mock, SetVideoSize(_, _, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetVideoFrameRateFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_CALL(*mock, SetVideoFrameRate(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorderInfo_SetVideoBitRateFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_CALL(*mock, SetVideoEncodingBitRate(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    AudioCaptureInfo audioInfo;
    EXPECT_EQ(screenCaptureServer_->InitRecorderInfo(screenCaptureServer_->recorder_, audioInfo), MSERR_UNKNOWN);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorder_PrepareFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->outputFd_ = 1;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    screenCaptureServer_->providers_ = CreateMockProviders();
    EXPECT_CALL(*mock, SetAudioDataSource(_, _)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mock, Prepare()).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->InitRecorder(), MSERR_UNKNOWN_RECORDER_PREPARE);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorder_SetOutputFileFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->outputFd_ = 1;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    screenCaptureServer_->providers_ = CreateMockProviders();
    EXPECT_CALL(*mock, SetAudioDataSource(_, _)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mock, SetOutputFile(_)).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->InitRecorder(), MSERR_UNKNOWN_RECORDER_SETFILE);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorder_SetAudioDataSourceFailed_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaults(*mock);
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->outputFd_ = 1;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    screenCaptureServer_->providers_ = CreateMockProviders();
    EXPECT_CALL(*mock, SetAudioDataSource(_, _)).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    EXPECT_EQ(screenCaptureServer_->InitRecorder(), MSERR_UNKNOWN_RECORDER_SETAUDIO);
    screenCaptureServer_->recorder_ = nullptr;
}

HWTEST_F(ScreenCaptureServerFunctionTest, RecorderMock_InitRecorder_InvalidFd_001, TestSize.Level2)
{
    screenCaptureServer_->outputFd_ = -1;
    EXPECT_EQ(screenCaptureServer_->InitRecorder(), MSERR_INVALID_FD);
}
} // namespace Media
} // namespace OHOS
