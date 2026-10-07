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

#include "recorder_server_unit_test.h"
#include <fcntl.h>
#include "media_errors.h"
#include "media_log.h"
#include "recorder_utils.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::RecorderTestParam;

namespace OHOS {
namespace Media {

/**
 * @tc.name: Coverage3_SetAudioDataSource_WrongStatus_001
 * @tc.desc: Coverage3 SetAudioDataSource WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetAudioDataSource_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    std::shared_ptr<IAudioDataSource> audioSource = nullptr;
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetAudioDataSource(audioSource, sourceId));
}

/**
 * @tc.name: Coverage3_SetAudioDataSource_EngineNull_001
 * @tc.desc: Coverage3 SetAudioDataSource EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetAudioDataSource_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    std::shared_ptr<IAudioDataSource> audioSource = nullptr;
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetAudioDataSource(audioSource, sourceId));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetFileGenerationMode_WrongStatus_001
 * @tc.desc: Coverage3 SetFileGenerationMode WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetFileGenerationMode_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetFileGenerationMode(FileGenerationMode::APP_CREATE));
}

/**
 * @tc.name: Coverage3_SetFileGenerationMode_EngineNull_001
 * @tc.desc: Coverage3 SetFileGenerationMode EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetFileGenerationMode_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetFileGenerationMode(FileGenerationMode::APP_CREATE));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetFileGenerationMode_NoVideo_001
 * @tc.desc: Coverage3 SetFileGenerationMode NoVideo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetFileGenerationMode_NoVideo_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    bool savedWithVideo = RS()->config_.withVideo;
    RS()->config_.withVideo = false;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetFileGenerationMode(FileGenerationMode::APP_CREATE));
    RS()->config_.withVideo = savedWithVideo;
}


/**
 * @tc.name: Coverage3_SetNextOutputFile_EngineNull_001
 * @tc.desc: Coverage3 SetNextOutputFile EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetNextOutputFile_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetNextOutputFile(1));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetMaxFileSize_EngineNull_001
 * @tc.desc: Coverage3 SetMaxFileSize EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMaxFileSize_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMaxFileSize(1048576));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetOutputFile_EngineNull_001
 * @tc.desc: Coverage3 SetOutputFile EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetOutputFile_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetOutputFile(1));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetMetaMimeType_EngineNull_001
 * @tc.desc: Coverage3 SetMetaMimeType EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMetaMimeType_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMetaMimeType(0, "test/mime"));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetMetaTimedKey_EngineNull_001
 * @tc.desc: Coverage3 SetMetaTimedKey EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMetaTimedKey_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMetaTimedKey(0, "test_key"));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetMetaSourceTrackMime_EngineNull_001
 * @tc.desc: Coverage3 SetMetaSourceTrackMime EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMetaSourceTrackMime_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMetaSourceTrackMime(0, "video/avc"));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetWatermark_EngineNull_001
 * @tc.desc: Coverage3 SetWatermark EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetWatermark_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetWatermark(buffer));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_AddWatermark_EngineNull_001
 * @tc.desc: Coverage3 AddWatermark EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_AddWatermark_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetUserMeta_EngineNull_001
 * @tc.desc: Coverage3 SetUserMeta EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetUserMeta_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetMaxDuration_EngineNull_001
 * @tc.desc: Coverage3 SetMaxDuration EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMaxDuration_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMaxDuration(60));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetCaptureRate_EngineNull_001
 * @tc.desc: Coverage3 SetCaptureRate EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetCaptureRate_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetCaptureRate(0, 30.0));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetFileSplitDuration_WrongStatus_001
 * @tc.desc: Coverage3 SetFileSplitDuration WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetFileSplitDuration_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
}

/**
 * @tc.name: Coverage3_SetFileSplitDuration_EngineNull_001
 * @tc.desc: Coverage3 SetFileSplitDuration EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetFileSplitDuration_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_OK, RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_GetMaxAmplitude_EngineNull_001
 * @tc.desc: Coverage3 GetMaxAmplitude EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_GetMaxAmplitude_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->GetMaxAmplitude(amplitude));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_GetCurrentCapturerChangeInfo_EngineNull_001
 * @tc.desc: Coverage3 GetCurrentCapturerChangeInfo EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_GetCurrentCapturerChangeInfo_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->GetCurrentCapturerChangeInfo(changeInfo));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_IsWatermarkSupported_EngineNull_001
 * @tc.desc: Coverage3 IsWatermarkSupported EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_IsWatermarkSupported_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    bool supported = false;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->IsWatermarkSupported(supported));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_TransmitQos_EngineNull_001
 * @tc.desc: Coverage3 TransmitQos EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_TransmitQos_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_OK, RS()->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_GetSurface_EngineNull_001
 * @tc.desc: Coverage3 GetSurface EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_GetSurface_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(nullptr, RS()->GetSurface(0));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_GetMetaSurface_EngineNull_001
 * @tc.desc: Coverage3 GetMetaSurface EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_GetMetaSurface_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(nullptr, RS()->GetMetaSurface(0));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetWillMuteWhenInterrupted_EngineNull_001
 * @tc.desc: Coverage3 SetWillMuteWhenInterrupted EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetWillMuteWhenInterrupted_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetWillMuteWhenInterrupted(true));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetGenre_EngineNull_001
 * @tc.desc: Coverage3 SetGenre EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetGenre_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    std::string genre = "test";
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetGenre(genre));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_SetUserCustomInfo_EngineNull_001
 * @tc.desc: Coverage3 SetUserCustomInfo EngineNull 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetUserCustomInfo_EngineNull_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto savedEngine = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = nullptr;
    Meta customInfo;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetUserCustomInfo(customInfo));
    RS()->recorderEngine_ = std::move(savedEngine);
}

/**
 * @tc.name: Coverage3_OnError_NullCallback_001
 * @tc.desc: Coverage3 OnError NullCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_OnError_NullCallback_001, TestSize.Level2)
{
    auto savedCb = RS()->recorderCb_;
    RS()->recorderCb_ = nullptr;
    RS()->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, MSERR_UNKNOWN);
    EXPECT_FALSE(RS()->lastErrMsg_.empty());
    RS()->recorderCb_ = savedCb;
}

/**
 * @tc.name: Coverage3_OnInfo_NullCallback_001
 * @tc.desc: Coverage3 OnInfo NullCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_OnInfo_NullCallback_001, TestSize.Level2)
{
    auto savedCb = RS()->recorderCb_;
    RS()->recorderCb_ = nullptr;
    RS()->OnInfo(IRecorderEngineObs::InfoType::MAX_DURATION_APPROACHING, 0);
    RS()->recorderCb_ = savedCb;
    auto cb2 = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb2);
    RS()->recorderCb_ = cb2;
    RS()->OnInfo(IRecorderEngineObs::InfoType::MAX_DURATION_APPROACHING, 42);
    RS()->recorderCb_ = savedCb;
    EXPECT_EQ(42, cb2->infoExtra_);
}

/**
 * @tc.name: Coverage3_OnAudioCaptureChange_NullCallback_001
 * @tc.desc: Coverage3 OnAudioCaptureChange NullCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_OnAudioCaptureChange_NullCallback_001, TestSize.Level2)
{
    auto savedCb = RS()->recorderCb_;
    RS()->recorderCb_ = nullptr;
    AudioRecorderChangeInfo changeInfo;
    RS()->OnAudioCaptureChange(changeInfo);
    RS()->recorderCb_ = savedCb;
    auto cb2 = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb2);
    RS()->recorderCb_ = cb2;
    RS()->OnAudioCaptureChange(changeInfo);
    RS()->recorderCb_ = savedCb;
    EXPECT_TRUE(cb2->audioCaptureChangeCalled_);
}

/**
 * @tc.name: Coverage3_GetStatusDescription_Illegal_001
 * @tc.desc: Coverage3 GetStatusDescription Illegal 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_GetStatusDescription_Illegal_001, TestSize.Level2)
{
    const std::string& desc = RS()->GetStatusDescription(static_cast<RecorderServer::RecStatus>(999));
    EXPECT_EQ(std::string("PLAYER_STATUS_ILLEGAL"), desc);
}

/**
 * @tc.name: Coverage3_OnError_WithCallback_001
 * @tc.desc: Coverage3 OnError WithCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_OnError_WithCallback_001, TestSize.Level2)
{
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    auto savedCb = RS()->recorderCb_;
    RS()->recorderCb_ = cb;
    RS()->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, MSERR_UNKNOWN);
    RS()->recorderCb_ = savedCb;
    EXPECT_EQ(MSERR_UNKNOWN, cb->GetErrorCode());
}

/**
 * @tc.name: Coverage3_SetVideoSource_WrongStatus_001
 * @tc.desc: Coverage3 SetVideoSource WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetVideoSource_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetVideoSource(VIDEO_SOURCE_SURFACE_YUV, sourceId));
}

/**
 * @tc.name: Coverage3_SetAudioSource_WrongStatus_001
 * @tc.desc: Coverage3 SetAudioSource WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetAudioSource_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetAudioSource(AUDIO_SOURCE_DEFAULT, sourceId));
}

/**
 * @tc.name: Coverage3_SetOutputFormat_WrongStatus_001
 * @tc.desc: Coverage3 SetOutputFormat WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetOutputFormat_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetOutputFormat(FORMAT_MPEG_4));
}

/**
 * @tc.name: Coverage3_SetMetaSource_WrongStatus_001
 * @tc.desc: Coverage3 SetMetaSource WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetMetaSource_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, sourceId));
}

/**
 * @tc.name: Coverage3_SetRecorderCallback_WrongStatus_001
 * @tc.desc: Coverage3 SetRecorderCallback WrongStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetRecorderCallback_WrongStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetRecorderCallback(cb));
}

/**
 * @tc.name: Coverage3_SetVideoIsHdr_False_001
 * @tc.desc: Coverage3 SetVideoIsHdr False 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetVideoIsHdr_False_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->taskQue_.Stop();
    EXPECT_EQ(MSERR_TASK_QUEUE_ERROR_5400102, RS()->SetVideoIsHdr(0, false));
    RS()->taskQue_.Start();
}

/**
 * @tc.name: Coverage3_SetVideoEnableTemporalScale_False_001
 * @tc.desc: Coverage3 SetVideoEnableTemporalScale False 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetVideoEnableTemporalScale_False_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->taskQue_.Stop();
    EXPECT_EQ(MSERR_TASK_QUEUE_ERROR_5400102, RS()->SetVideoEnableTemporalScale(0, false));
    RS()->taskQue_.Start();
}

/**
 * @tc.name: Coverage3_SetVideoEnableStableQualityMode_False_001
 * @tc.desc: Coverage3 SetVideoEnableStableQualityMode False 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetVideoEnableStableQualityMode_False_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->taskQue_.Stop();
    EXPECT_EQ(MSERR_TASK_QUEUE_ERROR_5400102, RS()->SetVideoEnableStableQualityMode(0, false));
    RS()->taskQue_.Start();
}

/**
 * @tc.name: Coverage3_SetVideoEnableBFrame_False_001
 * @tc.desc: Coverage3 SetVideoEnableBFrame False 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage3_SetVideoEnableBFrame_False_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->taskQue_.Stop();
    EXPECT_EQ(MSERR_TASK_QUEUE_ERROR_5400102, RS()->SetVideoEnableBFrame(0, false));
    RS()->taskQue_.Start();
}

} // namespace Media
} // namespace OHOS
