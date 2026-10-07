/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use a copy of the License at
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
 * @tc.name: recorder_StatusGuard_SetVideoEncoder_001
 * @tc.desc: recorder StatusGuard SetVideoEncoder 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoEncoder_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoEncoder(0, H264));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoSize_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoSize(0, 1280, 720));
}

/**
 * @tc.name: recorder_StatusGuard_SetVideoFrameRate_001
 * @tc.desc: recorder StatusGuard SetVideoFrameRate 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoFrameRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoFrameRate(0, 30));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoEncodingBitRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoEncodingBitRate(0, 2000000));
}

/**
 * @tc.name: recorder_StatusGuard_SetVideoIsHdr_001
 * @tc.desc: recorder StatusGuard SetVideoIsHdr 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoIsHdr_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetVideoIsHdr(0, true));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoEnableTemporalScale_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetVideoEnableTemporalScale(0, true));
}

/**
 * @tc.name: recorder_StatusGuard_SetVideoEnableStableQualityMode_001
 * @tc.desc: recorder StatusGuard SetVideoEnableStableQualityMode 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoEnableStableQualityMode_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetVideoEnableStableQualityMode(0, true));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoEnableBFrame_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetVideoEnableBFrame(0, true));
}

/**
 * @tc.name: recorder_StatusGuard_SetCaptureRate_001
 * @tc.desc: recorder StatusGuard SetCaptureRate 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetCaptureRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetCaptureRate(0, 30.0));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetAudioEncoder_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetAudioEncoder(0, AudioCodecFormat::AAC_LC));
}

/**
 * @tc.name: recorder_StatusGuard_SetAudioSampleRate_001
 * @tc.desc: recorder StatusGuard SetAudioSampleRate 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetAudioSampleRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetAudioSampleRate(0, 48000));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetAudioChannels_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetAudioChannels(0, 2));
}

/**
 * @tc.name: recorder_StatusGuard_SetAudioEncodingBitRate_001
 * @tc.desc: recorder StatusGuard SetAudioEncodingBitRate 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetAudioEncodingBitRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetAudioEncodingBitRate(0, 48000));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetAudioAacProfile_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetAudioAacProfile(0, AacProfile::AAC_LC));
}

/**
 * @tc.name: recorder_StatusGuard_SetMaxDuration_001
 * @tc.desc: recorder StatusGuard SetMaxDuration 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMaxDuration_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetMaxDuration(60));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMaxFileSize_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetMaxFileSize(1048576));
}

/**
 * @tc.name: recorder_StatusGuard_SetOutputFile_001
 * @tc.desc: recorder StatusGuard SetOutputFile 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetOutputFile_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetOutputFile(1));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetNextOutputFile_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetNextOutputFile(1));
}

/**
 * @tc.name: recorder_StatusGuard_SetGenre_001
 * @tc.desc: recorder StatusGuard SetGenre 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetGenre_001, TestSize.Level2)
{
    std::string genre = "test";
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetGenre(genre));
}

/**
 * @tc.name: recorder_StatusGuard_SetUserCustomInfo_001
 * @tc.desc: recorder StatusGuard SetUserCustomInfo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetUserCustomInfo_001, TestSize.Level2)
{
    Meta customInfo;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetUserCustomInfo(customInfo));
}

/**
 * @tc.name: recorder_StatusGuard_Prepare_001
 * @tc.desc: recorder StatusGuard Prepare 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_Prepare_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Prepare());
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_Start_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Start());
}

/**
 * @tc.name: recorder_StatusGuard_Pause_001
 * @tc.desc: recorder StatusGuard Pause 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_Pause_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Pause());
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_Resume_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Resume());
}

/**
 * @tc.name: recorder_StatusGuard_Stop_001
 * @tc.desc: recorder StatusGuard Stop 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_Stop_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Stop(false));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetFileSplitDuration_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION,
              recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
}

/**
 * @tc.name: recorder_StatusGuard_SetWatermark_001
 * @tc.desc: recorder StatusGuard SetWatermark 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetWatermark_001, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetWatermark(buffer));
}

/**
 * @tc.name: recorder_StatusGuard_SetUserMeta_001
 * @tc.desc: recorder StatusGuard SetUserMeta 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetUserMeta_001, TestSize.Level2)
{
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
}

/**
 * @tc.name: recorder_StatusGuard_GetMaxAmplitude_001
 * @tc.desc: recorder StatusGuard GetMaxAmplitude 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_GetMaxAmplitude_001, TestSize.Level2)
{
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->recorder_->GetMaxAmplitude(amplitude));
}

/**
 * @tc.name: recorder_StatusGuard_GetSurface_001
 * @tc.desc: recorder StatusGuard GetSurface 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_GetSurface_001, TestSize.Level2)
{
    EXPECT_EQ(nullptr, recorderServer_->GetSurface(0));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_GetMetaSurface_001, TestSize.Level2)
{
    EXPECT_EQ(nullptr, recorderServer_->GetMetaSurface(0));
}

/**
 * @tc.name: recorder_StatusGuard_SetMetaMimeType_001
 * @tc.desc: recorder StatusGuard SetMetaMimeType 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMetaMimeType_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetMetaMimeType(0, "test/mime"));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMetaTimedKey_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetMetaTimedKey(0, "test_key"));
}

/**
 * @tc.name: recorder_StatusGuard_SetMetaSourceTrackMime_001
 * @tc.desc: recorder StatusGuard SetMetaSourceTrackMime 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMetaSourceTrackMime_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetMetaSourceTrackMime(0, "video/avc"));
}

HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetMetaConfigs_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_SET_META_CONFIGS_FAILED_5400103, recorderServer_->recorder_->SetMetaConfigs(0));
}


/**
 * @tc.name: recorder_EngineNull_SetVideoSource_001
 * @tc.desc: recorder EngineNull SetVideoSource 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetVideoSource_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetVideoSource(VIDEO_SOURCE_SURFACE_YUV, sourceId));
}

/**
 * @tc.name: recorder_EngineNull_SetAudioSource_001
 * @tc.desc: recorder EngineNull SetAudioSource 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetAudioSource_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetAudioSource(AUDIO_SOURCE_DEFAULT, sourceId));
}

/**
 * @tc.name: recorder_EngineNull_SetOutputFormat_001
 * @tc.desc: recorder EngineNull SetOutputFormat 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetOutputFormat_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetOutputFormat(FORMAT_MPEG_4));
}

/**
 * @tc.name: recorder_EngineNull_SetRecorderCallback_001
 * @tc.desc: recorder EngineNull SetRecorderCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetRecorderCallback_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    auto cb = std::make_shared<RecorderCallbackTest>();
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetRecorderCallback(cb));
}

/**
 * @tc.name: recorder_EngineNull_SetMetaSource_001
 * @tc.desc: recorder EngineNull SetMetaSource 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetMetaSource_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101,
              recorderServer_->recorder_->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, sourceId));
}

/**
 * @tc.name: recorder_EngineNull_SetVideoSize_001
 * @tc.desc: recorder EngineNull SetVideoSize 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetVideoSize_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetVideoSize(0, 1280, 720));
}

/**
 * @tc.name: recorder_EngineNull_SetVideoEncoder_001
 * @tc.desc: recorder EngineNull SetVideoEncoder 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetVideoEncoder_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetVideoEncoder(0, H264));
}

/**
 * @tc.name: recorder_EngineNull_SetAudioEncoder_001
 * @tc.desc: recorder EngineNull SetAudioEncoder 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetAudioEncoder_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetAudioEncoder(0, AudioCodecFormat::AAC_LC));
}

/**
 * @tc.name: recorder_EngineNull_SetAudioEncodingBitRate_001
 * @tc.desc: recorder EngineNull SetAudioEncodingBitRate 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetAudioEncodingBitRate_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetAudioEncodingBitRate(0, 48000));
}

/**
 * @tc.name: recorder_EngineNull_Prepare_001
 * @tc.desc: recorder EngineNull Prepare 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_Prepare_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->Prepare());
}

/**
 * @tc.name: recorder_EngineNull_Start_001
 * @tc.desc: recorder EngineNull Start 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_Start_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->Start());
}

/**
 * @tc.name: recorder_EngineNull_Pause_001
 * @tc.desc: recorder EngineNull Pause 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_Pause_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->Pause());
}

/**
 * @tc.name: recorder_EngineNull_Resume_001
 * @tc.desc: recorder EngineNull Resume 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_Resume_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->Resume());
}

/**
 * @tc.name: recorder_EngineNull_Stop_001
 * @tc.desc: recorder EngineNull Stop 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_Stop_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->Stop(false));
}

/**
 * @tc.name: recorder_EngineNull_SetFileSplitDuration_001
 * @tc.desc: recorder EngineNull SetFileSplitDuration 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetFileSplitDuration_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_OK,
              recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
}

/**
 * @tc.name: recorder_EngineNull_SetWatermark_001
 * @tc.desc: recorder EngineNull SetWatermark 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetWatermark_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_PREPARED;
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetWatermark(buffer));
}

/**
 * @tc.name: recorder_EngineNull_SetUserMeta_001
 * @tc.desc: recorder EngineNull SetUserMeta 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetUserMeta_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_PREPARED;
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->SetUserMeta(userMeta));
}

/**
 * @tc.name: recorder_EngineNull_GetMaxAmplitude_001
 * @tc.desc: recorder EngineNull GetMaxAmplitude 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_GetMaxAmplitude_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->recorder_->GetMaxAmplitude(amplitude));
}

/**
 * @tc.name: recorder_EngineNull_GetCurrentCapturerChangeInfo_001
 * @tc.desc: recorder EngineNull GetCurrentCapturerChangeInfo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_GetCurrentCapturerChangeInfo_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->GetCurrentCapturerChangeInfo(changeInfo));
}

/**
 * @tc.name: recorder_EngineNull_IsWatermarkSupported_001
 * @tc.desc: recorder EngineNull IsWatermarkSupported 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_IsWatermarkSupported_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    bool supported = false;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->IsWatermarkSupported(supported));
}

/**
 * @tc.name: recorder_EngineNull_GetAvailableEncoder_001
 * @tc.desc: recorder EngineNull GetAvailableEncoder 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_GetAvailableEncoder_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    std::vector<EncoderCapabilityData> encoderInfo;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->recorder_->GetAvailableEncoder(encoderInfo));
}

/**
 * @tc.name: recorder_EngineNull_SetStabilizationMode_001
 * @tc.desc: recorder EngineNull SetStabilizationMode 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetStabilizationMode_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_EQ(MSERR_NO_MEMORY, recorderServer_->recorder_->SetStabilizationMode(true));
}

/**
 * @tc.name: recorder_EngineNull_SetWillMuteWhenInterrupted_001
 * @tc.desc: recorder EngineNull SetWillMuteWhenInterrupted 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetWillMuteWhenInterrupted_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->recorder_->SetWillMuteWhenInterrupted(true));
}

/**
 * @tc.name: recorder_EngineNull_SetMetaMimeType_001
 * @tc.desc: recorder EngineNull SetMetaMimeType 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetMetaMimeType_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->recorder_->SetMetaMimeType(0, "test/mime"));
}


/**
 * @tc.name: recorder_Callback_OnError_NullCb_001
 * @tc.desc: recorder Callback OnError NullCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnError_NullCb_001, TestSize.Level2)
{
    recorderServer_->recorder_->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, 200);
    EXPECT_FALSE(recorderServer_->recorder_->lastErrMsg_.empty());
}

/**
 * @tc.name: recorder_Callback_OnError_WithCb_001
 * @tc.desc: recorder Callback OnError WithCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnError_WithCb_001, TestSize.Level2)
{
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    recorderServer_->recorder_->recorderCb_ = cb;
    recorderServer_->recorder_->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, 300);
    EXPECT_FALSE(recorderServer_->recorder_->lastErrMsg_.empty());
    EXPECT_EQ(300, recorderServer_->recorder_->statisticalEventInfo_.errCode);
}

/**
 * @tc.name: recorder_Callback_OnInfo_NullCb_001
 * @tc.desc: recorder Callback OnInfo NullCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnInfo_NullCb_001, TestSize.Level2)
{
    recorderServer_->recorder_->OnInfo(IRecorderEngineObs::InfoType::INTERNEL_WARNING, 0);
    EXPECT_TRUE(recorderServer_->recorder_->recorderCb_ == nullptr);
}

/**
 * @tc.name: recorder_Callback_OnInfo_WithCb_001
 * @tc.desc: recorder Callback OnInfo WithCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnInfo_WithCb_001, TestSize.Level2)
{
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    recorderServer_->recorder_->recorderCb_ = cb;
    recorderServer_->recorder_->OnInfo(IRecorderEngineObs::InfoType::MAX_DURATION_APPROACHING, 1);
    EXPECT_EQ(1, cb->infoExtra_);
}

/**
 * @tc.name: recorder_Callback_OnAudioCaptureChange_NullCb_001
 * @tc.desc: recorder Callback OnAudioCaptureChange NullCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnAudioCaptureChange_NullCb_001, TestSize.Level2)
{
    AudioRecorderChangeInfo changeInfo;
    recorderServer_->recorder_->OnAudioCaptureChange(changeInfo);
    EXPECT_TRUE(recorderServer_->recorder_->recorderCb_ == nullptr);
}

/**
 * @tc.name: recorder_Callback_OnAudioCaptureChange_WithCb_001
 * @tc.desc: recorder Callback OnAudioCaptureChange WithCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Callback_OnAudioCaptureChange_WithCb_001, TestSize.Level2)
{
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    recorderServer_->recorder_->recorderCb_ = cb;
    AudioRecorderChangeInfo changeInfo;
    recorderServer_->recorder_->OnAudioCaptureChange(changeInfo);
    EXPECT_TRUE(cb->audioCaptureChangeCalled_);
}


/**
 * @tc.name: recorder_GetWatermarkCount_Overflow_001
 * @tc.desc: recorder GetWatermarkCount Overflow 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetWatermarkCount_Overflow_001, TestSize.Level2)
{
    int32_t count = 0;
    for (int32_t i = 0; i < WATERMARK_COUNT_MAX; i++) {
        EXPECT_EQ(MSERR_OK, recorderServer_->recorder_->GetWatermarkCount(count));
    }
    EXPECT_EQ(WATERMARK_COUNT_MAX, count);
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE, recorderServer_->recorder_->GetWatermarkCount(count));
}

/**
 * @tc.name: recorder_AddWatermark_InvalidWidth_001
 * @tc.desc: recorder AddWatermark InvalidWidth 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_InvalidWidth_001, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_VAL, recorderServer_->AddWatermark(buffer, 0, 100, watermarkCount));
}

/**
 * @tc.name: recorder_AddWatermark_InvalidHeight_001
 * @tc.desc: recorder AddWatermark InvalidHeight 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_InvalidHeight_001, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_VAL, recorderServer_->AddWatermark(buffer, 100, 0, watermarkCount));
}

/**
 * @tc.name: recorder_AddWatermark_WidthOverflow_001
 * @tc.desc: recorder AddWatermark WidthOverflow 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_WidthOverflow_001, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_VAL,
              recorderServer_->AddWatermark(buffer, WATERMARK_WIDTH_HEIGHT_MAX + 1, 100, watermarkCount));
}

/**
 * @tc.name: recorder_AddWatermark_OverflowAfterFill_001
 * @tc.desc: recorder AddWatermark OverflowAfterFill 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_OverflowAfterFill_001, TestSize.Level2)
{
    int32_t dummy = 0;
    for (int32_t i = 0; i < WATERMARK_COUNT_MAX; i++) {
        EXPECT_EQ(MSERR_OK, recorderServer_->recorder_->GetWatermarkCount(dummy));
    }
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE,
              recorderServer_->AddWatermark(buffer, 100, 100, watermarkCount));
}

/**
 * @tc.name: recorder_StatusGuard_SetVideoSqrFactor_001
 * @tc.desc: recorder StatusGuard SetVideoSqrFactor in wrong state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_StatusGuard_SetVideoSqrFactor_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->recorder_->SetVideoSqrFactor(0, 25));
}

/**
 * @tc.name: recorder_EngineNull_SetVideoSqrFactor_001
 * @tc.desc: recorder EngineNull SetVideoSqrFactor with stableQualityMode off
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_EngineNull_SetVideoSqrFactor_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    recorderServer_->recorder_->config_.enableStableQualityMode = false;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, recorderServer_->recorder_->SetVideoSqrFactor(0, 25));
}


/**
 * @tc.name: recorder_DumpInfo_FdMinusOne_001
 * @tc.desc: recorder DumpInfo FdMinusOne 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_DumpInfo_FdMinusOne_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->recorder_->DumpInfo(-1));
}

HWTEST_F(RecorderServerUnitTest, recorder_DumpInfo_FdValid_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->recorder_->DumpInfo(1));
}


/**
 * @tc.name: recorder_TransmitQos_UserInteractive_001
 * @tc.desc: recorder TransmitQos UserInteractive 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_TransmitQos_UserInteractive_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE));
}

HWTEST_F(RecorderServerUnitTest, recorder_TransmitQos_Background_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->TransmitQos(QOS::QosLevel::QOS_BACKGROUND));
}


/**
 * @tc.name: recorder_SetAudioEncoder_MpegM4Mismatch_001
 * @tc.desc: recorder SetAudioEncoder MpegM4Mismatch 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioEncoder_MpegM4Mismatch_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    recorderServer_->recorder_->config_.format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_AUDIOCODEC_FILEFORMAT_MATCH_ERROR_401,
              recorderServer_->SetAudioEncoder(0, AudioCodecFormat::AUDIO_MPEG));
}


/**
 * @tc.name: recorder_SetAudioEncodingBitRate_G711MuMismatch_001
 * @tc.desc: recorder SetAudioEncodingBitRate G711MuMismatch 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioEncodingBitRate_G711MuMismatch_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_CONFIGURED;
    recorderServer_->recorder_->config_.audioCodec = AudioCodecFormat::AUDIO_G711MU;
    EXPECT_EQ(MSERR_AUDIO_G711MU_MATCH_ERROR_401,
              recorderServer_->SetAudioEncodingBitRate(0, 48000));
}


/**
 * @tc.name: recorder_SetDataSource_AlwaysFails_001
 * @tc.desc: recorder SetDataSource AlwaysFails 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetDataSource_AlwaysFails_001, TestSize.Level2)
{
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetDataSource(METADATA, sourceId));
}


/**
 * @tc.name: recorder_RepeatGuard_Prepare_001
 * @tc.desc: recorder RepeatGuard Prepare 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_RepeatGuard_Prepare_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Prepare());
}

/**
 * @tc.name: recorder_RepeatGuard_Start_001
 * @tc.desc: recorder RepeatGuard Start 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_RepeatGuard_Start_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Start());
}

/**
 * @tc.name: recorder_RepeatGuard_Pause_001
 * @tc.desc: recorder RepeatGuard Pause 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_RepeatGuard_Pause_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Pause());
}

/**
 * @tc.name: recorder_RepeatGuard_Resume_001
 * @tc.desc: recorder RepeatGuard Resume 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_RepeatGuard_Resume_001, TestSize.Level2)
{
    recorderServer_->recorder_->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Resume());
}

} // namespace Media
} // namespace OHOS
