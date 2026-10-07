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
 * @tc.name: Mock_SetMetaConfigs_VideoMetaMakerInfo_001
 * @tc.desc: Mock SetMetaConfigs VideoMetaMakerInfo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMetaConfigs_VideoMetaMakerInfo_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.metaSource = MetaSourceType::VIDEO_META_MAKER_INFO;
    RS()->config_.videoCodec = H264;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetMetaConfigs(0));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetMetaConfigs_VideoMetaMakerInfo_ConfigFail_001
 * @tc.desc: Mock SetMetaConfigs VideoMetaMakerInfo ConfigFail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMetaConfigs_VideoMetaMakerInfo_ConfigFail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.metaSource = MetaSourceType::VIDEO_META_MAKER_INFO;
    RS()->config_.videoCodec = H264;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_SET_META_CONFIGS_FAILED_5400103, RS()->SetMetaConfigs(0));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetMetaConfigs_NonVideoMetaMakerInfo_001
 * @tc.desc: Mock SetMetaConfigs NonVideoMetaMakerInfo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMetaConfigs_NonVideoMetaMakerInfo_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.metaSource = MetaSourceType::VIDEO_META_SOURCE_INVALID;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetMetaConfigs(0));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetUserMeta_WrongState_001
 * @tc.desc: Mock SetUserMeta WrongState 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetUserMeta_WrongState_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retStatus_ = Status::ERROR_WRONG_STATE;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    auto userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_INVALID_STATE, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetUserMeta_InvalidData_001
 * @tc.desc: Mock SetUserMeta InvalidData 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetUserMeta_InvalidData_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retStatus_ = Status::ERROR_INVALID_DATA;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    auto userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetUserMeta_NullPointer_001
 * @tc.desc: Mock SetUserMeta NullPointer 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetUserMeta_NullPointer_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retStatus_ = Status::ERROR_NULL_POINTER;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    auto userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_NO_MEMORY, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetUserMeta_Success_001
 * @tc.desc: Mock SetUserMeta Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetUserMeta_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retStatus_ = Status::NO_ERROR;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    auto userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_OK, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetUserMeta_UnknownError_001
 * @tc.desc: Mock SetUserMeta UnknownError 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetUserMeta_UnknownError_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retStatus_ = Status::ERROR_UNKNOWN;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    auto userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_EQ(MSERR_UNKNOWN, RS()->SetUserMeta(userMeta));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Start_Success_001
 * @tc.desc: Mock Start Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Start_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Start());
    EXPECT_EQ(RecorderServer::REC_RECORDING, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Start_Fail_001
 * @tc.desc: Mock Start Fail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Start_Fail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->Start());
    EXPECT_EQ(RecorderServer::REC_ERROR, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Stop_Success_001
 * @tc.desc: Mock Stop Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Stop_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Stop(false));
    EXPECT_EQ(RecorderServer::REC_INITIALIZED, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Stop_Fail_001
 * @tc.desc: Mock Stop Fail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Stop_Fail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->Stop(false));
    EXPECT_EQ(RecorderServer::REC_ERROR, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Stop_FileGenerationMode_001
 * @tc.desc: Mock Stop FileGenerationMode 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Stop_FileGenerationMode_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    RS()->config_.fileGenerationMode = FileGenerationMode::AUTO_CREATE_CAMERA_SCENE;
    RS()->config_.uri = "test_uri";
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    RS()->recorderCb_ = cb;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Stop(false));
    EXPECT_EQ(RecorderServer::REC_INITIALIZED, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
    RS()->recorderCb_ = nullptr;
    RS()->config_.fileGenerationMode = FileGenerationMode::APP_CREATE;
    RS()->config_.uri = "";
}

/**
 * @tc.name: Mock_Prepare_Success_001
 * @tc.desc: Mock Prepare Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Prepare_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Prepare());
    EXPECT_EQ(RecorderServer::REC_PREPARED, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Prepare_Fail_001
 * @tc.desc: Mock Prepare Fail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Prepare_Fail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->Prepare());
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Pause_Success_001
 * @tc.desc: Mock Pause Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Pause_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Pause());
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Resume_Success_001
 * @tc.desc: Mock Resume Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Resume_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PAUSED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Resume());
    RS()->recorderEngine_ = std::move(saved);
}


/**
 * @tc.name: Mock_SetVideoEncoder_Success_001
 * @tc.desc: Mock SetVideoEncoder Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetVideoEncoder_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetVideoEncoder(0, H264));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Reset_Fail_001
 * @tc.desc: Mock Reset Fail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Reset_Fail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->Reset());
    EXPECT_EQ(RecorderServer::REC_ERROR, RS()->status_);
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Stop_NullSyncCallback_001
 * @tc.desc: Mock Stop NullSyncCallback 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Stop_NullSyncCallback_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto savedSync = RS()->syncCallback_;
    RS()->syncCallback_ = nullptr;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Stop(false));
    RS()->recorderEngine_ = std::move(saved);
    RS()->syncCallback_ = savedSync;
}

/**
 * @tc.name: Mock_SetVideoEncoder_Fail_001
 * @tc.desc: Mock SetVideoEncoder Fail 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetVideoEncoder_Fail_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_INVALID_OPERATION;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetVideoEncoder(0, H264));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetAudioEncoder_Success_001
 * @tc.desc: Mock SetAudioEncoder Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetAudioEncoder_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.format = FORMAT_MPEG_4;
    RS()->config_.audioCodec = AudioCodecFormat::AAC_LC;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetAudioEncoder(0, AudioCodecFormat::AAC_LC));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetMaxDuration_Success_001
 * @tc.desc: Mock SetMaxDuration Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMaxDuration_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetMaxDuration(60));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetOutputFile_Success_001
 * @tc.desc: Mock SetOutputFile Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetOutputFile_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetOutputFile(1));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetNextOutputFile_Success_001
 * @tc.desc: Mock SetNextOutputFile Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetNextOutputFile_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetNextOutputFile(1));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetMaxFileSize_Success_001
 * @tc.desc: Mock SetMaxFileSize Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMaxFileSize_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetMaxFileSize(1048576));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_GetMaxAmplitude_Success_001
 * @tc.desc: Mock GetMaxAmplitude Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_GetMaxAmplitude_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_OK, RS()->GetMaxAmplitude(amplitude));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_GetCurrentCapturerChangeInfo_Success_001
 * @tc.desc: Mock GetCurrentCapturerChangeInfo Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_GetCurrentCapturerChangeInfo_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(MSERR_OK, RS()->GetCurrentCapturerChangeInfo(changeInfo));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_Reset_Success_001
 * @tc.desc: Mock Reset Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_Reset_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->Reset());
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_IsWatermarkSupported_Success_001
 * @tc.desc: Mock IsWatermarkSupported Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_IsWatermarkSupported_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    bool supported = false;
    EXPECT_EQ(MSERR_OK, RS()->IsWatermarkSupported(supported));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetWatermark_Success_001
 * @tc.desc: Mock SetWatermark Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetWatermark_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(MSERR_OK, RS()->SetWatermark(buffer));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_AddWatermark_Success_001
 * @tc.desc: Mock AddWatermark Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_AddWatermark_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_OK, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_TransmitQos_Success_001
 * @tc.desc: Mock TransmitQos Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_TransmitQos_Success_001, TestSize.Level2)
{
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetStabilizationMode_Success_001
 * @tc.desc: Mock SetStabilizationMode Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetStabilizationMode_Success_001, TestSize.Level2)
{
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetStabilizationMode(true));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetFileSplitDuration_Success_001
 * @tc.desc: Mock SetFileSplitDuration Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetFileSplitDuration_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetVideoSource_Success_001
 * @tc.desc: Mock SetVideoSource Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetVideoSource_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_OK, RS()->SetVideoSource(VIDEO_SOURCE_SURFACE_YUV, sourceId));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetAudioSource_Success_001
 * @tc.desc: Mock SetAudioSource Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetAudioSource_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_OK, RS()->SetAudioSource(AUDIO_SOURCE_DEFAULT, sourceId));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetOutputFormat_Success_001
 * @tc.desc: Mock SetOutputFormat Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetOutputFormat_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    EXPECT_EQ(MSERR_OK, RS()->SetOutputFormat(FORMAT_MPEG_4));
    RS()->recorderEngine_ = std::move(saved);
}

/**
 * @tc.name: Mock_SetMetaSource_Success_001
 * @tc.desc: Mock SetMetaSource Success 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Mock_SetMetaSource_Success_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    auto mock = std::make_unique<MockRecorderEngine>();
    ASSERT_NE(nullptr, mock);
    mock->retInt_ = MSERR_OK;
    auto saved = std::move(RS()->recorderEngine_);
    RS()->recorderEngine_ = std::move(mock);
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_OK, RS()->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, sourceId));
    RS()->recorderEngine_ = std::move(saved);
}
} // namespace Media
} // namespace OHOS
