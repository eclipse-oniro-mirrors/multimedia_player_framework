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
 * @tc.name: Coverage2_EnqueueFail_Prepared_001
 * @tc.desc: Coverage2 EnqueueFail Prepared 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EnqueueFail_Prepared_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    RS()->taskQue_.Stop();
    EXPECT_NE(MSERR_OK, RS()->Start());
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_NE(MSERR_OK, RS()->SetWatermark(buffer));
    EXPECT_EQ(nullptr, RS()->GetSurface(0));
    EXPECT_EQ(nullptr, RS()->GetMetaSurface(0));
    int32_t amplitude = 0;
    EXPECT_NE(MSERR_OK, RS()->GetMaxAmplitude(amplitude));
    RS()->taskQue_.Start();
}

/**
 * @tc.name: Coverage2_EnqueueFail_Recording_001
 * @tc.desc: Coverage2 EnqueueFail Recording 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EnqueueFail_Recording_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    RS()->taskQue_.Stop();
    EXPECT_NE(MSERR_OK, RS()->Pause());
    EXPECT_NE(MSERR_OK, RS()->Stop(false));
    EXPECT_EQ(MSERR_OK, RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
    RS()->taskQue_.Start();
}

/**
 * @tc.name: Coverage2_EnqueueFail_ConfiguredMisc_001
 * @tc.desc: Coverage2 EnqueueFail ConfiguredMisc 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EnqueueFail_ConfiguredMisc_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->taskQue_.Stop();
    EXPECT_NE(MSERR_OK, RS()->SetWillMuteWhenInterrupted(true));
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_NE(MSERR_OK, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    ASSERT_NE(nullptr, userMeta);
    EXPECT_NE(MSERR_OK, RS()->SetUserMeta(userMeta));
    RS()->taskQue_.Start();
}


/**
 * @tc.name: Coverage2_EngineNull_ConfiguredVideo_001
 * @tc.desc: Coverage2 EngineNull ConfiguredVideo 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EngineNull_ConfiguredVideo_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoEncoder(0, H264));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoSize(0, 1280, 720));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoFrameRate(0, 30));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoEncodingBitRate(0, 2000000));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoIsHdr(0, true));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoEnableTemporalScale(0, true));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoEnableStableQualityMode(0, true));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetVideoEnableBFrame(0, true));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMetaTimedKey(0, "test_key"));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMetaSourceTrackMime(0, "video/avc"));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetCaptureRate(0, 30.0));
}

/**
 * @tc.name: Coverage2_EngineNull_ConfiguredAudio_001
 * @tc.desc: Coverage2 EngineNull ConfiguredAudio 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EngineNull_ConfiguredAudio_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetAudioSampleRate(0, 48000));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetAudioChannels(0, 2));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetAudioAacProfile(0, AacProfile::AAC_LC));
    Meta customInfo;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetUserCustomInfo(customInfo));
    std::string genre = "test";
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetGenre(genre));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMaxDuration(60));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetOutputFile(1));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetNextOutputFile(1));
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetMaxFileSize(1048576));
}

/**
 * @tc.name: Coverage2_EngineNull_PreparedSurface_001
 * @tc.desc: Coverage2 EngineNull PreparedSurface 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EngineNull_PreparedSurface_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    RS()->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(nullptr, RS()->GetSurface(0));
    EXPECT_EQ(nullptr, RS()->GetMetaSurface(0));
    RS()->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(nullptr, RS()->GetSurface(0));
    EXPECT_EQ(nullptr, RS()->GetMetaSurface(0));
    RS()->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(nullptr, RS()->GetSurface(0));
    EXPECT_EQ(nullptr, RS()->GetMetaSurface(0));
}

/**
 * @tc.name: Coverage2_EngineNull_MiscMethods_001
 * @tc.desc: Coverage2 EngineNull MiscMethods 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_EngineNull_MiscMethods_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->Reset());
    RS()->status_ = RecorderServer::REC_PREPARED;
    std::shared_ptr<AVBuffer> buffer;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->SetWatermark(buffer));
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.withVideo = true;
    RS()->SetLocation(30.0, 60.0);
    RS()->SetOrientationHint(90);
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_NULL_POINTER_5400101, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
}


/**
 * @tc.name: Coverage2_ValidEngine_VideoMethods_001
 * @tc.desc: Coverage2 ValidEngine VideoMethods 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_ValidEngine_VideoMethods_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetVideoIsHdr(0, true));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetVideoEnableTemporalScale(0, true));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetVideoEnableStableQualityMode(0, false));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetVideoEnableBFrame(0, false));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetMetaMimeType(0, "test/mime"));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetMetaTimedKey(0, "test_key"));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetMetaSourceTrackMime(0, "video/avc"));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetCaptureRate(0, 30.0));
}

/**
 * @tc.name: Coverage2_ValidEngine_AudioMethods_001
 * @tc.desc: Coverage2 ValidEngine AudioMethods 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_ValidEngine_AudioMethods_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetAudioSampleRate(0, 48000));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetAudioChannels(0, 2));
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetAudioAacProfile(0, AacProfile::AAC_LC));
    Meta customInfo;
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetUserCustomInfo(customInfo));
    std::string genre = "test";
    EXPECT_EQ(MSERR_RECORDER_ENGINE_ERROR_5400103, RS()->SetGenre(genre));
}

/**
 * @tc.name: Coverage2_ValidEngine_MiscMethods_001
 * @tc.desc: Coverage2 ValidEngine MiscMethods 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_ValidEngine_MiscMethods_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.withVideo = true;
    RS()->SetLocation(30.0, 60.0);
    EXPECT_TRUE(RS()->config_.withLocation);
    RS()->SetOrientationHint(90);
    EXPECT_EQ(90, RS()->config_.rotation);
    EXPECT_EQ(MSERR_OK, RS()->SetWillMuteWhenInterrupted(true));
}


/**
 * @tc.name: Coverage2_GetVideoMime_AllCases_001
 * @tc.desc: Coverage2 GetVideoMime AllCases 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetVideoMime_AllCases_001, TestSize.Level2)
{
    EXPECT_FALSE(RS()->GetVideoMime(VideoCodecFormat::H264).empty());
    EXPECT_FALSE(RS()->GetVideoMime(VideoCodecFormat::MPEG4).empty());
    EXPECT_FALSE(RS()->GetVideoMime(VideoCodecFormat::H265).empty());
    EXPECT_TRUE(RS()->GetVideoMime(VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT).empty());
}

/**
 * @tc.name: Coverage2_GetAudioMime_AllCases_001
 * @tc.desc: Coverage2 GetAudioMime AllCases 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetAudioMime_AllCases_001, TestSize.Level2)
{
    EXPECT_FALSE(RS()->GetAudioMime(AudioCodecFormat::AUDIO_DEFAULT).empty());
    EXPECT_FALSE(RS()->GetAudioMime(AudioCodecFormat::AAC_LC).empty());
    EXPECT_TRUE(RS()->GetAudioMime(AudioCodecFormat::AUDIO_G711MU).empty());
    EXPECT_TRUE(RS()->GetAudioMime(AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT).empty());
}

/**
 * @tc.name: Coverage2_GetContainerFormat_AllCases_001
 * @tc.desc: Coverage2 GetContainerFormat AllCases 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetContainerFormat_AllCases_001, TestSize.Level2)
{
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_MPEG_4).empty());
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_M4A).empty());
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_AMR).empty());
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_MP3).empty());
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_WAV).empty());
    EXPECT_FALSE(RS()->GetContainerFormat(OutputFormatType::FORMAT_AAC).empty());
    EXPECT_TRUE(RS()->GetContainerFormat(OutputFormatType::FORMAT_BUTT).empty());
}


/**
 * @tc.name: Coverage2_SetMetaDataReport_Hdr_001
 * @tc.desc: Coverage2 SetMetaDataReport Hdr 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_SetMetaDataReport_Hdr_001, TestSize.Level2)
{
    RS()->config_.isHdr = true;
    RS()->config_.videoCodec = H264;
    RS()->config_.audioCodec = AudioCodecFormat::AAC_LC;
    RS()->config_.format = FORMAT_MPEG_4;
    RS()->SetMetaDataReport();
    EXPECT_EQ(static_cast<int8_t>(RecorderServer::HdrType::HDR_TYPE_VIVID),
              RS()->statisticalEventInfo_.hdrType);
}

/**
 * @tc.name: Coverage2_SetMetaDataReport_NoHdr_001
 * @tc.desc: Coverage2 SetMetaDataReport NoHdr 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_SetMetaDataReport_NoHdr_001, TestSize.Level2)
{
    RS()->config_.isHdr = false;
    RS()->config_.videoCodec = MPEG4;
    RS()->config_.audioCodec = AudioCodecFormat::AUDIO_DEFAULT;
    RS()->config_.format = FORMAT_M4A;
    RS()->SetMetaDataReport();
    EXPECT_EQ(static_cast<int8_t>(RecorderServer::HdrType::HDR_TYPE_NONE),
              RS()->statisticalEventInfo_.hdrType);
}


/**
 * @tc.name: Coverage2_DumpInfo_WithErrMsg_001
 * @tc.desc: Coverage2 DumpInfo WithErrMsg 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_DumpInfo_WithErrMsg_001, TestSize.Level2)
{
    RS()->lastErrMsg_ = "test error message";
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(-1));
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(1));
}


/**
 * @tc.name: Coverage2_SetLocation_NotConfigured_001
 * @tc.desc: Coverage2 SetLocation NotConfigured 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_SetLocation_NotConfigured_001, TestSize.Level2)
{
    RS()->SetLocation(30.0, 60.0);
    EXPECT_FALSE(RS()->config_.withLocation);
}


/**
 * @tc.name: Coverage2_GetStatusDescription_Invalid_001
 * @tc.desc: Coverage2 GetStatusDescription Invalid 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetStatusDescription_Invalid_001, TestSize.Level2)
{
    const std::string &desc = RS()->GetStatusDescription(
        static_cast<RecorderServer::RecStatus>(-1));
    EXPECT_EQ("PLAYER_STATUS_ILLEGAL", desc);
    const std::string &desc2 = RS()->GetStatusDescription(
        static_cast<RecorderServer::RecStatus>(100));
    EXPECT_EQ("PLAYER_STATUS_ILLEGAL", desc2);
}


/**
 * @tc.name: Coverage2_AddWatermark_HeightOverflow_001
 * @tc.desc: Coverage2 AddWatermark HeightOverflow 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_AddWatermark_HeightOverflow_001, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_VAL,
              RS()->AddWatermark(buffer, 100, WATERMARK_WIDTH_HEIGHT_MAX + 1, watermarkCount));
}

/**
 * @tc.name: Coverage2_AddWatermark_StatusGuard_001
 * @tc.desc: Coverage2 AddWatermark StatusGuard 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_AddWatermark_StatusGuard_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    RS()->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    RS()->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
    RS()->status_ = RecorderServer::REC_ERROR;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->AddWatermark(buffer, 100, 100, watermarkCount));
}


/**
 * @tc.name: Coverage2_SetWillMute_StatusBranches_001
 * @tc.desc: Coverage2 SetWillMute StatusBranches 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_SetWillMute_StatusBranches_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    EXPECT_EQ(MSERR_OK, RS()->SetWillMuteWhenInterrupted(true));
    RS()->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetWillMuteWhenInterrupted(true));
    RS()->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->SetWillMuteWhenInterrupted(true));
}


/**
 * @tc.name: Coverage2_SetFileSplitDuration_StatusBranches_001
 * @tc.desc: Coverage2 SetFileSplitDuration StatusBranches 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_SetFileSplitDuration_StatusBranches_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(MSERR_INVALID_OPERATION,
              RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
    RS()->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(MSERR_OK,
              RS()->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, 0, 1000));
}


/**
 * @tc.name: Coverage2_Callback_OnError_NullCb_001
 * @tc.desc: Coverage2 Callback OnError NullCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Callback_OnError_NullCb_001, TestSize.Level2)
{
    RS()->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, 200);
    EXPECT_FALSE(RS()->lastErrMsg_.empty());
}

/**
 * @tc.name: Coverage2_Callback_OnError_WithCb_001
 * @tc.desc: Coverage2 Callback OnError WithCb 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Callback_OnError_WithCb_001, TestSize.Level2)
{
    auto cb = std::make_shared<RecorderCallbackTest>();
    ASSERT_NE(nullptr, cb);
    RS()->recorderCb_ = cb;
    RS()->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, 300);
    EXPECT_EQ(300, RS()->statisticalEventInfo_.errCode);
}

/**
 * @tc.name: Coverage2_GetAVRecorderConfig_WithLocation_001
 * @tc.desc: Coverage2 GetAVRecorderConfig WithLocation 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetAVRecorderConfig_WithLocation_001, TestSize.Level2)
{
    RS()->config_.withLocation = true;
    ConfigMap configMap;
    EXPECT_EQ(MSERR_OK, RS()->GetAVRecorderConfig(configMap));
    EXPECT_NE(configMap.end(), configMap.find("withLocation"));
    EXPECT_EQ(1, configMap["withLocation"]);
}

/**
 * @tc.name: Coverage2_GetWatermarkCount_Overflow_001
 * @tc.desc: Coverage2 GetWatermarkCount Overflow 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetWatermarkCount_Overflow_001, TestSize.Level2)
{
    int32_t count = 0;
    for (int32_t i = 0; i < WATERMARK_COUNT_MAX; i++) {
        EXPECT_EQ(MSERR_OK, RS()->GetWatermarkCount(count));
    }
    EXPECT_EQ(WATERMARK_COUNT_MAX, count);
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE, RS()->GetWatermarkCount(count));
}

/**
 * @tc.name: Coverage2_AddWatermark_OverflowAfterFill_001
 * @tc.desc: Coverage2 AddWatermark OverflowAfterFill 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_AddWatermark_OverflowAfterFill_001, TestSize.Level2)
{
    int32_t dummy = 0;
    for (int32_t i = 0; i < WATERMARK_COUNT_MAX; i++) {
        EXPECT_EQ(MSERR_OK, RS()->GetWatermarkCount(dummy));
    }
    std::shared_ptr<AVBuffer> buffer;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE,
              RS()->AddWatermark(buffer, 100, 100, watermarkCount));
}


/**
 * @tc.name: Coverage2_TransmitQos_UserInteractive_001
 * @tc.desc: Coverage2 TransmitQos UserInteractive 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_TransmitQos_UserInteractive_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, RS()->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE));
    EXPECT_EQ(QOS::QosLevel::QOS_USER_INTERACTIVE, RS()->clientQos_);
}

/**
 * @tc.name: Coverage2_TransmitQos_Background_001
 * @tc.desc: Coverage2 TransmitQos Background 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_TransmitQos_Background_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, RS()->TransmitQos(QOS::QosLevel::QOS_BACKGROUND));
    EXPECT_EQ(QOS::QosLevel::QOS_BACKGROUND, RS()->clientQos_);
}


/**
 * @tc.name: Coverage2_DumpInfo_FdMinusOne_001
 * @tc.desc: Coverage2 DumpInfo FdMinusOne 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_DumpInfo_FdMinusOne_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(-1));
}

HWTEST_F(RecorderServerUnitTest, Coverage2_DumpInfo_FdValid_001, TestSize.Level2)
{
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(1));
}


/**
 * @tc.name: Coverage2_GetLocation_001
 * @tc.desc: Coverage2 GetLocation 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_GetLocation_001, TestSize.Level2)
{
    RS()->config_.latitude = 30.0f;
    RS()->config_.longitude = 60.0f;
    Location location;
    EXPECT_EQ(MSERR_OK, RS()->GetLocation(location));
    EXPECT_FLOAT_EQ(30.0f, location.latitude);
    EXPECT_FLOAT_EQ(60.0f, location.longitude);
}

/**
 * @tc.name: Coverage2_Prepare_Repeat_001
 * @tc.desc: Coverage2 Prepare Repeat 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Prepare_Repeat_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PREPARED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->Prepare());
}

/**
 * @tc.name: Coverage2_Prepare_ErrorStatus_001
 * @tc.desc: Coverage2 Prepare ErrorStatus 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Prepare_ErrorStatus_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_ERROR;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->Prepare());
}

/**
 * @tc.name: Coverage2_Start_Repeat_001
 * @tc.desc: Coverage2 Start Repeat 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Start_Repeat_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->Start());
}

/**
 * @tc.name: Coverage2_Pause_Repeat_001
 * @tc.desc: Coverage2 Pause Repeat 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Pause_Repeat_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_PAUSED;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->Pause());
}

/**
 * @tc.name: Coverage2_Resume_Repeat_001
 * @tc.desc: Coverage2 Resume Repeat 001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage2_Resume_Repeat_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_RECORDING;
    EXPECT_EQ(MSERR_INVALID_OPERATION, RS()->Resume());
}

} // namespace Media
} // namespace OHOS
