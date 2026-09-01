/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "param_wrapper.h"
#include "pixel_map.h"
#include "scope_guard.h"
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "uri_helper.h"
#include <sys/stat.h>
#include <unistd.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {
/**
 * @tc.name: CheckCaptureMode_001
 * @tc.desc: captureMode < CAPTURE_HOME_SCREEN
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_001, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->CheckCaptureMode(CaptureMode::CAPTURE_INVAILD);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: CheckCaptureMode_002
 * @tc.desc: captureMode is invalid value greater than CAPTURE_SPECIFIED_APP
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_002, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->CheckCaptureMode(
        static_cast<CaptureMode>(CaptureMode::CAPTURE_SPECIFIED_APP + 1));
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: CheckCaptureMode_003
 * @tc.desc: captureMode is CAPTURE_VIRTUAL_EXTENDED_SCREEN, should be valid
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureMode_003, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->CheckCaptureMode(CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN);
    ASSERT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: CheckAllParams_Extended_001
 * @tc.desc: EXTENDED mode with empty displayIds_ should fail
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckAllParams_Extended_001, TestSize.Level2)
{
    SetValidConfig();
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    screenCaptureServer_->displayIds_.clear();
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

/**
 * @tc.name: CheckAllParams_Extended_002
 * @tc.desc: EXTENDED mode with invalid displayId should fail
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckAllParams_Extended_002, TestSize.Level2)
{
    SetValidConfig();
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    screenCaptureServer_->displayIds_.clear();
    screenCaptureServer_->displayIds_.push_back(99999);
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

/**
 * @tc.name: CheckAudioCapParam_002
 * @tc.desc: audioSource > APP_PLAYBACK
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioCapParam_002, TestSize.Level2)
{
    AudioCaptureInfo micCapInfo = {.audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = static_cast<AudioCaptureSourceType>(AudioCaptureSourceType::APP_PLAYBACK + 1)};
    ASSERT_NE(screenCaptureServer_->CheckAudioCapParam(micCapInfo), MSERR_OK);
}

/**
 * @tc.name: CheckVideoEncParam_006
 * @tc.desc: videoCodec < VIDEO_DEFAULT
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_006, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoEncInfo.videoCodec = static_cast<VideoCodecFormat>(VideoCodecFormat::VIDEO_DEFAULT - 1);
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioCapInfo_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.micCapInfo.audioChannels = 0;
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    ASSERT_NE(screenCaptureServer_->CheckAudioCapInfo(config_.audioInfo.micCapInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoCapInfo_001, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 1080;
    ASSERT_NE(screenCaptureServer_->CheckVideoCapInfo(config_.videoInfo.videoCapInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_001, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0;
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_002, TestSize.Level2)
{
    SetValidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_001, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5;
    area.h = 5;
    bool ret = screenCaptureServer_->CheckDisplayArea(0, area);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_002, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5;
    area.h = 5;
    bool ret = screenCaptureServer_->CheckDisplayArea(10, area);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDisplayArea_003, TestSize.Level2)
{
    OHOS::Rect area;
    area.x = 0;
    area.y = 0;
    area.w = 5000;
    area.h = 5000;
    bool ret = screenCaptureServer_->CheckDisplayArea(0, area);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_001, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 20;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(DMError::DM_ERROR_DEVICE_NOT_SUPPORT);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_002, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 18;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(DMError::DM_ERROR_DEVICE_NOT_SUPPORT);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_003, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 20;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(DMError::DM_OK);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAppVersionForUnsupport_004, TestSize.Level2)
{
    screenCaptureServer_->appVersion_ = 18;
    bool ret = screenCaptureServer_->CheckAppVersionForUnsupport(DMError::DM_OK);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetCaptureMode_NotConfigState_001
 * @tc.desc: SetCaptureMode rejected when captureState_ is not CAP_CONFIG (L830)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureMode_NotConfigState_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN), MSERR_INVALID_OPERATION);
    EXPECT_NE(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_HOME_SCREEN);
}

/**
 * @tc.name: SetDataType_NotConfigState_001
 * @tc.desc: SetDataType rejected when captureState_ is not CAP_CONFIG (L846)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetDataType_NotConfigState_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->SetDataType(DataType::ORIGINAL_STREAM), MSERR_INVALID_OPERATION_CREATE);
    EXPECT_NE(screenCaptureServer_->captureConfig_.dataType, DataType::ORIGINAL_STREAM);
}

/**
 * @tc.name: SetRecorderInfo_NotConfigState_001
 * @tc.desc: SetRecorderInfo rejected when captureState_ is not CAP_CONFIG (L867)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetRecorderInfo_NotConfigState_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    recorderInfo.fileFormat = "mp4";
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->SetRecorderInfo(recorderInfo), MSERR_INVALID_OPERATION_CREATE);
}

/**
 * @tc.name: SetOutputFile_NotConfigState_001
 * @tc.desc: SetOutputFile rejected when captureState_ is not CAP_CONFIG (L889)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetOutputFile_NotConfigState_001, TestSize.Level2)
{
    int32_t fd = open("/data/test/media/sc_setoutputfile_notconfig.mp4", O_RDWR | O_CREAT, 0777);
    ASSERT_GE(fd, 0);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->SetOutputFile(fd), MSERR_INVALID_OPERATION_CREATE);
    EXPECT_EQ(screenCaptureServer_->outputFd_, -1);
    close(fd);
}

/**
 * @tc.name: SetScreenCaptureCallback_NotConfigState_001
 * @tc.desc: SetScreenCaptureCallback rejected when not CAP_CONFIG (L925)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetScreenCaptureCallback_NotConfigState_001, TestSize.Level2)
{
    sptr<IStandardScreenCaptureListener> listener = new StandardScreenCaptureServerUnittestCallback();
    auto callback = std::make_shared<ScreenCaptureListenerCallback>(listener);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->SetScreenCaptureCallback(callback), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: InitAudioEncInfo_NotConfigState_001
 * @tc.desc: InitAudioEncInfo rejected when captureState_ is not CAP_CONFIG (L938)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioEncInfo_NotConfigState_001, TestSize.Level2)
{
    AudioEncInfo info = {.audioBitrate = 48000, .audioCodecformat = AudioCodecFormat::AAC_LC};
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->InitAudioEncInfo(info), MSERR_INVALID_OPERATION_CREATE);
}

/**
 * @tc.name: InitVideoEncInfo_NotConfigState_001
 * @tc.desc: InitVideoEncInfo rejected when captureState_ is not CAP_CONFIG (L952)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoEncInfo_NotConfigState_001, TestSize.Level2)
{
    VideoEncInfo info = {.videoCodec = VideoCodecFormat::H264, .videoBitrate = 2000000, .videoFrameRate = 30};
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->InitVideoEncInfo(info), MSERR_INVALID_OPERATION_CREATE);
}

/**
 * @tc.name: CheckDataType_002
 * @tc.desc: dataType out of range (> CAPTURE_FILE) returns MSERR_INVALID_VAL (L998)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckDataType_002, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->CheckDataType(static_cast<DataType>(DataType::CAPTURE_FILE + 1)),
        MSERR_INVALID_VAL);
    EXPECT_EQ(screenCaptureServer_->CheckDataType(DataType::INVAILD), MSERR_INVALID_VAL);
}

/**
 * @tc.name: IsSetHighlightConfig_001
 * @tc.desc: all highlight fields valid and CAPTURE_SPECIFIED_WINDOW -> true (L1524)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 4;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xffffff;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    EXPECT_TRUE(screenCaptureServer_->IsSetHighlightConfig());
}

/**
 * @tc.name: IsSetHighlightConfig_002
 * @tc.desc: lineThickness below MIN_LINE_WIDTH -> false (L1509)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_002, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 0;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xffffff;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}

/**
 * @tc.name: IsSetHighlightConfig_003
 * @tc.desc: lineColor in invalid range (between MAX_LINE_COLOR_RGB and MIN_LINE_COLOR_ARGB) -> false (L1513)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_003, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 4;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0x1000000; // > 0xffffff && < 0xff000000
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}

/**
 * @tc.name: IsSetHighlightConfig_004
 * @tc.desc: highlight mode neither CLOSED nor CORNER_WRAP -> false (L1517)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_004, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 4;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xffffff;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = static_cast<ScreenCaptureHighlightMode>(
        2); // neither CLOSED(0) nor CORNER_WRAP(1)
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}

/**
 * @tc.name: IsSetHighlightConfig_005
 * @tc.desc: captureMode not CAPTURE_SPECIFIED_WINDOW -> false (L1521)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_005, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 4;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xffffff;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED;
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}
// ===================== SetCaptureMode (L826-838) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureMode_CheckFail_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(screenCaptureServer_->SetCaptureMode(CaptureMode::CAPTURE_INVAILD), MSERR_INVALID_VAL);
}

// ===================== SetDataType (L840-862) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetDataType_NotConfigState_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->SetDataType(DataType::ORIGINAL_STREAM), MSERR_INVALID_OPERATION_CREATE);
}

// ===================== SetRecorderInfo (L864-884) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetRecorderInfo_NotConfigState_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    RecorderInfo info;
    info.fileFormat = "mp4";
    EXPECT_EQ(screenCaptureServer_->SetRecorderInfo(info), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetRecorderInfo_InvalidFormat_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    RecorderInfo info;
    info.fileFormat = "invalid";
    EXPECT_EQ(screenCaptureServer_->SetRecorderInfo(info), MSERR_INVALID_VAL);
}

// ===================== InitAudioEncInfo (L935-947) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioEncInfo_NotConfigState_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    AudioEncInfo info;
    EXPECT_EQ(screenCaptureServer_->InitAudioEncInfo(info), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitAudioEncInfo_CheckFail_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    AudioEncInfo info;
    info.audioCodecformat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT;
    info.audioBitrate = 48000;
    EXPECT_EQ(screenCaptureServer_->InitAudioEncInfo(info), MSERR_INVALID_VAL);
}

// ===================== InitVideoEncInfo (L949-961) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoEncInfo_NotConfigState_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    VideoEncInfo info;
    EXPECT_EQ(screenCaptureServer_->InitVideoEncInfo(info), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoEncInfo_CheckFail_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    VideoEncInfo info;
    info.videoCodec = VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT;
    info.videoBitrate = 2000000;
    info.videoFrameRate = 30;
    EXPECT_EQ(screenCaptureServer_->InitVideoEncInfo(info), MSERR_INVALID_VID_CODEC_FORMAT);
}

// ===================== CheckCaptureStreamParams (L1188-1227) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_SurfaceNullValid_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSampleRate = 16000;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioChannels = 2;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioChannels = 2;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = 720;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = 1280;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->surface_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_BothIgnore_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSampleRate = 0;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioChannels = 0;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSampleRate = 0;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioChannels = 0;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    screenCaptureServer_->isSurfaceMode_ = false;
    EXPECT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_INVALID_VAL);
}

// ===================== CheckCaptureFileParams (L1229-1274) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureFileParams_InvalidInner_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSampleRate = 0;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioChannels = 0;
    screenCaptureServer_->captureConfig_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSampleRate = 1;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioChannels = 2;
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_.audioInfo.audioEncInfo.audioBitrate = 48000;
    screenCaptureServer_->captureConfig_.audioInfo.audioEncInfo.audioCodecformat = AudioCodecFormat::AAC_LC;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    EXPECT_EQ(screenCaptureServer_->CheckCaptureFileParams(), MSERR_INVALID_VAL);
}

// ===================== IsSetHighlightConfig (L1507-1525) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_LineThicknessInvalid_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 0;
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSetHighlightConfig_ModeInvalid_B2, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.highlightConfig.lineThickness = 2;
    screenCaptureServer_->captureConfig_.highlightConfig.lineColor = 0xff0000;
    screenCaptureServer_->captureConfig_.highlightConfig.mode = ScreenCaptureHighlightMode::HIGHLIGHT_MODE_INVALID;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    EXPECT_FALSE(screenCaptureServer_->IsSetHighlightConfig());
}

// ===================== SetHighlightConfigForWindowManager (L1527-1553) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetHighlightConfigForWindowManager_MissionIdOverflow_B2, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back(
        {static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) + 1, true});
    Rosen::OutlineParams params;
    screenCaptureServer_->SetHighlightConfigForWindowManager(true, params);
    EXPECT_TRUE(params.persistentIds_.empty());
    screenCaptureServer_->missionInfos_.clear();
}

// ===================== ConvertToOutlineShape (L1555-1565) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, ConvertToOutlineShape_Default_B2, TestSize.Level2)
{
    auto shape = screenCaptureServer_->ConvertToOutlineShape(static_cast<ScreenCaptureHighlightMode>(99));
    EXPECT_EQ(shape, OutlineShape::OUTLINE_SHAPE_END);
}

// ===================== SetMaxVideoFrameRate (L3469-3493) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetMaxVideoFrameRate_NotActive_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(screenCaptureServer_->SetMaxVideoFrameRate(30), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMaxVideoFrameRate_InvalidRate_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->SetMaxVideoFrameRate(0), MSERR_INVALID_VAL);
}

/**
 * @tc.name: StartScreenCaptureStream_NotOriginalStream_001
 * @tc.desc: StartScreenCaptureStream rejected when dataType != ORIGINAL_STREAM (L1402)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureStream_NotOriginalStream_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    EXPECT_EQ(screenCaptureServer_->StartScreenCaptureStream(), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: StartScreenCaptureFile_NotCaptureFile_001
 * @tc.desc: StartScreenCaptureFile rejected when dataType != CAPTURE_FILE (L1414)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureFile_NotCaptureFile_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_EQ(screenCaptureServer_->StartScreenCaptureFile(), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: ShowCursorInner_InvalidScreenId_001
 * @tc.desc: ShowCursorInner returns MSERR_INVALID_VAL when virtualScreenId_ is invalid (L3345)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursorInner_InvalidScreenId_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = Rosen::SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->ShowCursorInner(), MSERR_INVALID_VAL);
}

/**
 * @tc.name: ResizeCanvas_NotOriginalStream_001
 * @tc.desc: ResizeCanvas rejected when dataType != ORIGINAL_STREAM in active state (L3380)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_NotOriginalStream_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(580, 1280), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SkipPrivacyModeInner_InvalidScreenId_001
 * @tc.desc: SkipPrivacyModeInner returns MSERR_INVALID_VAL when virtualScreenId_ is invalid (L3432)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SkipPrivacyModeInner_InvalidScreenId_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = Rosen::SCREEN_ID_INVALID;
    EXPECT_EQ(screenCaptureServer_->SkipPrivacyModeInner(), MSERR_INVALID_VAL);
}

/**
 * @tc.name: AddWatermark_NotCreatedState_001
 * @tc.desc: AddWatermark rejected when captureState_ != CREATED (L4114)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AddWatermark_NotCreatedState_001, TestSize.Level2)
{
    int32_t width = 200;
    int32_t height = 200;
    int32_t watermarkCount = 0;
    auto buffer = CreateWatermarkBuffer(); // sets state=CREATED, dataType=CAPTURE_FILE
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->AddWatermark(buffer, width, height, watermarkCount),
        MSERR_INVALID_OPERATION_CREATE);
}

/**
 * @tc.name: AddWatermark_NotCaptureFile_001
 * @tc.desc: AddWatermark returns MSERR_UNKNOWN when dataType != CAPTURE_FILE (L4116)
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AddWatermark_NotCaptureFile_001, TestSize.Level2)
{
    int32_t width = 200;
    int32_t height = 200;
    int32_t watermarkCount = 0;
    auto buffer = CreateWatermarkBuffer(); // state=CREATED, dataType=CAPTURE_FILE
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_EQ(screenCaptureServer_->AddWatermark(buffer, width, height, watermarkCount), MSERR_UNKNOWN);
}

// ===================== SetPickerMode (L3011-3024) =====================

/**
 * @tc.name: SetPickerMode_001
 * @tc.desc: SetPickerMode param validation: valid mode passes, out-of-range returns MSERR_INVALID_VAL
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetPickerMode_001, TestSize.Level2)
{
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    EXPECT_EQ(screenCaptureServer_->SetPickerMode(PickerMode::SCREEN_AND_WINDOW), MSERR_OK);
#else
    EXPECT_EQ(screenCaptureServer_->SetPickerMode(PickerMode::SCREEN_AND_WINDOW), MSERR_UNKNOWN_UNSUPPORT);
#endif
    EXPECT_EQ(screenCaptureServer_->SetPickerMode(static_cast<PickerMode>(-1)), MSERR_INVALID_VAL);
    EXPECT_EQ(screenCaptureServer_->SetPickerMode(static_cast<PickerMode>(7)), MSERR_INVALID_VAL);
}
} // namespace Media
} // namespace OHOS
