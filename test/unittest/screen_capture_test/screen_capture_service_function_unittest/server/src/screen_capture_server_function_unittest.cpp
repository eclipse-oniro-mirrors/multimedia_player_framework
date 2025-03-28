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

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServerFunctionTest"};
constexpr int32_t FLIE_CREATE_FLAGS = 0777;
static const std::string BUTTON_NAME_MIC = "mic";
static const std::string BUTTON_NAME_STOP = "stop";
}

namespace OHOS {
namespace Media {

void ScreenCaptureServerFunctionTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info_, policy_);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

void ScreenCaptureServerFunctionTest::SetUp()
{
    SetHapPermission();
    std::shared_ptr<IScreenCaptureService> tempServer_ = ScreenCaptureServer::Create();
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer_);
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    screenCaptureServer_->screenCaptureCb_ = std::make_shared<ScreenCaptureListenerCallback>(listener);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

void ScreenCaptureServerFunctionTest::TearDown()
{
    if (screenCaptureServer_) {
        screenCaptureServer_->Release();
        screenCaptureServer_ = nullptr;
    }
}

int32_t ScreenCaptureServerFunctionTest::SetInvalidConfig()
{
    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = SOURCE_DEFAULT
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT,
    };

    VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };

    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };

    AudioInfo audioInfo = {
        .micCapInfo = micCapinfo,
        .innerCapInfo = innerCapInfo,
    };

    VideoInfo videoInfo = {
        .videoCapInfo = videocapinfo,
        .videoEncInfo = videoEncInfo
    };

    config_ = {
        .captureMode = CAPTURE_HOME_SCREEN,
        .dataType = ORIGINAL_STREAM,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo
    };
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::SetValidConfig()
{
    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK,
    };

    VideoCaptureInfo videocapinfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };

    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };

    AudioInfo audioInfo = {
        .micCapInfo = micCapinfo,
        .innerCapInfo = innerCapInfo,
    };

    VideoInfo videoInfo = {
        .videoCapInfo = videocapinfo,
        .videoEncInfo = videoEncInfo
    };

    config_ = {
        .captureMode = CAPTURE_HOME_SCREEN,
        .dataType = ORIGINAL_STREAM,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo
    };
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::SetInvalidConfigFile(RecorderInfo &recorderInfo)
{
    AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };

    VideoCaptureInfo videoCapInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };

    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT,
    };

    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT,
    };

    AudioInfo audioInfo = {
        .micCapInfo = micCapinfo,
        .innerCapInfo = innerCapInfo,
        .audioEncInfo = audioEncInfo
    };

    VideoInfo videoInfo = {
        .videoCapInfo = videoCapInfo,
        .videoEncInfo = videoEncInfo
    };

    config_ = {
        .captureMode = CaptureMode::CAPTURE_HOME_SCREEN,
        .dataType = DataType::CAPTURE_FILE,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo,
        .recorderInfo = recorderInfo
    };
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::SetValidConfigFile(RecorderInfo &recorderInfo)
{
    AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };

    VideoCaptureInfo videoCapInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };

    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };

    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };

    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK,
    };

    AudioInfo audioInfo = {
        .micCapInfo = micCapinfo,
        .innerCapInfo = innerCapInfo,
        .audioEncInfo = audioEncInfo
    };

    VideoInfo videoInfo = {
        .videoCapInfo = videoCapInfo,
        .videoEncInfo = videoEncInfo
    };

    config_ = {
        .captureMode = CaptureMode::CAPTURE_HOME_SCREEN,
        .dataType = DataType::CAPTURE_FILE,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo,
        .recorderInfo = recorderInfo
    };
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::SetRecorderInfo(std::string name,
    RecorderInfo &recorderInfo)
{
    OpenFileFd(name);
    recorderInfo.url = "fd://" + std::to_string(outputFd_);
    recorderInfo.fileFormat = "mp4";
    return MSERR_OK;
}

static const std::string SCREEN_CAPTURE_ROOT_DIR = "/data/test/media/";

void ScreenCaptureServerFunctionTest::OpenFileFd(std::string name)
{
    if (outputFd_ != -1) {
        (void)::close(outputFd_);
        outputFd_ = -1;
    }
    outputFd_ = open((SCREEN_CAPTURE_ROOT_DIR + name).c_str(), O_RDWR | O_CREAT, FLIE_CREATE_FLAGS);
}

int32_t ScreenCaptureServerFunctionTest::InitFileScreenCaptureServer()
{
    int32_t ret = screenCaptureServer_->SetCaptureMode(config_.captureMode);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetCaptureMode failed");
    ret = screenCaptureServer_->SetDataType(config_.dataType);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetDataType failed");
    ret = screenCaptureServer_->SetRecorderInfo(config_.recorderInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetRecorderInfo failed");
    const std::string fdHead = "fd://";
    CHECK_AND_RETURN_RET_LOG(config_.recorderInfo.url.find(fdHead) != std::string::npos, MSERR_INVALID_VAL,
        "check url failed");
    int32_t outputFd = -1;
    std::string inputFd = config_.recorderInfo.url.substr(fdHead.size());
    CHECK_AND_RETURN_RET_LOG(StrToInt(inputFd, outputFd) == true && outputFd >= 0, MSERR_INVALID_VAL,
        "open file failed");
    ret = screenCaptureServer_->SetOutputFile(outputFd);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetOutputFile failed");
    ret = screenCaptureServer_->InitAudioEncInfo(config_.audioInfo.audioEncInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitAudioEncInfo failed");
    ret = screenCaptureServer_->InitAudioCap(config_.audioInfo.micCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "init micAudioCap failed");
    ret = screenCaptureServer_->InitAudioCap(config_.audioInfo.innerCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "init innerCapInfo failed, innerCapInfo should be valid");

    ret = screenCaptureServer_->InitVideoEncInfo(config_.videoInfo.videoEncInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoEncInfo failed");
    ret = screenCaptureServer_->InitVideoCap(config_.videoInfo.videoCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoCap failed");
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::InitStreamScreenCaptureServer()
{
    int32_t ret = screenCaptureServer_->SetCaptureMode(config_.captureMode);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetCaptureMode failed");
    ret = screenCaptureServer_->SetDataType(config_.dataType);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetDataType failed");
    ret = screenCaptureServer_->InitAudioCap(config_.audioInfo.micCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "init micAudioCap failed");
    ret = screenCaptureServer_->InitAudioCap(config_.audioInfo.innerCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "init innerCapInfo failed, innerCapInfo should be valid");
    ret = screenCaptureServer_->InitVideoCap(config_.videoInfo.videoCapInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoCap failed");
    return MSERR_OK;
}

int32_t ScreenCaptureServerFunctionTest::StartFileAudioCapture(AVScreenCaptureMixMode mixMode)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(mixMode, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    MEDIA_LOGI("StartFileAudioCapture start");
    int32_t ret = screenCaptureServer_->StartFileInnerAudioCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileInnerAudioCapture failed, ret:%{public}d,"
        "dataType:%{public}d", ret, screenCaptureServer_->captureConfig_.dataType);
    ret = screenCaptureServer_->StartFileMicAudioCapture();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("StartFileMicAudioCapture failed");
    }
    return ret;
}

int32_t ScreenCaptureServerFunctionTest::StartStreamAudioCapture()
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    MEDIA_LOGI("StartStreamAudioCapture start");
    int32_t ret = screenCaptureServer_->StartStreamInnerAudioCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartStreamInnerAudioCapture failed, ret:%{public}d,"
        "dataType:%{public}d", ret, screenCaptureServer_->captureConfig_.dataType);
    ret = screenCaptureServer_->StartStreamMicAudioCapture();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("StartFileMicAudioCapture failed");
    }
    MEDIA_LOGI("StartStreamAudioCapture end");
    return ret;
}

// videoCapInfo and innerCapInfo IGNORE
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// audioSampleRate INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 12345;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 54321;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_NE(InitStreamScreenCaptureServer(), MSERR_OK);
}

// videoCapInfo INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_003, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    config_.videoInfo.videoCapInfo.videoFrameHeight = -1;
    ASSERT_NE(InitStreamScreenCaptureServer(), MSERR_OK);
}

// dataType INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_004, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.dataType = DataType::INVAILD;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// surface_ is nullptr
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_005, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->surface_ = nullptr;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// audioSampleRate INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureStreamParamsInvalid_006, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 1;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// videoFrameWidth and videoFrameHeight INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_001.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    config_.videoInfo.videoCapInfo.videoFrameWidth = -1;
    config_.videoInfo.videoCapInfo.videoFrameHeight = -1;
    ASSERT_NE(InitFileScreenCaptureServer(), MSERR_OK);
}

// audioSampleRate INVALID
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_002.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 1;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_NE(InitFileScreenCaptureServer(), MSERR_OK);
}

// audioSampleRate and audioSampleRate are not equal
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_003.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 8000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// videoCapInfo Ignored, is valid
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_004, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_004.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_005, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_005.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = -1;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_006, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_006.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = -1;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// micCapInfo Ignored, is valid
HWTEST_F(ScreenCaptureServerFunctionTest, CaptureFileParamsInvalid_007, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_007.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 0;
    config_.audioInfo.micCapInfo.audioChannels = 0;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_EQ(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

// audioChannels is different
HWTEST_F(ScreenCaptureServerFunctionTest, capture_file_params_invalid_008, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capture_file_params_invalid_008.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 1;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    screenCaptureServer_->captureConfig_ = config_;
    ASSERT_NE(screenCaptureServer_->CheckAllParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetMissionIds_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->GetMissionIds(screenCaptureServer_->missionIds_), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetMissionIds_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs.push_back(1);
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs.push_back(2);
    ASSERT_EQ(screenCaptureServer_->GetMissionIds(screenCaptureServer_->missionIds_), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    screenCaptureServer_->captureCallback_->OnRendererStateChange(audioRendererChangeInfos);
    screenCaptureServer_->audioSource_->VoIPStateUpdate(audioRendererChangeInfos);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    screenCaptureServer_->audioSource_->VoIPStateUpdate(audioRendererChangeInfos);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    screenCaptureServer_->audioSource_->SpeakerStateUpdate(audioRendererChangeInfos);
    ASSERT_EQ(screenCaptureServer_->audioSource_->HasSpeakerStream(audioRendererChangeInfos), false);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    for (int i = 0; i < 7; ++i) {
        std::shared_ptr<AudioRendererChangeInfo> changeInfo = std::make_shared<AudioRendererChangeInfo>();
        audioRendererChangeInfos.push_back(changeInfo);
    }
    audioRendererChangeInfos.push_back(nullptr);
    audioRendererChangeInfos[0]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_WIRED_HEADSET;
    audioRendererChangeInfos[1]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_WIRED_HEADPHONES;
    audioRendererChangeInfos[2]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_BLUETOOTH_SCO;
    audioRendererChangeInfos[3]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_BLUETOOTH_A2DP;
    audioRendererChangeInfos[4]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_USB_HEADSET;
    audioRendererChangeInfos[5]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_USB_ARM_HEADSET;
    audioRendererChangeInfos[6]->outputDeviceInfo.deviceType_ = DEVICE_TYPE_SPEAKER;
    screenCaptureServer_->audioSource_->HasSpeakerStream(audioRendererChangeInfos);
    ASSERT_EQ(screenCaptureServer_->audioSource_->HasSpeakerStream(audioRendererChangeInfos), true);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    audioRendererChangeInfos.push_back(nullptr);
    for (int i = 0; i < 3; ++i) {
        std::shared_ptr<AudioRendererChangeInfo> changeInfo = std::make_shared<AudioRendererChangeInfo>();
        audioRendererChangeInfos.push_back(changeInfo);
    }
    audioRendererChangeInfos[1]->rendererState = RendererState::RENDERER_STOPPED;
    audioRendererChangeInfos[2]->rendererState = RendererState::RENDERER_RUNNING;
    audioRendererChangeInfos[2]->rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    audioRendererChangeInfos[3]->rendererState = RendererState::RENDERER_RUNNING;
    audioRendererChangeInfos[3]->rendererInfo.streamUsage =
        AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    screenCaptureServer_->audioSource_->HasVoIPStream(audioRendererChangeInfos);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AudioDataSource_005, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    screenCaptureServer_->audioSource_->speakerAliveStatus_ = true;
    screenCaptureServer_->audioSource_->SpeakerStateUpdate(audioRendererChangeInfos);
    screenCaptureServer_->audioSource_->speakerAliveStatus_ = false;
    screenCaptureServer_->audioSource_->SpeakerStateUpdate(audioRendererChangeInfos);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCapturePermission_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->CheckScreenCapturePermission(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoEncInfo.videoCodec = VIDEO_CODEC_FORMAT_BUTT;
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoEncInfo.videoBitrate = screenCaptureServer_->VIDEO_BITRATE_MIN - 1;
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_003, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoEncInfo.videoBitrate = screenCaptureServer_->VIDEO_BITRATE_MAX + 1;
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_004, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoEncInfo.videoFrameRate = screenCaptureServer_->VIDEO_FRAME_RATE_MIN - 1;
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoEncParam_005, TestSize.Level2)
{
    SetInvalidConfig();
    config_.videoInfo.videoEncInfo.videoFrameRate = screenCaptureServer_->VIDEO_FRAME_RATE_MAX + 1;
    ASSERT_NE(screenCaptureServer_->CheckVideoEncParam(config_.videoInfo.videoEncInfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetOutputFile_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->SetOutputFile(-1), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->OnStartScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("on_start_screen_capture_unittest_002.mp4", recorderInfo);
    SetInvalidConfigFile(recorderInfo);
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->OnStartScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetScreenScaleMode_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->SetScreenScaleMode(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnReceiveUserPrivacyAuthority_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->OnReceiveUserPrivacyAuthority(false), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnReceiveUserPrivacyAuthority_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    ASSERT_NE(screenCaptureServer_->OnReceiveUserPrivacyAuthority(false), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnReceiveUserPrivacyAuthority_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    ASSERT_NE(screenCaptureServer_->OnReceiveUserPrivacyAuthority(true), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnReceiveUserPrivacyAuthority_004, TestSize.Level2)
{
    screenCaptureServer_->screenCaptureCb_ = nullptr;
    ASSERT_NE(screenCaptureServer_->OnReceiveUserPrivacyAuthority(false), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RepeatStartAudioCapture_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->innerAudioCapture_->Start(screenCaptureServer_->appInfo_), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RepeatResumeAudioCapture_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_NE(screenCaptureServer_->innerAudioCapture_->Resume(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RepeatPauseAudioCapture_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->innerAudioCapture_->Pause(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    ASSERT_EQ(screenCaptureServer_->UpdatePrivacyUsingPermissionState(START_VIDEO), true);
    ASSERT_EQ(screenCaptureServer_->UpdatePrivacyUsingPermissionState(STOP_VIDEO), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdatePrivacyUsingPermissionState_002, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    ASSERT_EQ(screenCaptureServer_->UpdatePrivacyUsingPermissionState(START_VIDEO), false);
    ASSERT_EQ(screenCaptureServer_->UpdatePrivacyUsingPermissionState(STOP_VIDEO), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureWithSurface_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    ASSERT_NE(screenCaptureServer_->StartScreenCaptureWithSurface(nullptr, true), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixAudio_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    const int channels = 2;
    const int bufferSize = 10;
    const char zeroChar = (char)0;
    const char minChar = (char)127;
    const char maxChar = (char)-128;
    char innerBuffer[bufferSize] = {zeroChar, maxChar, minChar, zeroChar, maxChar, minChar, zeroChar, maxChar,
        minChar, zeroChar};
    char micBuffer[bufferSize] = {maxChar, minChar, zeroChar, maxChar, minChar, zeroChar, maxChar, minChar,
        zeroChar, maxChar};
    char* srcData[channels] = {nullptr};
    srcData[0] = innerBuffer;
    srcData[1] = micBuffer;
    char mixData[bufferSize];
    screenCaptureServer_->audioSource_->MixAudio(srcData, mixData, channels, bufferSize);
    ASSERT_EQ(mixData[0], maxChar);
    ASSERT_EQ(mixData[bufferSize - 1], maxChar);
}

// MixAudio input channels param is 0
HWTEST_F(ScreenCaptureServerFunctionTest, MixAudio_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    const int channels = 2;
    const int bufferSize = 10;
    const char zeroChar = (char)0;
    const char minChar = (char)127;
    const char maxChar = (char)-128;
    char innerBuffer[bufferSize] = {zeroChar, maxChar, minChar, zeroChar, maxChar, minChar, zeroChar, maxChar,
        minChar, zeroChar};
    char micBuffer[bufferSize] = {maxChar, minChar, zeroChar, maxChar, minChar, zeroChar, maxChar, minChar,
        zeroChar, maxChar};
    char* srcData[channels] = {nullptr};
    srcData[0] = innerBuffer;
    srcData[1] = micBuffer;
    char mixData[bufferSize] = {zeroChar};
    screenCaptureServer_->audioSource_->MixAudio(srcData, mixData, 0, bufferSize);
    ASSERT_EQ(mixData[0], zeroChar);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenConnectListenerInScreenCapture_001, TestSize.Level2)
{
    screenCaptureServer_->displayScreenId_ = 1; // 1 display screen id
    screenCaptureServer_->RegisterScreenConnectListener();
    uint64_t screenId = 1; // 1 disconnect screen id
    screenCaptureServer_->screenConnectListener_->OnConnect(screenId);
    screenCaptureServer_->screenConnectListener_->OnDisconnect(screenId);
    screenCaptureServer_->screenConnectListener_->OnChange(screenId);
    ASSERT_NE(screenCaptureServer_->screenConnectListener_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ScreenConnectListenerInScreenCapture_002, TestSize.Level2)
{
    screenCaptureServer_->displayScreenId_ = 2;  // 2 display screen id
    screenCaptureServer_->RegisterScreenConnectListener();
    uint64_t screenId = 1; // 1 disconnect screen id
    screenCaptureServer_->screenConnectListener_->OnConnect(screenId);
    screenCaptureServer_->screenConnectListener_->OnDisconnect(screenId);
    screenCaptureServer_->screenConnectListener_->OnChange(screenId);
    ASSERT_NE(screenCaptureServer_->screenConnectListener_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotificationSubscriber_001, TestSize.Level2)
{
    auto notificationSubscriber = NotificationSubscriber();
    notificationSubscriber.OnConnected();
    notificationSubscriber.OnDisconnected();
    notificationSubscriber.OnDied();
    ASSERT_NE(&notificationSubscriber, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotificationSubscriber_002, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> screenCaptureServerInner;
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServerInner = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    screenCaptureServerInner->SetScreenCaptureCallback(screenCaptureCb);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);

    auto notificationSubscriber = NotificationSubscriber();
    if (screenCaptureServerInner->serverMap_.begin() != screenCaptureServerInner->serverMap_.end()) {
        int32_t notificationId = screenCaptureServerInner->serverMap_.begin()->first;
        OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption =
            new(std::nothrow) OHOS::Notification::NotificationButtonOption();
        buttonOption->SetButtonName(BUTTON_NAME_STOP);
        notificationSubscriber.OnResponse(notificationId, buttonOption);
    }
    ASSERT_NE(&notificationSubscriber, nullptr);

    screenCaptureServerInner->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotificationSubscriber_003, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> screenCaptureServerInner;
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServerInner = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    screenCaptureServerInner->SetScreenCaptureCallback(screenCaptureCb);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);

    auto notificationSubscriber = NotificationSubscriber();
    if (screenCaptureServerInner->serverMap_.begin() != screenCaptureServerInner->serverMap_.end()) {
        int32_t notificationId = screenCaptureServerInner->serverMap_.begin()->first;
        OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption =
            new(std::nothrow) OHOS::Notification::NotificationButtonOption();
        buttonOption->SetButtonName("null");
        notificationSubscriber.OnResponse(notificationId, buttonOption);
    }

    sleep(RECORDER_TIME);
    ASSERT_NE(&notificationSubscriber, nullptr);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotificationSubscriber_004, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> screenCaptureServerInner;
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServerInner = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    RecorderInfo recorderInfo{};
    SetValidConfigFile(recorderInfo);
    config_.dataType = DataType::ORIGINAL_STREAM;
    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb =
        std::make_shared<ScreenCaptureServerUnittestCallbackMock>(listener);
    screenCaptureServerInner->SetScreenCaptureCallback(screenCaptureCb);
    screenCaptureServerInner->SetCaptureMode(config_.captureMode);
    screenCaptureServerInner->SetDataType(config_.dataType);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.innerCapInfo);
    screenCaptureServerInner->InitVideoCap(config_.videoInfo.videoCapInfo);
    screenCaptureServerInner->InitAudioCap(config_.audioInfo.micCapInfo);
    int32_t ret = screenCaptureServerInner->StartScreenCapture(false);
    ASSERT_EQ(ret, MSERR_OK);
    sleep(RECORDER_TIME);

    auto notificationSubscriber = NotificationSubscriber();
    int32_t invalidNotificationId = ScreenCaptureServer::maxSessionId_ + 1;
    OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption =
        new(std::nothrow) OHOS::Notification::NotificationButtonOption();
    buttonOption->SetButtonName("null");
    notificationSubscriber.OnResponse(invalidNotificationId, buttonOption);

    sleep(RECORDER_TIME);
    ASSERT_NE(&notificationSubscriber, nullptr);
    screenCaptureServerInner->StopScreenCapture();
    screenCaptureServerInner->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetDisplayId_001, TestSize.Level2)
{
    uint64_t displayId = 0;
    screenCaptureServer_->SetDisplayId(displayId);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.displayId, displayId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMissionId_001, TestSize.Level2)
{
    uint64_t missionId = 0;
    screenCaptureServer_->SetMissionId(missionId);
    ASSERT_EQ(screenCaptureServer_->missionIds_.back(), missionId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureInner_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    ASSERT_EQ(screenCaptureServer_->StartScreenCaptureInner(false), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureInner_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    ASSERT_NE(screenCaptureServer_->StartScreenCaptureInner(true), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsTelInCallSkipList_001, TestSize.Level2)
{
    screenCaptureServer_->isCalledBySystemApp_ = true;
    screenCaptureServer_->appName_ = HiviewCareBundleName;
    ASSERT_EQ(screenCaptureServer_->IsTelInCallSkipList(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsTelInCallSkipList_002, TestSize.Level2)
{
    screenCaptureServer_->isCalledBySystemApp_ = true;
    screenCaptureServer_->appName_ = "";
    ASSERT_EQ(screenCaptureServer_->IsTelInCallSkipList(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsTelInCallSkipList_003, TestSize.Level2)
{
    screenCaptureServer_->isCalledBySystemApp_ = false;
    screenCaptureServer_->appName_ = "";
    ASSERT_EQ(screenCaptureServer_->IsTelInCallSkipList(), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetStringByResourceName_001, TestSize.Level2)
{
    screenCaptureServer_->InitResourceManager();
    std::string liveViewText = ScreenCaptureServer::QUOTATION_MARKS_STRING;
    liveViewText += screenCaptureServer_->GetStringByResourceName(
        ScreenCaptureServer::NOTIFICATION_SCREEN_RECORDING_TITLE_ID).c_str();
    MEDIA_LOGI("GetStringByResourceName liveViewText: %{public}s", liveViewText.c_str());
    ASSERT_EQ(screenCaptureServer_->GetStringByResourceName(
        ScreenCaptureServer::NOTIFICATION_SCREEN_RECORDING_TITLE_ID).size() > 0, true);
    ASSERT_EQ(screenCaptureServer_->GetStringByResourceName("NOT_EXITS_ID").size() == 0, true);
    screenCaptureServer_->resourceManager_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->GetStringByResourceName(
        ScreenCaptureServer::NOTIFICATION_SCREEN_RECORDING_TITLE_ID).size() > 0, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCaptureConfig_001, TestSize.Level2)
{
    screenCaptureServer_->SetCaptureConfig(CAPTURE_INVAILD, -1);
    screenCaptureServer_->SetCaptureConfig(CAPTURE_INVAILD, 0);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs.back(), 0);
}

#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
HWTEST_F(ScreenCaptureServerFunctionTest, TryNotificationOnPostStartScreenCapture_001, TestSize.Level2)
{
    int32_t ret = screenCaptureServer_->TryNotificationOnPostStartScreenCapture();
    ASSERT_NE(ret, MSERR_OK);
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseAudioBufferMix_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int32_t ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::MIX_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::MIC_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::INNER_MODE);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReleaseAudioBufferMix_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int32_t ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::MIX_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::MIC_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->ReleaseAudioBufferMix(AVScreenCaptureMixMode::INNER_MODE);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_001, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    const int bufferSize = 10;
    uint8_t *innerBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    uint8_t *micBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    std::shared_ptr<AudioBuffer> innerAudioBuffer = std::make_shared<AudioBuffer>(innerBuffer, bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<AudioBuffer> micAudioBuffer = std::make_shared<AudioBuffer>(micBuffer, bufferSize, 0,
        SOURCE_DEFAULT);
    uint8_t data[bufferSize];
    std::shared_ptr<AVMemory> bufferMem = AVMemory::CreateAVMemory(data, bufferSize, bufferSize);
    int32_t ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_002, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    const int bufferSize = 10;
    uint8_t *innerBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    std::shared_ptr<AudioBuffer> innerAudioBuffer = std::make_shared<AudioBuffer>(innerBuffer, bufferSize, 0,
        SOURCE_DEFAULT);
    std::shared_ptr<AudioBuffer> micAudioBuffer;
    uint8_t data[bufferSize];
    std::shared_ptr<AVMemory> bufferMem = AVMemory::CreateAVMemory(data, bufferSize, bufferSize);
    int32_t ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MixModeBufferWrite_003, TestSize.Level2)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    const int bufferSize = 10;
    uint8_t *micBuffer = (uint8_t *)malloc(sizeof(uint8_t) * bufferSize);
    std::shared_ptr<AudioBuffer> innerAudioBuffer;
    std::shared_ptr<AudioBuffer> micAudioBuffer = std::make_shared<AudioBuffer>(micBuffer, bufferSize, 0,
        SOURCE_DEFAULT);
    uint8_t data[bufferSize];
    std::shared_ptr<AVMemory> bufferMem = AVMemory::CreateAVMemory(data, bufferSize, bufferSize);
    int32_t ret = screenCaptureServer_->audioSource_->MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBufferMix_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    std::shared_ptr<AudioBuffer> innerAudioBuffer;
    std::shared_ptr<AudioBuffer> micAudioBuffer;
    int32_t ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::MIX_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::MIC_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::INNER_MODE);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AcquireAudioBufferMix_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    std::shared_ptr<AudioBuffer> innerAudioBuffer;
    std::shared_ptr<AudioBuffer> micAudioBuffer;
    int32_t ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::MIX_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::MIC_MODE);
    ASSERT_EQ(ret, MSERR_OK);
    ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer,
        AVScreenCaptureMixMode::INNER_MODE);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetChoiceFromJson_001, TestSize.Level2)
{
    Json::Value root;
    std::string content = "ghgh%^&%^$*^(}{^af&**)";
    std::string value;
    screenCaptureServer_->GetChoiceFromJson(root, content, "choice", value);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetChoiceFromJson_002, TestSize.Level2)
{
    Json::Value root;
    std::string content = "{\"choice_\": \"true\"}";
    std::string value;
    screenCaptureServer_->GetChoiceFromJson(root, content, "choice", value);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartFileInnerAudioCapture_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.state =
        AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->speakerAliveStatus_ = false;
    screenCaptureServer_->StartFileInnerAudioCapture();
    screenCaptureServer_->StartFileMicAudioCapture();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartFileInnerAudioCapture_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("start_file_inner_audio_capture_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo.state =
        AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    screenCaptureServer_->StartFileInnerAudioCapture();
    screenCaptureServer_->StartFileMicAudioCapture();
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

#ifdef SUPPORT_CALL
HWTEST_F(ScreenCaptureServerFunctionTest, StopAndRelease_001, TestSize.Level2)
{
    ScreenCaptureObserverCallBack* obcb = new ScreenCaptureObserverCallBack(screenCaptureServer_);
    if (obcb) {
        ASSERT_EQ(obcb->StopAndRelease(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER), true);
    }
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopAndRelease_002, TestSize.Level2)
{
    ScreenCaptureObserverCallBack* obcb = new ScreenCaptureObserverCallBack(screenCaptureServer_);
    if (obcb) {
        screenCaptureServer_->Release();
        screenCaptureServer_ = nullptr;
        ASSERT_EQ(obcb->StopAndRelease(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER), true);
    }
}

/**
* @tc.name: OnTelCallStateChanged_001
* @tc.desc: in call with tel skip
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_tel_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    screenCaptureServer_->appName_ = HiviewCareBundleName;
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: OnTelCallStateChanged_002
* @tc.desc: in call and out call with mic on, CAPTURE_FILE
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_tel_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: OnTelCallStateChanged_003
* @tc.desc: in call and out call with mic off, CAPTURE_FILE
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_tel_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(StartFileAudioCapture(AVScreenCaptureMixMode::MIX_MODE), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: OnTelCallStateChanged_004
* @tc.desc: in call and out call with mic on, ORIGINAL_STREAM
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: OnTelCallStateChanged_005
* @tc.desc: out call and out call with mic on, ORIGINAL_STREAM (invalid state)
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_005, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(false), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: OnTelCallStateChanged_006
* @tc.desc: in call and in call with mic on, ORIGINAL_STREAM (invalid state)
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, OnTelCallStateChanged_006, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->TelCallStateUpdated(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->TelCallAudioStateUpdated(true), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursor_001, TestSize.Level2)
{
    screenCaptureServer_->showCursor_ = true;
    int ret = screenCaptureServer_->ShowCursor(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursor_002, TestSize.Level2)
{
    screenCaptureServer_->showCursor_ = false;
    int ret = screenCaptureServer_->ShowCursor(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursor_003, TestSize.Level2)
{
    int ret = screenCaptureServer_->ShowCursor(false);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursor_004, TestSize.Level2)
{
    screenCaptureServer_->showCursor_ = false;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->virtualScreenId_ = 0;
    int ret = screenCaptureServer_->ShowCursor(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursorInner_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    int ret = screenCaptureServer_->ShowCursorInner();
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShowCursorInner_002, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->showCursor_ = false;
    int ret = screenCaptureServer_->ShowCursorInner();
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnDeviceAdded_001, TestSize.Level2)
{
    std::shared_ptr<MouseChangeListener> listener = std::make_shared<MouseChangeListener>(screenCaptureServer_);
    int32_t inputDeviceId = 9;
    listener->OnDeviceAdded(inputDeviceId, "test");
    ASSERT_EQ(inputDeviceId == 9, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnDeviceRemoved_001, TestSize.Level2)
{
    std::shared_ptr<MouseChangeListener> listener = std::make_shared<MouseChangeListener>(screenCaptureServer_);
    int32_t inputDeviceId = 9;
    listener->OnDeviceRemoved(inputDeviceId, "test");
    ASSERT_EQ(inputDeviceId == 9, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RegisterMMISystemAbilityListener_001, TestSize.Level2)
{
    sptr<ISystemAbilityStatusChange> listener(new (std::nothrow) MMISystemAbilityListener(screenCaptureServer_));
    ASSERT_EQ(screenCaptureServer_->RegisterMMISystemAbilityListener(), true);
}

// regist two times
HWTEST_F(ScreenCaptureServerFunctionTest, RegisterMMISystemAbilityListener_002, TestSize.Level2)
{
    sptr<ISystemAbilityStatusChange> listener(new (std::nothrow) MMISystemAbilityListener(screenCaptureServer_));
    ASSERT_EQ(screenCaptureServer_->RegisterMMISystemAbilityListener(), true);
    ASSERT_EQ(screenCaptureServer_->RegisterMMISystemAbilityListener(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UnRegisterMMISystemAbilityListener_001, TestSize.Level2)
{
    sptr<ISystemAbilityStatusChange> listener(new (std::nothrow) MMISystemAbilityListener(screenCaptureServer_));
    ASSERT_EQ(screenCaptureServer_->UnRegisterMMISystemAbilityListener(), true);
}

// unregist after regist
HWTEST_F(ScreenCaptureServerFunctionTest, UnRegisterMMISystemAbilityListener_002, TestSize.Level2)
{
    sptr<ISystemAbilityStatusChange> listener(new (std::nothrow) MMISystemAbilityListener(screenCaptureServer_));
    ASSERT_EQ(screenCaptureServer_->RegisterMMISystemAbilityListener(), true);
    ASSERT_EQ(screenCaptureServer_->UnRegisterMMISystemAbilityListener(), true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnAddSystemAbility_001, TestSize.Level2)
{
    sptr<MMISystemAbilityListener> listener = new MMISystemAbilityListener(screenCaptureServer_);
    int32_t systemAbilityId = 10;
    std::string deviceId = "9";
    listener->OnAddSystemAbility(systemAbilityId, deviceId);
    ASSERT_EQ(systemAbilityId == 10, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnAddSystemAbility_002, TestSize.Level2)
{
    sptr<MMISystemAbilityListener> listener = new MMISystemAbilityListener(screenCaptureServer_);
    int32_t systemAbilityId = 10;
    std::string deviceId = "9";
    screenCaptureServer_->SetMouseChangeListener(nullptr);
    listener->OnAddSystemAbility(systemAbilityId, deviceId);
    ASSERT_EQ(systemAbilityId == 10, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnRemoveSystemAbility_001, TestSize.Level2)
{
    sptr<MMISystemAbilityListener> listener = new MMISystemAbilityListener(screenCaptureServer_);
    int32_t systemAbilityId = 10;
    std::string deviceId = "9";
    listener->OnRemoveSystemAbility(systemAbilityId, deviceId);
    ASSERT_EQ(systemAbilityId == 10, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RegisterMouseChangeListener_001, TestSize.Level2)
{
    std::string type = "change";
    screenCaptureServer_->RegisterMouseChangeListener(type);
    ASSERT_EQ(type == "change", true);
}


HWTEST_F(ScreenCaptureServerFunctionTest, RegisterMouseChangeListener_002, TestSize.Level2)
{
    std::string type = "change";
    screenCaptureServer_->RegisterMouseChangeListener(type);
    screenCaptureServer_->RegisterMouseChangeListener(type);
    ASSERT_EQ(type == "change", true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UnRegisterMouseChangeListener_001, TestSize.Level2)
{
    std::string type = "change";
    screenCaptureServer_->UnRegisterMouseChangeListener(type);
    ASSERT_EQ(type == "change", true);
}


HWTEST_F(ScreenCaptureServerFunctionTest, UnRegisterMouseChangeListener_002, TestSize.Level2)
{
    std::string type = "change";
    screenCaptureServer_->UnRegisterMouseChangeListener(type);
    screenCaptureServer_->UnRegisterMouseChangeListener(type);
    ASSERT_EQ(type == "change", true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UnRegisterMouseChangeListener_003, TestSize.Level2)
{
    std::string type = "change";
    screenCaptureServer_->RegisterMouseChangeListener(type);
    screenCaptureServer_->UnRegisterMouseChangeListener(type);
    ASSERT_EQ(type == "change", true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCaptureSuccessAction_001, TestSize.Level2)
{
    screenCaptureServer_->showCursor_ = false;
    screenCaptureServer_->PostStartScreenCaptureSuccessAction();
    ASSERT_EQ(screenCaptureServer_->showCursor_ == false, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCaptureSuccessAction_002, TestSize.Level2)
{
    screenCaptureServer_->showCursor_ = true;
    screenCaptureServer_->PostStartScreenCaptureSuccessAction();
    ASSERT_EQ(screenCaptureServer_->showCursor_ == true, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCanvasRotation_001, TestSize.Level2)
{
    int ret = screenCaptureServer_->SetCanvasRotation(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetCanvasRotation_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    int ret = screenCaptureServer_->SetCanvasRotation(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->virtualScreenId_ = 0;
    int ret = screenCaptureServer_->ResizeCanvas(580, 1280);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->ResizeCanvas(580, 1280);
    ASSERT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->ResizeCanvas(-580, 1280);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_004, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->ResizeCanvas(10241, 1280);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_005, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->ResizeCanvas(580, -1280);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_006, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->ResizeCanvas(580, 4321);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCaptureByEvent_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->StopScreenCaptureByEvent(AVScreenCaptureStateCode::
        SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCaptureByEvent_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    int ret = screenCaptureServer_->StopScreenCaptureByEvent(AVScreenCaptureStateCode::
        SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SkipPrivacyMode_001, TestSize.Level2)
{
    std::vector<uint64_t> windowIDsVec;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    int ret = screenCaptureServer_->SkipPrivacyMode(windowIDsVec);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMaxVideoFrameRate_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->SetMaxVideoFrameRate(-1);
    ASSERT_EQ(ret, MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMaxVideoFrameRate_002, TestSize.Level2)
{
    screenCaptureServer_->virtualScreenId_ = 0;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    int ret = screenCaptureServer_->SetMaxVideoFrameRate(5);
    ASSERT_NE(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneOn_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    int ret = screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneOn_002, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    int ret = screenCaptureServer_->SetMicrophoneOn();
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneOff_001, TestSize.Level2)
{
    int ret = screenCaptureServer_->SetMicrophoneOff();
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetMicrophoneEnabled_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    int ret = screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetSystemScreenRecorderStatus_001, TestSize.Level2)
{
    screenCaptureServer_->appName_ =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"];
    screenCaptureServer_->SetSystemScreenRecorderStatus(false);
    ASSERT_EQ(ScreenCaptureServer::systemScreenRecorderPid_, -1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetSystemScreenRecorderStatus_002, TestSize.Level2)
{
    screenCaptureServer_->appName_ =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
    screenCaptureServer_->appInfo_.appPid = 15000;
    screenCaptureServer_->SetSystemScreenRecorderStatus(true);
    ASSERT_EQ(ScreenCaptureServer::systemScreenRecorderPid_, 15000);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetSystemScreenRecorderStatus_003, TestSize.Level2)
{
    ScreenCaptureServer::systemScreenRecorderPid_ = -1;
    screenCaptureServer_->appName_ =
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
    screenCaptureServer_->appInfo_.appPid = 15000;
    screenCaptureServer_->SetSystemScreenRecorderStatus(false);
    ASSERT_EQ(ScreenCaptureServer::systemScreenRecorderPid_, -1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSystemScreenRecorder_001, TestSize.Level2)
{
    ScreenCaptureServer::systemScreenRecorderPid_ = -1;
    bool ret = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(15000);
    ASSERT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSystemScreenRecorder_002, TestSize.Level2)
{
    ScreenCaptureServer::systemScreenRecorderPid_ = -1;
    bool ret = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(-1);
    ASSERT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, IsSystemScreenRecorderWorking_001, TestSize.Level2)
{
    screenCaptureServer_->SetSystemScreenRecorderStatus(false);
    bool ret = ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorderWorking();
    ASSERT_EQ(ret, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartStreamHomeVideoCapture_001, TestSize.Level2)
{
    SetValidConfig();
    screenCaptureServer_->isSurfaceMode_ = false;
    ASSERT_EQ(screenCaptureServer_->StartStreamHomeVideoCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckDataType_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->CheckDataType(DataType::ENCODED_STREAM), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioCapParam_001, TestSize.Level2)
{
    AudioCaptureInfo micCapinfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_INVALID
    };
    ASSERT_NE(screenCaptureServer_->CheckAudioCapParam(micCapinfo), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckVideoCapParam_001, TestSize.Level2)
{
    VideoCaptureInfo videoCapInfo_1 = {
        .videoFrameWidth = -1,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };
    ASSERT_NE(screenCaptureServer_->CheckVideoCapParam(videoCapInfo_1), MSERR_OK);
    VideoCaptureInfo videoCapInfo_2 = {
        .videoFrameWidth = 720,
        .videoFrameHeight = -1,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };
    ASSERT_NE(screenCaptureServer_->CheckVideoCapParam(videoCapInfo_2), MSERR_OK);
    VideoCaptureInfo videoCapInfo_3 = {
        .videoFrameWidth = screenCaptureServer_->VIDEO_FRAME_WIDTH_MAX + 1,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };
    ASSERT_NE(screenCaptureServer_->CheckVideoCapParam(videoCapInfo_3), MSERR_OK);
    VideoCaptureInfo videoCapInfo_4 = {
        .videoFrameWidth = 720,
        .videoFrameHeight = screenCaptureServer_->VIDEO_FRAME_HEIGHT_MAX + 1,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA
    };
    ASSERT_NE(screenCaptureServer_->CheckVideoCapParam(videoCapInfo_4), MSERR_OK);
    VideoCaptureInfo videoCapInfo_5 = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1080,
        .videoSource = VideoSourceType::VIDEO_SOURCE_SURFACE_YUV
    };
    ASSERT_NE(screenCaptureServer_->CheckVideoCapParam(videoCapInfo_5), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckAudioEncParam_001, TestSize.Level2)
{
    AudioEncInfo audioEncInfo_1 = {
        .audioBitrate = 48000,
        .audioCodecformat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT
    };
    ASSERT_NE(screenCaptureServer_->CheckAudioEncParam(audioEncInfo_1), MSERR_OK);
    AudioEncInfo audioEncInfo_2 = {
        .audioBitrate = screenCaptureServer_->AUDIO_BITRATE_MIN - 1,
        .audioCodecformat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT
    };
    ASSERT_NE(screenCaptureServer_->CheckAudioEncParam(audioEncInfo_2), MSERR_OK);
    AudioEncInfo audioEncInfo_3 = {
        .audioBitrate = screenCaptureServer_->AUDIO_BITRATE_MAX + 1,
        .audioCodecformat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT
    };
    ASSERT_NE(screenCaptureServer_->CheckAudioEncParam(audioEncInfo_3), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RefreshResConfig_001, TestSize.Level2)
{
    screenCaptureServer_->RefreshResConfig();
    screenCaptureServer_->resConfig_ = Global::Resource::CreateResConfig();
    screenCaptureServer_->RefreshResConfig();
    ASSERT_NE(screenCaptureServer_->resConfig_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopAudioCapture_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->StopAudioCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartBufferThread_001, TestSize.Level2)
{
    ScreenCapBufferConsumerListener *surfaceCb = new ScreenCapBufferConsumerListener(nullptr, nullptr);
    surfaceCb->isSurfaceCbInThreadStopped_ = false;
    EXPECT_EQ(surfaceCb->StartBufferThread(), MSERR_OK);
    delete surfaceCb;
    surfaceCb = nullptr;
}
} // Media
} // OHOS