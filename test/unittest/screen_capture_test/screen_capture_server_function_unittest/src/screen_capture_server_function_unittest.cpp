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
    screenCaptureServer_->Release();
    screenCaptureServer_ = nullptr;
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

int32_t ScreenCaptureServerFunctionTest::StartFileAudioCapture()
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(
        AVScreenCaptureMixMode::MIX_MODE, screenCaptureServer_.get());
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
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileInnerAudioCapture failed, ret:%{public}d,"
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

HWTEST_F(ScreenCaptureServerFunctionTest, StartPrivacyWindow_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->StartPrivacyWindow(), MSERR_OK);
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
    screenCaptureServer_->audioSource_->HasSpeakerStream(audioRendererChangeInfos);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    std::string choice = "{\"choice\": \"false\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_003, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = -1;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_004, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    std::string choice = "{\"choice\": \"12345\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_005, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_006, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_007, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_008, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = 1;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    std::string choice = "{\"choice\": \"true\"}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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

#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_002, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_003, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    ASSERT_NE(screenCaptureServer_->RequestUserPrivacyAuthority(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_004, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(), MSERR_OK);
}
#endif

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

HWTEST_F(ScreenCaptureServerFunctionTest, PrivateWindowListenerInScreenCapture_001, TestSize.Level2)
{
    screenCaptureServer_->RegisterPrivateWindowListener();
    screenCaptureServer_->displayListener_->OnPrivateWindow(true);
    ASSERT_NE(screenCaptureServer_->displayListener_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrivateWindowListenerInScreenCapture_002, TestSize.Level2)
{
    screenCaptureServer_->RegisterPrivateWindowListener();
    screenCaptureServer_->displayListener_->OnPrivateWindow(false);
    ASSERT_NE(screenCaptureServer_->displayListener_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotificationSubscriber_001, TestSize.Level2)
{
    auto notificationSubscriber = NotificationSubscriber();
    notificationSubscriber.OnConnected();
    notificationSubscriber.OnDisconnected();
    notificationSubscriber.OnDied();
    ASSERT_NE(&notificationSubscriber, nullptr);
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
} // Media
} // OHOS