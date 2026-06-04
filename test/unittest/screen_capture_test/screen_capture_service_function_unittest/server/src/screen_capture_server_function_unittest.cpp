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
#include <gtest/gtest.h>
#include "screen_capture_server_function_unittest.h"
#include "mock/mock_audio_capturer.h"
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
#include "screen_capture_monitor_service_stub.h"
#include "screen_capture_monitor_listener_proxy.h"
#include "audio_capturer_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServerFunctionTest"};
constexpr int32_t FLIE_CREATE_FLAGS = 0777;
static const std::string BUTTON_NAME_MIC = "mic";
static const std::string BUTTON_NAME_STOP = "stop";
static constexpr size_t DEFAULT_BUFFER_SIZE = 4096;
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
    std::shared_ptr<IScreenCaptureService> tempServer = ScreenCaptureServer::Create();
    screenCaptureServer_ = std::static_pointer_cast<ScreenCaptureServer>(tempServer);
    ASSERT_NE(screenCaptureServer_, nullptr);

    SetMockBuilder(screenCaptureServer_);

    sptr<IStandardScreenCaptureListener> listener = new(std::nothrow) StandardScreenCaptureServerUnittestCallback();
    screenCaptureServer_->screenCaptureCb_ = std::make_shared<ScreenCaptureListenerCallback>(listener);
}

void ScreenCaptureServerFunctionTest::SetMockBuilder(std::shared_ptr<ScreenCaptureServer> server)
{
    server->audioCapturerWrapperBuilder_ = [this](AudioCaptureInfo &audioInfo,
        std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb, std::string &&name,
        ScreenCaptureContentFilter filter) -> std::shared_ptr<AudioCapturerWrapper> {
        return CreateTestWrapper(audioInfo, name, true, true);
    };
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

void ScreenCaptureServerFunctionTest::SetSCInnerAudioCaptureAndPushData(std::shared_ptr<AudioBuffer> innerAudioBuffer)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo,
        "OS_InnerAudioCapture", true);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(innerAudioBuffer);
}

void ScreenCaptureServerFunctionTest::SetSCMicAudioCaptureAndPushData(std::shared_ptr<AudioBuffer> micAudioBuffer)
{
    auto wrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo,
        "OS_MicAudioCapture", false);
    wrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    wrapper->availBuffers_.push_back(micAudioBuffer);
}

std::shared_ptr<AudioCapturerWrapper> ScreenCaptureServerFunctionTest::CreateTestWrapper(
    AudioCaptureInfo &audioInfo, const std::string &name, bool isInner, bool expectStart)
{
    MEDIA_LOGI("CreateTestWrapper S");
    auto wrapper = std::make_shared<AudioCapturerWrapper>(
        audioInfo, screenCaptureServer_->screenCaptureCb_, std::string(name),
        screenCaptureServer_->contentFilter_);
    SetWrapperBuilder(wrapper, expectStart);
    if (isInner) {
        screenCaptureServer_->innerAudioCapture_ = wrapper;
    } else {
        screenCaptureServer_->micAudioCapture_ = wrapper;
    }
    return wrapper;
}

void ScreenCaptureServerFunctionTest::SetWrapperBuilder(std::shared_ptr<AudioCapturerWrapper> wrapper, bool expectStart)
{
    MEDIA_LOGI("SetWrapperBuilder S");
    wrapper->audioCapturerBuilder_ =
        [expectStart](const AudioStandard::AudioCapturerOptions &options,
           const AudioStandard::AppInfo &appInfo) -> std::shared_ptr<AudioStandard::AudioCapturer> {
            auto mockCapturer = std::make_shared<MockAudioCapturer>();
            if (expectStart) {
                EXPECT_CALL(*mockCapturer, Start()).WillRepeatedly(Return(true));
                EXPECT_CALL(*mockCapturer, Release()).WillRepeatedly(Return(true));
                EXPECT_CALL(*mockCapturer, Stop()).WillRepeatedly(Return(true));
                EXPECT_CALL(*mockCapturer, GetBufferSize(_))
                    .WillRepeatedly(DoAll(SetArgReferee<0>(DEFAULT_BUFFER_SIZE), Return(0)));
                EXPECT_CALL(*mockCapturer, Read(_, _, _)).WillRepeatedly(Return(DEFAULT_BUFFER_SIZE));
                EXPECT_CALL(*mockCapturer, GetTimeStampInfo(_, _))
                    .WillRepeatedly(DoAll(SetArgReferee<0>(AudioStandard::Timestamp()), Return(true)));
                EXPECT_CALL(*mockCapturer, SetCapturerCallback(_)).WillRepeatedly(Return(0));
                EXPECT_CALL(*mockCapturer, SetAudioSourceConcurrency(_)).WillRepeatedly(Return(0));
            }
            return mockCapturer;
        };
}

void ScreenCaptureServerFunctionTest::SetupAudioDataSource(AVScreenCaptureMixMode mode)
{
    screenCaptureServer_->audioSource_ = std::make_unique<AudioDataSource>(mode, screenCaptureServer_.get());
    screenCaptureServer_->captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    screenCaptureServer_->captureCallback_->SetAudioSource(screenCaptureServer_->audioSource_);
}

} // Media
} // OHOS
