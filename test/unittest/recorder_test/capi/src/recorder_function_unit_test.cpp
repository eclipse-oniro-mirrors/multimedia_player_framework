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

#include "recorder_function_unit_test.h"

#include <iostream>
#include <fcntl.h>
#include <thread>
#include <nativetoken_kit.h>
#include <token_setproc.h>
#include <accesstoken_kit.h>
#include "surface/window.h"
#include "native_window.h"
#include "media_log.h"
#include "media_errors.h"
#include "display/composer/v1_2/display_composer_type.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;
using namespace testing::ext;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_RECORDER, "NativeAVRecorder" };
}

const std::string RECORDER_ROOT = "/data/test/media/";
std::atomic<bool> isExit_ { false };
const int32_t STUB_STREAM_COUNT = 602;
const int32_t STRIDE_ALIGN = 8;
const int32_t FRAME_DURATION = 30000;
const int32_t SEC_TO_NS = 1000000000;
const int32_t RECORDING_TIME = 3;

static HapInfoParams hapInfo = {
    .userID = 100, // 100 user ID
    .bundleName = "com.ohos.test.recordertdd",
    .instIndex = 0, // 0 index
    .appIDDesc = "com.ohos.test.recordertdd",
    .isSystemApp = true
};

static HapPolicyParams hapPolicy = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.avrecorder",
    .permList = { },
    .permStateList = {
        {
            .permissionName = "ohos.permission.CAMERA",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.MICROPHONE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.READ_MEDIA",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.WRITE_MEDIA",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.KEEP_BACKGROUND_RUNNING",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.DUMP",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

static OH_AVRecorder_Profile audioProfile_ = {
    .audioBitrate = 96000,
    .audioSampleRate = 48000,
    .audioChannels = 2,
    .audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC,
    .fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4,
};

static OH_AVRecorder_Location location_ = {
    .latitude = 31.123456,
    .longitude = 121.123456,
};

static OH_AVRecorder_MetadataTemplate customInfo_ = {
    .key = nullptr,
    .value = nullptr,
};

static OH_AVRecorder_Metadata metadata_ = {
    .genre = nullptr,
    .videoOrientation = nullptr,
    .location = location_,
    .customInfo = customInfo_,
};

static OH_AVRecorder_Config audioConfig_ = {
    .audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC,
    .profile = audioProfile_,
    .url = nullptr,
    .fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE,
    .metadata = metadata_,
};

static void OnStateChange(OH_AVRecorder *recorder, OH_AVRecorder_State state,
    OH_AVRecorder_StateChangeReason reason, void *userData)
{
    (void)recorder;
    (void)userData;

    const char *reasonStr = (reason == OH_AVRecorder_StateChangeReason::AVRECORDER_USER) ? "USER" :
        (reason == OH_AVRecorder_StateChangeReason::AVRECORDER_BACKGROUND) ? "BACKGROUND" : "UNKNOWN";

    if (state == AVRECORDER_IDLE) {
        MEDIA_LOGI("AVRecorder OnStateChange IDLE, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_PREPARED) {
        MEDIA_LOGI("AVRecorder OnStateChange PREPARED, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_STARTED) {
        MEDIA_LOGI("AVRecorder OnStateChange STARTED, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_PAUSED) {
        MEDIA_LOGI("AVRecorder OnStateChange PAUSED, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_STOPPED) {
        MEDIA_LOGI("AVRecorder OnStateChange STOPPED, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_RELEASED) {
        MEDIA_LOGI("AVRecorder OnStateChange RELEASED, reason: %{public}s", reasonStr);
    }
    if (state == AVRECORDER_ERROR) {
        MEDIA_LOGI("AVRecorder OnStateChange ERROR, reason: %{public}s", reasonStr);
    }
}

static void OnError(OH_AVRecorder *recorder, int32_t errorCode, const char *errorMsg, void *userData)
{
    (void)recorder;
    (void)userData;
    
    MEDIA_LOGE("AVRecorder ErrorCallback errorCode: %d, errorMsg: %s \n", errorCode, errorMsg);
}

#ifdef SUPPORT_RECORDER_CREATE_FILE
static void OnUri(OH_AVRecorder *recorder, OH_MediaAsset *asset, void *userData)
{
    (void)recorder;
    (void)userData;
}
#endif

void RecorderFunctionUnitTest::SetUpTestCase(void)
{
    std::system("setenforce 0");
    SetSelfTokenPremission();
}

void RecorderFunctionUnitTest::TearDownTestCase(void) {}

void RecorderFunctionUnitTest::SetUp(void)
{
    recorder_ = OH_AVRecorder_Create();
    EXPECT_NE(recorder_, nullptr);

    int32_t ret = OH_AVRecorder_SetStateCallback(recorder_, OnStateChange, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_SetErrorCallback(recorder_, OnError, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

#ifdef SUPPORT_RECORDER_CREATE_FILE
    ret = OH_AVRecorder_SetUriCallback(recorder_, OnUri, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);
#endif
}

void RecorderFunctionUnitTest::TearDown(void)
{
    if (recorder_ != nullptr) {
        OH_AVRecorder_Release(recorder_);
        recorder_ = nullptr;
    }
}

void RecorderFunctionUnitTest::SetSelfTokenPremission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

OH_AVErrCode RequesetBuffer(OHNativeWindow *window, const OH_AVRecorder_Config *config)
{
    MEDIA_LOGI("RequestBuffer loop start.");
    CHECK_AND_RETURN_RET_LOG(window != nullptr, AV_ERR_INVALID_VAL, "input window is nullptr!");
    OHOS::sptr<OHOS::Surface> producerSurface_ = window->surface;
    CHECK_AND_RETURN_RET_LOG(producerSurface_ != nullptr, AV_ERR_INVALID_VAL, "input surface is nullptr!");

    BufferRequestConfig requestConfig;
    requestConfig.width = config->profile.videoFrameWidth;
    requestConfig.height = config->profile.videoFrameHeight;
    requestConfig.strideAlignment = STRIDE_ALIGN;
    requestConfig.format = OHOS::HDI::Display::Composer::V1_2::PixelFormat::PIXEL_FMT_YCBCR_420_SP;
    requestConfig.usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;
    requestConfig.timeout = INT_MAX;
    BufferFlushConfig flushConfig;
    flushConfig.damage.x = 0;
    flushConfig.damage.y = 0;
    flushConfig.damage.w = config->profile.videoFrameWidth;
    flushConfig.damage.h = config->profile.videoFrameHeight;
    flushConfig.timestamp = 0;
    int32_t count = 0;

    while (count < STUB_STREAM_COUNT) {
        CHECK_AND_RETURN_RET_LOG(!isExit_.load(), AV_ERR_OK, "Exit RequestBuffer");
        MEDIA_LOGI("RequestBuffer loop count: %{public}d", count);
        OHOS::sptr<OHOS::SurfaceBuffer> buffer;
        int32_t releaseFence;
        OHOS::SurfaceError ret = producerSurface_->RequestBuffer(buffer, releaseFence, requestConfig);
        if (ret != SURFACE_ERROR_OK || buffer == nullptr) {
            MEDIA_LOGI("RequestBuffer failed");
            continue;
        }

        struct timespec timestamp = {0, 0};
        clock_gettime(1, &timestamp);
        int64_t pts = static_cast<int64_t>(timestamp.tv_sec) * SEC_TO_NS + static_cast<int64_t>(timestamp.tv_nsec);
        int32_t isKeyFrame = (count % 30 == 0) ? 1 : 0;
        int32_t bufferSize = requestConfig.width * requestConfig.height * 3 / 2;
        MEDIA_LOGI("RequestBuffer loop bufferSize: %{public}d", bufferSize);
        buffer->GetExtraData()->ExtraSet("dataSize", bufferSize);
        buffer->GetExtraData()->ExtraSet("timeStamp", pts);
        buffer->GetExtraData()->ExtraSet("isKeyFrame", isKeyFrame);
        usleep(FRAME_DURATION);

        producerSurface_->FlushBuffer(buffer, -1, flushConfig);
        count++;
    }
    MEDIA_LOGI("RequestBuffer loop end.");
    return AV_ERR_OK;
}


/**
 * @tc.name: Recorder_Audio_001
 * @tc.desc: Test audio recording process 001
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_001, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_001 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_001.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 48000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_001 out.");
}

/**
 * @tc.name: Recorder_Audio_002
 * @tc.desc: Test audio recording process 002
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_002, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_002 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_002.wav").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 64000;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_G711MU;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_WAV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_002 out.");
}

/**
 * @tc.name: Recorder_Audio_003
 * @tc.desc: Test audio recording process 003
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_003, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_003 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_003.m4a").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 48000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 96000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4A;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_003 out.");
}

/**
 * @tc.name: Recorder_Audio_004
 * @tc.desc: Test audio recording process 004
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_004, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_004 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_004.mp3").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 16000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_MP3;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MP3;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_004 out.");
}

#ifdef SUPPORT_CODEC_TYPE_HEVC
/**
 * @tc.name: Recorder_Audio_005
 * @tc.desc: Test audio recording process 005, amr not support rk2568
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_005, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_005 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_005.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 6700;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    // OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_NB not support rk2568
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_NB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_005 out.");
}
#endif

#ifdef SUPPORT_CODEC_TYPE_HEVC
/**
 * @tc.name: Recorder_Audio_006
 * @tc.desc: Test audio recording process 006, amr not support rk2568
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_006, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_006 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_006.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 4750;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    // OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_NB not support rk2568
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_NB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_006 out.");
}
#endif

#ifdef SUPPORT_CODEC_TYPE_HEVC
/**
 * @tc.name: Recorder_Audio_007
 * @tc.desc: Test audio recording process 007, amr not support rk2568
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_007, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_007 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_007.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 6600;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 16000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    // OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB not support rk2568
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_007 out.");
}
#endif

#ifdef SUPPORT_CODEC_TYPE_HEVC
/**
 * @tc.name: Recorder_Audio_008
 * @tc.desc: Test audio recording process 008, amr not support rk2568
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_008, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_008 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_008.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 23850;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 16000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    // OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB not support rk2568
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_008 out.");
}
#endif

/**
 * @tc.name: Recorder_Audio_009
 * @tc.desc: Test audio recording process 009, expect failure
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_009, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_009 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_009.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 16000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_009 out.");
}

/**
 * @tc.name: Recorder_Audio_010
 * @tc.desc: Test audio recording process 010, expect failure
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_010, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_010 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_010.amr").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 15850;
    config.profile.audioChannels = 1;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AMR_WB;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AMR;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_010 out.");
}

/**
 * @tc.name: Recorder_Audio_011
 * @tc.desc: Test audio recording process 011
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_011, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_011 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_011.mp3").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 32000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 48000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_MP3;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MP3;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_011 out.");
}

/**
 * @tc.name: Recorder_Audio_012
 * @tc.desc: Test audio recording process 012
 * @tc.type: FUNC
 */
HWTEST_F(RecorderFunctionUnitTest, Recorder_Audio_012, TestSize.Level2)
{
    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_012 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Audio_012.mp3").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 64000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_MP3;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MP3;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);
    
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME/2);

    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(RECORDING_TIME);

    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("RecorderFunctionUnitTest Recorder_Audio_012 out.");
}