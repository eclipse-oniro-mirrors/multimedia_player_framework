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

#include "recorder_unit_test.h"

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
        },
        {
            .permissionName = "ohos.permission.GET_BUNDLE_INFO",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

static OH_AVRecorder_Profile profile_ = {
    .audioBitrate = 48000,
    .audioChannels = 2,
    .audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC,
    .audioSampleRate = 48000,
    .fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4,
    .videoBitrate = 2000000,
    .videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC,
    .videoFrameWidth = 1920,
    .videoFrameHeight = 1080,
    .videoFrameRate = 30,
    .isHdr = false,
    .enableTemporalScale = false,
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

static OH_AVRecorder_Config config_ = {
    .audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC,
    .videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV,
    .profile = profile_,
    .url = nullptr,
    .fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE,
    .metadata = metadata_,
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

void NativeRecorderUnitTest::SetUpTestCase(void)
{
    SetSelfTokenPremission();
}

void NativeRecorderUnitTest::TearDownTestCase(void) {}

void NativeRecorderUnitTest::SetUp(void)
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

void NativeRecorderUnitTest::TearDown(void)
{
    if (recorder_ != nullptr) {
        OH_AVRecorder_Release(recorder_);
        recorder_ = nullptr;
    }
}

void NativeRecorderUnitTest::SetSelfTokenPremission()
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
 * @tc.name: Recorder_Prepare_001
 * @tc.desc: Test recorder preparation process
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_001 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Prepare_001.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_001 out.");
}

/**
 * @tc.name: Recorder_Prepare_002
 * @tc.desc: Test recorder preparation process with min param
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 48000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 280000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 176;
    config.profile.videoFrameHeight = 144;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Prepare_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_002 out.");
}

#ifdef SUPPORT_CODEC_TYPE_HEVC
/**
 * @tc.name: Recorder_Prepare_003
 * @tc.desc: Test recorder preparation process with max param
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("270");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 48000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 70000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_HEVC;
    config.profile.videoFrameWidth = 3840;
    config.profile.videoFrameHeight = 2160;
    config.profile.videoFrameRate = 60;
    config.profile.isHdr = true;
    config.profile.enableTemporalScale = true;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_CAMCORDER;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_ES;

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Prepare_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_003 out.");
}
#endif

/**
 * @tc.name: Recorder_Prepare_004
 * @tc.desc: Test recorder preparation process
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_004 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("fd://1234");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("90");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 640;
    config.profile.videoFrameHeight = 480;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_004 out.");
}

/**
 * @tc.name: Recorder_Prepare_005
 * @tc.desc: Test recorder preparation process failure situation
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_005, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_005 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("invalid_url");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("90");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 640;
    config.profile.videoFrameHeight = 480;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_005 out.");
}

/**
 * @tc.name: Recorder_Prepare_006
 * @tc.desc: Test recorder preparation process failure situation 2
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_006, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_006 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("fd://-1");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("90");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 640;
    config.profile.videoFrameHeight = 480;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_APP_CREATE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_006 out.");
}

/**
 * @tc.name: Recorder_Prepare_007
 * @tc.desc: Test recorder preparation process failure situation 3
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_007, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_007 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("invalid");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 1280;
    config.profile.videoFrameHeight = 720;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_007 out.");
}

/**
 * @tc.name: Recorder_Prepare_008
 * @tc.desc: Test recorder preparation process success situation
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_008, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_008 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = nullptr;
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 1280;
    config.profile.videoFrameHeight = 720;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);

    #ifdef SUPPORT_RECORDER_CREATE_FILE
    EXPECT_EQ(ret, AV_ERR_OK);
    #else
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    #endif

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_008 out.");
}

/**
 * @tc.name: Recorder_Prepare_009
 * @tc.desc: Test recorder preparation process success situation 2
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_009, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_009 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = nullptr;
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 1280;
    config.profile.videoFrameHeight = 720;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;


    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_009 out.");
}

/**
 * @tc.name: Recorder_Prepare_010
 * @tc.desc: Test recorder preparation process failure situation
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_010, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_010 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("95");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.profile.audioBitrate = 96000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 2000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 1280;
    config.profile.videoFrameHeight = 720;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV;
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_010 out.");
}

/**
 * @tc.name: Recorder_GetAVRecorderConfig_001
 * @tc.desc: Test recorder GetAVRecorderConfig process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetAVRecorderConfig_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_001 in.");

    OH_AVRecorder_Config *configGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ASSERT_NE(configGet, nullptr);
    EXPECT_EQ(configGet->profile.audioBitrate, 0);
    EXPECT_EQ(configGet->profile.audioChannels, 0);
    EXPECT_EQ(configGet->profile.audioCodec, static_cast<OH_AVRecorder_CodecMimeType>(AUDIO_CODEC_FORMAT_BUTT));
    EXPECT_EQ(configGet->profile.audioSampleRate, 0);
    EXPECT_EQ(configGet->profile.fileFormat,
            static_cast<OH_AVRecorder_ContainerFormatType>(OutputFormatType::FORMAT_BUTT));
    EXPECT_EQ(configGet->profile.videoBitrate, 0);
    EXPECT_EQ(configGet->profile.videoCodec, static_cast<OH_AVRecorder_CodecMimeType>(VIDEO_CODEC_FORMAT_BUTT));
    EXPECT_EQ(configGet->profile.videoFrameHeight, 0);
    EXPECT_EQ(configGet->profile.videoFrameWidth, 0);
    EXPECT_EQ(configGet->profile.videoFrameRate, 0);
    EXPECT_EQ(configGet->audioSourceType, static_cast<OH_AVRecorder_AudioSourceType>(AUDIO_SOURCE_INVALID));
    EXPECT_EQ(configGet->videoSourceType, static_cast<OH_AVRecorder_VideoSourceType>(VIDEO_SOURCE_BUTT));
    EXPECT_EQ(configGet->metadata.location.latitude, 0.0);
    EXPECT_EQ(configGet->metadata.location.longitude, 0.0);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_001 out.");
}

/**
 * @tc.name: Recorder_GetAVRecorderConfig_002
 * @tc.desc: Test recorder GetAVRecorderConfig process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetAVRecorderConfig_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("90");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_GetAVRecorderConfig_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    OH_AVRecorder_Config *configGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ASSERT_NE(configGet, nullptr);
    EXPECT_EQ(configGet->profile.audioBitrate, 48000);
    EXPECT_EQ(configGet->profile.audioChannels, 2);
    EXPECT_EQ(configGet->profile.audioCodec, OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC);
    EXPECT_EQ(configGet->profile.audioSampleRate, 48000);
    EXPECT_EQ(configGet->profile.fileFormat, OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4);
    EXPECT_EQ(configGet->profile.videoBitrate, 2000000);
    EXPECT_EQ(configGet->profile.videoCodec, OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC);
    EXPECT_EQ(configGet->profile.videoFrameHeight, 1080);
    EXPECT_EQ(configGet->profile.videoFrameWidth, 1920);
    EXPECT_EQ(configGet->profile.videoFrameRate, 30);
    EXPECT_EQ(configGet->audioSourceType, OH_AVRecorder_AudioSourceType::AVRECORDER_MIC);
    EXPECT_EQ(configGet->videoSourceType, OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_YUV);
    EXPECT_EQ(configGet->metadata.location.latitude, 31);
    EXPECT_EQ(configGet->metadata.location.longitude, 121);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_002 out.");
}

/**
 * @tc.name: Recorder_GetAVRecorderConfig_003
 * @tc.desc: Test recorder GetAVRecorderConfig process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetAVRecorderConfig_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("270");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 64000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.audioSampleRate = 64000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4;
    config.profile.videoBitrate = 25000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC;
    config.profile.videoFrameWidth = 3840;
    config.profile.videoFrameHeight = 2160;
    config.profile.videoFrameRate = 24;
    config.profile.isHdr = true;
    config.profile.enableTemporalScale = true;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_CAMCORDER;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_ES;

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_GetAVRecorderConfig_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    OH_AVRecorder_Config *configGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ASSERT_NE(configGet, nullptr);
    EXPECT_EQ(configGet->profile.audioBitrate, 64000);
    EXPECT_EQ(configGet->profile.audioChannels, 2);
    EXPECT_EQ(configGet->profile.audioCodec, OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC);
    EXPECT_EQ(configGet->profile.audioSampleRate, 64000);
    EXPECT_EQ(configGet->profile.fileFormat, OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_MPEG_4);
    EXPECT_EQ(configGet->profile.videoBitrate, 25000000);
    EXPECT_EQ(configGet->profile.videoCodec, OH_AVRecorder_CodecMimeType::AVRECORDER_VIDEO_AVC);
    EXPECT_EQ(configGet->profile.videoFrameHeight, 2160);
    EXPECT_EQ(configGet->profile.videoFrameWidth, 3840);
    EXPECT_EQ(configGet->audioSourceType, OH_AVRecorder_AudioSourceType::AVRECORDER_CAMCORDER);
    EXPECT_EQ(configGet->videoSourceType, OH_AVRecorder_VideoSourceType::AVRECORDER_SURFACE_ES);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_003 out.");
}

/**
 * @tc.name: Recorder_GetInputSurface_001
 * @tc.desc: Test recorder GetInputSurface process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetInputSurface_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetInputSurface_001 in.");

    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_NE(ret, AV_ERR_OK);
    EXPECT_EQ(windowGet, nullptr);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetInputSurface_001 out.");
}

/**
 * @tc.name: Recorder_GetInputSurface_002
 * @tc.desc: Test recorder GetInputSurface process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetInputSurface_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetInputSurface_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_GetInputSurface_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    EXPECT_NE(windowGet, nullptr);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetInputSurface_002 out.");
}

/**
 * @tc.name: Recorder_UpdateRotation_001
 * @tc.desc: Test recorder UpdateRotation process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_UpdateRotation_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_001 in.");

    int32_t rotation = 180;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_001 out.");
}

/**
 * @tc.name: Recorder_UpdateRotation_002
 * @tc.desc: Test recorder UpdateRotation process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_UpdateRotation_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_UpdateRotation_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t rotation = 180;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_002 out.");
}

/**
 * @tc.name: Recorder_UpdateRotation_003
 * @tc.desc: Test recorder UpdateRotation process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_UpdateRotation_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_003 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t rotation = 90;

    int32_t ret = AV_ERR_OK;

    ret = OH_AVRecorder_Prepare(recorder_, &config);
    #ifdef SUPPORT_RECORDER_CREATE_FILE
    EXPECT_EQ(ret, AV_ERR_OK);
    #else
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    #endif
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);


    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_003 out.");
}

/**
 * @tc.name: Recorder_UpdateRotation_004
 * @tc.desc: Test recorder UpdateRotation process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_UpdateRotation_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_004 in.");

    OH_AVRecorder_Config config = config_;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t ret = AV_ERR_OK;

    ret = OH_AVRecorder_Prepare(recorder_, &config);
    #ifdef SUPPORT_RECORDER_CREATE_FILE
    EXPECT_EQ(ret, AV_ERR_OK);
    #else
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    #endif

    int32_t rotation = 0;
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    rotation = 90;
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    rotation = 180;
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    rotation = 270;
    ret = OH_AVRecorder_UpdateRotation(recorder_, rotation);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_UpdateRotation_004 out.");
}

/**
 * @tc.name: Recorder_Start_001
 * @tc.desc: Test recorder start process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_001 out.");
}

/**
 * @tc.name: Recorder_Start_002
 * @tc.desc: Test recorder start process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Start_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_002 out.");
}

/**
 * @tc.name: Recorder_Pause_001
 * @tc.desc: Test recorder pause process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_001 out.");
}

/**
 * @tc.name: Recorder_Pause_002
 * @tc.desc: Test recorder pause process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Pause_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_002 out.");
}

/**
 * @tc.name: Recorder_Pause_003
 * @tc.desc: Test recorder pause process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Pause_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_003 out.");
}

/**
 * @tc.name: Recorder_Resume_001
 * @tc.desc: Test recorder resume process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_001 out.");
}

/**
 * @tc.name: Recorder_Resume_002
 * @tc.desc: Test recorder resume process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Resume_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_002 out.");
}

/**
 * @tc.name: Recorder_Resume_003
 * @tc.desc: Test recorder pause process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Resume_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_003 out.");
}

/**
 * @tc.name: Recorder_Resume_004
 * @tc.desc: Test recorder pause process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_004 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Resume_004.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(1);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_004 out.");
}

/**
 * @tc.name: Recorder_Stop_001
 * @tc.desc: Test recorder stop process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_001 out.");
}

/**
 * @tc.name: Recorder_Stop_002
 * @tc.desc: Test recorder stop process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Stop_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_002 out.");
}

/**
 * @tc.name: Recorder_Stop_003
 * @tc.desc: Test recorder stop process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Stop_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_003 out.");
}

/**
 * @tc.name: Recorder_Stop_004
 * @tc.desc: Test recorder stop process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_004 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Stop_004.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(1);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_004 out.");
}

/**
 * @tc.name: Recorder_Stop_005
 * @tc.desc: Test recorder stop process 005
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_005, TestSize.Level2)
{
#ifndef SUPPORT_RECORDER_CREATE_FILE
    #define SUPPORT_RECORDER_CREATE_FILE
    #define SUPPORT_RECORDER_CREATE_FILE_DEFINED_IN_TESTCASE
#endif
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_005 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.fileGenerationMode = OH_AVRecorder_FileGenerationMode::AVRECORDER_AUTO_CREATE_CAMERA_SCENE;

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Stop_005.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_005 out.");
#ifdef SUPPORT_RECORDER_CREATE_FILE_DEFINED_IN_TESTCASE
    #undef SUPPORT_RECORDER_CREATE_FILE
    #undef SUPPORT_RECORDER_CREATE_FILE_DEFINED_IN_TESTCASE
#endif
}

/**
 * @tc.name: Recorder_Reset_001
 * @tc.desc: Test recorder reset process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Reset_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_001 out.");
}

/**
 * @tc.name: Recorder_Reset_002
 * @tc.desc: Test recorder reset process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Reset_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_002 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Reset_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_002 out.");
}

/**
 * @tc.name: Recorder_Reset_003
 * @tc.desc: Test recorder reset process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Reset_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_003 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Reset_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_003 out.");
}

/**
 * @tc.name: Recorder_Reset_004
 * @tc.desc: Test recorder reset process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Reset_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_004 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_Reset_004.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Reset(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Reset_004 out.");
}

/**
 * @tc.name: Recorder_Release_001
 * @tc.desc: Test recorder release process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Release_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Release_001 in.");

    int32_t ret = AV_ERR_OK;
    if (recorder_ != nullptr) {
        ret = OH_AVRecorder_Release(recorder_);
        EXPECT_EQ(ret, AV_ERR_OK);
        recorder_ = nullptr;
    }

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Release_001 out.");
}

/**
 * @tc.name: Recorder_GetAvailableEncoder_001
 * @tc.desc: Test recorder getAvailableEncoder process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetAvailableEncoder_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAvailableEncoder_001 in.");

    OH_AVRecorder_EncoderInfo *info = nullptr;
    int32_t length = 0;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_GetAvailableEncoder(recorder_, &info, &length);
    EXPECT_EQ(ret, AV_ERR_OK);
    EXPECT_NE(info, nullptr);
    EXPECT_NE(length, 0);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAvailableEncoder_001 out.");
}

/**
 * @tc.name: Recorder_SetStateCallback_001
 * @tc.desc: Test recorder setStateCallback process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetStateCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_001 in.");

    int32_t ret = OH_AVRecorder_SetStateCallback(recorder_, OnStateChange, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_001 out.");
}

/**
 * @tc.name: Recorder_SetStateCallback_002
 * @tc.desc: Test recorder setStateCallback process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetStateCallback_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_002 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetStateCallback(recorder_, OnStateChange, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_002 out.");
}

/**
 * @tc.name: Recorder_SetStateCallback_003
 * @tc.desc: Test recorder setStateCallback process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetStateCallback_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_003 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetStateCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_003 out.");
}

/**
 * @tc.name: Recorder_SetStateCallback_004
 * @tc.desc: Test recorder SetStateCallback process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetStateCallback_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_004 in.");

    int32_t ret = OH_AVRecorder_SetStateCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_004 out.");
}

/**
 * @tc.name: Recorder_SetErrorCallback_001
 * @tc.desc: Test recorder setErrorCallback process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetErrorCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_001 in.");

    int32_t ret = OH_AVRecorder_SetErrorCallback(recorder_, OnError, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_001 out.");
}

/**
 * @tc.name: Recorder_SetErrorCallback_002
 * @tc.desc: Test recorder SetErrorCallback process 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetErrorCallback_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_002 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetErrorCallback(recorder_, OnError, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_002 out.");
}

/**
 * @tc.name: Recorder_SetErrorCallback_003
 * @tc.desc: Test recorder SetErrorCallback process 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetErrorCallback_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_003 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetErrorCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_003 out.");
}

/**
 * @tc.name: Recorder_SetErrorCallback_004
 * @tc.desc: Test recorder SetErrorCallback process 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetErrorCallback_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_004 in.");

    int32_t ret = OH_AVRecorder_SetErrorCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_004 out.");
}

/**
 * @tc.name: Recorder_SetUriCallback_001
 * @tc.desc: Test recorder SetUriCallback process 001
 * @tc.type: FUNC
 */
#ifdef SUPPORT_RECORDER_CREATE_FILE
HWTEST_F(NativeRecorderUnitTest, Recorder_SetUriCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_001 in.");

    int32_t ret = OH_AVRecorder_SetUriCallback(recorder_, OnUri, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_001 out.");
}
#endif

/**
 * @tc.name: Recorder_SetUriCallback_002
 * @tc.desc: Test recorder SetUriCallback process 002
 * @tc.type: FUNC
 */
#ifdef SUPPORT_RECORDER_CREATE_FILE
HWTEST_F(NativeRecorderUnitTest, Recorder_SetUriCallback_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_002 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetUriCallback(recorder_, OnUri, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_002 out.");
}
#endif

/**
 * @tc.name: Recorder_SetUriCallback_003
 * @tc.desc: Test recorder SetUriCallback process 003
 * @tc.type: FUNC
 */
#ifdef SUPPORT_RECORDER_CREATE_FILE
HWTEST_F(NativeRecorderUnitTest, Recorder_SetUriCallback_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_003 in.");

    OH_AVRecorder_Release(recorder_);
    recorder_ = OH_AVRecorder_Create();
    int32_t ret = OH_AVRecorder_SetUriCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_003 out.");
}
#endif

/**
 * @tc.name: Recorder_SetUriCallback_004
 * @tc.desc: Test recorder SetUriCallback process 004
 * @tc.type: FUNC
 */
#ifdef SUPPORT_RECORDER_CREATE_FILE
HWTEST_F(NativeRecorderUnitTest, Recorder_SetUriCallback_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_004 in.");

    int32_t ret = OH_AVRecorder_SetUriCallback(recorder_, nullptr, nullptr);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetUriCallback_004 out.");
}
#endif

/**
 * @tc.name: Recorder_SetMaxDuration_001
 * @tc.desc: Test recorder setmaxduration undefined
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_001 in.");

    OH_AVRecorder_Config config = config_;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_001.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_001 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_002
 * @tc.desc: Test recorder setmaxduration -1
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_002 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = -1;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_002.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_002 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_003
 * @tc.desc: Test recorder setmaxduration 0
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_003 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = 0;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_003.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_003 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_004
 * @tc.desc: Test recorder setmaxduration 1
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_004 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = 1;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_004.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(5);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_004 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_005
 * @tc.desc: Test recorder setmaxduration 5
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_005, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_005 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = 5;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_005.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(10);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_005 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_006
 * @tc.desc: Test recorder setmaxduration int max but stop first
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_006, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_006 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = INT32_MAX;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_006.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_006 out.");
}

/**
 * @tc.name: Recorder_SetMaxDuration_007
 * @tc.desc: Test recorder setmaxduration int max with pause and resume
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_SetMaxDuration_007, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_007 in.");

    OH_AVRecorder_Config config = config_;
    config.maxDuration = INT32_MAX;
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t outputFd = open((RECORDER_ROOT + "Recorder_SetMaxDuration_007.mp4").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());
    OHNativeWindow *windowGet = nullptr;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetInputSurface(recorder_, &windowGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    isExit_.store(false);
    std::unique_ptr<std::thread> requesetBufferThread_;
    requesetBufferThread_.reset(new(std::nothrow) std::thread(RequesetBuffer, windowGet, &config));
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(1);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_EQ(ret, AV_ERR_OK);
    sleep(3);
    if (requesetBufferThread_ != nullptr) {
        isExit_.store(true);
        requesetBufferThread_->join();
        requesetBufferThread_ = nullptr;
    }
    ret = OH_AVRecorder_Stop(recorder_);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetMaxDuration_007 out.");
}

/**
 * @tc.name: Recorder_AAC_001
 * @tc.desc: Test AAC container format
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_AAC_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_AAC_001 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_AAC_001.aac").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 32000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 8000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AAC;
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

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_AAC_001 out.");
}

/**
 * @tc.name: Recorder_AAC_002
 * @tc.desc: Test AAC container format
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_AAC_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_AAC_002 in.");

    OH_AVRecorder_Config config = audioConfig_;
    int32_t outputFd = open((RECORDER_ROOT + "Recorder_AAC_002.aac").c_str(), O_RDWR);
    const std::string fdHead = "fd://";
    config.url = strdup((fdHead + std::to_string(outputFd)).c_str());

    config.metadata.genre = strdup("");
    config.metadata.customInfo.key = strdup("abc");
    config.metadata.customInfo.value = strdup("123");
    config.metadata.location.latitude = 31.791863;
    config.metadata.location.longitude = 64.574687;

    config.profile.audioBitrate = 32000;
    config.profile.audioChannels = 2;
    config.profile.audioSampleRate = 96000;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::AVRECORDER_MIC;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AVRECORDER_AUDIO_AAC;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::AVRECORDER_CFT_AAC;
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

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_AAC_002 out.");
}