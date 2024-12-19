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
#include <nativetoken_kit.h>
#include <token_setproc.h>
#include <accesstoken_kit.h>
#include "media_log.h"
#include "media_errors.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;
using namespace testing::ext;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_RECORDER, "NativeAVRecorder" };
}

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

static OH_AVRecorder_Profile sProfile = {
    .audioBitrate = 48000,
    .audioChannels = 2,
    .audioCodec = OH_AVRecorder_CodecMimeType::AUDIO_AAC,
    .audioSampleRate = 48000,
    .fileFormat = OH_AVRecorder_ContainerFormatType::CFT_MPEG_4,
    .videoBitrate = 2000000,
    .videoCodec = OH_AVRecorder_CodecMimeType::VIDEO_HEVC,
    .videoFrameWidth = 1920,
    .videoFrameHeight = 1080,
    .videoFrameRate = 30,
    .isHdr = false,
    .enableTemporalScale = false,
};

static OH_AVRecorder_Location sLocation = {
    .latitude = 31.123456,
    .longitude = 121.123456,
};

static OH_AVRecorder_MetadataTemplate sCustomInfo = {
    .key = nullptr,
    .value = nullptr,
};

static OH_AVRecorder_Metadata sMetadata = {
    .genre = nullptr,
    .videoOrientation = nullptr,
    .location = sLocation,
    .customInfo = sCustomInfo,
};

static OH_AVRecorder_Config sConfig = {
    .audioSourceType = OH_AVRecorder_AudioSourceType::MIC,
    .videoSourceType = OH_AVRecorder_VideoSourceType::SURFACE_YUV,
    .profile = sProfile,
    .url = nullptr,
    .fileGenerationMode = OH_AVRecorder_FileGenerationMode::AUTO_CREATE_CAMERA_SCENE,
    .metadata = sMetadata,
};

static void AVRecorderStateChangeCb(OH_AVRecorder *recorder,
    OH_AVRecorder_State state, OH_AVRecorder_StateChangeReason reason, void *userData)
{
    MEDIA_LOGI("AVRecorderStateChangeCb reason: %d, OH_AVRecorder_State: %d \n", reason, state);
}

static void AVRecorderErrorCb(OH_AVRecorder *recorder, int32_t errorCode, const char *errorMsg,
    void *userData)
{
    MEDIA_LOGE("AVRecorderErrorCb errorCode: %d, errorMsg: %s \n", errorCode, errorMsg);
}

void NativeRecorderUnitTest::SetUpTestCase(void)
{
    SetSelfTokenPremission();
}

void NativeRecorderUnitTest::TearDownTestCase(void) {}

void NativeRecorderUnitTest::SetUp(void)
{
    recorder_ = OH_AVRecorder_Create();
    EXPECT_NE(recorder_, nullptr);

    int32_t ret = AV_ERR_OK;
    OH_AVRecorder_OnStateChange stateChangeCb = AVRecorderStateChangeCb;
    ret = OH_AVRecorder_SetStateCallback(recorder_, stateChangeCb, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    OH_AVRecorder_OnError errorCb = AVRecorderErrorCb;
    ret = OH_AVRecorder_SetErrorCallback(recorder_, errorCb, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);
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

/**
 * @tc.name: Recorder_Prepare_001
 * @tc.desc: Test recorder preparation process
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_001 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 48000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::CFT_MPEG_4;
    config.profile.videoBitrate = 280000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::VIDEO_AVC;
    config.profile.videoFrameWidth = 176;
    config.profile.videoFrameHeight = 144;
    config.profile.videoFrameRate = 30;
    config.profile.isHdr = false;
    config.profile.enableTemporalScale = false;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::MIC;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::SURFACE_YUV;

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

/**
 * @tc.name: Recorder_Prepare_003
 * @tc.desc: Test recorder preparation process with max param
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_003 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("270");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 48000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AUDIO_AAC;
    config.profile.audioSampleRate = 48000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::CFT_MPEG_4;
    config.profile.videoBitrate = 70000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::VIDEO_HEVC;
    config.profile.videoFrameWidth = 3840;
    config.profile.videoFrameHeight = 2160;
    config.profile.videoFrameRate = 60;
    config.profile.isHdr = true;
    config.profile.enableTemporalScale = true;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::CAMCORDER;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::SURFACE_ES;

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

/**
 * @tc.name: Recorder_GetAVRecorderConfig_001
 * @tc.desc: Test recorder GetAVRecorderConfig process 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_GetAVRecorderConfig_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_GetAVRecorderConfig_001 in.");

    OH_AVRecorder_Config *configGet = static_cast<OH_AVRecorder_Config *>(malloc(sizeof(OH_AVRecorder_Config)));

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
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

    free(configGet);

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("fd://02");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("90");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    OH_AVRecorder_Config *configGet = static_cast<OH_AVRecorder_Config *>(malloc(sizeof(OH_AVRecorder_Config)));

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    EXPECT_EQ(configGet->profile.audioBitrate, 48000);
    EXPECT_EQ(configGet->profile.audioChannels, 2);
    EXPECT_EQ(configGet->profile.audioCodec, OH_AVRecorder_CodecMimeType::AUDIO_AAC);
    EXPECT_EQ(configGet->profile.audioSampleRate, 48000);
    EXPECT_EQ(configGet->profile.fileFormat, OH_AVRecorder_ContainerFormatType::CFT_MPEG_4);
    EXPECT_EQ(configGet->profile.videoBitrate, 2000000);
    EXPECT_EQ(configGet->profile.videoCodec, OH_AVRecorder_CodecMimeType::VIDEO_HEVC);
    EXPECT_EQ(configGet->profile.videoFrameHeight, 1080);
    EXPECT_EQ(configGet->profile.videoFrameWidth, 1920);
    EXPECT_EQ(configGet->profile.videoFrameRate, 30);
    EXPECT_EQ(configGet->audioSourceType, OH_AVRecorder_AudioSourceType::MIC);
    EXPECT_EQ(configGet->videoSourceType, OH_AVRecorder_VideoSourceType::SURFACE_YUV);
    EXPECT_EQ(configGet->metadata.location.latitude, 31);
    EXPECT_EQ(configGet->metadata.location.longitude, 121);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    free(configGet);

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("fd://10");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("270");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");
    config.profile.audioBitrate = 64000;
    config.profile.audioChannels = 2;
    config.profile.audioCodec = OH_AVRecorder_CodecMimeType::AUDIO_AAC;
    config.profile.audioSampleRate = 64000;
    config.profile.fileFormat = OH_AVRecorder_ContainerFormatType::CFT_MPEG_4;
    config.profile.videoBitrate = 25000000;
    config.profile.videoCodec = OH_AVRecorder_CodecMimeType::VIDEO_AVC;
    config.profile.videoFrameWidth = 3840;
    config.profile.videoFrameHeight = 2160;
    config.profile.videoFrameRate = 24;
    config.profile.isHdr = true;
    config.profile.enableTemporalScale = true;
    config.audioSourceType = OH_AVRecorder_AudioSourceType::CAMCORDER;
    config.videoSourceType = OH_AVRecorder_VideoSourceType::SURFACE_ES;

    OH_AVRecorder_Config *configGet = static_cast<OH_AVRecorder_Config *>(malloc(sizeof(OH_AVRecorder_Config)));

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_GetAVRecorderConfig(recorder_, &configGet);
    EXPECT_EQ(ret, AV_ERR_OK);
    EXPECT_EQ(configGet->profile.audioBitrate, 64000);
    EXPECT_EQ(configGet->profile.audioChannels, 2);
    EXPECT_EQ(configGet->profile.audioCodec, OH_AVRecorder_CodecMimeType::AUDIO_AAC);
    EXPECT_EQ(configGet->profile.audioSampleRate, 64000);
    EXPECT_EQ(configGet->profile.fileFormat, OH_AVRecorder_ContainerFormatType::CFT_MPEG_4);
    EXPECT_EQ(configGet->profile.videoBitrate, 25000000);
    EXPECT_EQ(configGet->profile.videoCodec, OH_AVRecorder_CodecMimeType::VIDEO_AVC);
    EXPECT_EQ(configGet->profile.videoFrameHeight, 2160);
    EXPECT_EQ(configGet->profile.videoFrameWidth, 3840);
    EXPECT_EQ(configGet->profile.videoFrameRate, 24);
    EXPECT_EQ(configGet->audioSourceType, OH_AVRecorder_AudioSourceType::CAMCORDER);
    EXPECT_EQ(configGet->videoSourceType, OH_AVRecorder_VideoSourceType::SURFACE_ES);
    EXPECT_EQ(configGet->metadata.location.latitude, 31);
    EXPECT_EQ(configGet->metadata.location.longitude, 121);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    free(configGet);

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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
 * @tc.name: Recorder_Start_001
 * @tc.desc: Test recorder start process failure 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_failure_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_failure_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_failure_001 out.");
}

/**
 * @tc.name: Recorder_Start_002
 * @tc.desc: Test recorder start process failure 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_failure_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_failure_002 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Start_failure_002 out.");
}

/**
 * @tc.name: Recorder_Pause_001
 * @tc.desc: Test recorder pause process failure 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_failure_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_001 out.");
}

/**
 * @tc.name: Recorder_Pause_002
 * @tc.desc: Test recorder pause process failure 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_failure_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_002 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_002 out.");
}

/**
 * @tc.name: Recorder_Pause_003
 * @tc.desc: Test recorder pause process failure 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Pause_failure_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_003 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Pause_failure_003 out.");
}

/**
 * @tc.name: Recorder_Resume_001
 * @tc.desc: Test recorder resume process failure 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_failure_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_001 out.");
}

/**
 * @tc.name: Recorder_Resume_002
 * @tc.desc: Test recorder resume process failure 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_failure_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_002 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_002 out.");
}

/**
 * @tc.name: Recorder_Resume_003
 * @tc.desc: Test recorder pause process failure 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_failure_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_003 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_003 out.");
}

/**
 * @tc.name: Recorder_Resume_004
 * @tc.desc: Test recorder pause process failure 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Resume_failure_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_004 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);
    ret = OH_AVRecorder_Stop(recorder_);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Resume_failure_004 out.");
}

/**
 * @tc.name: Recorder_Stop_001
 * @tc.desc: Test recorder stop process failure 001
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_failure_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_001 in.");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_001 out.");
}

/**
 * @tc.name: Recorder_Stop_002
 * @tc.desc: Test recorder stop process failure 002
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_failure_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_002 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_002 out.");
}

/**
 * @tc.name: Recorder_Stop_003
 * @tc.desc: Test recorder stop process failure 003
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_failure_003, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_003 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_003 out.");
}

/**
 * @tc.name: Recorder_Stop_004
 * @tc.desc: Test recorder stop process failure 004
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Stop_failure_004, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_004 in.");

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Resume(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Stop(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);

    free(config.url);
    free(config.metadata.genre);
    free(config.metadata.videoOrientation);
    free(config.metadata.customInfo.key);
    free(config.metadata.customInfo.value);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Stop_failure_004 out.");
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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
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

    OH_AVRecorder_Config config = sConfig;
    config.url = strdup("");
    config.metadata.genre = strdup("");
    config.metadata.videoOrientation = strdup("0");
    config.metadata.customInfo.key = strdup("");
    config.metadata.customInfo.value = strdup("");

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_Prepare(recorder_, &config);
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = OH_AVRecorder_Start(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
    sleep(3);
    ret = OH_AVRecorder_Pause(recorder_);
    EXPECT_NE(ret, AV_ERR_OK);
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
static void AVRecorderStateChangeCbAlter(OH_AVRecorder *recorder,
    OH_AVRecorder_State state, OH_AVRecorder_StateChangeReason reason, void *userData)
{
    MEDIA_LOGI("AVRecorderStateChangeCbAlter reason: %d, OH_AVRecorder_State: %d \n", reason, state);
}

HWTEST_F(NativeRecorderUnitTest, Recorder_SetStateCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_001 in.");

    OH_AVRecorder_OnStateChange stateChangeCb = AVRecorderStateChangeCbAlter;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_SetStateCallback(recorder_, stateChangeCb, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetStateCallback_001 out.");
}

/**
 * @tc.name: Recorder_SetErrorCallback_001
 * @tc.desc: Test recorder setErrorCallback process 001
 * @tc.type: FUNC
 */
static void AVRecorderErrorCbAlter(OH_AVRecorder *recorder, int32_t errorCode, const char *errorMsg,
    void *userData)
{
    MEDIA_LOGE("AVRecorderErrorCbAlter errorCode: %d, errorMsg: %s \n", errorCode, errorMsg);
}

HWTEST_F(NativeRecorderUnitTest, Recorder_SetErrorCallback_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_001 in.");

    OH_AVRecorder_OnError errorCb = AVRecorderErrorCbAlter;

    int32_t ret = AV_ERR_OK;
    ret = OH_AVRecorder_SetErrorCallback(recorder_, errorCb, nullptr);
    EXPECT_EQ(ret, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderUnitTest Recorder_SetErrorCallback_001 out.");
}
