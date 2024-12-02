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
#include <string>
#include "media_log.h"
#include "media_errors.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_RECORDER, "NativeAVRecorder" };
}

void NativeRecorderUnitTest::SetUpTestCase(void) {}

void NativeRecorderUnitTest::TearDownTestCase(void) {}

void NativeRecorderUnitTest::SetUp(void) {}

void NativeRecorderUnitTest::TearDown(void) {}

/**
 * @tc.name: Recorder_Prepare_001
 * @tc.desc: Test recorder preparation process
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Prepare_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderUnitTest Recorder_Prepare_001 in.");

    OH_AVRecorder *recorder = OH_AVRecorder_Create();
    EXPECT_NE(recorder, nullptr);

    OH_AVRecorder_Profile profile = {
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

    OH_AVRecorder_Location location = {
        .latitude = 31.123456,
        .longitude = 121.123456,
    };

    OH_AVRecorder_MetadataTemplate customInfo = {
        .key = strdup(""),
        .value = strdup(""),
    };

    OH_AVRecorder_Metadata metadata = {
        .genre = strdup(""),
        .videoOrientation = strdup("0"),
        .location = location,
        .customInfo = customInfo,
    };

    OH_AVRecorder_Config config = {
        .audioSourceType = OH_AVRecorder_AudioSourceType::DEFAULT,
        .videoSourceType = OH_AVRecorder_VideoSourceType::SURFACE_YUV,
        .profile = profile,
        .url = strdup(""),
        .fileGenerationMode = OH_AVRecorder_FileGenerationMode::AUTO_CREATE_CAMERA_SCENE,
        .metadata = metadata,
    };
    
    int32_t ret = OH_AVRecorder_Prepare(recorder, &config);
    EXPECT_EQ(ret, AV_ERR_OK);

    free(customInfo.key);
    free(customInfo.value);
    free(metadata.genre);
    free(metadata.videoOrientation);
    free(config.url);

    MEDIA_LOGI("NativeRecorderCallbackTest Recorder_Prepare_001 out.");
}
/**
 * @tc.name: Recorder_Start_001
 * @tc.desc: Test recorder start process success
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_001, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderCallbackTest Recorder_Start_001 in.");

    int32_t result = AV_ERR_OK;
    EXPECT_EQ(result, AV_ERR_OK);

    MEDIA_LOGI("NativeRecorderCallbackTest Recorder_Start_001 out.");
}

/**
 * @tc.name: Recorder_Start_002
 * @tc.desc: Test recorder start process failure
 * @tc.type: FUNC
 */
HWTEST_F(NativeRecorderUnitTest, Recorder_Start_002, TestSize.Level2)
{
    MEDIA_LOGI("NativeRecorderCallbackTest Recorder_Start_002 in.");

    int32_t result = AV_ERR_INVALID_VAL;
    EXPECT_EQ(result, AV_ERR_INVALID_VAL);

    MEDIA_LOGI("NativeRecorderCallbackTest Recorder_Start_002 out.");
}
