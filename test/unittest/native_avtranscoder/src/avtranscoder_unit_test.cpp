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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "avtranscoder.h"
#include "avtranscoder_unit_test.h"
#include "avtranscoder_mock.h"
#include "media_errors.h"
#include "gtest/gtest.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

static const std::string CHINESE_COLOR_MP4 = "/data/test/ChineseColor_H264_AAC_480p_15fps.mp4";
static const std::string MOCK_OUTPUT_MP4 = "/data/test/Mock_Output.mp4";
static const int32_t ZERO = 0;
static const int32_t MOCK_VIDEO_WIDTH = 640;
static const int32_t MOCK_VIDEO_HEIGHT = 480;
static const int64_t TRANSCODER_FILE_OFFSET = 37508084;
static const int64_t TRANSCODER_FILE_SIZE = 2735029;
constexpr int32_t TRASCODER_AUDIO_ENCODING_BIT_RATE = 20000;
constexpr int32_t TRASCODER_VIDEO_ENCODING_BIT_RATE = 30000;
static const int32_t MOCK_NEG = -1;

void NativeAVTranscoderUnitTest::SetUpTestCase(void) {}

void NativeAVTranscoderUnitTest::TearDownTestCase(void) {}

void NativeAVTranscoderUnitTest::SetUp(void) {}

void NativeAVTranscoderUnitTest::TearDown(void) {}

void MockOnStateChange(OH_AVTranscoder *transcoder, OH_AVTranscoder_State state, void *userData)
{
    if (transcoder == nullptr) {
        return;
    }
    MockUserData* mockUserData = static_cast<MockUserData*>(userData);
    if (mockUserData == nullptr) {
        return;
    }
    switch (state) {
        case OH_AVTranscoder_State::AVTRANSCODER_PREPARED:
            mockUserData->state_ = OH_AVTranscoder_State::AVTRANSCODER_PREPARED;
            break;
        case OH_AVTranscoder_State::AVTRANSCODER_STARTED:
            mockUserData->state_ = OH_AVTranscoder_State::AVTRANSCODER_STARTED;
            break;
        case OH_AVTranscoder_State::AVTRANSCODER_PAUSED:
            mockUserData->state_ = OH_AVTranscoder_State::AVTRANSCODER_PAUSED;
            break;
        case OH_AVTranscoder_State::AVTRANSCODER_CANCELLED:
            mockUserData->state_ = OH_AVTranscoder_State::AVTRANSCODER_CANCELLED;
            break;
        case OH_AVTranscoder_State::AVTRANSCODER_COMPLETED:
            mockUserData->state_ = OH_AVTranscoder_State::AVTRANSCODER_COMPLETED;
            break;
    }
}

void MockOnError(OH_AVTranscoder *transcoder, int32_t errorCode, const char *errorMsg,
    void *userData)
{
    if (transcoder == nullptr) {
        return;
    }
}

void MockOnProgressUpdate(OH_AVTranscoder *transcoder, int progress, void *userData)
{
    if (transcoder == nullptr) {
        return;
    }
}

void NativeAVTranscoderUnitTest::InitAVTranscoderCallback(OH_AVTranscoder* transcoder, MockUserData& mockUserData)
{
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_SetErrorCallback(transcoder, MockOnError, static_cast<void*>(&mockUserData));
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_SetProgressUpdateCallback(transcoder,
                                                          MockOnProgressUpdate,
                                                          static_cast<void*>(&mockUserData));
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_SetStateCallback(transcoder,
                                                 MockOnStateChange,
                                                 static_cast<void*>(&mockUserData));
    ASSERT_EQ(errorCode, AV_ERR_OK);
}

void NativeAVTranscoderUnitTest::InitAVTranscoderConfig(OH_AVTranscoder_Config* config, int32_t srcFd, int32_t dstFd)
{
    OH_AVErrCode errorCode{ AV_ERR_OK };

    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    errorCode = OH_AVTranscoderConfig_SetSrcFD(config, srcFd, offset, size);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstFD(config, dstFd);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstFileType(config, OH_AVOutputFormat::AV_OUTPUT_FORMAT_MPEG_4);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstVideoType(config, "video/avc");
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstAudioType(config, "audio/mp4a-latm");
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstAudioBitrate(config, TRASCODER_AUDIO_ENCODING_BIT_RATE);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstVideoBitrate(config, TRASCODER_VIDEO_ENCODING_BIT_RATE);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_SetDstVideoResolution(config, MOCK_VIDEO_WIDTH, MOCK_VIDEO_HEIGHT);
    ASSERT_EQ(errorCode, AV_ERR_OK);
}

/**
 * @tc.name: AVTranscoder_Complete001
 * @tc.desc: Verify the regular transcoding process.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Complete001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Complete001 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);

    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Complete001 end";
}

/**
 * @tc.name: AVTranscoder_Pause001
 * @tc.desc: Verify that pause and resume during verification transcoding.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Pause001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause001 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);
    
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    
    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Resume(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause001 end";
}

/**
 * @tc.name: AVTranscoder_Cancel001
 * @tc.desc: Verify that Cancel operation during transcoding.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Cancel001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel001 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel001 end";
}

/**
 * @tc.name: AVTranscoder_Prepare001
 * @tc.desc: Verify that repeated prepare operation will fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Prepare001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Prepare001 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Prepare001 end";
}

/**
 * @tc.name: AVTranscoder_Start001
 * @tc.desc: Verify that repeated Start operation will not fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Start001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start001 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    
    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigRelease001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_Release when input parameter is nullptr will fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigRelease001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigRelease001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_Release(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigRelease001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetSrcFD001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetSrcFD when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetSrcFD001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetSrcFD001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetSrcFD(nullptr, MOCK_NEG, MOCK_NEG, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetSrcFD(config, MOCK_NEG, MOCK_NEG, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetSrcFD(config, ZERO, MOCK_NEG, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetSrcFD(config, ZERO, ZERO, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetSrcFD(config, ZERO, ZERO, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetSrcFD001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetDstFD001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstFD when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetDstFD001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstFD001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstFD(nullptr, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstFD(config, MOCK_NEG);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetDstFD(config, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstFD001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetVideoType001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstVideoType when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetVideoType001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetVideoType001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstVideoType(nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstVideoType(config, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetDstVideoType(config, "Mock");
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetVideoType001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetAudioType001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstAudioType when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetAudioType001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetAudioType001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstAudioType(nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstAudioType(config, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetDstAudioType(config, "Mock");
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetAudioType001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetDstFileType001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstFileType when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetDstFileType001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstFileType001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstFileType(nullptr, OH_AVOutputFormat::AV_OUTPUT_FORMAT_AMR);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstFileType(config, OH_AVOutputFormat::AV_OUTPUT_FORMAT_AMR);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstFileType001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetDstAudioBitrate001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstAudioBitrate when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetDstAudioBitrate001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstAudioBitrate001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstAudioBitrate(nullptr, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstAudioBitrate(config, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstAudioBitrate001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetDstVideoBitrate001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstVideoBitrate when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetDstVideoBitrate001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstVideoBitrate001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstVideoBitrate(nullptr, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstVideoBitrate(config, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstVideoBitrate001 end";
}

/**
 * @tc.name: AVTranscoder_ConfigSetDstVideoResolution001
 * @tc.desc: Verify that call OH_AVTranscoderConfig_SetDstVideoResolution when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_ConfigSetDstVideoResolution001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstVideoResolution001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoderConfig_SetDstVideoResolution(nullptr, ZERO, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    errorCode = OH_AVTranscoderConfig_SetDstVideoResolution(config, ZERO, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetDstVideoResolution(config, MOCK_VIDEO_WIDTH, ZERO);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_SetDstVideoResolution(config, MOCK_VIDEO_WIDTH, MOCK_VIDEO_HEIGHT);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_ConfigSetDstVideoResolution001 end";
}

/**
 * @tc.name: AVTranscoder_Prepare002
 * @tc.desc: Verify that call OH_AVTranscoder_Prepare when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Prepare002, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Prepare002 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);

    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    errorCode = OH_AVTranscoder_Prepare(transcoder, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Prepare002 end";
}

/**
 * @tc.name: AVTranscoder_Start002
 * @tc.desc: Verify that call OH_AVTranscoder_Start when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Start002, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start002 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Start(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start002 end";
}

/**
 * @tc.name: AVTranscoder_Start003
 * @tc.desc: Verify that call OH_AVTranscoder_Start when prepare operation has not been invoked.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Start003, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start003 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Start003 end";
}

/**
 * @tc.name: AVTranscoder_Pause002
 * @tc.desc: Verify that call OH_AVTranscoder_Pause when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Pause002, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause002 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Pause(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause002 end";
}

/**
 * @tc.name: AVTranscoder_Pause003
 * @tc.desc: Verify that call OH_AVTranscoder_Pause when pre-operation has not been invoked.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Pause003, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause003 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause003 end";
}

/**
 * @tc.name: AVTranscoder_Pause004
 * @tc.desc: Verify that repeated Pause operation will not fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Pause004, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause004 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    
    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Pause004 end";
}

/**
 * @tc.name: AVTranscoder_Resume001
 * @tc.desc: Verify that call OH_AVTranscoder_Resume when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Resume001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Resume(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume001 end";
}

/**
 * @tc.name: AVTranscoder_Resume002
 * @tc.desc: Verify that call OH_AVTranscoder_Resume when pre-operation has not been invoked.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Resume002, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume002 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Resume(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume002 end";
}

/**
 * @tc.name: AVTranscoder_Resume003
 * @tc.desc: Verify that repeated Resume operation will not fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Resume003, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume003 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    
    errorCode = OH_AVTranscoder_Resume(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Resume(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Resume003 end";
}

/**
 * @tc.name: AVTranscoder_Cancel002
 * @tc.desc: Verify that call OH_AVTranscoder_Cancel when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Cancel002, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel002 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Cancel(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel002 end";
}

/**
 * @tc.name: AVTranscoder_Cancel003
 * @tc.desc: Verify that call OH_AVTranscoder_Cancel when pre-operation has not been invoked.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Cancel003, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel003 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel003 end";
}

/**
 * @tc.name: AVTranscoder_Cancel004
 * @tc.desc: Verify that repeated Cancel operation will fail.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Cancel004, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel004 start";
    OH_AVTranscoder *transcoder = OH_AVTranscoder_Create();
    ASSERT_NE(transcoder, nullptr);

    MockUserData mockUserData;
    InitAVTranscoderCallback(transcoder, mockUserData);

    OH_AVTranscoder_Config *config = OH_AVTranscoderConfig_Create();
    ASSERT_NE(config, nullptr);
    int32_t srcFd = open(CHINESE_COLOR_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= ZERO);
    int32_t dstFd = open(MOCK_OUTPUT_MP4.c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= ZERO);
    InitAVTranscoderConfig(config, srcFd, dstFd);

    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Prepare(transcoder, config);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Start(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Pause(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    
    errorCode = OH_AVTranscoder_Resume(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    errorCode = OH_AVTranscoder_Cancel(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OPERATE_NOT_PERMIT);

    errorCode = OH_AVTranscoderConfig_Release(config);
    ASSERT_EQ(errorCode, AV_ERR_OK);
    errorCode = OH_AVTranscoder_Release(transcoder);
    ASSERT_EQ(errorCode, AV_ERR_OK);

    close(srcFd);
    close(dstFd);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Cancel004 end";
}

/**
 * @tc.name: AVTranscoder_Release001
 * @tc.desc: Verify that call OH_AVTranscoder_Release when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_Release001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Release001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_Release(nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_Release001 end";
}

/**
 * @tc.name: AVTranscoder_SetStateCallback001
 * @tc.desc: Verify that call OH_AVTranscoder_SetStateCallback when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_SetStateCallback001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetStateCallback001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_SetStateCallback(nullptr, nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetStateCallback001 end";
}

/**
 * @tc.name: AVTranscoder_SetErrorCallback001
 * @tc.desc: Verify that call OH_AVTranscoder_SetErrorCallback when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_SetErrorCallback001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetErrorCallback001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_SetErrorCallback(nullptr, nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetErrorCallback001 end";
}

/**
 * @tc.name: AVTranscoder_SetProgressUpdateCallback001
 * @tc.desc: Verify that call OH_AVTranscoder_SetProgressUpdateCallback when input parameter is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVTranscoderUnitTest, AVTranscoder_SetProgressUpdateCallback001, Level3)
{
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetProgressUpdateCallback001 start";
    OH_AVErrCode errorCode{ AV_ERR_OK };
    errorCode = OH_AVTranscoder_SetProgressUpdateCallback(nullptr, nullptr, nullptr);
    ASSERT_EQ(errorCode, AV_ERR_INVALID_VAL);
    GTEST_LOG_(INFO) << "NativeAVTranscoderUnitTest: AVTranscoder_SetProgressUpdateCallback001 end";
}