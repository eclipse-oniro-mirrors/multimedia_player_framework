/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "transcoder_server_unit_test.h"
#include <unistd.h>
#include <fcntl.h>
#include <securec.h>
#include "media_errors.h"
#include "av_common.h"
#include "meta/video_types.h"
#include "media_errors.h"
#include "media_log.h"
#include <thread>
#include <chrono>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace TranscoderTestParam {
    constexpr uint32_t TRASCODER_AUDIO_ENCODING_BIT_RATE = 20000;
    constexpr uint32_t TRASCODER_VIDEO_ENCODING_BIT_RATE = 30000;
    constexpr int32_t TRANSCODER_BUFFER_WIDTH = 320;
    constexpr int32_t TRANSCODER_BUFFER_HEIGHT = 240;
    constexpr int32_t TRANSCODER_BUFFER_WIDTH_480P = 640;
    constexpr int32_t TRANSCODER_BUFFER_HEIGHT_480P = 480;
    constexpr uint64_t TRANSCODER_FILE_OFFSET = 37508084;
    constexpr uint64_t TRANSCODER_FILE_SIZE = 2735029;
    const std::string TRANSCODER_ROOT_SRC = "/data/test/media/transcoder_src/";
    const std::string TRANSCODER_ROOT_DST = "/data/test/media/transcoder_dst/";
    constexpr int32_t RETRY_TIMES = 5;
    constexpr int32_t CHECK_INTERVAL_MS = 100;
} // namespace TranscoderTestParam
using namespace TranscoderTestParam;
const std::string HEVC_LIB_PATH = std::string(AV_CODEC_PATH) + "/libav_codec_hevc_parser.z.so";
const std::string VPE_LIB_PATH = std::string(AV_CODEC_PATH) + "/libvideoprocessingengine.z.so";

void TransCoderUnitTest::SetUpTestCase(void) {}

void TransCoderUnitTest::TearDownTestCase(void) {}

void TransCoderUnitTest::SetUp(void)
{
    transcoder_ = TransCoderServer::Create();
    ASSERT_NE(nullptr, transcoder_);
}

void TransCoderUnitTest::TearDown(void)
{
    if (transcoder_ != nullptr) {
        transcoder_->Release();
    }
}

void TransCoderCallbackTest::OnError(int32_t errorCode, const std::string &errorMsg)
{
    status_ = TransCoderServer::REC_ERROR;
    cout << "Error received, errorType:" << errorCode << " errorCode:" << errorMsg << endl;
}

void TransCoderCallbackTest::OnInfo(int32_t type, int32_t extra)
{
    cout << "Info received, Infotype:" << type << " Infocode:" << extra << endl;
}

bool TransCoderCallbackTest::CheckStateChange()
{
    int retryTimes = RETRY_TIMES;
    while (retryTimes--) {
        if (status_ == TransCoderServer::REC_ERROR) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));
    }
    return false;
}

/**
 * @tc.name: transcoder_PureVideo_001
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with codec format H264
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideo_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));

    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideo_002
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with codec format h264 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideo_002, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideo_003
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with codec format H265
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideo_003, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideo_004
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with codec format h265 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideo_004, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_SetColorSpace_001
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
 
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_002
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_002, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_003
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_003, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_004
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_004, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_010
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_010, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_NONE;
    EXPECT_EQ(MSERR_INVALID_VAL, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_011
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_011, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_EBU_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_012
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_012, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_SMPTE_C_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_013
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_013, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_014
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_014, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_SetColorSpace_015
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_015, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
 
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_016
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_016, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_017
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_017, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_018
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_018, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_019
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_019, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_NONE;
    EXPECT_EQ(MSERR_INVALID_VAL, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_020
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_020, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_EBU_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_021
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_021, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_SMPTE_C_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_022
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_022, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_023
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec mp3 and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_023, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_SetColorSpace_024
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_024, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
 
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_025
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_025, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_026
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_026, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_027
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_027, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    int32_t videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
    int32_t videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_028
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_028, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_NONE;
    EXPECT_EQ(MSERR_INVALID_VAL, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_029
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_029, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_EBU_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_030
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_030, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT601_SMPTE_C_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_031
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_031, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_BT709_FULL;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
 
/**
 * @tc.name: transcoder_SetColorSpace_032
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with codec G711MU and different color space settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetColorSpace_032, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    TranscoderColorSpace colorSpaceFmt = TRANSCODER_COLORSPACE_P3_LIMIT;
    EXPECT_EQ(MSERR_OK, transcoder_->SetColorSpace(colorSpaceFmt));
    
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_001
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H264
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_002
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h264 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_002, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_003
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H265
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_003, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_004
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h265 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_004, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_005
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H264 and mp3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_005, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_006
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h264
 *  and mp3 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_006, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_007
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H265 and mp3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_007, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_008
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h265
 *  and mp3 pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_008, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_MPEG;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_009
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H264 and G711MU
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_009, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_010
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h264
 *  and G711MU pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_010, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_011
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format H265 and G711MU
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_011, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideo_012
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with codec format h265
 *  and G711MU pause and resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideo_012, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AUDIO_G711MU;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    if (access(HEVC_LIB_PATH.c_str(), F_OK) == 0) {
        encoder = H265;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureAudioAbnormal_case_001
 * @tc.desc: transcoder pure audio 01.mp3 with cancle before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureAudioAbnormal_case_001, TestSize.Level2)
{
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "01.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "01_dst.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_TRUE(cb->CheckStateChange());
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_M4A;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoder = AAC_LC;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncoder(encoder));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureAudioAbnormal_case_002
 * @tc.desc: transcoder pure audio 01.mp3 with pause before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureAudioAbnormal_case_002, TestSize.Level2)
{
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "01.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "01_dst.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_TRUE(cb->CheckStateChange());
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_M4A;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoder = AAC_LC;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncoder(encoder));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureAudioAbnormal_case_003
 * @tc.desc: transcoder pure audio 01.mp3 with resume before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureAudioAbnormal_case_003, TestSize.Level2)
{
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "01.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "01_dst.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_TRUE(cb->CheckStateChange());
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFile(dstFd));
    OutputFormatType format = FORMAT_M4A;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoder = AAC_LC;
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncoder(encoder));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideoAbnormal_case_001
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideoAbnormal_case_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideoAbnormal_case_002
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideoAbnormal_case_002, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_PureVideoAbnormal_case_003
 * @tc.desc: transcoder pure video AVC_Baseline@L1.2_81.0Kbps_320x240.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_PureVideoAbnormal_case_003, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "AVC_Baseline@L1.2_81.0Kbps_320x240_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(TRANSCODER_BUFFER_WIDTH, TRANSCODER_BUFFER_HEIGHT));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideoAbnormal_case_001
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideoAbnormal_case_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideoAbnormal_case_002
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideoAbnormal_case_002, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Pause());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_AudioVideoAbnormal_case_003
 * @tc.desc: transcoder audio and video ChineseColor_H264_AAC_480p_15fps.mp4 with cancel before prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_AudioVideoAbnormal_case_003, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_INVALID_OPERATION, transcoder_->Resume());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}

/**
 * @tc.name: transcoder_SetEnableBFrame_001
 * @tc.desc: transcode ChineseColor_H264_AAC_480p_15fps.mp4 with enable b frame encoding settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoderUnitTest, transcoder_SetEnableBFrame_001, TestSize.Level2)
{
    int32_t srcFd = open((TRANSCODER_ROOT_SRC + "ChineseColor_H264_AAC_480p_15fps.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(srcFd >= 0);
    int64_t offset = TRANSCODER_FILE_OFFSET;
    int64_t size = TRANSCODER_FILE_SIZE;
    EXPECT_EQ(MSERR_OK, transcoder_->SetInputFile(srcFd, offset, size));
    int32_t dstFd = open((TRANSCODER_ROOT_DST + "ChineseColor_H264_AAC_480p_15fps_dst.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(dstFd >= 0);
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFile(dstFd));
    std::shared_ptr<TransCoderCallbackTest> cb = std::make_shared<TransCoderCallbackTest>();
    EXPECT_EQ(MSERR_OK, transcoder_->SetTransCoderCallback(cb));
    OutputFormatType format = FORMAT_MPEG_4;
    EXPECT_EQ(MSERR_OK, transcoder_->SetOutputFormat(format));
    AudioCodecFormat encoderAudio = AAC_LC;
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncoder(encoderAudio));
    EXPECT_EQ(MSERR_OK, transcoder_->SetAudioEncodingBitRate(TRASCODER_AUDIO_ENCODING_BIT_RATE));
    VideoCodecFormat encoder = H264;
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncoder(encoder));
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoEncodingBitRate(TRASCODER_VIDEO_ENCODING_BIT_RATE));
    bool enableBFrame = true;
    EXPECT_EQ(MSERR_OK, transcoder_->SetEnableBFrame(enableBFrame));
    int32_t videoWidth = -1;
    int32_t videoHeight = -1;
    if (access(VPE_LIB_PATH.c_str(), F_OK) == 0) {
        videoWidth = TRANSCODER_BUFFER_WIDTH;
        videoHeight = TRANSCODER_BUFFER_HEIGHT;
    } else {
        videoWidth = TRANSCODER_BUFFER_WIDTH_480P;
        videoHeight = TRANSCODER_BUFFER_HEIGHT_480P;
    }
    EXPECT_EQ(MSERR_OK, transcoder_->SetVideoSize(videoWidth, videoHeight));
    EXPECT_EQ(MSERR_OK, transcoder_->Prepare());
    EXPECT_EQ(MSERR_OK, transcoder_->Start());
    EXPECT_EQ(MSERR_OK, transcoder_->Cancel());
    EXPECT_EQ(MSERR_OK, transcoder_->Release());
    close(dstFd);
    close(srcFd);
}
} // namespace Media
} // namespace OHOS