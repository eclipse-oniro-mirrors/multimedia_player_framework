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
#include <fstream>
#include "avmetadata_extractor.h"
#include "avmetadata_extractor_base.h"
#include "avmetadataextractor_unit_test.h"
#include "native_player_magic.h"
#include "native_mfmagic.h"
#include "gtest/gtest.h"
#include "media_errors.h"

#include "pixel_map.h"
#include "pixelmap_native_impl.h"

#include "avmedia_source.h"
#include "native_media_source_impl.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

#define ALC "/data/test/MP3_SURFACE.mp3"
#define MD "/data/test/ChineseColor_H264_AAC_480p_15fps.mp4"
#define LOC "/data/test/camera_info_parser.mp4"
static const string TEST_FILE_PATH = "/data/test/media/test_264_B_Gop25_4sec_cover.mp4";

void NativeMetadataExtractorUnitTest::SetUpTestCase(void) {}

void NativeMetadataExtractorUnitTest::TearDownTestCase(void) {}

void NativeMetadataExtractorUnitTest::SetUp(void) {}

void NativeMetadataExtractorUnitTest::TearDown(void) {}

static int32_t AVSourceReadAt(OH_AVBuffer *data, int32_t length, int64_t pos)
{
    if (data == nullptr) {
        printf("AVSourceReadAt : data is nullptr!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    std::ifstream infile(TEST_FILE_PATH, std::ofstream::binary);
    if (!infile.is_open()) {
        printf("AVSourceReadAt : open file failed! file:%s\n", TEST_FILE_PATH.c_str());
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;  // 打开文件失败
    }

    infile.seekg(0, std::ios::end);
    int64_t fileSize = infile.tellg();
    if (pos >= fileSize) {
        printf("AVSourceReadAt : pos over or equals file size!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_EOF;  // pos已经是文件末尾位置，无法读取
    }

    if (pos + length > fileSize) {
        length = fileSize - pos;    // pos+length长度超过文件大小时，读取从pos到文件末尾的数据
    }

    infile.seekg(pos, std::ios::beg);
    if (length <= 0) {
        printf("AVSourceReadAt : raed length less than zero!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }
    char* buffer = new char[length];
    infile.read(buffer, length);
    infile.close();

    errno_t result = memcpy_s(reinterpret_cast<char *>(OH_AVBuffer_GetAddr(data)),
        OH_AVBuffer_GetCapacity(data), buffer, length);
    delete[] buffer;
    if (result != 0) {
        printf("memcpy_s failed!");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    return length;
}

int64_t GetFileSize(const string &fileName)
{
    int64_t fileSize = 0;
    if (!fileName.empty()) {
        struct stat fileStatus {};
        if (stat(fileName.c_str(), &fileStatus) == 0) {
            fileSize = static_cast<int64_t>(fileStatus.st_size);
        }
    }
    return fileSize;
}

/**
 * @tc.name: AVMetadataExtractor_Create_0100
 * @tc.desc: Test create a metadata extractor object
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_Create_0100, Level2)
{
    OH_AVMetadataExtractor* metadataextractor = nullptr;
    metadataextractor = OH_AVMetadataExtractor_Create();

    ASSERT_NE(nullptr, metadataextractor);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_SetFDSource_0100
 * @tc.desc: Test set up a data source
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_SetFDSource_0100, Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t offset = 0;
    int64_t size = -1;

    int32_t ret = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, size);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_FetchMetadata_0100
 * @tc.desc: Test get metadata
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchMetadata_0100, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    OH_AVFormat* avMetadata = OH_AVFormat_Create();

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t offset = 0;
    int64_t size = -1;

    int32_t ret = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, size);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, ret);
    

    ret = OH_AVMetadataExtractor_FetchMetadata(metadataextractor, avMetadata);
    EXPECT_EQ(AV_ERR_OK, ret);

    OH_AVMetadataExtractor_Release(metadataextractor);
    OH_AVFormat_Destroy(avMetadata);
}

/**
 * @tc.name: AVMetadataExtractor_FetchMetadata_0200
 * @tc.desc: Test get metadata
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchMetadata_0200, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    OH_AVFormat* avMetadata = OH_AVFormat_Create();

    int32_t fd = open(LOC, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t offset = 0;
    int64_t size = -1;

    int32_t ret = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, size);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, ret);
    

    ret = OH_AVMetadataExtractor_FetchMetadata(metadataextractor, avMetadata);
    EXPECT_EQ(AV_ERR_OK, ret);

    OH_AVMetadataExtractor_Release(metadataextractor);
    OH_AVFormat_Destroy(avMetadata);
}

/**
 * @tc.name: AVMetadataExtractor_FetchAlbumCover_0100
 * @tc.desc: Test get the albumCover
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchAlbumCover_0100, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(ALC, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t offset = 0;
    int64_t size = -1;
    int32_t ret = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, size);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, ret);

    OH_PixelmapNative* pixelmapNative = nullptr;

    ret = OH_AVMetadataExtractor_FetchAlbumCover(metadataextractor, &pixelmapNative);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMetadataExtractor_Release(metadataextractor);
    OH_PixelmapNative_Release(pixelmapNative);
}

/**
 * @tc.name: AVMetadataExtractor_Release_0100
 * @tc.desc: Test release the metadata extractor object
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_Release_0100, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    OH_AVErrCode ret = OH_AVMetadataExtractor_Release(metadataextractor);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.number    : AVMetadataExtractor_FetchFrameByTime_0100
 * @tc.name      : FetchFrameByTime_WithValidSourceAndParams
 * @tc.desc      : Set FD source and fetch a frame at timeUs using valid output params.
 * @tc.type      : FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFrameByTime_0100, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = 100;
    OH_PixelmapNative* pixelMap = nullptr;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(metadataextractor, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, &pixelMap);
    EXPECT_EQ(AV_ERR_OK, result);
    EXPECT_NE(nullptr, pixelMap);

    auto err1 = OH_PixelmapNative_Release(pixelMap);
    EXPECT_EQ(IMAGE_SUCCESS, err1);
    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.number    : AVMetadataExtractor_FetchFrameByTime_0200
 * @tc.name      : FetchFrameByTime_NullExtractor
 * @tc.desc      : Call FetchFrameByTime with a null extractor.
 * @tc.type      : FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFrameByTime_0200, Level2)
{
    int64_t timeUs = 100;
    OH_PixelmapNative* pixelMap = nullptr;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(nullptr, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, &pixelMap);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);
    EXPECT_EQ(nullptr, pixelMap);

    EXPECT_NO_THROW(OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams));
}

/**
 * @tc.number    : AVMetadataExtractor_FetchFrameByTime_0300
 * @tc.name      : FetchFrameByTime_OutputSizeZero
 * @tc.desc      : Set FD source and call FetchFrameByTime with output size (0,0).
 * @tc.type      : FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFrameByTime_0300, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = 100;
    OH_PixelmapNative* pixelMap = nullptr;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 0, 0);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(metadataextractor, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, &pixelMap);
    EXPECT_EQ(AV_ERR_OK, result);
    EXPECT_NE(nullptr, pixelMap);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.number    : AVMetadataExtractor_FetchFrameByTime_0400
 * @tc.name      : FetchFrameByTime_InvalidTime
 * @tc.desc      : Set FD source and call FetchFrameByTime with invalid timeUs (-1).
 * @tc.type      : FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFrameByTime_0400, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = -1;
    OH_PixelmapNative* pixelMap = nullptr;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(metadataextractor, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, &pixelMap);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);
    EXPECT_EQ(nullptr, pixelMap);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.number    : AVMetadataExtractor_FetchFrameByTime_0500
 * @tc.name      : FetchFrameByTime_NullPixelMapOut
 * @tc.desc      : Set FD source and valid output params but pass null pixel map output pointer.
 * @tc.type      : FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFrameByTime_0500, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = 100;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(metadataextractor, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

static void AVMetadataExtractorOnFrameFetched(OH_AVMetadataExtractor* extractor,
    const OH_AVMetadataExtractor_FrameInfo* frameInfo, OH_AVErrCode code, void* userData)
{
    ASSERT_NE(nullptr, extractor);
}

/**
 * @ts.name: AVMetadataExtractor_FetchFramesByTimes_0100
 * @tc.desc: Set FD source and fetch frames at multiple timeUs using valid output params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFramesByTimes_0100, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUsArray[] = {1000, 2000, 3000};
    uint64_t timesUsSize = std::size(timeUsArray);

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFramesByTimes(metadataextractor, timeUsArray,
        timesUsSize, OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams,
        AVMetadataExtractorOnFrameFetched, nullptr);
    EXPECT_EQ(AV_ERR_OK, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @ts.name: AVMetadataExtractor_FetchFramesByTimes_0200
 * @tc.desc: Test fetch frames at multiple timeUs using valid output params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFramesByTimes_0200, Level2)
{
    int64_t timeUsArray[] = {1000, 2000, 3000};
    uint64_t timesUsSize = std::size(timeUsArray);

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFramesByTimes(nullptr, timeUsArray,
        timesUsSize, OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams,
        AVMetadataExtractorOnFrameFetched, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
}

/**
 * @ts.name: AVMetadataExtractor_FetchFramesByTimes_0300
 * @tc.desc: Test fetch frames at multiple timeUs using valid output params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFramesByTimes_0300, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUsArray[] = {1000, 2000, 3000};
    uint64_t timesUsSize = std::size(timeUsArray);

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 0, 0);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFramesByTimes(metadataextractor, timeUsArray,
        timesUsSize, OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams,
        AVMetadataExtractorOnFrameFetched, nullptr);
    EXPECT_EQ(AV_ERR_OK, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @ts.name: AVMetadataExtractor_FetchFramesByTimes_0400
 * @tc.desc: Test fetch frames at multiple timeUs using valid output params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFramesByTimes_0400, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    uint64_t timesUsSize = 0;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 0, 0);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFramesByTimes(metadataextractor, nullptr,
        timesUsSize, OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams,
        AVMetadataExtractorOnFrameFetched, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @ts.name: AVMetadataExtractor_FetchFramesByTimes_0500
 * @tc.desc: Test fetch frames at multiple timeUs using valid output params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_FetchFramesByTimes_0500, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUsArray[] = {1000, 2000, 3000};
    uint64_t timesUsSize = std::size(timeUsArray);

    auto result = OH_AVMetadataExtractor_FetchFramesByTimes(metadataextractor, timeUsArray,
        timesUsSize, OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, nullptr,
        AVMetadataExtractorOnFrameFetched, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, result);

    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @ts.name: AVMetadataExtractor_CancelAllFetchFrames_0100
 * @tc.desc: Test cancel all fetch frames requests.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_CancelAllFetchFrames_0100, Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = 100;
    OH_PixelmapNative* pixelMap = nullptr;

    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);

    auto result = OH_AVMetadataExtractor_FetchFrameByTime(metadataextractor, timeUs,
        OH_AVMedia_SeekMode::OH_AVMEDIA_SEEK_NEXT_SYNC, pixelMapParams, &pixelMap);
    OH_AVMetadataExtractor_CancelAllFetchFrames(metadataextractor);
    EXPECT_EQ(AV_ERR_OK, result);

    OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams);
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.name: AVMetadataExtractor_SetMediaSource_0100
 * @tc.desc: Test set up a data source using media source.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_SetMediaSource_0100, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    const char* url = "http://example.com/video.mp4";
    OH_AVHttpHeader* header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource* mediaSource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediaSource, nullptr);

    auto res = OH_AVMetadataExtractor_SetMediaSource(metadataextractor, mediaSource);
    EXPECT_EQ(AV_ERR_OK, res);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_SetMediaSource_0200
 * @tc.desc: Test set up a data source using media source.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_SetMediaSource_0200, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = nullptr;
    ASSERT_EQ(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;
    auto mediaSource = OH_AVMediaSource_CreateWithFd(fd, offset, fileSize);

    auto res = OH_AVMetadataExtractor_SetMediaSource(metadataextractor, mediaSource);
    EXPECT_EQ(AV_ERR_INVALID_VAL, res);
    close(fd);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_SetMediaSource_0300
 * @tc.desc: Test set up a data source using media source.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_SetMediaSource_0300, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    auto res = OH_AVMetadataExtractor_SetMediaSource(metadataextractor, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, res);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_SetMediaSource_0400
 * @tc.desc: Test set up a data source using media source.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_SetMediaSource_0400, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int64_t size = GetFileSize(TEST_FILE_PATH);
    OH_AVDataSource dataSource = {size, AVSourceReadAt};
    OH_AVMediaSource *avMediaSource = OH_AVMediaSource_CreateWithDataSource(&dataSource);

    auto res = OH_AVMetadataExtractor_SetMediaSource(metadataextractor, avMediaSource);
    EXPECT_EQ(AV_ERR_OK, res);
    OH_AVMetadataExtractor_Release(metadataextractor);
}

/**
 * @tc.name: AVMetadataExtractor_GetTrackDescription_0100
 * @tc.desc: Set FD source and get track description at index 0.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_GetTrackDescription_0100, TestSize.Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);
    int32_t index = 0;

    OH_AVFormat* trackDesc = OH_AVMetadataExtractor_GetTrackDescription(metadataextractor, index);
    EXPECT_NE(nullptr, trackDesc);

    if (trackDesc != nullptr) {
        OH_AVFormat_Destroy(trackDesc);
    }
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.name: AVMetadataExtractor_GetTrackDescription_0200
 * @tc.desc: Set FD source and request track description with out-of-range index.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_GetTrackDescription_0200, TestSize.Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);
    int32_t index = 100;

    OH_AVFormat* trackDesc = OH_AVMetadataExtractor_GetTrackDescription(metadataextractor, index);
    EXPECT_EQ(nullptr, trackDesc);

    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.name: AVMetadataExtractor_GetTrackDescription_0300
 * @tc.desc: Call GetTrackDescription with a null extractor.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_GetTrackDescription_0300, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = nullptr;
    int32_t index = 0;

    OH_AVFormat* trackDesc = OH_AVMetadataExtractor_GetTrackDescription(metadataextractor, index);
    EXPECT_EQ(nullptr, trackDesc);
}

/**
 * @tc.name: OH_AVMetadataExtractor_GetCustomInfo_0100
 * @tc.desc: Set FD source and retrieve custom metadata info.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, OH_AVMetadataExtractor_GetCustomInfo_0100, TestSize.Level2)
{
    auto metadataextractor = OH_AVMetadataExtractor_Create();
    ASSERT_NE(nullptr, metadataextractor);

    int32_t fd = open(MD, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVMetadataExtractor_SetFDSource(metadataextractor, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    OH_AVFormat* trackDesc = OH_AVMetadataExtractor_GetCustomInfo(metadataextractor);
    EXPECT_NE(nullptr, trackDesc);

    if (trackDesc != nullptr) {
        OH_AVFormat_Destroy(trackDesc);
    }
    auto res = OH_AVMetadataExtractor_Release(metadataextractor);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
 * @tc.name: OH_AVMetadataExtractor_GetCustomInfo_0200
 * @tc.desc: Call GetCustomInfo with a null extractor.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, OH_AVMetadataExtractor_GetCustomInfo_0200, TestSize.Level2)
{
    OH_AVMetadataExtractor* metadataextractor = nullptr;

    OH_AVFormat* trackDesc = OH_AVMetadataExtractor_GetCustomInfo(metadataextractor);
    EXPECT_EQ(nullptr, trackDesc);
}

/**
 * @tc.name: OH_AVMetadataExtractor_OutputParam_Create_Destroy_0100
 * @tc.desc: Create and destroy OH_AVMetadataExtractor_OutputParam.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, OH_AVMetadataExtractor_OutputParam_Destroy_0100, TestSize.Level2)
{
    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    EXPECT_NE(pixelMapParams, nullptr);
    EXPECT_NO_THROW(OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams));
}

/**
 * @tc.name: AVMetadataExtractor_OutputParams_SetSize_0100
 * @tc.desc: Set output size to (0,0).
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_OutputParams_SetSize_0100, TestSize.Level2)
{
    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 0, 0);
    EXPECT_EQ(true, err);
    EXPECT_NO_THROW(OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams));
}

/**
 * @tc.name: AVMetadataExtractor_OutputParams_SetSize_0200
 * @tc.desc: Set output size to (100,100).
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_OutputParams_SetSize_0200, TestSize.Level2)
{
    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, 100, 100);
    EXPECT_EQ(true, err);
    EXPECT_NO_THROW(OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams));
}

/**
 * @tc.name: AVMetadataExtractor_OutputParams_SetSize_0300
 * @tc.desc: Set output size to (-1,-1).
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_OutputParams_SetSize_0300, TestSize.Level2)
{
    auto pixelMapParams = OH_AVMetadataExtractor_OutputParam_Create();
    auto err = OH_AVMetadataExtractor_OutputParam_SetSize(pixelMapParams, -1, -1);
    EXPECT_EQ(true, err);
    EXPECT_NO_THROW(OH_AVMetadataExtractor_OutputParam_Destroy(pixelMapParams));
}

/**
 * @tc.name: AVMetadataExtractor_Keys_0100
 * @tc.desc: Verify predefined metadata key string constants match expected literal values.
 * @tc.type: FUNC
 */
HWTEST_F(NativeMetadataExtractorUnitTest, AVMetadataExtractor_Keys_0100, TestSize.Level2)
{
    const char* key1 = OH_AVMETADATA_EXTRACTOR_ALBUM;
    EXPECT_EQ(key1, "album");
    const char* key2 = OH_AVMETADATA_EXTRACTOR_ALBUM_ARTIST;
    EXPECT_EQ(key2, "albumArtist");
    const char* key3 = OH_AVMETADATA_EXTRACTOR_ARTIST;
    EXPECT_EQ(key3, "artist");
    const char* key4 = OH_AVMETADATA_EXTRACTOR_AUTHOR;
    EXPECT_EQ(key4, "author");
    const char* key5 = OH_AVMETADATA_EXTRACTOR_DATE_TIME;
    EXPECT_EQ(key5, "dateTime");
    const char* key6 = OH_AVMETADATA_EXTRACTOR_DATE_TIME_FORMAT;
    EXPECT_EQ(key6, "dateTimeFormat");
    const char* key7 = OH_AVMETADATA_EXTRACTOR_COMPOSER;
    EXPECT_EQ(key7, "composer");
    const char* key8 = OH_AVMETADATA_EXTRACTOR_DURATION;
    EXPECT_EQ(key8, "duration");
    const char* key9 = OH_AVMETADATA_EXTRACTOR_GENRE;
    EXPECT_EQ(key9, "genre");
    const char* key10 = OH_AVMETADATA_EXTRACTOR_HAS_AUDIO;
    EXPECT_EQ(key10, "hasAudio");
    const char* key11 = OH_AVMETADATA_EXTRACTOR_HAS_VIDEO;
    EXPECT_EQ(key11, "hasVideo");
    const char* key12 = OH_AVMETADATA_EXTRACTOR_MIME_TYPE;
    EXPECT_EQ(key12, "mimeType");
    const char* key13 = OH_AVMETADATA_EXTRACTOR_TRACK_COUNT;
    EXPECT_EQ(key13, "trackCount");
    const char* key14 = OH_AVMETADATA_EXTRACTOR_SAMPLE_RATE;
    EXPECT_EQ(key14, "sampleRate");
    const char* key15 = OH_AVMETADATA_EXTRACTOR_TITLE;
    EXPECT_EQ(key15, "title");
    const char* key16 = OH_AVMETADATA_EXTRACTOR_VIDEO_HEIGHT;
    EXPECT_EQ(key16, "videoHeight");
    const char* key17 = OH_AVMETADATA_EXTRACTOR_VIDEO_WIDTH;
    EXPECT_EQ(key17, "videoWidth");
    const char* key18 = OH_AVMETADATA_EXTRACTOR_VIDEO_ORIENTATION;
    EXPECT_EQ(key18, "videoOrientation");
    const char* key19 = OH_AVMETADATA_EXTRACTOR_VIDEO_IS_HDR_VIVID;
    EXPECT_EQ(key19, "hdrType");
    const char* key20 = OH_AVMETADATA_EXTRACTOR_LOCATION_LATITUDE;
    EXPECT_EQ(key20, "latitude");
    const char* key21 = OH_AVMETADATA_EXTRACTOR_LOCATION_LONGITUDE;
    EXPECT_EQ(key21, "longitude");
}