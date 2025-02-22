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
#include "avmetadata_extractor.h"
#include "avmetadata_extractor_base.h"
#include "avmetadataextractor_unit_test.h"
#include "native_player_magic.h"
#include "native_mfmagic.h"
#include "gtest/gtest.h"
#include "media_errors.h"

#include "pixel_map.h"
#include "pixelmap_native_impl.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

#define ALC "/data/test/MP3_SURFACE.mp3"
#define MD "/data/test/ChineseColor_H264_AAC_480p_15fps.mp4"
#define LOC "/data/test/camera_info_parser.mp4"

void NativeMetadataExtractorUnitTest::SetUpTestCase(void) {}

void NativeMetadataExtractorUnitTest::TearDownTestCase(void) {}

void NativeMetadataExtractorUnitTest::SetUp(void) {}

void NativeMetadataExtractorUnitTest::TearDown(void) {}

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