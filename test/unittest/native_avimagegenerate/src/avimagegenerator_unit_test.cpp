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
#include "avimage_generator.h"
#include "avimage_generator_base.h"
#include "avimagegenerator_unit_test.h"
#include "gtest/gtest.h"
#include "media_errors.h"
#include "pixelmap_native_impl.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

#define PATH "/data/test/ChineseColor_H264_AAC_480p_15fps.mp4"

void NativeImageGeneratorUnitTest::SetUpTestCase(void) {}

void NativeImageGeneratorUnitTest::TearDownTestCase(void) {}

void NativeImageGeneratorUnitTest::SetUp(void) {}

void NativeImageGeneratorUnitTest::TearDown(void) {}

/**
    * @tc.number    : AVImageGenerator_Create_0100
    * @tc.name      : SetSource AVImageGenerator_Create
    * @tc.desc      : Verify the functionality of creating AVImageGenerator object.
 */
HWTEST_F(NativeImageGeneratorUnitTest, OH_AVImageGenerator_Create_0100, Level2)
{
    auto imagegenerator = OH_AVImageGenerator_Create();
    ASSERT_NE(nullptr, imagegenerator);

    OH_AVImageGenerator_Release(imagegenerator);
}

/**
    * @tc.number    : AVImageGenerator_SetFDSource_0100
    * @tc.name      : SetSource AVImageGenerator_SetFDSource
    * @tc.desc      : AVImageGenerator set file descriptor source
 */
HWTEST_F(NativeImageGeneratorUnitTest, OH_AVImageGenerator_SetFDSource_0100, Level2)
{
    auto imagegenerator = OH_AVImageGenerator_Create();
    ASSERT_NE(nullptr, imagegenerator);

    int32_t fd = open(PATH, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto result  = OH_AVImageGenerator_SetFDSource(imagegenerator, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, result);

    auto res = OH_AVImageGenerator_Release(imagegenerator);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
    * @tc.number    : AVImageGenerator_FetchFrameByTime_0100
    * @tc.name      : SetSource AVImageGenerator_FetchFrameByTime
    * @tc.desc      : AVImageGenerator fetch frame by time
 */
HWTEST_F(NativeImageGeneratorUnitTest, OH_AVImageGenerator_FetchFrameByTime_0100, Level2)
{
    auto imagegenerator = OH_AVImageGenerator_Create();
    ASSERT_NE(nullptr, imagegenerator);

    int32_t fd = open(PATH, O_RDONLY);
    ASSERT_GT(fd, 0);
    int64_t fileSize = -1;
    int64_t offset = 0;

    auto re = OH_AVImageGenerator_SetFDSource(imagegenerator, fd, offset, fileSize);
    close(fd);
    EXPECT_EQ(AV_ERR_OK, re);

    int64_t timeUs = 100;
    OH_PixelmapNative* pixelMap = nullptr;

    auto result = OH_AVImageGenerator_FetchFrameByTime(imagegenerator, timeUs,
        OH_AVImageGenerator_QueryOptions::OH_AVIMAGE_GENERATOR_QUERY_NEXT_SYNC, &pixelMap);
    EXPECT_EQ(AV_ERR_OK, result);
    EXPECT_NE(nullptr, pixelMap);

    auto err = OH_PixelmapNative_Release(pixelMap);
    EXPECT_EQ(IMAGE_SUCCESS, err);
    auto res = OH_AVImageGenerator_Release(imagegenerator);
    ASSERT_EQ(AV_ERR_OK, res);
}

/**
    * @tc.number    : AVImageGenerator_Release_0100
    * @tc.name      : SetSource AVImageGenerator_Release
    * @tc.desc      : AVImageGenerator release
 */
HWTEST_F(NativeImageGeneratorUnitTest, OH_AVImageGenerator_Release_0100, Level2)
{
    auto imagegenerator  = OH_AVImageGenerator_Create();
    ASSERT_NE(nullptr, imagegenerator);
    auto result = OH_AVImageGenerator_Release(imagegenerator);
    ASSERT_EQ(AV_ERR_OK, result);
}