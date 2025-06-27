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

#include "media_errors.h"
#include "avmetadatahelper_impl_unittest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

const static int32_t WIDTH = 100;
const static int32_t HEIGHT = 100;
const static size_t SIZE = WIDTH * HEIGHT * 2;
const static int32_t INVALID_SCALE_MODE = -1;

namespace OHOS {
namespace Media {
void AVMetadataHelperImplUnitTest::SetUpTestCase(void)
{
}

void AVMetadataHelperImplUnitTest::TearDownTestCase(void)
{
}

void AVMetadataHelperImplUnitTest::SetUp(void)
{
    metadataHelperImpl_ = std::make_shared<AVMetadataHelperImpl>();
}

void AVMetadataHelperImplUnitTest::TearDown(void)
{
    metadataHelperImpl_ = nullptr;
}

/**
 * @tc.name  : Test DumpPixelMap
 * @tc.number: DumpPixelMap_001
 * @tc.desc  : Test DumpPixelMap surfaceBuffer == nullptr
 */
HWTEST_F(AVMetadataHelperImplUnitTest, DumpPixelMap_001, TestSize.Level1)
{
    std::shared_ptr<MockPixelMap> pixelMap = std::make_shared<MockPixelMap>();
    EXPECT_CALL(*pixelMap, GetWidth()).WillOnce(Return(WIDTH));
    EXPECT_CALL(*pixelMap, GetHeight()).WillOnce(Return(HEIGHT));
    EXPECT_CALL(*pixelMap, GetPixelFormat()).WillOnce(Return(PixelFormat::RGB_565));
    EXPECT_CALL(*pixelMap, GetAllocatorType()).WillOnce(Return(AllocatorType::DMA_ALLOC));
    EXPECT_CALL(*pixelMap, GetFd()).WillOnce(Return(nullptr));

    int32_t ret = metadataHelperImpl_->DumpPixelMap(true, pixelMap, ".dump");
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test DumpAVBuffer
 * @tc.number: DumpAVBuffer_001
 * @tc.desc  : Test DumpAVBuffer surfaceBuffer == nullptr
 */
HWTEST_F(AVMetadataHelperImplUnitTest, DumpAVBuffer_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> frameBuffer = std::make_shared<AVBuffer>();
    frameBuffer->meta_ = std::make_shared<Meta>();
    auto mockAVMemory = std::make_shared<MockAVMemory>();
    frameBuffer->memory_ = mockAVMemory;
    EXPECT_CALL(*(mockAVMemory), GetSurfaceBuffer()).WillOnce(Return(nullptr));
    EXPECT_CALL(*(mockAVMemory), GetAddr()).WillOnce(Return(nullptr));
    EXPECT_CALL(*(mockAVMemory), GetSize()).WillOnce(Return(SIZE));

    int32_t ret = metadataHelperImpl_->DumpAVBuffer(true, frameBuffer, ".dump");
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test DumpAVBuffer
 * @tc.number: DumpAVBuffer_002
 * @tc.desc  : Test DumpAVBuffer surfaceBuffer != nullptr
 */
HWTEST_F(AVMetadataHelperImplUnitTest, DumpAVBuffer_002, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> frameBuffer = std::make_shared<AVBuffer>();
    frameBuffer->meta_ = std::make_shared<Meta>();
    auto mockAVMemory = std::make_shared<MockAVMemory>();
    frameBuffer->memory_ = mockAVMemory;
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    EXPECT_CALL(*(mockAVMemory), GetSurfaceBuffer()).WillOnce(Return(surfaceBuffer));
    EXPECT_CALL(*(mockSurfaceBuffer), GetVirAddr()).WillOnce(Return(nullptr));
    EXPECT_CALL(*(mockSurfaceBuffer), GetSize()).WillOnce(Return(SIZE));

    int32_t ret = metadataHelperImpl_->DumpAVBuffer(true, frameBuffer, ".dump");
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test FormatColorSpaceInfo
 * @tc.number: FormatColorSpaceInfo_001
 * @tc.desc  : Test FormatColorSpaceInfo colorSpaceInfo.primaries
 *             == CM_ColorSpacePrimaries::COLORPRIMARIES_P3_D65
 */
HWTEST_F(AVMetadataHelperImplUnitTest, FormatColorSpaceInfo_001, TestSize.Level1)
{
    // Test colorSpaceInfo.matrix == CM_Matrix::MATRIX_BT601_P
    CM_ColorSpaceInfo colorSpaceInfo {
        .primaries = CM_ColorPrimaries::COLORPRIMARIES_P3_D65,
        .matrix = CM_Matrix::MATRIX_BT601_P
    };
    metadataHelperImpl_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, CM_Matrix::MATRIX_P3);

    // Test colorSpaceInfo.matrix != CM_Matrix::MATRIX_BT601_P
    colorSpaceInfo.matrix = CM_Matrix::MATRIX_BT601_N;
    metadataHelperImpl_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, CM_Matrix::MATRIX_BT601_N);
}

/**
 * @tc.name  : Test FormatColorSpaceInfo
 * @tc.number: FormatColorSpaceInfo_002
 * @tc.desc  : Test FormatColorSpaceInfo colorSpaceInfo.primaries
 *             == CM_ColorSpacePrimaries::COLORPRIMARIES_BT601_P
 */
HWTEST_F(AVMetadataHelperImplUnitTest, FormatColorSpaceInfo_002, TestSize.Level1)
{
    // Test colorSpaceInfo.matrix == CM_Matrix::MATRIX_BT601_N
    CM_ColorSpaceInfo colorSpaceInfo {
        .primaries = CM_ColorPrimaries::COLORPRIMARIES_BT601_P,
        .matrix = CM_Matrix::MATRIX_BT601_N
    };
    metadataHelperImpl_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, CM_Matrix::MATRIX_BT601_P);

    // Test colorSpaceInfo.matrix == CM_Matrix::MATRIX_P3
    colorSpaceInfo.matrix = CM_Matrix::MATRIX_P3;
    metadataHelperImpl_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, CM_Matrix::MATRIX_BT601_P);

    // Test colorSpaceInfo.matrix != CM_Matrix::MATRIX_BT601_N
    // && colorSpaceInfo.matrix != CM_Matrix::MATRIX_P3
    colorSpaceInfo.matrix = CM_Matrix::MATRIX_BT709;
    metadataHelperImpl_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, CM_Matrix::MATRIX_BT709);
}

/**
 * @tc.name  : Test ScalePixelMapByMode
 * @tc.number: ScalePixelMapByMode_001
 * @tc.desc  : Test ScalePixelMapByMode scaleMode = default
 */
HWTEST_F(AVMetadataHelperImplUnitTest, ScalePixelMapByMode_001, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    AVMetadataHelperImpl::PixelMapInfo pixelMapInfo;
    PixelMapParams param;
    int32_t scaleMode = INVALID_SCALE_MODE;
    AVMetadataHelperImpl::ScalePixelMapByMode(pixelMap, pixelMapInfo, param, scaleMode);
    EXPECT_EQ(pixelMap, nullptr);
}
} // namespace Media
} // namespace OHOS