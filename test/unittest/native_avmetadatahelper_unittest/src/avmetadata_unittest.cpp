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
#include "avmetadata_unittest.h"


namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;
void AVMetadataUnittest::SetUpTestCase(void)
{
}

void AVMetadataUnittest::TearDownTestCase(void)
{
}

void AVMetadataUnittest::SetUp(void)
{
    avmetadataPtr_ = std::make_shared<AVMetadataHelperImpl>();
}

void AVMetadataUnittest::TearDown(void)
{
    avmetadataPtr_ = nullptr;
}

/**
 * @tc.number    : DumpPixelMap_001
 * @tc.name      : DumpPixelMap
 * @tc.desc      : Test pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC
 */
HWTEST_F(AVMetadataUnittest, DumpPixelMap_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    bool isDump = true;
    auto mockPixelMap = std::make_shared<MockPixelMap>();
    EXPECT_CALL(*mockPixelMap, GetWidth()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockPixelMap, GetHeight()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockPixelMap, GetPixelFormat()).WillRepeatedly(Return(PixelFormat::YCBCR_P010));
    EXPECT_CALL(*mockPixelMap, GetAllocatorType()).WillRepeatedly(Return(AllocatorType::DMA_ALLOC));
    EXPECT_CALL(*mockPixelMap, GetFd()).WillRepeatedly(Return(nullptr));
    std::shared_ptr<PixelMap> pixelMap = mockPixelMap;
    std::string fileNameSuffix;
    avmetadataPtr_->DumpPixelMap(isDump, pixelMap, fileNameSuffix);
    EXPECT_NE(avmetadataPtr_, nullptr);
}

/**
 * @tc.number    : DumpAVBuffer_001
 * @tc.name      : DumpAVBuffer
 * @tc.desc      : Test surfaceBuffer == nullptr
 */
HWTEST_F(AVMetadataUnittest, DumpAVBuffer_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    bool isDump = true;
    auto mockBuffer = std::make_shared<MockAVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->meta_ = std::make_shared<Meta>();
    auto mockMemory = std::make_shared<MockAVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    uint8_t* test = nullptr;
    EXPECT_CALL(*mockMemory, GetAddr()).WillRepeatedly(Return(test));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> frameBuffer = mockBuffer;
    std::string fileNameSuffix;
    auto ret = avmetadataPtr_->DumpAVBuffer(isDump, frameBuffer, fileNameSuffix);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number    : DumpAVBuffer_002
 * @tc.name      : DumpAVBuffer
 * @tc.desc      : Test surfaceBuffer != nullptr
 */
HWTEST_F(AVMetadataUnittest, DumpAVBuffer_002, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*(mockSurfaceBuffer), GetSize()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(mockSurfaceBuffer), GetVirAddr()).WillRepeatedly(Return(nullptr));
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    bool isDump = true;
    auto mockBuffer = std::make_shared<MockAVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->meta_ = std::make_shared<Meta>();
    auto mockMemory = std::make_shared<MockAVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    uint8_t* test = nullptr;
    EXPECT_CALL(*mockMemory, GetAddr()).WillRepeatedly(Return(test));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(mockSurfaceBuffer));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> frameBuffer = mockBuffer;
    std::string fileNameSuffix;
    auto ret = avmetadataPtr_->DumpAVBuffer(isDump, frameBuffer, fileNameSuffix);
    EXPECT_NE(mockMemory->GetSurfaceBuffer(), nullptr);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number    : FormatColorSpaceInfo_001
 * @tc.name      : FormatColorSpaceInfo
 * @tc.desc      : Test all
 */
HWTEST_F(AVMetadataUnittest, FormatColorSpaceInfo_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    OHOS::HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo colorSpaceInfo;
    colorSpaceInfo.primaries =
        OHOS::HDI::Display::Graphic::Common::V1_0::CM_ColorPrimaries::COLORPRIMARIES_P3_D65;
    colorSpaceInfo.matrix = OHOS::HDI::Display::Graphic::Common::V1_0::CM_Matrix::MATRIX_BT601_P;
    avmetadataPtr_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, OHOS::HDI::Display::Graphic::Common::V1_0::CM_Matrix::MATRIX_P3);

    colorSpaceInfo.primaries = OHOS::HDI::Display::Graphic::Common::V1_0::CM_ColorPrimaries::COLORPRIMARIES_BT601_P;
    colorSpaceInfo.matrix = OHOS::HDI::Display::Graphic::Common::V1_0::CM_Matrix::MATRIX_BT601_N;
    avmetadataPtr_->FormatColorSpaceInfo(colorSpaceInfo);
    EXPECT_EQ(colorSpaceInfo.matrix, OHOS::HDI::Display::Graphic::Common::V1_0::CM_Matrix::MATRIX_BT601_P);
}

/**
 * @tc.number    : SetPixelMapYuvInfo_001
 * @tc.name      : SetPixelMapYuvInfo
 * @tc.desc      : Test retVal != OHOS::GSERROR_OK || planes == nullptr
 *                 Test surfaceBuffer == nullptr || needModifyStride == false
 */
HWTEST_F(AVMetadataUnittest, SetPixelMapYuvInfo_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    auto mockSurfaceBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*(mockSurfaceBuffer), GetPlanesInfo(_)).WillRepeatedly(Return(GSError::GSERROR_INVALID_ARGUMENTS));
    sptr<SurfaceBuffer> surfaceBuffer(mockSurfaceBuffer);
    auto mockPixelMap = std::make_shared<MockPixelMap>();
    EXPECT_CALL(*mockPixelMap, GetWidth()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockPixelMap, GetHeight()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockPixelMap, SetImageYUVInfo(_)).WillRepeatedly(Return());
    std::shared_ptr<PixelMap> pixelMap = mockPixelMap;
    AVMetadataHelperImpl::PixelMapInfo pixelMapInfo;
    pixelMapInfo.isHdr = true;
    bool needModifyStride = true;
    avmetadataPtr_->SetPixelMapYuvInfo(surfaceBuffer, pixelMap, pixelMapInfo, needModifyStride);
    surfaceBuffer = nullptr;
    avmetadataPtr_->SetPixelMapYuvInfo(surfaceBuffer, pixelMap, pixelMapInfo, needModifyStride);
    EXPECT_EQ(mockPixelMap->GetWidth(), 0);
}

/**
 * @tc.number    : SetHelperCallback_001
 * @tc.name      : SetHelperCallback
 * @tc.desc      : Test all
 */
HWTEST_F(AVMetadataUnittest, SetHelperCallback_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    std::shared_ptr<HelperCallback> callback = nullptr;
    avmetadataPtr_->avMetadataHelperService_ = nullptr;
    auto ret = avmetadataPtr_->SetHelperCallback(callback);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number    : ScalePixelMapByMode_001
 * @tc.name      : ScalePixelMapByMode
 * @tc.desc      : Test all
 */
HWTEST_F(AVMetadataUnittest, ScalePixelMapByMode_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    auto mockPixelMap = std::make_shared<MockPixelMap>();
    EXPECT_CALL(*mockPixelMap, GetWidth()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockPixelMap, GetHeight()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockPixelMap, scale(_, _)).WillRepeatedly(Return());
    std::shared_ptr<PixelMap> pixelMap = mockPixelMap;
    AVMetadataHelperImpl::PixelMapInfo info;
    PixelMapParams param;
    int32_t scaleMode = 0;
    avmetadataPtr_->ScalePixelMapByMode(pixelMap, info, param, scaleMode);
    scaleMode = 1;
    avmetadataPtr_->ScalePixelMapByMode(pixelMap, info, param, scaleMode);
    scaleMode = 2;
    avmetadataPtr_->ScalePixelMapByMode(pixelMap, info, param, scaleMode);
    EXPECT_EQ(mockPixelMap->GetHeight(), 1);
}

/**
 * @tc.number    : CreatePixelMapYuv_001
 * @tc.name      : CreatePixelMapYuv
 * @tc.desc      : Test pixelMapInfo.pixelFormat == PixelFormat::UNKNOWN
 *                 Test frameBuffer->memory_->GetSize() != 0
 *                 && frameBuffer->memory_->GetSurfaceBuffer() == nullptr
 */
HWTEST_F(AVMetadataUnittest, CreatePixelMapYuv_001, TestSize.Level0)
{
    ASSERT_NE(avmetadataPtr_, nullptr);
    auto mockBuffer = std::make_shared<MockAVBuffer>();
    EXPECT_CALL(*mockBuffer, GetUniqueId()).WillRepeatedly(Return(1));
    mockBuffer->meta_ = std::make_shared<Meta>();
    auto mockMemory = std::make_shared<MockAVMemory>();
    EXPECT_CALL(*mockMemory, GetSize()).WillRepeatedly(Return(1));
    EXPECT_CALL(*mockMemory, GetSurfaceBuffer()).WillRepeatedly(Return(nullptr));
    mockBuffer->memory_ = mockMemory;
    std::shared_ptr<AVBuffer> frameBuffer = mockBuffer;
    AVMetadataHelperImpl::PixelMapInfo pixelMapInfo;
    pixelMapInfo.pixelFormat = PixelFormat::UNKNOWN;
    auto ret = avmetadataPtr_->CreatePixelMapYuv(frameBuffer, pixelMapInfo);
    EXPECT_EQ(ret, nullptr);
}
} // namespace Media
} // namespace OHOS
