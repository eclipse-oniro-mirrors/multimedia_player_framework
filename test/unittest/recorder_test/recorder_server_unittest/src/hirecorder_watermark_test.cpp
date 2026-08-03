/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "recorder_server_unit_test.h"
#include "recorder_server_mock.h"
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::RecorderTestParam;

namespace {
std::shared_ptr<AVBuffer> CreateWatermarkBuffer(int32_t width, int32_t height, std::vector<uint8_t> &rawData)
{
    int32_t pixelSize = 4;
    int32_t bufferWidth = (width > 0 && width < INT_MAX / pixelSize / (height > 0 ? height : 1)) ? width : 100;
    int32_t bufferHeight = (height > 0 && height < INT_MAX / pixelSize / bufferWidth) ? height : 50;
    int32_t dataLength = bufferWidth * bufferHeight * pixelSize;
    rawData.resize(dataLength);
    auto buffer = AVBuffer::CreateAVBuffer(rawData.data(), dataLength, dataLength);
    if (buffer != nullptr) {
        buffer->meta_->Set<Tag::VIDEO_COORDINATE_W>(width);
        buffer->meta_->Set<Tag::VIDEO_COORDINATE_H>(height);
        buffer->meta_->Set<Tag::VIDEO_STRIDE>(width * pixelSize);
    }
    return buffer;
}
}

class HiRecorderWatermarkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<RecorderServerMock> recorderServer_;
};

void HiRecorderWatermarkTest::SetUpTestCase() {}

void HiRecorderWatermarkTest::TearDownTestCase() {}

void HiRecorderWatermarkTest::SetUp()
{
    recorderServer_ = std::make_shared<RecorderServerMock>();
    ASSERT_NE(recorderServer_, nullptr);
    ASSERT_TRUE(recorderServer_->CreateRecorder());
}

void HiRecorderWatermarkTest::TearDown()
{
    if (recorderServer_ != nullptr) {
        recorderServer_->Reset();
        recorderServer_->Release();
    }
    recorderServer_ = nullptr;
}

/**
 * @tc.name: hirecorder_AddWatermark_001
 * @tc.desc: AddWatermark with valid buffer for the first time (create filter)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_001, TestSize.Level0)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(150, 75, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 150, 75, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_002
 * @tc.desc: AddWatermark with valid buffer (reuse existing filter)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_002, TestSize.Level0)
{
    std::vector<uint8_t> data1;
    auto watermarkBuffer = CreateWatermarkBuffer(150, 75, data1);
    ASSERT_NE(watermarkBuffer, nullptr);
    int32_t watermarkCount1 = 0;
    ASSERT_EQ(recorderServer_->AddWatermark(watermarkBuffer, 150, 75, watermarkCount1), MSERR_OK);

    std::vector<uint8_t> data2;
    auto watermarkBuffer2 = CreateWatermarkBuffer(180, 90, data2);
    ASSERT_NE(watermarkBuffer2, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer2, 180, 90, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_003
 * @tc.desc: AddWatermark with nullptr buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_003, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> watermarkBuffer = nullptr;

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, 50, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_004
 * @tc.desc: AddWatermark with minimum size (1x1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_004, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(1, 1, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 1, 1, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_005
 * @tc.desc: AddWatermark with width = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_005, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(0, 50, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 0, 50, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_006
 * @tc.desc: AddWatermark with height = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_006, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(100, 0, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, 0, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_007
 * @tc.desc: AddWatermark with negative width
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_007, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(-1, 50, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, -1, 50, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);

}

/**
 * @tc.name: hirecorder_AddWatermark_008
 * @tc.desc: AddWatermark with negative height
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_008, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(100, -1, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, -1, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_009
 * @tc.desc: AddWatermark with width and height both 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_009, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(0, 0, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 0, 0, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_010
 * @tc.desc: AddWatermark with width and height both -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_010, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(-1, -1, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, -1, -1, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);

}

/**
 * @tc.name: hirecorder_AddWatermark_011
 * @tc.desc: AddWatermark with nullptr buffer and zero dimensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_011, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> watermarkBuffer = nullptr;

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 0, 0, watermarkCount);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_012
 * @tc.desc: AddWatermark with INT_MAX width
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_012, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(INT_MAX, 50, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, INT_MAX, 50, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_013
 * @tc.desc: AddWatermark with INT_MAX height
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_013, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(100, INT_MAX, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, INT_MAX, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_014
 * @tc.desc: AddWatermark with INT_MIN width
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_014, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(INT_MIN, 50, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, INT_MIN, 50, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_015
 * @tc.desc: AddWatermark with INT_MIN height
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_015, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(100, INT_MIN, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, INT_MIN, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_016
 * @tc.desc: AddWatermark with width and height both INT_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_016, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(INT_MAX, INT_MAX, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, INT_MAX, INT_MAX, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_017
 * @tc.desc: AddWatermark with width = 0, height = -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_017, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(0, -1, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 0, -1, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_018
 * @tc.desc: AddWatermark with width = -1, height = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_018, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(-1, 0, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, -1, 0, watermarkCount);

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_019
 * @tc.desc: AddWatermark with boundary value width = 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_019, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(2, 50, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 2, 50, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: hirecorder_AddWatermark_020
 * @tc.desc: AddWatermark with boundary value height = 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HiRecorderWatermarkTest, hirecorder_AddWatermark_020, TestSize.Level2)
{
    std::vector<uint8_t> data;
    auto watermarkBuffer = CreateWatermarkBuffer(100, 2, data);
    ASSERT_NE(watermarkBuffer, nullptr);

    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(watermarkBuffer, 100, 2, watermarkCount);

    EXPECT_EQ(ret, MSERR_OK);
}
