/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "codec/video/encoder/video_encoder.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEncoderTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test VideoEncoder Start method
HWTEST_F(VideoEncoderTest, VideoEncoder_Start, TestSize.Level0)
{
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoEncoder Stop method
HWTEST_F(VideoEncoderTest, VideoEncoder_Stop, TestSize.Level0)
{
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(videoEncoder.Stop(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoEncoder Finish method
HWTEST_F(VideoEncoderTest, VideoEncoder_Flush, TestSize.Level0)
{
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(videoEncoder.Flush(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoEncoder SendEOF method
HWTEST_F(VideoEncoderTest, VideoEncoder_SendEOF, TestSize.Level0)
{
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoEncoder ConfigureEncoder method
HWTEST_F(VideoEncoderTest, VideoEncoder_ConfigureEncoder, TestSize.Level0)
{
    OH_AVFormat* format = OH_AVFormat_Create();
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(videoEncoder.ConfigureEncoder(format), VEFError::ERR_INTERNAL_ERROR);
    OH_AVFormat_Destroy(format);
}

// test VideoEncoder CreateEncoder method
HWTEST_F(VideoEncoderTest, VideoEncoder_CreateEncoder, TestSize.Level0)
{
    OH_AVFormat* format = OH_AVFormat_Create();
    VideoEncoder videoEncoder(1, nullptr);
    EXPECT_EQ(videoEncoder.Start(), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(videoEncoder.CreateEncoder(format), VEFError::ERR_INTERNAL_ERROR);
    OH_AVFormat_Destroy(format);
}
} // namespace Media
} // namespace OHOS