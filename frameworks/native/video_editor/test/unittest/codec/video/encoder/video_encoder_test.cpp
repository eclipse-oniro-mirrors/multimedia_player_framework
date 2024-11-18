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
#include <native_avcodec_videoencoder.h>
#include <native_avcodec_base.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEncoderTest : public testing::Test {
protected:
    void SetUp() override
    {
        std::function cb = [&](OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
            return VEFError::ERR_OK;
        };
        encoder_ = std::make_shared<VideoEncoder>(12, cb); // 12 VideoEncoder构造函数入参id
        codec_ = OH_VideoEncoder_CreateByMime(OH_AVCODEC_MIMETYPE_VIDEO_AVC);
        uint32_t buffersize = 1024 * 1024;
        sampleMem_ = OH_AVMemory_Create(buffersize);
        format_ = OH_AVFormat_Create();
    }

    void TearDown() override
    {
        if (codec_ != nullptr) {
            OH_VideoEncoder_Destroy(codec_);
            codec_ = nullptr;
        }
        if (sampleMem_ != nullptr) {
            OH_AVMemory_Destroy(sampleMem_);
            sampleMem_ = nullptr;
        }
        if (format_ != nullptr) {
            OH_AVFormat_Destroy(format_);
            format_ = nullptr;
        }
    }

private:
    std::shared_ptr<VideoEncoder> encoder_ = nullptr;
    OH_AVCodec* codec_ = nullptr;
    OH_AVMemory* sampleMem_ = nullptr;
    OH_AVFormat* format_ = nullptr;
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

HWTEST_F(VideoEncoderTest, VideoEncoder_CodecOnError, TestSize.Level0)
{
    std::string userData = "audio/mp4a-latm";
    encoder_->CodecOnError(codec_, 0, nullptr);
    encoder_->CodecOnError(nullptr, 0, &userData);
    encoder_->CodecOnError(nullptr, 0, nullptr);
    encoder_->CodecOnError(codec_, 0, &userData);
    EXPECT_EQ(encoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoEncoderTest, VideoEncoder_CodecOnNewOutputData, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    std::string userData = "audio/mp4a-latm";
    encoder_->CodecOnNewOutputData(nullptr, 0, nullptr, nullptr, nullptr);
    encoder_->CodecOnNewOutputData(codec_, 0, nullptr, nullptr, nullptr);
    encoder_->CodecOnNewOutputData(nullptr, 0, nullptr, nullptr, &userData);
    encoder_->CodecOnNewOutputData(codec_, 0, sampleMem_, nullptr, nullptr);
    encoder_->CodecOnNewOutputData(nullptr, 0, sampleMem_, &attr, nullptr);
    encoder_->CodecOnNewOutputData(nullptr, 0, nullptr, &attr, &userData);
    encoder_->CodecOnNewOutputData(codec_, 0, sampleMem_, &attr, nullptr);
    encoder_->CodecOnNewOutputData(nullptr, 0, sampleMem_, &attr, &userData);
    EXPECT_EQ(encoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoEncoderTest, VideoEncoder_CodecOnStreamChanged, TestSize.Level0)
{
    std::string userData = "audio/mp4a-latm";
    encoder_->CodecOnStreamChanged(nullptr, nullptr, nullptr);
    encoder_->CodecOnStreamChanged(codec_, nullptr, nullptr);
    encoder_->CodecOnStreamChanged(nullptr, format_, nullptr);
    encoder_->CodecOnStreamChanged(nullptr, nullptr, &userData);
    encoder_->CodecOnStreamChanged(codec_, format_, nullptr);
    encoder_->CodecOnStreamChanged(nullptr, format_, &userData);
    encoder_->CodecOnStreamChanged(codec_, nullptr, &userData);
    encoder_->CodecOnStreamChanged(codec_, format_, &userData);
    EXPECT_EQ(encoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoEncoderTest, VideoEncoder_WriteFrame, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 0;
    EXPECT_EQ(encoder_->WriteFrame(sampleMem_, &attr), VEFError::ERR_OK);

    std::function encb = [&](OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_INTERNAL_ERROR;
    };
    auto encoder = std::make_shared<VideoEncoder>(12, encb); // 12 VideoEncoder构造函数入参id
    encoder->codecState_ = true;
    EXPECT_EQ(encoder->WriteFrame(sampleMem_, &attr), VEFError::ERR_OK);

    std::function encoderCb = [&](OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_OK;
    };
    auto encoder1 = std::make_shared<VideoEncoder>(12, encoderCb); // 12 VideoEncoder构造函数入参id
    encoder1->codecState_ = true;
    EXPECT_EQ(encoder1->WriteFrame(sampleMem_, &attr), VEFError::ERR_OK);
}
} // namespace Media
} // namespace OHOS