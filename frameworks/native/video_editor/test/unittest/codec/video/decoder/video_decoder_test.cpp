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
#include "gmock/gmock.h"
#include "codec/video/decoder/video_decoder.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDecodeCallbackTester : public VideoDecodeCallback {
public:
    VideoDecodeCallbackTester() = default;
    virtual ~VideoDecodeCallbackTester() = default;
    void OnDecodeFrame(uint64_t pts) override
    {
        pts_ = pts;
    };
    void OnDecodeResult(CodecResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    CodecResult result_ { CodecResult::FAILED };
};

class VideoDecoderTest : public testing::Test {
protected:
    void SetUp() override
    {
        id_ = 1;
        decoder_ = std::make_shared<VideoDecoder>(id_, cb_, onDecodeFrameCallback_, onDecodeResultCallback_);
    }

    void TearDown() override
    {
    }

    uint64_t id_;
    CodecOnInData cb_;
    std::shared_ptr<VideoDecoder> decoder_;
    CodecOnDecodeFrame onDecodeFrameCallback_;
    CodecOnDecodeResult onDecodeResultCallback_;
};

// test VideoDecoder Start method
HWTEST_F(VideoDecoderTest, VideoDecoder_Start, TestSize.Level0)
{
    EXPECT_EQ(decoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoDecoder Stop method
HWTEST_F(VideoDecoderTest, VideoDecoder_Stop, TestSize.Level0)
{
    EXPECT_EQ(decoder_->Stop(), VEFError::ERR_INTERNAL_ERROR);
}
} // namespace Media
} // namespace OHOS