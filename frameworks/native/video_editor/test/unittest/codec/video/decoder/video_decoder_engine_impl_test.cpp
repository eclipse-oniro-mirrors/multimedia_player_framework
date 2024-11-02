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
#include "codec/video/decoder/video_decoder_engine_impl.h"

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

class VideoDecoderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// Test the constructor of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, construct, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->GetId(), 12345);
    EXPECT_EQ(engine->fd_, 50);
    EXPECT_EQ(engine->cb_, cb);
}

// Test the Init method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, init_ok, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_INTERNAL_ERROR);
}

/**
 * @tc.name  : VideoDecoderEngineImpl_001
 * @tc.number: VideoDecoderEngineImpl_001
 * @tc.desc  : Test when InitDeMuxer failed with error then return error
 */
HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_001, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_INTERNAL_ERROR);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_ok, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 0;
    EXPECT_EQ(cb->pts_, pts);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_when_cb_invalid, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 100;
    cb = nullptr;
}
} // namespace Media
} // namespace OHOS