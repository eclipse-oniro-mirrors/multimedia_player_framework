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
#include "codec/video/decoder/video_decoder_engine_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDecoderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

class VideoDecodeCallbackTester : public VideoDecodeCallback {
public:
    VideoDecodeCallbackTester() = default;
    virtual ~VideoDecodeCallbackTester() = default;
    void OnDecodeFrame(uint64_t pts) override
    {
        pts_ = pts;
    };
    void OnDecodeResult(VideoDecodeResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    VideoDecodeResult result_ { VideoDecodeResult::FAILED };
};

// Test the constructor of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, construct, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->GetId(), 12345);
    EXPECT_EQ(engine->fd_, 50);
    EXPECT_EQ(engine->cb_.lock(), cb);
}

// Test the Init method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, init_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
}

// Test the SetNativeWindow method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, set_native_window_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->SetNativeWindow(nullptr), VEFError::ERR_OK);
}

// Test the GetVideoFormat method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, get_native_window, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->GetVideoFormat(), nullptr);
}

// Test the StartDecode method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, start_decode_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->StartDecode(), VEFError::ERR_OK);
}

// Test the StopDecode method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, stop_decode_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->StopDecode(), VEFError::ERR_OK);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 100;
    engine->OnDecodeFrame(pts);
    EXPECT_EQ(cb->pts_, pts);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_when_cb_invalid, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 100;
    cb = nullptr;
    engine->OnDecodeFrame(pts);
}

// Test the OnDecodeResult method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_result_ok, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    VideoDecodeResult result = VideoDecodeResult::SUCCESS;
    engine->OnDecodeResult(result);
    EXPECT_EQ(cb->result_, result);
}

// Test the OnDecodeResult method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_result_when_cb_invalid, TestSize.Level0)
{
    auto cb = std::make_shared<VideoDecodeCallbackTester>();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    cb = nullptr;
    VideoDecodeResult result = VideoDecodeResult::SUCCESS;
    engine->OnDecodeResult(result);
}

} // namespace Media
} // namespace OHOS