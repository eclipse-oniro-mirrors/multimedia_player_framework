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
#include <fcntl.h>
#include "ut_common_data.h"

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
HWTEST_F(VideoDecoderEngineImplTest, init_error, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDecoderEngineImplTest, init_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    (void)close(srcFd);
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

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_initDeMuxer_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->InitDeMuxer(), VEFError::ERR_OK);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, VideoDecoderEngineImpl_StopDecode_error, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, 1, cb);
    EXPECT_EQ(engine->StopDecode(), VEFError::ERR_INTERNAL_ERROR);
}

// Test the OnDecodeFrame method of VideoDecoderEngineImpl
HWTEST_F(VideoDecoderEngineImplTest, on_decode_frame_ok, TestSize.Level0)
{
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(12345, 50, cb);
    uint64_t pts = 0;
    EXPECT_EQ(cb->pts_, pts);
}

HWTEST_F(VideoDecoderEngineImplTest, OnAudioDecodeResult_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    CodecResult failResult = CodecResult::FAILED;
    CodecResult cancelResult = CodecResult::CANCELED;
    engine->OnAudioDecodeResult(sucResult);
    engine->OnAudioDecodeResult(failResult);
    engine->OnAudioDecodeResult(cancelResult);
    EXPECT_EQ(cb->result_, cancelResult);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, OnVideoDecodeResult_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    CodecResult failResult = CodecResult::FAILED;
    CodecResult cancelResult = CodecResult::CANCELED;
    engine->OnVideoDecodeResult(sucResult);
    engine->OnVideoDecodeResult(failResult);
    engine->OnVideoDecodeResult(cancelResult);
    EXPECT_EQ(cb->result_, cancelResult);
    engine->OnVideoDecoderFrame(80);
    EXPECT_EQ(cb->pts_, 80);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, OnVideoDecodeResult_success, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    CodecResult sucResult = CodecResult::SUCCESS;
    engine->OnVideoDecodeResult(sucResult);
    engine->OnAudioDecodeResult(sucResult);
    EXPECT_EQ(cb->result_, sucResult);
    (void)close(srcFd);
}

HWTEST_F(VideoDecoderEngineImplTest, GetVideoDuration_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = std::make_shared<VideoDecoderEngineImpl>(1, srcFd, cb);
    EXPECT_EQ(engine->Init(), VEFError::ERR_OK);
    EXPECT_EQ(engine->GetVideoDuration(), 10034000);
    (void)close(srcFd);
}
} // namespace Media
} // namespace OHOS