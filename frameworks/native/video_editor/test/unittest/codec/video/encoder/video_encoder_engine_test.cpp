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
#include "media_log.h"
#include "codec/video_encoder_engine.h"
#include "codec/video/encoder/video_encoder_engine_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEncoderEngineTest : public testing::Test {
protected:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

class VideoEncodeCallbackTester : public VideoEncodeCallback {
public:
    VideoEncodeCallbackTester() = default;
    virtual ~VideoEncodeCallbackTester() = default;
    void OnEncodeFrame(uint64_t pts) override
    {
        pts_ = pts;
    };
    void OnEncodeResult(VideoEncodeResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    VideoEncodeResult result_ { VideoEncodeResult::FAILED };
};

// Test when cb is nullptr then Create returns nullptr.
HWTEST_F(VideoEncoderEngineTest, create_when_cb_is_nullptr, TestSize.Level0)
{
    int fd = 1;
    auto videoFormat = OH_AVFormat_Create();
    auto cb = std::make_shared<VideoEncodeCallbackTester>();
    cb.reset();
    auto engine = IVideoEncoderEngine::Create(fd, videoFormat, cb);
    EXPECT_EQ(engine, nullptr);
    OH_AVFormat_Destroy(videoFormat);
}

// Test when videoFormat is nullptr then Create returns nullptr.
HWTEST_F(VideoEncoderEngineTest, create_when_video_format_is_nullptr, TestSize.Level0)
{
    int fd = 1;
    auto cb = std::make_shared<VideoEncodeCallbackTester>();
    std::shared_ptr<IVideoEncoderEngine> engine = IVideoEncoderEngine::Create(fd, nullptr, cb);
    EXPECT_EQ(engine, nullptr);
}

// Test when create endocer engine ok.
HWTEST_F(VideoEncoderEngineTest, create_ok, TestSize.Level0)
{
    int fd = 1;
    auto videoFormat = OH_AVFormat_Create();
    auto cb = std::make_shared<VideoEncodeCallbackTester>();
    std::shared_ptr<IVideoEncoderEngine> engine = IVideoEncoderEngine::Create(fd, videoFormat, cb);
    EXPECT_NE(engine, nullptr);
    OH_AVFormat_Destroy(videoFormat);
}

} // namespace Media
} // namespace OHOS