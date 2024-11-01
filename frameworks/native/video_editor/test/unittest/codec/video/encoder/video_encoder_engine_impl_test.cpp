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
#include "codec/video/encoder/video_encoder_engine_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEncoderEngineImplTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
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
    void OnEncodeResult(CodecResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    CodecResult result_ { CodecResult::FAILED };
};

// Test VideoEncoderEngineImpl constructor
HWTEST_F(VideoEncoderEngineImplTest, construct, TestSize.Level0)
{
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb);
    EXPECT_EQ(engine->GetId(), 20);
}

// Test VideoEncoderEngineImpl Init method
HWTEST_F(VideoEncoderEngineImplTest, init_ok, TestSize.Level0)
{
    VideoEncodeCallbackTester* cb = new VideoEncodeCallbackTester();
    auto engine = std::make_shared<VideoEncoderEngineImpl>(20, cb);
    VideoEncodeParam enCoderParam;
    EXPECT_EQ(engine->Init(enCoderParam), VEFError::ERR_INTERNAL_ERROR);
}

} // namespace Media
} // namespace OHOS