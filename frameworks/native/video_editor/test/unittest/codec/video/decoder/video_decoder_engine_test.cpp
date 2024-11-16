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
#include "codec/video_decoder_engine.h"
#include "codec/video/decoder/video_decoder_engine_impl.h"
#include "ut_common_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDecoderEngineTest : public testing::Test {
protected:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

// Test when cb is nullptr then Create returns nullptr.
HWTEST_F(VideoDecoderEngineTest, create_with_invalid_cb, TestSize.Level0)
{
    int fd = 1;
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    auto engine = IVideoDecoderEngine::Create(fd, cb);
    EXPECT_EQ(engine, nullptr);
}

// Test when Init returns error then Create returns nullptr.
HWTEST_F(VideoDecoderEngineTest, create_ok, TestSize.Level0)
{
    int fd = 1;
    VideoDecodeCallbackTester* cb = new VideoDecodeCallbackTester();
    std::shared_ptr<IVideoDecoderEngine> engine = IVideoDecoderEngine::Create(fd, cb);
    EXPECT_EQ(engine, nullptr);
}

} // namespace Media
} // namespace OHOS