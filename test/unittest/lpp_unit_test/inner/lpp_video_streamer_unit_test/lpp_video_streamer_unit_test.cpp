/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <vector>
#include "lpp_video_streamer_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void VideoStreamerUnitTest::SetUpTestCase(void)
{}

void VideoStreamerUnitTest::TearDownTestCase(void)
{}

void VideoStreamerUnitTest::SetUp(void)
{}

void VideoStreamerUnitTest::TearDown(void)
{}

/**
 * @tc.name  : VideoCreateByMime
 * @tc.number: VideoCreateByMime
 * @tc.desc  : FUNC
 */
HWTEST_F(VideoStreamerUnitTest, VideoCreateByMime_001, TestSize.Level1)
{
    std::string invalidMime = "invalid";
    std::shared_ptr<VideoStreamer> invalidVideoPlayer = VideoStreamerFactory::CreateByMime(invalidMime);
    EXPECT_EQ(invalidVideoPlayer, nullptr);

    std::string validMime = "video/avc";
    VideoStreamerFactory::GetLppCapacity();
    std::shared_ptr<VideoStreamer> validVideoPlayer = VideoStreamerFactory::CreateByMime(validMime);
    EXPECT_NE(validVideoPlayer, nullptr);
}
}  // namespace Media
}  // namespace OHOS
