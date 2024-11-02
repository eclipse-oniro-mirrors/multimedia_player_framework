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
#include "codec/video/encoder/video_muxer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoMuxerTest : public testing::Test {
protected:
    void SetUp() override
    {
        muxer_ = new VideoMuxer(1);
    }

    void TearDown() override
    {
        if (muxer_ != nullptr) {
            delete muxer_;
        }
        muxer_ = nullptr;
    }

    VideoMuxer* muxer_;
};

// test VideoMuxer Start method
HWTEST_F(VideoMuxerTest, VideoMuxer_Start, TestSize.Level0)
{
    EXPECT_EQ(muxer_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoMuxer Stop method
HWTEST_F(VideoMuxerTest, VideoMuxer_Stop, TestSize.Level0)
{
    EXPECT_EQ(muxer_->Stop(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoMuxer AddVideoTrack method
HWTEST_F(VideoMuxerTest, VideoMuxer_AddVideoTrack, TestSize.Level0)
{
    EXPECT_EQ(muxer_->AddVideoTrack(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoMuxer AddAudioTrack method
HWTEST_F(VideoMuxerTest, VideoMuxer_AddAudioTrack, TestSize.Level0)
{
    EXPECT_EQ(muxer_->AddAudioTrack(nullptr), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoMuxer WriteAudioData method
HWTEST_F(VideoMuxerTest, WriteAudioData, TestSize.Level0)
{
    OH_AVMemory* data =OH_AVMemory_Create(12);
    EXPECT_EQ(muxer_->WriteAudioData(data, nullptr), VEFError::ERR_INTERNAL_ERROR);
    OH_AVMemory_Destroy(data);
}
} // namespace Media
} // namespace OHOS