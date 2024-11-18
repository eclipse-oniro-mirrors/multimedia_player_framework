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
#include "ut_common_data.h"
#include <native_avcodec_base.h>

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
HWTEST_F(VideoMuxerTest, VideoMuxer_WriteAudioData, TestSize.Level0)
{
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* data =OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(muxer_->WriteAudioData(nullptr, nullptr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(muxer_->WriteAudioData(data, nullptr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(muxer_->WriteAudioData(nullptr, &attr), VEFError::ERR_INTERNAL_ERROR);
    EXPECT_EQ(muxer_->WriteAudioData(data, &attr), VEFError::ERR_INTERNAL_ERROR);
    OH_AVMemory_Destroy(data);
}

HWTEST_F(VideoMuxerTest, VideoMuxer_WriteVideoData, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoMuxerParam muxerParam;
    muxerParam.targetFileFd = srcFd;
    EXPECT_EQ(muxer_->Init(muxerParam), VEFError::ERR_OK);
    uint32_t buffersize = 1024 * 1024;
    OH_AVMemory* data =OH_AVMemory_Create(buffersize);
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(muxer_->WriteVideoData(data, &attr), VEFError::ERR_OK);

    OH_AVCodecBufferAttr attr1;
    attr1.size = 1024 * 1024;
    attr1.pts = 100;
    attr1.flags = 1;
    EXPECT_EQ(muxer_->WriteAudioData(data, &attr1), VEFError::ERR_INTERNAL_ERROR);
    OH_AVMemory_Destroy(data);
}
} // namespace Media
} // namespace OHOS