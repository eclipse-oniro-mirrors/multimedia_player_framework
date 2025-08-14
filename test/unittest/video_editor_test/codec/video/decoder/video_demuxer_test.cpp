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
#include "codec/video/decoder/video_demuxer.h"
#include "ut_common_data.h"
#include <fcntl.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoDemuxerTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test VideoDemuxer Init method
HWTEST_F(VideoDemuxerTest, VideoDemuxer_Init_001, TestSize.Level0)
{
    VideoDeMuxer videoDeMuxer(1, 1);
    EXPECT_EQ(videoDeMuxer.Init(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(VideoDemuxerTest, VideoDemuxer_Init_ok, TestSize.Level0)
{
    std::string fileName = "H264_AAC.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDeMuxer videoDeMuxer(1, srcFd);
    EXPECT_EQ(videoDeMuxer.Init(), VEFError::ERR_OK);
    (void)close(srcFd);
}

// test VideoDemuxer ParseTrackInfo method
HWTEST_F(VideoDemuxerTest, VideoDemuxer_ParseTrackInfo_002, TestSize.Level0)
{
    VideoDeMuxer videoDeMuxer(1, 1);
    EXPECT_EQ(videoDeMuxer.ParseTrackInfo(), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoDemuxer ReadVideoData method
HWTEST_F(VideoDemuxerTest, VideoDemuxer_ReadVideoData_003, TestSize.Level0)
{
    VideoDeMuxer videoDeMuxer(1, 1);
    EXPECT_EQ(videoDeMuxer.ReadVideoData(nullptr, nullptr), VEFError::ERR_INTERNAL_ERROR);
}

// test VideoDemuxer ReadAudioData method
HWTEST_F(VideoDemuxerTest, VideoDemuxer_ReadAudioData_004, TestSize.Level0)
{
    VideoDeMuxer videoDeMuxer(1, 1);
    EXPECT_EQ(videoDeMuxer.ReadAudioData(nullptr, nullptr), VEFError::ERR_INTERNAL_ERROR);
}
} // namespace Media
} // namespace OHOS