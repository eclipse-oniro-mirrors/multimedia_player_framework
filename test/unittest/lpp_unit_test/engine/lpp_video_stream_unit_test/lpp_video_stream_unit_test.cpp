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
#include "lpp_video_stream_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppVideoStreamUnitTest::SetUpTestCase(void)
{
}

void LppVideoStreamUnitTest::TearDownTestCase(void)
{
}

void LppVideoStreamUnitTest::SetUp(void)
{
    videoStreamImpl_ = std::make_shared<HiLppVideoStreamerImpl>();
    streamerId_ = videoStreamImpl_->streamerId_;
    vdec_ = std::make_shared<LppVideoDecoderAdapter>(streamerId_, videoStreamImpl_->isLpp_);
    dataMgr_ = std::make_shared<LppVideoDataManager>(streamerId_, videoStreamImpl_->isLpp_);
    syncMgr_ = std::make_shared<LppSyncManager>(streamerId_, videoStreamImpl_->isLpp_);
}

void LppVideoStreamUnitTest::TearDown(void)
{
    videoStreamImpl_ = nullptr;
    dataMgr_ = nullptr;
    vdec_ = nullptr;
    syncMgr_ = nullptr;
}

/**
* @tc.name    : Test SetVideoSurface API
* @tc.number  : SetVideoSurface_001
* @tc.desc    : Test SetVideoSurface interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, SetVideoSurface_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = true;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, SetVideoSurface(_)).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    EXPECT_CALL(*syncMgr_, SetTunnelId(_)).WillRepeatedly(Return(MSERR_INVALID_VAL));
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->isLpp_ = isLpp;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    auto res = videoStreamImpl_->SetVideoSurface(surface);
    EXPECT_EQ(res, MSERR_INVALID_VAL);
}

/**
* @tc.name    : Test SetVideoSurface API
* @tc.number  : SetVideoSurface_002
* @tc.desc    : Test SetVideoSurface interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, SetVideoSurface_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = false;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, SetVideoSurface(_)).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    auto res = videoStreamImpl_->SetVideoSurface(surface);
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_001
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartDecode_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = true;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->isChannelSetDone_ = true;
    auto res = videoStreamImpl_->StartDecode();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_002
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartDecode_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = false;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, SetChannelIdDone).WillRepeatedly(Return());
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->isChannelSetDone_ = true;
    auto res = videoStreamImpl_->StartDecode();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_001
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartRender_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = true;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, GetShareBuffer(_)).WillRepeatedly(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    auto res = videoStreamImpl_->StartRender();
    EXPECT_EQ(res, MSERR_UNKNOWN);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_002
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartRender_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = false;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, StartRender).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Stop()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, GetShareBuffer(_)).WillRepeatedly(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*syncMgr_, StartRender).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*syncMgr_, Stop()).WillOnce(Return(MSERR_OK));
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->surface_ = Surface::CreateSurfaceAsConsumer();
    auto res = videoStreamImpl_->StartRender();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test OnEvent API
* @tc.number  : OnEvent_001
* @tc.desc    : Test OnEvent interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, OnEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_DATA_NEEDED, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_FIRST_FRAME_READY, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_VIDEO_RENDERING_START, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_COMPLETE, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_RESOLUTION_CHANGE, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_BUFFERING, ""});
    EXPECT_EQ(videoStreamImpl_->callbackLooper_, nullptr);
}
} // namespace Media
} // namespace OHOS
