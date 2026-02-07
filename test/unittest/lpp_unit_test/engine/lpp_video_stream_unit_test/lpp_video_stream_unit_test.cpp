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
    callbackLooper_ = std::make_shared<LppVideoCallbackLooper>(streamerId_);
}

void LppVideoStreamUnitTest::TearDown(void)
{
    videoStreamImpl_->vdec_ = nullptr;
    videoStreamImpl_->dataMgr_ = nullptr;
    videoStreamImpl_->syncMgr_ = nullptr;
    videoStreamImpl_->callbackLooper_ = nullptr;
    videoStreamImpl_ = nullptr;
    dataMgr_ = nullptr;
    vdec_ = nullptr;
    syncMgr_ = nullptr;
    callbackLooper_ = nullptr;
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    EXPECT_CALL(*syncMgr_, SetTunnelId(_)).WillRepeatedly(Return(MSERR_INVALID_VAL));
    videoStreamImpl_->isLpp_ = isLpp;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    auto res = videoStreamImpl_->SetVideoSurface(surface);
    EXPECT_EQ(res, MSERR_INVALID_VAL);
    videoStreamImpl_->SetVideoSurface(surface);
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->isChannelSetDone_ = true;
    auto res = videoStreamImpl_->StartDecode();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_003
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartDecode_003, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = true;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->isChannelSetDone_ = false;
    auto res = videoStreamImpl_->StartDecode();
    EXPECT_EQ(res, MSERR_OK);
}
 
/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_004
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, StartDecode_004, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    bool isLpp = false;
    ASSERT_NE(nullptr, vdec_);
    EXPECT_CALL(*vdec_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, SetChannelIdDone).WillRepeatedly(Return());
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    EXPECT_CALL(*dataMgr_, StartDecode).WillRepeatedly(Return(MSERR_OK));
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->isChannelSetDone_ = false;
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, GetShareBuffer(_)).WillRepeatedly(Return(MSERR_UNKNOWN));
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
    videoStreamImpl_->vdec_ = vdec_;
    ASSERT_NE(nullptr, dataMgr_);
    videoStreamImpl_->dataMgr_ = dataMgr_;
    ASSERT_NE(nullptr, syncMgr_);
    EXPECT_CALL(*syncMgr_, GetShareBuffer(_)).WillRepeatedly(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*syncMgr_, StartRender).WillRepeatedly(Return(MSERR_OK));
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
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_VIDEO_TARGET_ARRIVED, ""});
    videoStreamImpl_->OnEvent({"VideoSource", EventType::EVENT_ERROR, ""});
    EXPECT_EQ(videoStreamImpl_->callbackLooper_, nullptr);
}


/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_001
 * @tc.desc    : Test Prepare interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Prepare_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);

    auto mockEngine = std::make_shared<MockILppAudioStreamerEngine>();
    videoStreamImpl_->audioStreamerEngine_ = std::weak_ptr<ILppAudioStreamerEngine>(mockEngine);
    bool isLpp = true;
    videoStreamImpl_->isLpp_ = isLpp;
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*vdec_, SetEventReceiver(_)).WillOnce(Return());
    EXPECT_CALL(*dataMgr_, SetEventReceiver(_)).WillOnce(Return());
    EXPECT_CALL(*syncMgr_, SetEventReceiver(_)).WillOnce(Return());
    EXPECT_CALL(*vdec_, Prepare()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*dataMgr_, Prepare()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*syncMgr_, Prepare()).WillOnce(Return(MSERR_OK));

    auto mockProducer = std::make_shared<MockAVBufferQueueProducer>();
    auto producer = OHOS::sptr<AVBufferQueueProducer>(mockProducer.get());
    EXPECT_CALL(*vdec_, GetInputBufferQueue()).WillOnce(Return(OHOS::sptr<Media::AVBufferQueueProducer>(producer)));
    EXPECT_CALL(*dataMgr_, SetDecoderInputProducer(OHOS::sptr<Media::AVBufferQueueProducer>(producer)))
        .WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Prepare();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_002
 * @tc.desc    : Test Prepare interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Prepare_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    auto mockEngine = std::make_shared<MockILppAudioStreamerEngine>();
    videoStreamImpl_->audioStreamerEngine_ = std::weak_ptr<ILppAudioStreamerEngine>(mockEngine);

    bool isLpp = true;
    videoStreamImpl_->isLpp_ = isLpp;

    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;

    EXPECT_CALL(*vdec_, Prepare()).Times(0);
    EXPECT_CALL(*dataMgr_, Prepare()).Times(0);
    EXPECT_CALL(*syncMgr_, Prepare()).Times(0);

    auto ret = videoStreamImpl_->Prepare();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test RenderFirstFrame API
 * @tc.number  : RenderFirstFrame_001
 * @tc.desc    : Test RenderFirstFrame interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, RenderFirstFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;

    EXPECT_CALL(*vdec_, RenderFirstFrame()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->RenderFirstFrame();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test RenderFirstFrame API
 * @tc.number  : RenderFirstFrame_002
 * @tc.desc    : Test RenderFirstFrame interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, RenderFirstFrame_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;

    EXPECT_CALL(*vdec_, RenderFirstFrame()).WillOnce(Return(MSERR_INVALID_VAL));

    auto ret = videoStreamImpl_->RenderFirstFrame();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Pause API
 * @tc.number  : Pause_001
 * @tc.desc    : Test Pause interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Pause_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*dataMgr_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Pause()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Pause API
 * @tc.number  : Pause_002
 * @tc.desc    : Test Pause interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Pause_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, Pause()).WillOnce(Return(MSERR_INVALID_VAL));
    EXPECT_CALL(*dataMgr_, Pause()).Times(0);
    EXPECT_CALL(*vdec_, Pause()).Times(0);

    auto ret = videoStreamImpl_->Pause();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Resume API
 * @tc.number  : Resume_001
 * @tc.desc    : Test Resume interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Resume_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, Resume()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Resume()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*dataMgr_, Resume()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Resume();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Resume API
 * @tc.number  : Resume_002
 * @tc.desc    : Test Resume interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Resume_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, Resume()).WillOnce(Return(MSERR_INVALID_VAL));
    EXPECT_CALL(*vdec_, Resume()).Times(0);
    EXPECT_CALL(*dataMgr_, Resume()).Times(0);

    auto ret = videoStreamImpl_->Resume();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Flush API
 * @tc.number  : Flush_001
 * @tc.desc    : Test Flush interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Flush_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*dataMgr_, Flush()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Flush()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*syncMgr_, Flush()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Flush();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Flush API
 * @tc.number  : Flush_002
 * @tc.desc    : Test Flush interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Flush_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = nullptr;

    EXPECT_CALL(*dataMgr_, Flush()).Times(0);
    EXPECT_CALL(*vdec_, Flush()).Times(0);
    EXPECT_CALL(*syncMgr_, Flush()).Times(0);

    auto ret = videoStreamImpl_->Flush();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Reset API
 * @tc.number  : Reset_001
 * @tc.desc    : Test Reset interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Reset_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;
    videoStreamImpl_->surface_ = Surface::CreateSurfaceAsConsumer();
    videoStreamImpl_->shareBufferFd_ = 1;

    EXPECT_CALL(*syncMgr_, Reset()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Release()).WillRepeatedly(Return(MSERR_OK));  // WillRepeatedly
    EXPECT_CALL(*dataMgr_, Reset()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Reset();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Reset API
 * @tc.number  : Reset_002
 * @tc.desc    : Test Reset interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Reset_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = nullptr;

    EXPECT_CALL(*syncMgr_, Reset()).Times(0);
    EXPECT_CALL(*vdec_, Release()).Times(0);
    EXPECT_CALL(*dataMgr_, Reset()).Times(0);

    auto ret = videoStreamImpl_->Reset();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test SetPlaybackSpeed API
 * @tc.number  : SetPlaybackSpeed_001
 * @tc.desc    : Test SetPlaybackSpeed interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetPlaybackSpeed_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, SetPlaybackSpeed(1.0f)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, SetPlaybackSpeed(1.0f)).Times(1);

    auto ret = videoStreamImpl_->SetPlaybackSpeed(1.0f);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test SetPlaybackSpeed API
 * @tc.number  : SetPlaybackSpeed_002
 * @tc.desc    : Test SetPlaybackSpeed interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetPlaybackSpeed_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, SetPlaybackSpeed(-1.0f)).WillOnce(Return(MSERR_INVALID_VAL));
    EXPECT_CALL(*vdec_, SetPlaybackSpeed(-1.0f)).Times(0);

    auto ret = videoStreamImpl_->SetPlaybackSpeed(-1.0f);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test SetSyncAudioStreamer API
 * @tc.number  : SetSyncAudioStreamer_001
 * @tc.desc    : Test SetSyncAudioStreamer interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetSyncAudioStreamer_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);

    auto ret = videoStreamImpl_->SetSyncAudioStreamer(123);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test SetTargetStartFrame API
 * @tc.number  : SetTargetStartFrame_001
 * @tc.desc    : Test SetTargetStartFrame interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetTargetStartFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*vdec_, SetTargetPts(1000)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*syncMgr_, SetTargetStartFrame(1000, 500)).Times(1);

    auto ret = videoStreamImpl_->SetTargetStartFrame(1000, 500);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test SetTargetStartFrame API
 * @tc.number  : SetTargetStartFrame_002
 * @tc.desc    : Test SetTargetStartFrame interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetTargetStartFrame_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*vdec_, SetTargetPts(-1000)).WillOnce(Return(MSERR_INVALID_VAL));
    EXPECT_CALL(*syncMgr_, SetTargetStartFrame(-1000, 500)).Times(0);

    auto ret = videoStreamImpl_->SetTargetStartFrame(-1000, 500);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test GetStreamerId API
 * @tc.number  : GetStreamerId_001
 * @tc.desc    : Test GetStreamerId interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, GetStreamerId_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    EXPECT_CALL(lppEngineManager, AddLppVideoInstance(_, _)).WillOnce(Return());
    std::string streamerId = videoStreamImpl_->GetStreamerId();
    EXPECT_NE(streamerId.find("LppV_"), std::string::npos);
}

/**
 * @tc.name    : Test SetParameter API
 * @tc.number  : SetParameter_001
 * @tc.desc    : Test SetParameter interface with valid parameters
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetParameter_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;

    Format params;
    params.PutIntValue("width", 1920);
    EXPECT_CALL(*vdec_, SetParameter(_)).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->SetParameter(params);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Configure API
 * @tc.number  : Configure_001
 * @tc.desc    : Test Configure interface with valid parameters
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, Configure_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    Format params;
    params.PutIntValue("width", 1920);

    EXPECT_CALL(*vdec_, Configure(_)).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->Configure(params);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test GetLppSyncManager API
 * @tc.number  : GetLppSyncManager_001
 * @tc.desc    : Test GetLppSyncManager interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, GetLppSyncManager_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->syncMgr_ = syncMgr_;
    auto syncMgr = videoStreamImpl_->GetLppSyncManager();

    EXPECT_NE(nullptr, syncMgr);
    EXPECT_EQ(syncMgr, videoStreamImpl_->syncMgr_);
}

/**
 * @tc.name    : Test HandleDataNeededEvent API
 * @tc.number  : HandleDataNeededEvent_001
 * @tc.desc    : Test HandleDataNeededEvent interface with valid event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleDataNeededEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;

    Event event{"VideoSource", EventType::EVENT_DATA_NEEDED, ""};
    event.param = std::pair<int64_t, int64_t>(1024, 10);
    EXPECT_CALL(*callbackLooper_, OnDataNeeded(_, _)).Times(1);

    videoStreamImpl_->HandleDataNeededEvent(event);
}

/**
 * @tc.name    : Test HandleFirstFrameReadyEvent API
 * @tc.number  : HandleFirstFrameReadyEvent_001
 * @tc.desc    : Test HandleFirstFrameReadyEvent interface with valid event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleFirstFrameReadyEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;

    Event event{"VideoSource", EventType::EVENT_FIRST_FRAME_READY, ""};
    EXPECT_CALL(*callbackLooper_, OnFirstFrameReady()).Times(1);

    videoStreamImpl_->HandleFirstFrameReadyEvent(event);
}

/**
 * @tc.name    : Test HandleRenderStartedEvent API
 * @tc.number  : HandleRenderStartedEvent_001
 * @tc.desc    : Test HandleRenderStartedEvent interface with valid event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleRenderStartedEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;

    Event event{"VideoSource", EventType::EVENT_VIDEO_RENDERING_START, ""};
    EXPECT_CALL(*callbackLooper_, OnRenderStarted()).Times(1);

    videoStreamImpl_->HandleRenderStartedEvent(event);
}

/**
 * @tc.name    : Test HandleCompleteEvent API
 * @tc.number  : HandleCompleteEvent_001
 * @tc.desc    : Test HandleCompleteEvent interface with valid event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleCompleteEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    Event event{"VideoSource", EventType::EVENT_COMPLETE, ""};

    EXPECT_CALL(*syncMgr_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*dataMgr_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*callbackLooper_, OnEos()).Times(1);

    videoStreamImpl_->HandleCompleteEvent(event);
}

/**
 * @tc.name    : Test HandleResolutionChangeEvent API
 * @tc.number  : HandleResolutionChangeEvent_001
 * @tc.desc    : Test HandleResolutionChangeEvent interface with valid event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleResolutionChangeEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;

    Event event;
    Format format;
    format.PutIntValue("width", 1920);
    event.param = format;

    EXPECT_CALL(*callbackLooper_, OnStreamChanged(_)).Times(1);

    videoStreamImpl_->HandleResolutionChangeEvent(event);
}

/**
 * @tc.name    : Test SetObs API
 * @tc.number  : SetObs_001
 * @tc.desc    : Test SetObs interface with valid obs
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetObs_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;
    std::weak_ptr<ILppVideoStreamerEngineObs> obs;
    EXPECT_CALL(*callbackLooper_, StartWithLppVideoStreamerEngineObs(_)).Times(1);
    videoStreamImpl_->SetObs(obs);
}

/**
 * @tc.name    : Test SetLppAudioStreamerId API
 * @tc.number  : SetLppAudioStreamerId_001
 * @tc.desc    : Test SetLppAudioStreamerId interface with valid audioStreamerId
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, SetLppAudioStreamerId_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    std::string audioStreamerId = "";
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    EXPECT_CALL(lppEngineManager, GetLppAudioInstance(StrEq(""))).WillOnce(Return(nullptr));
    auto ret = videoStreamImpl_->SetLppAudioStreamerId(audioStreamerId);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test HandleErrorEvent API
 * @tc.number  : HandleErrorEvent_001
 * @tc.desc    : Test HandleErrorEvent interface with valid error event
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, HandleErrorEvent_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->callbackLooper_ = callbackLooper_;

    Event event;
    event.param = std::pair<MediaServiceErrCode, std::string>(MSERR_INVALID_OPERATION, "invaid opreation");

    EXPECT_CALL(*callbackLooper_, OnError(_, _)).Times(1);

    videoStreamImpl_->HandleErrorEvent(event);
}

/**
 * @tc.name    : Test EosPause API
 * @tc.number  : EosPause_001
 * @tc.desc    : Test EosPause interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoStreamUnitTest, EosPause_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->vdec_ = vdec_;
    videoStreamImpl_->dataMgr_ = dataMgr_;
    videoStreamImpl_->syncMgr_ = syncMgr_;

    EXPECT_CALL(*syncMgr_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*vdec_, Pause()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*dataMgr_, Pause()).WillOnce(Return(MSERR_OK));

    auto ret = videoStreamImpl_->EosPause();

    EXPECT_EQ(ret, MSERR_OK);
}

/**
* @tc.name    : Test GetLatestPts API
* @tc.number  : GetLatestPts_001
* @tc.desc    : Test GetLatestPts interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, GetLatestPts_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->isLpp_ = true;
    videoStreamImpl_->syncMgr_ = syncMgr_;
    EXPECT_CALL(*syncMgr_, GetLatestPts(_)).WillOnce(Return(MSERR_OK));
    int64_t pts = 0;
    auto res = videoStreamImpl_->GetLatestPts(pts);
    EXPECT_EQ(res, MSERR_OK);
}
 
/**
* @tc.name    : Test GetLatestPts API
* @tc.number  : GetLatestPts_002
* @tc.desc    : Test GetLatestPts interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoStreamUnitTest, GetLatestPts_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoStreamImpl_);
    videoStreamImpl_->isLpp_ = false;
    videoStreamImpl_->vdec_ = vdec_;
    EXPECT_CALL(*vdec_, GetLastCommonPts()).WillOnce(Return(MSERR_OK));
 
    int64_t pts = 0;
    auto res = videoStreamImpl_->GetLatestPts(pts);
    EXPECT_EQ(res, MSERR_OK);
}
} // namespace Media
} // namespace OHOS
