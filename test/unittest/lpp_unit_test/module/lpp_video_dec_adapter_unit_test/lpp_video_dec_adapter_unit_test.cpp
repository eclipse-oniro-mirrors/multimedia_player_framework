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
#include "lpp_video_dec_adapter_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppVideoDecAdapterUnitTest::SetUpTestCase(void)
{
}

void LppVideoDecAdapterUnitTest::TearDownTestCase(void)
{
}

void LppVideoDecAdapterUnitTest::SetUp(void)
{
    videoDecAdapter_ = std::make_shared<LppVideoDecoderAdapter>(streamerId_, isLpp_);
    videoDecoder_ = std::make_shared<MediaAVCodec::AVCodecVideoDecoder>();
    inputBufferQueueConsumer_ = sptr<MockAVBufferQueueConsumer>::MakeSptr();
}

void LppVideoDecAdapterUnitTest::TearDown(void)
{
    inputBufferQueueConsumer_ = nullptr;
    videoDecoder_ = nullptr;
    videoDecAdapter_ = nullptr;
}

/**
* @tc.name    : Test Init API
* @tc.number  : Init_001
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, Init_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->isLppEnabled_ = true;
    bool switchToCommon = true;
    int32_t res = videoDecAdapter_->Init("video/avc", switchToCommon);
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test Init API
* @tc.number  : Init_002
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, Init_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->isLppEnabled_ = false;
    bool switchToCommon = true;
    int32_t res = videoDecAdapter_->Init("video/avc", switchToCommon);
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_001
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, StartRender_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec);
    EXPECT_CALL(*eventRec, OnEvent(_)).WillOnce(Return());
    videoDecAdapter_->SetEventReceiver(eventRec);
    EXPECT_EQ(videoDecAdapter_->outputBuffers_.empty(), true);
    int32_t res = videoDecAdapter_->StartRender();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_002
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, StartRender_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    EXPECT_CALL(*videoDecoder_, ReleaseOutputBuffer(_, _)).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec);
    EXPECT_CALL(*eventRec, OnEvent(_)).WillOnce(Return());
    videoDecAdapter_->SetEventReceiver(eventRec);
    uint32_t index = 10;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 33;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer));
    int32_t res = videoDecAdapter_->StartRender();
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(videoDecAdapter_->lastPts_.load(), buffer->pts_);
}

/**
* @tc.name    : Test HandleQueueBufferAvailable API
* @tc.number  : HandleQueueBufferAvailable_001
* @tc.desc    : Test HandleQueueBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, HandleQueueBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    ASSERT_NE(nullptr, inputBufferQueueConsumer_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;
    videoDecAdapter_->setChannelIdDone_ = true;
    EXPECT_CALL(*inputBufferQueueConsumer_, AcquireBuffer(_))
        .WillOnce([](std::shared_ptr<AVBuffer>& outBuffer) {
            outBuffer = std::make_shared<AVBuffer>();
            outBuffer->flag_ = 0;
            outBuffer->meta_ = std::make_shared<Meta>();
            outBuffer->meta_->SetData(Tag::REGULAR_TRACK_ID, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return Status::OK;
        });
    EXPECT_CALL(*videoDecoder_, QueueInputBuffer(_)).WillRepeatedly(Return(MediaAVCodec::AVCS_ERR_UNKNOWN));
    videoDecAdapter_->HandleQueueBufferAvailable();
    EXPECT_EQ(videoDecAdapter_->setChannelIdDone_, true);
}

/**
* @tc.name    : Test HandleQueueBufferAvailable API
* @tc.number  : HandleQueueBufferAvailable_002
* @tc.desc    : Test HandleQueueBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, HandleQueueBufferAvailable_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    ASSERT_NE(nullptr, inputBufferQueueConsumer_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;
    videoDecAdapter_->setChannelIdDone_ = true;
    EXPECT_CALL(*inputBufferQueueConsumer_, AcquireBuffer(_))
        .WillOnce([](std::shared_ptr<AVBuffer>& outBuffer) {
            outBuffer = std::make_shared<AVBuffer>();
            outBuffer->flag_ = MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS;
            outBuffer->meta_ = std::make_shared<Meta>();
            outBuffer->meta_->SetData(Tag::REGULAR_TRACK_ID, 1);
            outBuffer->memory_ = std::make_shared<MockAVMemory>();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return Status::OK;
        });
    EXPECT_CALL(*videoDecoder_, QueueInputBuffer(_)).WillRepeatedly(Return(MediaAVCodec::AVCS_ERR_UNKNOWN));
    videoDecAdapter_->HandleQueueBufferAvailable();
    EXPECT_EQ(videoDecAdapter_->setChannelIdDone_, true);
}

/**
* @tc.name    : Test OnInputBufferAvailable API
* @tc.number  : OnInputBufferAvailable_001
* @tc.desc    : Test OnInputBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, OnInputBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, inputBufferQueueConsumer_);
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;
    EXPECT_CALL(*inputBufferQueueConsumer_, IsBufferInQueue(_)).WillOnce(Return(false));
    EXPECT_CALL(*inputBufferQueueConsumer_, GetQueueSize()).WillOnce(Return(0));
    EXPECT_CALL(*inputBufferQueueConsumer_, SetQueueSizeAndAttachBuffer(_, _, _)).WillOnce(Return(Status::OK));
    uint32_t index = 1;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->meta_ = std::make_shared<Meta>();
    videoDecAdapter_->OnInputBufferAvailable(index, buffer);
    EXPECT_EQ(videoDecAdapter_->bufferVector_.size(), 1);
}

/**
* @tc.name    : Test OnInputBufferAvailable API
* @tc.number  : OnInputBufferAvailable_002
* @tc.desc    : Test OnInputBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, OnInputBufferAvailable_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, inputBufferQueueConsumer_);
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;
    EXPECT_CALL(*inputBufferQueueConsumer_, IsBufferInQueue(_)).WillOnce(Return(true));
    EXPECT_CALL(*inputBufferQueueConsumer_, ReleaseBuffer(_)).WillOnce(Return(Status::OK));
    uint32_t index = 1;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->meta_ = std::make_shared<Meta>();
    videoDecAdapter_->OnInputBufferAvailable(index, buffer);
    EXPECT_EQ(videoDecAdapter_->bufferVector_.size(), 0);
}

/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_001
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, StartDecode_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_
        = std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->initTargetPts_ = -1;
    EXPECT_CALL(*videoDecoder_, Start()).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));
    int32_t res = videoDecAdapter_->StartDecode();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test StartDecode API
* @tc.number  : StartDecode_002
* @tc.desc    : Test StartDecode interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, StartDecode_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_
        = std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->initTargetPts_ = 3000;
    EXPECT_CALL(*videoDecoder_, Start()).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));
    EXPECT_CALL(*videoDecoder_, SetParameter(_)).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));
    int32_t res = videoDecAdapter_->StartDecode();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetTargetPts API
* @tc.number  : SetTargetPts_001
* @tc.desc    : Test SetTargetPts interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, SetTargetPts_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->firstStarted_ = false;
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    int32_t res = videoDecAdapter_->SetTargetPts(3000);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetTargetPts API
* @tc.number  : SetTargetPts_002
* @tc.desc    : Test SetTargetPts interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, SetTargetPts_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->firstStarted_ = true;
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    EXPECT_CALL(*videoDecoder_, SetParameter(_)).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));
    int32_t res = videoDecAdapter_->SetTargetPts(3000);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_001
* @tc.desc    : Test Flush interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, Flush_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    ASSERT_NE(nullptr, inputBufferQueueConsumer_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;
    auto buffer = std::make_shared<AVBuffer>();
    std::vector<std::shared_ptr<AVBuffer>> bufferVector_;
    bufferVector_.push_back(buffer);
    videoDecAdapter_->bufferVector_ = bufferVector_;
    EXPECT_CALL(*videoDecoder_, Flush()).Times(1);
    EXPECT_CALL(*inputBufferQueueConsumer_, DetachBuffer(buffer)).Times(1);
    EXPECT_CALL(*inputBufferQueueConsumer_, SetQueueSize(0)).Times(1);
    int32_t res = videoDecAdapter_->Flush();
    EXPECT_EQ(res, MSERR_OK);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_002
* @tc.desc    : Test Flush interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, Flush_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->inputBufferQueueConsumer_ = nullptr;
    auto buffer = std::make_shared<AVBuffer>();
    std::vector<std::shared_ptr<AVBuffer>> bufferVector_;
    bufferVector_.push_back(buffer);
    videoDecAdapter_->bufferVector_ = bufferVector_;
    EXPECT_CALL(*videoDecoder_, Flush()).Times(1);
    EXPECT_CALL(*inputBufferQueueConsumer_, DetachBuffer(buffer)).Times(0);
    EXPECT_CALL(*inputBufferQueueConsumer_, SetQueueSize(0)).Times(0);
    int32_t res = videoDecAdapter_->Flush();
    EXPECT_EQ(res, MSERR_OK);
}

/**
 * @tc.name    : Test SetVideoSurface API
 * @tc.number  : SetVideoSurface_001
 * @tc.desc    : Test SetVideoSurface interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, SetVideoSurface_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();

    EXPECT_CALL(*videoDecoder_, SetOutputSurface(_)).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));

    int32_t result = videoDecAdapter_->SetVideoSurface(surface);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test PrepareBufferQueue API
 * @tc.number  : PrepareBufferQueue_001
 * @tc.desc    : Test PrepareBufferQueue interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, PrepareBufferQueue_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    int32_t result = videoDecAdapter_->PrepareBufferQueue();
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_001
 * @tc.desc    : Test Prepare interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, Prepare_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    EXPECT_CALL(*videoDecoder_, Prepare()).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));

    int32_t result = videoDecAdapter_->Prepare();
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_002
 * @tc.desc    : Test Prepare interface when videoDecoder_ is null
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, Prepare_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->videoDecoder_ = nullptr;
    videoDecAdapter_->inputBufferQueueConsumer_ = inputBufferQueueConsumer_;

    int32_t result = videoDecAdapter_->Prepare();
    EXPECT_EQ(result, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : Test RenderFirstFrame API
 * @tc.number  : RenderFirstFrame_001
 * @tc.desc    : Test RenderFirstFrame interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, RenderFirstFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    videoDecAdapter_->firstFrameDecoded_ = true;
    videoDecAdapter_->firstFrameRenderred_ = false;

    EXPECT_CALL(*videoDecoder_, ReleaseOutputBuffer(_, _)).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));

    uint32_t index = 10;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 33;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer));
    index = 11;
    std::shared_ptr<AVBuffer> buffer1 = std::make_shared<AVBuffer>();
    buffer->pts_ = 34;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer1));

    int32_t result = videoDecAdapter_->RenderFirstFrame();
    EXPECT_EQ(result, MSERR_OK);

    EXPECT_TRUE(videoDecAdapter_->firstFrameRenderred_);
}

/**
 * @tc.name    : Test Pause API
 * @tc.number  : Pause_001
 * @tc.desc    : Test Pause interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, Pause_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);

    int32_t result = videoDecAdapter_->Pause();
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_EQ(videoDecAdapter_->lastRenderTimeNs_.load(), 0);
    EXPECT_EQ(videoDecAdapter_->lastPts_.load(), 0);
}

/**
 * @tc.name    : Test Stop API
 * @tc.number  : Stop_001
 * @tc.desc    : Test Stop interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, Stop_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    EXPECT_CALL(*videoDecoder_, Stop()).WillOnce(Return(MSERR_OK));

    int32_t result = videoDecAdapter_->Stop();
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test Reset API
 * @tc.number  : Reset_001
 * @tc.desc    : Test Reset interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, Reset_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    EXPECT_CALL(*videoDecoder_, Reset()).WillOnce(Return(MediaAVCodec::AVCS_ERR_OK));

    int32_t result = videoDecAdapter_->Reset();
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test SetParameter API
 * @tc.number  : SetParameter_001
 * @tc.desc    : Test SetParameter interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, SetParameter_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    Format param;

    EXPECT_CALL(*videoDecoder_, SetParameter(_)).WillOnce(Return(MSERR_OK));

    int32_t result = videoDecAdapter_->SetParameter(param);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name    : Test GetChannelId API
 * @tc.number  : GetChannelId_001
 * @tc.desc    : Test GetChannelId interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, GetChannelId_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    int32_t channelId = -1;

    EXPECT_CALL(*videoDecoder_, GetChannelId(_)).WillOnce(DoAll(SetArgReferee<0>(123), Return(MSERR_OK)));

    int32_t result = videoDecAdapter_->GetChannelId(channelId);
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_EQ(channelId, 123);
}

/**
 * @tc.name    : Test SetChannelIdDone API
 * @tc.number  : SetChannelIdDone_001
 * @tc.desc    : Test SetChannelIdDone interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, SetChannelIdDone_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->setChannelIdDone_.store(false);

    videoDecAdapter_->SetChannelIdDone();

    EXPECT_TRUE(videoDecAdapter_->setChannelIdDone_.load());
}

/**
 * @tc.name    : Test GetInputBufferQueue API
 * @tc.number  : GetInputBufferQueue_001
 * @tc.desc    : Test GetInputBufferQueue interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, GetInputBufferQueue_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, videoDecoder_);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    videoDecAdapter_->PrepareBufferQueue();

    auto result = videoDecAdapter_->GetInputBufferQueue();
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name    : Test OnQueueBufferAvailable API
 * @tc.number  : OnQueueBufferAvailable_001
 * @tc.desc    : Test OnQueueBufferAvailable interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnQueueBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);

    ASSERT_NE(nullptr, videoDecAdapter_->decodertask_);
    videoDecAdapter_->OnQueueBufferAvailable();
    EXPECT_NE(nullptr, videoDecAdapter_->decodertask_);
}

/**
 * @tc.name    : Test OnOutputBufferAvailable API
 * @tc.number  : OnOutputBufferAvailable_001
 * @tc.desc    : Test OnOutputBufferAvailable interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnOutputBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;

    uint32_t index = 1;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 12345;
    videoDecAdapter_->firstFrameRenderred_ = true;
    videoDecAdapter_->renderStarted_ = true;

    videoDecAdapter_->OnOutputBufferAvailable(index, buffer);

    EXPECT_FALSE(videoDecAdapter_->outputBuffers_.empty());
    EXPECT_EQ(videoDecAdapter_->outputBuffers_.size(), 1);
}

/**
 * @tc.name    : Test HandleEosFrame API
 * @tc.number  : HandleEosFrame_001
 * @tc.desc    : Test HandleEosFrame interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, HandleEosFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec);
    videoDecAdapter_->SetEventReceiver(eventRec);
    videoDecAdapter_->jobIdx_ = 2;
    videoDecAdapter_->jobIdxBase_ = 1;

    uint32_t index = 10;
    std::shared_ptr<AVBuffer> buffer1 = std::make_shared<AVBuffer>();
    buffer1->pts_ = 33;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer1));

    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->flag_ = static_cast<uint32_t>(Plugins::AVBufferFlag::EOS);

    bool result = videoDecAdapter_->HandleEosFrame(0, buffer);
    EXPECT_TRUE(result);
}

/**
 * @tc.name    : Test HandleCommonFrame API
 * @tc.number  : HandleCommonFrame_001
 * @tc.desc    : Test HandleCommonFrame interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, HandleCommonFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->isLppEnabled_ = false;

    videoDecAdapter_->jobIdx_ = 2;
    videoDecAdapter_->jobIdxBase_ = 1;

    uint32_t index = 10;
    std::shared_ptr<AVBuffer> buffer1 = std::make_shared<AVBuffer>();
    buffer1->pts_ = 33;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer1));

    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 12345;

    bool result = videoDecAdapter_->HandleCommonFrame(0, buffer);
    EXPECT_TRUE(result);
}

/**
 * @tc.name    : Test HandleLppFrame API
 * @tc.number  : HandleLppFrame_001
 * @tc.desc    : Test HandleLppFrame interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, HandleLppFrame_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->decodertask_ =
        std::make_unique<Task>("test_start_decode", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    videoDecAdapter_->videoDecoder_ = videoDecoder_;
    videoDecAdapter_->isLppEnabled_ = true;
    videoDecAdapter_->jobIdx_ = 2;
    videoDecAdapter_->jobIdxBase_ = 1;

    uint32_t index = 10;
    std::shared_ptr<AVBuffer> buffer1 = std::make_shared<AVBuffer>();
    buffer1->pts_ = 33;
    videoDecAdapter_->outputBuffers_.push_back(std::make_pair(index, buffer1));

    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->pts_ = 12345;

    bool result = videoDecAdapter_->HandleLppFrame(0, buffer);
    EXPECT_TRUE(result);
}

/**
 * @tc.name    : Test NotifyFirstFrameDecoded API
 * @tc.number  : NotifyFirstFrameDecoded_001
 * @tc.desc    : Test NotifyFirstFrameDecoded interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, NotifyFirstFrameDecoded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec);
    EXPECT_CALL(*eventRec, OnEvent(_)).WillOnce(Return());
    videoDecAdapter_->SetEventReceiver(eventRec);
    videoDecAdapter_->firstFrameDecoded_ = false;

    videoDecAdapter_->NotifyFirstFrameDecoded();
    EXPECT_TRUE(videoDecAdapter_->firstFrameDecoded_);
}

/**
 * @tc.name    : Test CalcAnchorDiffTimeNs API
 * @tc.number  : CalcAnchorDiffTimeNs_001
 * @tc.desc    : Test CalcAnchorDiffTimeNs interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, CalcAnchorDiffTimeNs_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<LppSyncManager> syncMgr = std::make_shared<LppSyncManager>("1", true);
    videoDecAdapter_->syncMgr_ = syncMgr;

    int64_t pts = 1000;
    int64_t diffTimeNs = 0;
    bool isCalclated = false;

    int64_t anchorPts = 500;
    int64_t anchorClock = 1000000;
    EXPECT_CALL(*syncMgr, GetTimeAnchor(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(anchorPts), SetArgReferee<1>(anchorClock), Return(0)));

    videoDecAdapter_->CalcAnchorDiffTimeNs(pts, diffTimeNs, isCalclated);
    EXPECT_TRUE(isCalclated);
}

/**
 * @tc.name    : Test CalcPreFrameDiffTimeNs API
 * @tc.number  : CalcPreFrameDiffTimeNs_001
 * @tc.desc    : Test CalcPreFrameDiffTimeNs interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, CalcPreFrameDiffTimeNs_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    int64_t pts = 1000;
    int64_t diffTimeNs = 0;
    bool isCalclated = false;

    int64_t lastRenderTimeNs = 500000;
    int64_t lastPts = 500;
    videoDecAdapter_->lastRenderTimeNs_.store(lastRenderTimeNs);
    videoDecAdapter_->lastPts_.store(lastPts);

    videoDecAdapter_->CalcPreFrameDiffTimeNs(pts, diffTimeNs, isCalclated);
    EXPECT_TRUE(isCalclated);
}

/**
 * @tc.name    : Test OnOutputBufferBinded API
 * @tc.number  : OnOutputBufferBinded_001
 * @tc.desc    : Test OnOutputBufferBinded interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnOutputBufferBinded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<LppSyncManager> syncMgr = std::make_shared<LppSyncManager>("1", true);
    videoDecAdapter_->syncMgr_ = syncMgr;

    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap;
    bufferMap[0] = nullptr;

    EXPECT_CALL(*syncMgr, BindOutputBuffers(bufferMap)).Times(1);

    videoDecAdapter_->OnOutputBufferBinded(bufferMap);
}

/**
 * @tc.name    : Test OnOutputBufferUnbinded API
 * @tc.number  : OnOutputBufferUnbinded_001
 * @tc.desc    : Test OnOutputBufferUnbinded interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnOutputBufferUnbinded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<LppSyncManager> syncMgr = std::make_shared<LppSyncManager>("1", true);
    videoDecAdapter_->syncMgr_ = syncMgr;

    EXPECT_CALL(*syncMgr, UnbindOutputBuffers()).Times(1);

    videoDecAdapter_->OnOutputBufferUnbinded();
}

/**
 * @tc.name    : Test OnError API
 * @tc.number  : OnError_001
 * @tc.desc    : Test OnError interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnError_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec); 
    videoDecAdapter_->SetEventReceiver(eventRec);

    MediaAVCodec::AVCodecErrorType errorType = MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_INTERNAL;
    int32_t errorCode = MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_INTERNAL;
    EXPECT_CALL(*eventRec, OnEvent(_)).Times(1);
    videoDecAdapter_->OnError(errorType, errorCode);
}

/**
 * @tc.name    : Test OnOutputFormatChanged API
 * @tc.number  : OnOutputFormatChanged_001
 * @tc.desc    : Test OnOutputFormatChanged interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, OnOutputFormatChanged_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<MockEventReceiver> eventRec = std::make_shared<MockEventReceiver>();
    ASSERT_NE(nullptr, eventRec);
    videoDecAdapter_->SetEventReceiver(eventRec);

    Format format;
    format.PutIntValue("width", 1920);
    format.PutIntValue("height", 1080);
    EXPECT_CALL(*eventRec, OnEvent(_)).Times(1);
    videoDecAdapter_->OnOutputFormatChanged(format);
}

/**
 * @tc.name    : Test GeneratedJobIdx API
 * @tc.number  : GeneratedJobIdx_001
 * @tc.desc    : Test GeneratedJobIdx interface in normal case
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppVideoDecAdapterUnitTest, GeneratedJobIdx_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    videoDecAdapter_->jobIdxBase_ = 0;

    int64_t jobIdx = videoDecAdapter_->GeneratedJobIdx();

    EXPECT_EQ(jobIdx, 1);
}

/**
* @tc.name    : Test LppVideoDecoderCallback API
* @tc.number  : Callback_001
* @tc.desc    : Test LppVideoDecoderCallback interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecAdapterUnitTest, Callback_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    std::shared_ptr<LppVideoDecoderCallback> callback = std::make_shared<LppVideoDecoderCallback>(videoDecAdapter_);
    ASSERT_NE(nullptr, callback);

    MediaAVCodec::AVCodecErrorType errorType = MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_FRAMEWORK_FAILED;
    int32_t errorCode = 1001;
    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnError(errorType, errorCode);

    MediaAVCodec::Format format;
    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnOutputFormatChanged(format);

    auto buffer = std::make_shared<AVBuffer>();
    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnInputBufferAvailable(0, buffer);
    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnOutputBufferAvailable(0, buffer);

    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap = {};
    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnOutputBufferBinded(bufferMap);

    EXPECT_NE(callback->videoDecoderAdapter_.lock(), nullptr);
    callback->OnOutputBufferUnbinded();
}
} // namespace Media
} // namespace OHOS