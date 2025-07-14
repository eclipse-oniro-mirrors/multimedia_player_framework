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
    PipeLineThreadPool::GetInstance().DestroyThread(streamerId_);
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
} // namespace Media
} // namespace OHOS
