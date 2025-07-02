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
#include "lpp_video_data_manager_unit_test.h"

namespace {
    constexpr uint32_t MAX_BUFFER_SIZE_TEST = 2 * 1024 * 1024;
}
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppVideoDataManagerUnitTest::SetUpTestCase(void)
{
}

void LppVideoDataManagerUnitTest::TearDownTestCase(void)
{
}

void LppVideoDataManagerUnitTest::SetUp(void)
{
    videoDataMgr_ = std::make_shared<LppVideoDataManager>(streamerId_, isLpp_);
}

void LppVideoDataManagerUnitTest::TearDown(void)
{
    videoDataMgr_ = nullptr;
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_001
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    EXPECT_EQ(videoDataMgr_->dataPacket_, nullptr);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_002
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_LE(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_003
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->flag_.push_back(10);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_GT(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_004
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->flag_.push_back(10);
    framePacket->pts_.push_back(33);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_GT(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_005
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->pts_.push_back(33);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_LE(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_006
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->pts_.push_back(33);
    framePacket->size_.push_back(100);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_LE(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_007
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->flag_.push_back(10);
    framePacket->size_.push_back(100);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_GT(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_008
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Return());
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->size_.push_back(100);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_LE(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_LE(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), true);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_009
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    EXPECT_CALL(*producer, RequestBuffer(_, _, _)).WillOnce(Return(Status::OK));
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->flag_.push_back(10);
    framePacket->pts_.push_back(33);
    framePacket->size_.push_back(100);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_GT(framePacket->flag_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->pts_.size(), framePacket->vectorReadIndex_);
    EXPECT_GT(framePacket->size_.size(), framePacket->vectorReadIndex_);
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), false);
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, false);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_010
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->Init();
    framePacket->Enable();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_NE(buffer->memory_, nullptr);
    buffer->memory_->SetSize(10);
    bool appendRes = framePacket->AppendOneBuffer(buffer);
    EXPECT_TRUE(appendRes);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), false);
    std::shared_ptr<AVBuffer> buffer2 = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_CALL(*producer, RequestBuffer(_, _, _)).WillOnce(
        DoAll(
            Invoke([&buffer2](std::shared_ptr<AVBuffer>& outBuffer, const AVBufferConfig& config, int32_t timeoutMs) {
                outBuffer = buffer2;
            }),
            Return(Status::OK)
        )
    );
    EXPECT_CALL(*producer, PushBuffer(_, _)).WillOnce(Return(Status::ERROR_UNKNOWN));
    videoDataMgr_->disablePacketInput_ = true;
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, false);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_011
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDataManagerUnitTest, HandleBufferAvailable_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDataMgr_);
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    ASSERT_NE(nullptr, eventReceiver);
    videoDataMgr_->SetEventReceiver(eventReceiver);
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    ASSERT_NE(nullptr, producer);
    videoDataMgr_->inputProducer_ = producer;
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    ASSERT_NE(nullptr, framePacket);
    framePacket->Init();
    framePacket->Enable();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_NE(buffer->memory_, nullptr);
    buffer->memory_->SetSize(10);
    bool appendRes = framePacket->AppendOneBuffer(buffer);
    EXPECT_TRUE(appendRes);
    videoDataMgr_->dataPacket_ = framePacket;
    EXPECT_EQ(videoDataMgr_->dataPacket_->IsEmpty(), false);
    std::shared_ptr<AVBuffer> buffer2 = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_CALL(*producer, RequestBuffer(_, _, _)).WillOnce(
        DoAll(
            Invoke([&buffer2](std::shared_ptr<AVBuffer>& outBuffer, const AVBufferConfig& config, int32_t timeoutMs) {
                outBuffer = buffer2;
            }),
            Return(Status::OK)
        )
    );
    EXPECT_CALL(*producer, PushBuffer(_, _)).WillOnce(Return(Status::ERROR_UNKNOWN));
    videoDataMgr_->disablePacketInput_ = false;
    videoDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(videoDataMgr_->isRequiringData_, false);
}
} // namespace Media
} // namespace OHOS