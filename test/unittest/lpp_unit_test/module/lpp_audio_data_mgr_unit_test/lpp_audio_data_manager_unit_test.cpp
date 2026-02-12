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
#include "lpp_audio_data_manager_unit_test.h"

namespace {
    constexpr uint32_t MAX_BUFFER_SIZE_TEST = 2 * 1024 * 1024;
}
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppAudioDataManagerUnitTest::SetUpTestCase(void)
{
}

void LppAudioDataManagerUnitTest::TearDownTestCase(void)
{
}

void LppAudioDataManagerUnitTest::SetUp(void)
{
    streamerId_ = std::string("LPPADataUnitTest_") +
        std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());

    audioDataMgr_ = std::make_shared<LppAudioDataManager>(streamerId_);
    audioDataMgr_->dataTask_
        = std::make_unique<Task>("LppAData", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
}

void LppAudioDataManagerUnitTest::TearDown(void)
{
    audioDataMgr_ = nullptr;
    PipeLineThreadPool::GetInstance().DestroyThread(streamerId_);
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_001
* @tc.desc    : Test Prepare interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Prepare_001, TestSize.Level1)
{
    audioDataMgr_->dataTask_ = nullptr;
    int32_t res = audioDataMgr_->Prepare();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetDecoderInputProducer API
* @tc.number  : SetDecoderInputProducer_001
* @tc.desc    : Test SetDecoderInputProducer interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, SetDecoderInputProducer_001, TestSize.Level1)
{
    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    sptr<IProducerListener> targetListener = nullptr;
    EXPECT_CALL(*producer, SetBufferAvailableListener(_)).WillOnce(
        DoAll(
            Invoke([&targetListener](sptr<IProducerListener>& listener) { targetListener = listener; }),
            Return(Status::OK)
        )
    );
    int32_t res = audioDataMgr_->SetDecoderInputProducer(producer);
    EXPECT_EQ(res, 0);
    EXPECT_NE(targetListener, nullptr);
    targetListener->OnBufferAvailable();
    res = audioDataMgr_->Reset();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Start API
* @tc.number  : Start_001
* @tc.desc    : Test Start interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Start_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Start();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_001
* @tc.desc    : Test Start interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Pause_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Pause();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_001
* @tc.desc    : Test Start interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Resume_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Resume();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_001
* @tc.desc    : Test Flush interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Flush_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Flush();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Stop API
* @tc.number  : Stop_001
* @tc.desc    : Test Stop interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Stop_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Stop();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Reset API
* @tc.number  : Reset_001
* @tc.desc    : Test Reset interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, Reset_001, TestSize.Level1)
{
    int32_t res = audioDataMgr_->Reset();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test ProcessNewData API
* @tc.number  : ProcessNewData_001
* @tc.desc    : Test ProcessNewData interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, ProcessNewData_001, TestSize.Level1)
{
    audioDataMgr_->dataTask_->Start();
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    int32_t res = audioDataMgr_->ProcessNewData(framePacket);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetEventReceiver API
* @tc.number  : SetEventReceiver_001
* @tc.desc    : Test SetEventReceiver interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, SetEventReceiver_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    audioDataMgr_->SetEventReceiver(eventReceiver);
    EXPECT_NE(audioDataMgr_->eventReceiver_, nullptr);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_001
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, HandleBufferAvailable_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    audioDataMgr_->SetEventReceiver(eventReceiver);
    EXPECT_NE(audioDataMgr_->eventReceiver_, nullptr);

    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    sptr<IBrokerListener> targetListener = nullptr;
    EXPECT_CALL(*producer, SetBufferAvailableListener(_)).WillOnce(Return(Status::OK));
    int32_t res = audioDataMgr_->SetDecoderInputProducer(producer);
    EXPECT_EQ(res, 0);
    bool onEventSuccess = false;
    audioDataMgr_->isRequiringData_ = false;
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillOnce(Invoke([&onEventSuccess](const Event& event) {
        onEventSuccess = true;
    }));
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_TRUE(audioDataMgr_->isRequiringData_);
    EXPECT_TRUE(onEventSuccess);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_002
* @tc.desc    : Test HandleBufferAvailable interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioDataManagerUnitTest, HandleBufferAvailable_002, TestSize.Level1)
{
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    audioDataMgr_->SetEventReceiver(eventReceiver);
    EXPECT_NE(audioDataMgr_->eventReceiver_, nullptr);

    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    sptr<IBrokerListener> targetListener = nullptr;
    EXPECT_CALL(*producer, SetBufferAvailableListener(_)).WillOnce(Return(Status::OK));
    int32_t res = audioDataMgr_->SetDecoderInputProducer(producer);
    EXPECT_EQ(res, 0);

    audioDataMgr_->isRequiringData_ = false;

    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    framePacket->Enable();

    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_NE(buffer->memory_, nullptr);
    buffer->memory_->SetSize(10);
    bool appendRes = framePacket->AppendOneBuffer(buffer);
    EXPECT_TRUE(appendRes);
    audioDataMgr_->dataPacket_ = framePacket;

    std::shared_ptr<AVBuffer> buffer2 = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    EXPECT_CALL(*producer, RequestBuffer(_, _, _)).WillOnce(
        DoAll(
            Invoke([&buffer2](std::shared_ptr<AVBuffer>& outBuffer, const AVBufferConfig& config, int32_t timeoutMs) {
                outBuffer = buffer2;
            }),
            Return(Status::OK)
        )
    );
    bool pushBufferSuccess = false;
    EXPECT_CALL(*producer, PushBuffer(_, _)).WillOnce(
        DoAll(
            Invoke([&pushBufferSuccess](const std::shared_ptr<AVBuffer>& inBuffer, bool available) {
                pushBufferSuccess = true;
            }),
            Return(Status::OK)
        )
    );
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_TRUE(pushBufferSuccess);
}

void LppAudioDataManagerUnitTest::HandleBufferAvailableFunTest0031()
{
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    EXPECT_NE(audioDataMgr_->dataPacket_, nullptr);
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.push_back(1);
    audioDataMgr_->dataPacket_->pts_.push_back(1);
    audioDataMgr_->dataPacket_->size_.clear();
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    EXPECT_NE(audioDataMgr_->dataPacket_, nullptr);
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.push_back(1);
    audioDataMgr_->dataPacket_->pts_.clear();
    audioDataMgr_->dataPacket_->size_.push_back(1);
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.push_back(1);
    audioDataMgr_->dataPacket_->pts_.clear();
    audioDataMgr_->dataPacket_->size_.clear();
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);
}

void LppAudioDataManagerUnitTest::HandleBufferAvailableFunTest0032()
{
    sptr<LppDataPacket> framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.clear();
    audioDataMgr_->dataPacket_->pts_.push_back(1);
    audioDataMgr_->dataPacket_->size_.push_back(1);
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.clear();
    audioDataMgr_->dataPacket_->pts_.push_back(1);
    audioDataMgr_->dataPacket_->size_.clear();
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.clear();
    audioDataMgr_->dataPacket_->pts_.clear();
    audioDataMgr_->dataPacket_->size_.push_back(1);
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    framePacket = sptr<LppDataPacket>::MakeSptr();
    framePacket->Init();
    audioDataMgr_->dataPacket_ = framePacket;
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_->flag_.clear();
    audioDataMgr_->dataPacket_->pts_.clear();
    audioDataMgr_->dataPacket_->size_.clear();
    audioDataMgr_->dataPacket_->vectorReadIndex_ = 0;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_003
* @tc.desc    : Test HandleBufferAvailable interface
*/
HWTEST_F(LppAudioDataManagerUnitTest, HandleBufferAvailable_003, TestSize.Level1)
{
    std::shared_ptr<OHOS::Media::MockEventReceiver> eventReceiver = std::make_shared<OHOS::Media::MockEventReceiver>();
    bool onEventSuccess = false;
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillRepeatedly(Invoke([&onEventSuccess](const Event &event) {
        onEventSuccess = true;
    }));
    audioDataMgr_->SetEventReceiver(eventReceiver);
    EXPECT_NE(audioDataMgr_->eventReceiver_, nullptr);

    sptr<MockAVBufferQueueProducer> producer = sptr<MockAVBufferQueueProducer>::MakeSptr();
    sptr<IBrokerListener> targetListener = nullptr;
    EXPECT_CALL(*producer, SetBufferAvailableListener(_)).WillOnce(Return(Status::OK));
    int32_t res = audioDataMgr_->SetDecoderInputProducer(producer);
    EXPECT_EQ(res, 0);
    audioDataMgr_->isRequiringData_ = false;
    audioDataMgr_->dataPacket_ = nullptr;
    audioDataMgr_->HandleBufferAvailable();
    EXPECT_EQ(audioDataMgr_->isRequiringData_, true);

    HandleBufferAvailableFunTest0031();

    HandleBufferAvailableFunTest0032();
}
} // namespace Media
} // namespace OHOS