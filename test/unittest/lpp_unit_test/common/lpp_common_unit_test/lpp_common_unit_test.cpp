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
#include "lpp_common_unit_test.h"

constexpr uint32_t MAX_BUFFER_SIZE_TEST = 2 * 1024 * 1024;
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppDataPacketUnitTest::SetUpTestCase(void)
{
}

void LppDataPacketUnitTest::TearDownTestCase(void)
{
}

void LppDataPacketUnitTest::SetUp(void)
{
    packet_ = std::make_shared<LppDataPacket>();
    ASSERT_NE(nullptr, packet_);
}

void LppDataPacketUnitTest::TearDown(void)
{
    if (packet_ != nullptr) {
        packet_->Clear();
        packet_.reset();
    }
}

/**
 * @tc.name  : WriteToByteBuffer_001
 * @tc.number: WriteToByteBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteToByteBuffer_001, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 0;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_FALSE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_TRUE(packet_->IsEos());
    EXPECT_TRUE(packet_->WriteToByteBuffer(buffer));
}

/**
 * @tc.name  : WriteToByteBuffer_002
 * @tc.number: WriteToByteBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteToByteBuffer_002, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 1;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_TRUE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_FALSE(packet_->IsEos());
    EXPECT_FALSE(packet_->WriteToByteBuffer(buffer));
}

/**
 * @tc.name  : WriteToByteBuffer_003
 * @tc.number: WriteToByteBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteToByteBuffer_003, TestSize.Level1)
{
    packet_->flag_.push_back(0);
    packet_->vectorReadIndex_ = 0;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_FALSE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_FALSE(packet_->IsEos());
    EXPECT_TRUE(packet_->WriteToByteBuffer(buffer));

    packet_->dumpBufferNeeded_ = true;
    const std::string DUMP_PARAM = "a";
    buffer = nullptr;
    packet_->DumpAVBufferToFile(DUMP_PARAM, buffer, true);

    buffer = std::make_shared<AVBuffer>();
    packet_->DumpAVBufferToFile(DUMP_PARAM, buffer, true);

    allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    Status ret = buffer->memory_->SetSize(1);
    EXPECT_EQ(ret, Status::OK);
    EXPECT_TRUE(buffer->memory_->GetAddr() != nullptr);
    packet_->dumpFileNameInput_ = "_DUMP_INPUT.bin";
    packet_->DumpAVBufferToFile(DUMP_PARAM, buffer, true);
}

/**
 * @tc.name  : WriteOneFrameToAVBuffer_001
 * @tc.number: WriteOneFrameToAVBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteOneFrameToAVBuffer_001, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 0;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_FALSE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_TRUE(packet_->IsEos());
    int offset = 0;
    offset += sizeof(uint32_t);
    EXPECT_EQ(packet_->WriteOneFrameToAVBuffer(buffer, offset), false);
}

/**
 * @tc.name  : WriteOneFrameToAVBuffer_002
 * @tc.number: WriteOneFrameToAVBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteOneFrameToAVBuffer_002, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 1;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_TRUE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_FALSE(packet_->IsEos());
    int offset = 0;
    offset += sizeof(uint32_t);
    EXPECT_NE(packet_->WriteOneFrameToAVBuffer(buffer, offset), true);
}

/**
 * @tc.name  : WriteOneFrameToAVBuffer_003
 * @tc.number: WriteOneFrameToAVBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteOneFrameToAVBuffer_003, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 1;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_TRUE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_FALSE(packet_->IsEos());
    packet_->Disable();
    EXPECT_NE(packet_->WriteOneFrameToAVBuffer(buffer), true);
}

/**
 * @tc.name  : WriteOneFrameToAVBuffer_004
 * @tc.number: WriteOneFrameToAVBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteOneFrameToAVBuffer_004, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 0;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_FALSE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = buffer->memory_;
    EXPECT_TRUE(packet_->IsEos());
    packet_->IsEnable();
    buffer=nullptr;
    EXPECT_EQ(packet_->WriteOneFrameToAVBuffer(buffer), true);
}

/**
 * @tc.name  : WriteOneFrameToAVBuffer_005
 * @tc.number: WriteOneFrameToAVBuffer
 * @tc.desc  : FUNC
 */

HWTEST_F(LppDataPacketUnitTest, WriteOneFrameToAVBuffer_005, TestSize.Level1)
{
    packet_->flag_.push_back(MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS);
    packet_->vectorReadIndex_ = 0;
    packet_->pts_.push_back(2);
    packet_->size_.push_back(3);
    EXPECT_FALSE(packet_->IsEmpty());
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE_TEST);
    packet_->memory_ = nullptr;
    EXPECT_FALSE(packet_->IsEos());
    EXPECT_FALSE(packet_->WriteOneFrameToAVBuffer(buffer));
}
} // namespace Media
} // namespace OHOS
