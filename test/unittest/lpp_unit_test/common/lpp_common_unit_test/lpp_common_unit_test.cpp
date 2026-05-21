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
constexpr int32_t MAX_BUFFER_SIZE = 10 * 1024 * 1024;
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

/**
 * @tc.name  : ReadVector_001
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with negative elem in size_ vector (should return false)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_001, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 1;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem = -1;
    parcel.WriteInt32(elem);

    bool result = packet_->ReadVector(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : ReadVector_002
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with elem exceeding MAX_BUFFER_SIZE (should return false)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_002, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 1;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem = MAX_BUFFER_SIZE + 1;
    parcel.WriteInt32(elem);

    bool result = packet_->ReadVector(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : ReadVector_003
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with elem = 0 (boundary value, should return true)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_003, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 1;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem = 0;
    parcel.WriteInt32(elem);

    bool result = packet_->ReadVector(parcel);
    EXPECT_TRUE(result);
    EXPECT_EQ(packet_->size_.size(), 1);
    EXPECT_EQ(packet_->size_[0], 0);
}

/**
 * @tc.name  : ReadVector_004
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with elem = MAX_BUFFER_SIZE (boundary value, should return true)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_004, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 1;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem = MAX_BUFFER_SIZE;
    parcel.WriteInt32(elem);

    bool result = packet_->ReadVector(parcel);
    EXPECT_TRUE(result);
    EXPECT_EQ(packet_->size_.size(), 1);
    EXPECT_EQ(packet_->size_[0], MAX_BUFFER_SIZE);
}

/**
 * @tc.name  : ReadVector_005
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with normal valid elem (should return true)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_005, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 3;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000 + i;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem1 = 1024;
    int32_t elem2 = 2048;
    int32_t elem3 = 4096;
    parcel.WriteInt32(elem1);
    parcel.WriteInt32(elem2);
    parcel.WriteInt32(elem3);

    bool result = packet_->ReadVector(parcel);
    EXPECT_TRUE(result);
    EXPECT_EQ(packet_->size_.size(), 3);
    EXPECT_EQ(packet_->size_[0], 1024);
    EXPECT_EQ(packet_->size_[1], 2048);
    EXPECT_EQ(packet_->size_[2], 4096);
}

/**
 * @tc.name  : ReadVector_006
 * @tc.number: ReadVector
 * @tc.desc  : Test ReadVector with mixed valid and invalid elem (should return false on invalid)
 */

HWTEST_F(LppDataPacketUnitTest, ReadVector_006, TestSize.Level1)
{
    MessageParcel parcel;

    int64_t size = 2;

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        uint32_t flag = 1;
        parcel.WriteUint32(flag);
    }

    parcel.WriteInt64(size);

    for (int i = 0; i < size; i++) {
        int64_t pts = 1000 + i;
        parcel.WriteInt64(pts);
    }

    parcel.WriteInt64(size);

    int32_t elem1 = 1024;
    int32_t elem2 = -1;
    parcel.WriteInt32(elem1);
    parcel.WriteInt32(elem2);

    bool result = packet_->ReadVector(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : Init_001
 * @tc.number: Init_001
 * @tc.desc  : Test Init with streamerId
 */
HWTEST_F(LppDataPacketUnitTest, Init_001, TestSize.Level1)
{
    packet_->Init("test_streamer");
    EXPECT_NE(packet_->streamerId_, "");
    EXPECT_EQ(packet_->dumpFileNameInput_, "test_streamer_DUMP_INPUT.bin");
}

/**
 * @tc.name  : WriteToMessageParcel_001
 * @tc.number: WriteToMessageParcel_001
 * @tc.desc  : Test WriteToMessageParcel with valid data
 */
HWTEST_F(LppDataPacketUnitTest, WriteToMessageParcel_001, TestSize.Level1)
{
    packet_->Init();
    packet_->Enable();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(100);
    packet_->AppendOneBuffer(buffer);
    MessageParcel parcel;
    EXPECT_TRUE(packet_->WriteToMessageParcel(parcel));
}

/**
 * @tc.name  : WriteToMessageParcel_002
 * @tc.number: WriteToMessageParcel_002
 * @tc.desc  : Test WriteToMessageParcel with nullptr buffer_
 */
HWTEST_F(LppDataPacketUnitTest, WriteToMessageParcel_002, TestSize.Level1)
{
    packet_->buffer_ = nullptr;
    MessageParcel parcel;
    EXPECT_FALSE(packet_->WriteToMessageParcel(parcel));
}

/**
 * @tc.name  : ReadFromMessageParcel_001
 * @tc.number: ReadFromMessageParcel_001
 * @tc.desc  : Test ReadFromMessageParcel with valid data
 */
HWTEST_F(LppDataPacketUnitTest, ReadFromMessageParcel_001, TestSize.Level1)
{
    packet_->Init();
    packet_->Enable();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(100);
    packet_->AppendOneBuffer(buffer);
    MessageParcel writeParcel;
    packet_->WriteToMessageParcel(writeParcel);
    packet_->Clear();
    EXPECT_TRUE(packet_->ReadFromMessageParcel(writeParcel));
}

/**
 * @tc.name  : ReadFromMessageParcel_002
 * @tc.number: ReadFromMessageParcel_002
 * @tc.desc  : Test ReadFromMessageParcel with invalid data
 */
HWTEST_F(LppDataPacketUnitTest, ReadFromMessageParcel_002, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt64(-1);
    EXPECT_FALSE(packet_->ReadFromMessageParcel(parcel));
}

/**
 * @tc.name  : WriteVector_001
 * @tc.number: WriteVector_001
 * @tc.desc  : Test WriteVector with valid data
 */
HWTEST_F(LppDataPacketUnitTest, WriteVector_001, TestSize.Level1)
{
    packet_->flag_.push_back(1);
    packet_->pts_.push_back(1000);
    packet_->size_.push_back(100);
    MessageParcel parcel;
    EXPECT_TRUE(packet_->WriteVector(parcel));
}

/**
 * @tc.name  : DumpAVBufferToFile_001
 * @tc.number: DumpAVBufferToFile_001
 * @tc.desc  : Test DumpAVBufferToFile when dump is disabled
 */
HWTEST_F(LppDataPacketUnitTest, DumpAVBufferToFile_001, TestSize.Level1)
{
    packet_->dumpBufferNeeded_ = false;
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(100);
    packet_->DumpAVBufferToFile("a", buffer, true);
}

/**
 * @tc.name  : DumpAVBufferToFile_002
 * @tc.number: DumpAVBufferToFile_002
 * @tc.desc  : Test DumpAVBufferToFile with invalid parameter
 */
HWTEST_F(LppDataPacketUnitTest, DumpAVBufferToFile_002, TestSize.Level1)
{
    packet_->dumpBufferNeeded_ = true;
    packet_->dumpFileNameInput_ = "";
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(100);
    packet_->DumpAVBufferToFile("x", buffer, true);
}

/**
 * @tc.name  : DumpAVBufferToFile_003
 * @tc.number: DumpAVBufferToFile_003
 * @tc.desc  : Test DumpAVBufferToFile with zero size buffer
 */
HWTEST_F(LppDataPacketUnitTest, DumpAVBufferToFile_003, TestSize.Level1)
{
    packet_->dumpBufferNeeded_ = true;
    packet_->dumpFileNameInput_ = "test.bin";
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(0);
    packet_->DumpAVBufferToFile("a", buffer, true);
}
} // namespace Media
} // namespace OHOS
