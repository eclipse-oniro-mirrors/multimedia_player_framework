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
#include "lpp_common.h"
#include "buffer/avbuffer.h"
#include "common/native_mfmagic.h"
#include "media_log.h"
#include "media_errors.h"
#include "native_avbuffer.h"
#include "surface_buffer_impl.h"
#include "common/log.h"
#include <securec.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppDataPacket"};
constexpr uint32_t MAX_BUFFER_SIZE = 2 * 1024 * 1024;
}  // namespace
namespace OHOS {
namespace Media {

void LppDataPacket::Init()
{
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE);
    CHECK_AND_RETURN_LOG(buffer != nullptr, "CreateAVBuffer failed");
    memory_ = buffer->memory_;
}

int32_t LppDataPacket::GetRemainedCapacity()
{
    int32_t ret = memory_->GetCapacity() - memory_->GetSize();
    MEDIA_LOGI("GetRemainedCapacity GetCapacity  %{public}d", memory_->GetCapacity());
    MEDIA_LOGI("GetRemainedCapacity GetSize  %{public}d", memory_->GetSize());
    return ret;
}

bool LppDataPacket::AppendOneBuffer(const std::shared_ptr<AVBuffer> &buffer)
{
    MEDIA_LOGI("AppendOneBuffer");
    if (buffer == nullptr) {
        MEDIA_LOGI("buffer nullptr");
        return false;
    }
    std::shared_ptr<OHOS::Media::AVMemory> memory = buffer->memory_;
    if (memory == nullptr) {
        MEDIA_LOGI("memory nullptr");
        return false;
    }
    if (memory_ == nullptr) {
        MEDIA_LOGI("memory_ nullptr");
        return false;
    }
    if (memory_->GetAddr() == nullptr) {
        MEDIA_LOGI("memory_ getaddr nullptr");
        return false;
    }
    auto bufferSize = static_cast<int>(buffer->memory_->GetSize());
    MEDIA_LOGI("AppendOneBuffer pts=  %{public}ld, flag_ = %{public}d, bufferSize = %{public}d",
        buffer->pts_,
        buffer->flag_,
        bufferSize);
    auto ret = memory_->Write(buffer->memory_->GetAddr(), bufferSize, dataOffset_);
    if (ret < bufferSize) {  // write error
        MEDIA_LOGW("memory_->Write fail, write size is " PUBLIC_LOG_D32, ret);
        return false;
    }
    flag_.push_back(buffer->flag_);
    pts_.push_back(buffer->pts_);
    size_.push_back(bufferSize);
    dataOffset_ += bufferSize;
    MEDIA_LOGI("AppendOneBuffer done, current memory_ Size  %{public}d", memory_->GetSize());
    return true;
}

bool LppDataPacket::WriteVector(MessageParcel &bufferParcel)
{
    bufferParcel.WriteInt64(static_cast<int64_t>(flag_.size()));
    for (const auto &elem : flag_) {
        bufferParcel.WriteUint32(elem);
    }
    bufferParcel.WriteInt64(static_cast<int64_t>(pts_.size()));
    for (const auto &elem : pts_) {
        bufferParcel.WriteInt64(elem);
    }
    bufferParcel.WriteInt64(static_cast<int64_t>(size_.size()));
    for (const auto &elem : size_) {
        bufferParcel.WriteInt32(elem);
    }
    return true;
}

bool LppDataPacket::WriteToMessageParcel(MessageParcel &parcel)
{
    MEDIA_LOGI("WriteToMessageParcel");
    MessageParcel bufferParcel;
    WriteVector(bufferParcel);
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE);
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, false, "CreateAVBuffer failed");
    buffer->memory_ = memory_;

    MEDIA_LOGI("LppDataPacket WriteToMessageParcel: GetUniqueId %{public}uld, GetMemoryType %{public}u, GetCapacity "
               "%{public}d, GetSize %{public}d",
        static_cast<unsigned int>(buffer->GetUniqueId()),
        static_cast<unsigned int>(buffer->memory_->GetMemoryType()),
        buffer->memory_->GetCapacity(),
        buffer->memory_->GetSize());
    MessageParcel bufferParcel1;
    buffer->WriteToMessageParcel(bufferParcel1);

    parcel.Append(bufferParcel);
    parcel.Append(bufferParcel1);
    MEDIA_LOGI("WriteToMessageParcel");
    return true;
}

bool LppDataPacket::ReadVector(MessageParcel &parcel)
{
    int64_t size = 0;
    std::vector<uint32_t> flag;
    parcel.ReadInt64(size);
    for (int i = 0; i < size; i++) {
        uint32_t elem = 0;
        parcel.ReadUint32(elem);
        flag.push_back(elem);
        MEDIA_LOGI("ReadVector flag_  %{public}d", elem);
    }
    flag_ = flag;

    parcel.ReadInt64(size);
    MEDIA_LOGI("ReadVector size  %{public}ld", size);
    std::vector<int64_t> pts;
    for (int i = 0; i < size; i++) {
        int64_t elem = 0;
        parcel.ReadInt64(elem);
        MEDIA_LOGI("ReadVector elem  %{public}ld", elem);
        pts.push_back(elem);
    }
    pts_ = pts;

    parcel.ReadInt64(size);
    MEDIA_LOGI("ReadVector size  %{public}ld", size);
    std::vector<int> sizes;
    for (int i = 0; i < size; i++) {
        int elem = 0;
        parcel.ReadInt32(elem);
        MEDIA_LOGI("ReadVector elem  %{public}d", elem);
        sizes.push_back(elem);
    }
    size_ = sizes;
    return true;
}

bool LppDataPacket::ReadFromMessageParcel(MessageParcel &parcel)
{
    MEDIA_LOGI("ReadFromMessageParcel");
    ReadVector(parcel);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, false, "CreateAVBuffer failed");
    buffer->ReadFromMessageParcel(parcel, false);
    MEDIA_LOGI("LppDataPacket ReadFromMessageParcel: GetUniqueId %{public}uld, GetMemoryType %{public}u, GetCapacity "
               "%{public}d, GetSize %{public}d",
        static_cast<unsigned int>(buffer->GetUniqueId()),
        static_cast<unsigned int>(buffer->memory_->GetMemoryType()),
        buffer->memory_->GetCapacity(),
        buffer->memory_->GetSize());
    memory_ = buffer->memory_;
    MEDIA_LOGI("ReadFromMessageParcel");
    return true;
}

bool LppDataPacket::WriteToByteBuffer(std::shared_ptr<AVBuffer> &avBuffer)
{
    MEDIA_LOGI("WriteToByteBuffer in");
    CHECK_AND_RETURN_RET_LOG(!IsEmpty(), false, "LppDataPacket isEmpty..");
    frameCount_ = 0;
    if (IsEos()) {
        avBuffer->flag_ = avBuffer->flag_ | MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
        MEDIA_LOGI("eos without others");
        vectorReadIndex_++;
        return true;
    }
    uint8_t *buffer = avBuffer->memory_->GetAddr();
    int32_t capacity = avBuffer->memory_->GetCapacity();
    int offset = 0;
    offset += sizeof(uint32_t);
    while (!IsEmpty()) {
        offset = WriteOneFrameToAVBuffer(avBuffer, offset);
        CHECK_AND_RETURN_RET_LOG(offset > 0, false, "Write Frame failed..");
        avBuffer->memory_->SetSize(offset);
        MEDIA_LOGI("flag_ %{public}d, offset %{public}d, GetCapacity %{public}d, size %{public}d",
            avBuffer->flag_, offset, capacity, avBuffer->memory_->GetSize());
    }
    CHECK_AND_RETURN_RET_LOG(frameCount_ > 0, false, "LppDataPacket isEmpty..");
    auto ret = memcpy_s(buffer, sizeof(uint32_t), &frameCount_, sizeof(uint32_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "memcpy failed");
    avBuffer->flag_ = avBuffer->flag_ | MediaAVCodec::AVCODEC_BUFFER_FLAG_MUL_FRAME;
    MEDIA_LOGI("WriteToByteBuffer out");
    return true;
}

int LppDataPacket::WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &avbuffer, int offset)
{
    if (avbuffer == nullptr || avbuffer->memory_ == nullptr) {
        MEDIA_LOGW("buffer or memory is nullptr");
        return true;
    }

    // EOS和其他数据帧一起，EOS帧只置位，不占用聚包个数
    if (IsEos()) {
        MEDIA_LOGI("EOS with others");
        avbuffer->flag_ = avbuffer->flag_ | MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
        vectorReadIndex_++;
        return offset;
    }
    uint8_t *buffer = avbuffer->memory_->GetAddr();
    auto ret = memcpy_s(buffer + offset, sizeof(int64_t), &pts_[vectorReadIndex_], sizeof(int64_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, 0, "memcpy failed");
    offset += sizeof(int64_t);
    ret = memcpy_s(buffer + offset, sizeof(uint32_t), &size_[vectorReadIndex_], sizeof(uint32_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, 0, "memcpy failed");
    offset += sizeof(uint32_t);
    ret = memcpy_s(buffer + offset, size_[vectorReadIndex_], memory_->GetAddr() + dataOffset_, size_[vectorReadIndex_]);
    CHECK_AND_RETURN_RET_LOG(ret == 0, 0, "memcpy failed");
    offset += size_[vectorReadIndex_];
    dataOffset_ += size_[vectorReadIndex_];
    vectorReadIndex_++;
    frameCount_++;
    MEDIA_LOGI(
        "WriteToByteBuffer: pts_ %{public}ld, size_ %{public}d", pts_[vectorReadIndex_], size_[vectorReadIndex_]);
    MEDIA_LOGI("Read one buffer from DataPacket, currentIndex =  %{public}zu", vectorReadIndex_);
    return offset;
}

bool LppDataPacket::IsEmpty()
{
    return flag_.size() <= vectorReadIndex_ || pts_.size() <= vectorReadIndex_ || size_.size() <= vectorReadIndex_;
}

bool LppDataPacket::WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &buffer)
{
    if (IsEmpty() || memory_->GetAddr() == nullptr) {
        MEDIA_LOGW("Current Packet is Empty;");
        return false;
    }
    if (buffer == nullptr || buffer->memory_ == nullptr) {
        MEDIA_LOGW("buffer or memory is nullptr");
        return true;
    }
    buffer->flag_ = flag_[vectorReadIndex_];
    buffer->pts_ = pts_[vectorReadIndex_];
    auto bufferSize = size_[vectorReadIndex_];
    buffer->memory_->Write(memory_->GetAddr() + dataOffset_, bufferSize, 0);
    dataOffset_ += bufferSize;
    MEDIA_LOGI("Read one buffer from DataPacket, currentIndex =  %{public}zu", vectorReadIndex_);
    vectorReadIndex_++;
    return true;
}

void LppDataPacket::Clear()
{
    flag_.clear();
    pts_.clear();
    size_.clear();
    memory_->SetSize(0);
    dataOffset_ = 0;
    vectorReadIndex_ = 0;
}

bool LppDataPacket::IsEos()
{
    if (IsEmpty() || memory_->GetAddr() == nullptr) {
        MEDIA_LOGW("Current Packet is Empty;");
        return false;
    }
    return flag_[vectorReadIndex_] & MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
}

}  // namespace Media
}  // namespace OHOS