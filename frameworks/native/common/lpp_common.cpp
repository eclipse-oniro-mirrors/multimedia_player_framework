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
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppDataPacket"};
constexpr uint32_t MAX_BUFFER_SIZE = 10 * 1024 * 1024;
const std::string DUMP_FILE_DIR_SANDBOX = "/data/storage/el2/base/files/";
const std::string DUMP_FILE_DIR_SERVER = "/data/media/pipelinedump/";
constexpr size_t DUMP_DATA_UNIT = 1;  // data unit is 1 byte
const std::string DUMP_PARAM = "a";
constexpr int64_t MAX_BUFFER_CNT = 100;
}  // namespace
namespace OHOS {
namespace Media {

void LppDataPacket::Init(std::string streamerId)
{
    Init();
    streamerId_ = streamerId;
    std::string enableDump;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_video_lpp_dump", enableDump, "false");
    dumpBufferNeeded_ = ret == 0 ? enableDump == "true" : false;
    dumpFileNameInput_ = streamerId_ + "_DUMP_INPUT.bin";
}

void LppDataPacket::Init()
{
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    buffer_ = AVBuffer::CreateAVBuffer(allocator, MAX_BUFFER_SIZE);
    CHECK_AND_RETURN_LOG(buffer_ != nullptr, "buffer_ create failed");
    memory_ = buffer_->memory_;
    inUser_ = false;
}

int32_t LppDataPacket::GetRemainedCapacity()
{
    CHECK_AND_RETURN_RET_LOG(memory_ != nullptr, 0, "local memory is nullptr");
    int32_t remainedCapacity = memory_->GetCapacity() - dataOffset_;
    CHECK_AND_RETURN_RET_LOG(remainedCapacity >= 0, 0, "negative remainedCapacity!");
    return remainedCapacity;
}

bool LppDataPacket::AppendOneBuffer(const std::shared_ptr<AVBuffer> &buffer)
{
    CHECK_AND_RETURN_RET_LOG(inUser_, false, "data packet not in user!");
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr && buffer->memory_, false, "buffer or memory nullptr");
    CHECK_AND_RETURN_RET_LOG(memory_ != nullptr && memory_->GetAddr() != nullptr, false, "local memory is nullptr");
    int32_t nextSize = buffer->memory_->GetSize();
    CHECK_AND_RETURN_RET_LOG(nextSize <= GetRemainedCapacity(), false, "remained capacity not enough");
    int32_t writeLength = memory_->Write(buffer->memory_->GetAddr(), nextSize, dataOffset_);
    CHECK_AND_RETURN_RET_LOG(writeLength == nextSize, false, "remained capacity not enough");

    flag_.push_back(buffer->flag_);
    pts_.push_back(buffer->pts_);
    size_.push_back(nextSize);
    dataOffset_ += nextSize;
    DumpAVBufferToFile(DUMP_PARAM, buffer, true);
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
    MessageParcel metaParcel;
    bool ret = WriteVector(metaParcel);
    CHECK_AND_RETURN_RET_LOG(ret, false, "write meta failed");
    CHECK_AND_RETURN_RET_LOG(buffer_ != nullptr, false, "buffer is nullptr");
    MessageParcel dataParcel;
    ret = buffer_->WriteToMessageParcel(dataParcel);

    CHECK_AND_RETURN_RET_LOG(ret, false, "write data failed");
    ret = parcel.Append(metaParcel);
    CHECK_AND_RETURN_RET_LOG(ret, false, "write meta failed");
    ret = parcel.Append(dataParcel);
    CHECK_AND_RETURN_RET_LOG(ret, false, "write data failed");
    return true;
}

bool LppDataPacket::ReadVector(MessageParcel &parcel)
{
    int64_t size = 0;
    parcel.ReadInt64(size);
    CHECK_AND_RETURN_RET_LOG(size >= 0 && size <= MAX_BUFFER_CNT, false, "invalid buffer cnt");
    for (int i = 0; i < size; i++) {
        uint32_t elem = 0;
        parcel.ReadUint32(elem);
        flag_.push_back(elem);
    }

    parcel.ReadInt64(size);
    std::vector<int64_t> pts;
    for (int i = 0; i < size; i++) {
        int64_t elem = 0;
        parcel.ReadInt64(elem);
        pts_.push_back(elem);
    }

    parcel.ReadInt64(size);
    for (int i = 0; i < size; i++) {
        int elem = 0;
        parcel.ReadInt32(elem);
        size_.push_back(elem);
    }
    return true;
}

bool LppDataPacket::ReadFromMessageParcel(MessageParcel &parcel)
{
    Clear();
    bool ret = ReadVector(parcel);
    CHECK_AND_RETURN_RET_LOG(ret, false, "read meta failed");
    buffer_ = AVBuffer::CreateAVBuffer();
    CHECK_AND_RETURN_RET_LOG(buffer_ != nullptr, false, "create avbuffer failed");
    ret = buffer_->ReadFromMessageParcel(parcel, false);
    CHECK_AND_RETURN_RET_LOG(ret, false, "read data failed");
    memory_ = buffer_->memory_;
    return true;
}

bool LppDataPacket::WriteToByteBuffer(std::shared_ptr<AVBuffer> &avBuffer)
{
    CHECK_AND_RETURN_RET_LOG(avBuffer != nullptr && avBuffer->memory_ != nullptr, false, "buffer or memory is nullptr");
    CHECK_AND_RETURN_RET_LOG(!IsEmpty(), false, "LppDataPacket isEmpty..");
    frameCount_ = 0;
    if (IsEos()) {
        avBuffer->flag_ = avBuffer->flag_ | MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
        vectorReadIndex_++;
        return true;
    }
    int offset = 0;
    offset += sizeof(uint32_t);
    bool writeContinue = true;
    while (!IsEmpty() && writeContinue) {
        writeContinue = WriteOneFrameToAVBuffer(avBuffer, offset);
    }
    avBuffer->memory_->SetSize(offset);
    CHECK_AND_RETURN_RET_LOG(frameCount_ > 0, false, "LppDataPacket isEmpty..");
    uint8_t *buffer = avBuffer->memory_->GetAddr();
    CHECK_AND_RETURN_RET_LOG(avBuffer->memory_->GetCapacity() >= sizeof(uint32_t), false, "not enough capacity");
    int32_t ret = memcpy_s(buffer, sizeof(uint32_t), &frameCount_, sizeof(uint32_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "memcopy error");
    avBuffer->flag_ |= MediaAVCodec::AVCODEC_BUFFER_FLAG_MUL_FRAME;
    return true;
}

bool LppDataPacket::WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &avbuffer, int& offset)
{
    CHECK_AND_RETURN_RET_LOG(avbuffer != nullptr && avbuffer->memory_ != nullptr, false, "buffer or memory is nullptr");

    // EOS和其他数据帧一起，EOS帧只置位，不占用聚包个数
    if (IsEos()) {
        MEDIA_LOGD("EOS with others");
        avbuffer->flag_ = avbuffer->flag_ | MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
        vectorReadIndex_++;
        return false;
    }

    int32_t writeLength = sizeof(int64_t) + sizeof(uint32_t) + size_[vectorReadIndex_];
    CHECK_AND_RETURN_RET_LOG(avbuffer->memory_->GetCapacity() - offset >= writeLength, false, "not enough capacity");

    uint8_t *buffer = avbuffer->memory_->GetAddr();

    CHECK_AND_RETURN_RET_LOG(offset >= 0, false, "offset is less than 0.");
    int32_t ret = 0;
    ret = memcpy_s(buffer + offset, sizeof(int64_t), &pts_[vectorReadIndex_], sizeof(int64_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "memcopy error");
    offset += sizeof(int64_t);
    ret = memcpy_s(buffer + offset, sizeof(uint32_t), &size_[vectorReadIndex_], sizeof(uint32_t));
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "memcopy error");
    offset += sizeof(uint32_t);
    CHECK_AND_RETURN_RET_LOG(memory_ != nullptr, false, "memory_ is nullptr");
    ret = memcpy_s(buffer + offset, size_[vectorReadIndex_], memory_->GetAddr() + dataOffset_, size_[vectorReadIndex_]);
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "memcopy error");
    offset += size_[vectorReadIndex_];
    dataOffset_ += size_[vectorReadIndex_];
    vectorReadIndex_++;
    frameCount_++;
    return true;
}

bool LppDataPacket::IsEmpty()
{
    return flag_.size() <= vectorReadIndex_ || pts_.size() <= vectorReadIndex_ || size_.size() <= vectorReadIndex_;
}

bool LppDataPacket::WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &buffer)
{
    if (IsEmpty() || memory_ == nullptr || memory_->GetAddr() == nullptr) {
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
    vectorReadIndex_++;
    return true;
}

void LppDataPacket::Clear()
{
    flag_.clear();
    pts_.clear();
    size_.clear();
    memory_ = nullptr;
    buffer_ = nullptr;
    dataOffset_ = 0;
    vectorReadIndex_ = 0;
}

void LppDataPacket::Disable()
{
    inUser_ = false;
}

void LppDataPacket::Enable()
{
    inUser_ = true;
    flag_.clear();
    pts_.clear();
    size_.clear();
    memory_->SetSize(0);
    dataOffset_ = 0;
    vectorReadIndex_ = 0;
}

bool LppDataPacket::IsEnable()
{
    return inUser_;
}

bool LppDataPacket::IsEos()
{
    if (IsEmpty() || memory_ == nullptr || memory_->GetAddr() == nullptr) {
        MEDIA_LOGW("Current Packet is Empty;");
        return false;
    }
    return flag_[vectorReadIndex_] & MediaAVCodec::AVCODEC_BUFFER_FLAG_EOS;
}

void LppDataPacket::DumpAVBufferToFile(
    const std::string &para, const std::shared_ptr<AVBuffer> &buffer, const bool isClient)
{
    FALSE_RETURN_NOLOG(dumpBufferNeeded_);
    MEDIA_LOG_D("dump avbuffer to %{public}s", dumpFileNameInput_.c_str());
    if (buffer == nullptr || buffer->memory_ == nullptr) {
        MEDIA_LOG_E("buffer or memory is nullptr.");
        return;
    }
    FALSE_RETURN_MSG(
        (para == "w" || para == "a") && !dumpFileNameInput_.empty(), "para or dumpFileNameInput_ is invalid.");
    size_t bufferSize = static_cast<size_t>(buffer->memory_->GetSize());
    FALSE_RETURN((bufferSize != 0) && (buffer->memory_->GetAddr() != nullptr));
    std::string mode = para + "b+";
    std::string filePath = (isClient ? DUMP_FILE_DIR_SANDBOX : DUMP_FILE_DIR_SERVER) + dumpFileNameInput_;

    if (filePath == "") {
        return;
    }
    MEDIA_LOG_D("dump avbuffer to %{public}s", filePath.c_str());
    char path[PATH_MAX] = {0x00};
    const char *inputPath = filePath.c_str();
    if (strlen(inputPath) > PATH_MAX || realpath(inputPath, path) == nullptr) {
        MEDIA_LOG_E("dump buffer failed due to Invalid path");
        return;
    }
    FILE *dumpFile = std::fopen(path, mode.c_str());
    if (dumpFile == nullptr) {
        MEDIA_LOG_E("dump buffer to file failed.");
        return;
    }
    size_t ret =
        fwrite(reinterpret_cast<const char *>(buffer->memory_->GetAddr()), DUMP_DATA_UNIT, bufferSize, dumpFile);
    if (ret != bufferSize) {
        MEDIA_LOG_W("dump is fail.");
    }
    std::fclose(dumpFile);
}

}  // namespace Media
}  // namespace OHOS