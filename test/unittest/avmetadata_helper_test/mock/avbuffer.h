/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef AVBUFFER_H
#define AVBUFFER_H

#include <memory>
#include <string>
#include "buffer/avallocator.h"
#include "common/status.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class AVBuffer {
public:
    ~AVBuffer() {};

    MOCK_METHOD(std::shared_ptr<AVBuffer>, CreateAVBuffer, (const AVBufferConfig &config), ());

    MOCK_METHOD(std::shared_ptr<AVBuffer>, CreateAVBuffer,
                (std::shared_ptr<AVAllocator> allocator, int32_t capacity, int32_t align), ());

    MOCK_METHOD(std::shared_ptr<AVBuffer>, CreateAVBuffer, (uint8_t *ptr, int32_t capacity, int32_t size), ());

    MOCK_METHOD(std::shared_ptr<AVBuffer>, CreateAVBuffer, (sptr<SurfaceBuffer> surfaceBuffer), ());

    MOCK_METHOD(std::shared_ptr<AVBuffer>, CreateAVBuffer, (), ());

    MOCK_METHOD(AVBufferConfig&, GetConfig, (), ());

    MOCK_METHOD(uint64_t, GetUniqueId, (), ());

    MOCK_METHOD(bool, WriteToMessageParcel, (MessageParcel &parcel), ());

    MOCK_METHOD(bool, ReadFromMessageParcel, (MessageParcel &parcel, bool isSurfaceBuffer), ());

    using MetaData = std::vector<uint8_t>;

    int64_t pts_;
    int64_t dts_;
    int64_t duration_;
    uint32_t flag_;
    std::shared_ptr<Meta> meta_;
    std::shared_ptr<AVMemory> memory_;

private:
    AVBuffer();
    Status Init(std::shared_ptr<AVAllocator> allocator, int32_t capacity = 0, int32_t align = 0);
    Status Init(uint8_t *ptr, int32_t capacity, int32_t size = 0);
    Status Init(sptr<SurfaceBuffer> surfaceBuffer);
    AVBufferConfig config_;
};

/**
 * @brief AVBuffer's memory.
 */
class AVMemory {
public:
    friend class AVBuffer;
    ~AVMemory() = default;

    MOCK_METHOD(MemoryType, GetMemoryType, (), ());

    MOCK_METHOD(MemoryFlag, GetMemoryFlag, (), ());

    MOCK_METHOD(int32_t, GetCapacity, (), ());

    MOCK_METHOD(int32_t, GetConfig, (), ());

    MOCK_METHOD(Status, SetSize, (int32_t size), ());

    MOCK_METHOD(int32_t, GetSize, (), ());

    MOCK_METHOD(int32_t, GetOffset, (), ());

    MOCK_METHOD(Status, SetOffset, (int32_t offset), ());

    MOCK_METHOD(int32_t, GetFileDescriptor, (), ());

    MOCK_METHOD(uint8_t*, GetAddr, (), ());

    MOCK_METHOD(int32_t, Write, (const uint8_t *in, int32_t writeSize, int32_t position), ());

    MOCK_METHOD(int32_t, Read, (uint8_t *out, int32_t readSize, int32_t position), ());

    MOCK_METHOD(sptr<SurfaceBuffer>, GetSurfaceBuffer, (), ());
};
} // namespace Media
} // namespace OHOS
#endif // AVBUFFER_H