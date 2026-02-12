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
#ifndef AVBUFFER_QUEUE_CONSUMER_MOCK_H
#define AVBUFFER_QUEUE_CONSUMER_MOCK_H
#include <gmock/gmock.h>
#include "buffer/avbuffer_queue.h"

namespace OHOS {
namespace Media {
class MockAVBufferQueueConsumer : public AVBufferQueueConsumer {
public:
    MOCK_METHOD(uint32_t, GetQueueSize, (), (override));
    MOCK_METHOD(Status, SetQueueSize, (uint32_t size), (override));
    MOCK_METHOD(bool, IsBufferInQueue, (const std::shared_ptr<AVBuffer>& buffer), (override));
    MOCK_METHOD(Status, AcquireBuffer, (std::shared_ptr<AVBuffer>& outBuffer), (override));
    MOCK_METHOD(Status, ReleaseBuffer, (const std::shared_ptr<AVBuffer>& inBuffer), (override));
    MOCK_METHOD(Status, AttachBuffer, (std::shared_ptr<AVBuffer>& inBuffer, bool isFilled), (override));
    MOCK_METHOD(Status, DetachBuffer, (const std::shared_ptr<AVBuffer>& outBuffer), (override));
    MOCK_METHOD(Status, SetBufferAvailableListener, (sptr<IConsumerListener>& listener), (override));
    MOCK_METHOD(Status, SetQueueSizeAndAttachBuffer,
        (uint32_t size, std::shared_ptr<AVBuffer>& buffer, bool isFilled), (override));
    MOCK_METHOD(uint32_t, GetFilledBufferSize, (), (override));
};

class MockAVMemory : public AVMemory {
public:
    MockAVMemory() = default;
    virtual ~MockAVMemory() = default;
    MOCK_METHOD(MemoryType, GetMemoryType, (), ());
    MOCK_METHOD(MemoryFlag, GetMemoryFlag, (), ());
    MOCK_METHOD(int32_t, GetCapacity, (), ());
    MOCK_METHOD(int32_t, GetSize, (), ());
    Status SetSize(int32_t size)
    {
        (void)size;
        return Status::OK;
    }
    MOCK_METHOD(int32_t, GetOffset, (), ());
    MOCK_METHOD(Status, SetOffset, (int32_t offset), ());
    MOCK_METHOD(int32_t, GetFileDescriptor, (), ());
    MOCK_METHOD(uint8_t*, GetAddr, (), ());
    MOCK_METHOD(int32_t, Write, (const uint8_t* in, int32_t writeSize, int32_t position), ());
    MOCK_METHOD(int32_t, Read, (uint8_t* out, int32_t readSize, int32_t position), ());
    MOCK_METHOD(void, Reset, (), ());
    MOCK_METHOD(sptr<SurfaceBuffer>, GetSurfaceBuffer, (), ());

protected:
    MOCK_METHOD(Status, Init, (), ());
    MOCK_METHOD(Status, Init, (MessageParcel& parcel), ());
    MOCK_METHOD(Status, InitSurfaceBuffer, (MessageParcel& parcel), ());
    MOCK_METHOD(Status, InitSurfaceBuffer, (sptr<SurfaceBuffer> surfaceBuffer), ());
    MOCK_METHOD(bool, WriteToMessageParcel, (MessageParcel& parcel), ());
    MOCK_METHOD(bool, ReadFromMessageParcel, (MessageParcel& parcel), ());
    MOCK_METHOD(bool, ReadCommonFromMessageParcel, (MessageParcel& parcel), ());
    MOCK_METHOD(bool, SkipCommonFromMessageParcel, (MessageParcel& parcel), ());
    MOCK_METHOD(bool, WriteCommonToMessageParcel, (MessageParcel& parcel), ());
    int32_t capacity_ = 0;
    int32_t align_;
    int32_t offset_;
    int32_t size_;
    uint8_t *base_;
    uint64_t uid_;
    std::shared_ptr<AVAllocator> allocator_;
    static std::shared_ptr<AVMemory> CreateAVMemory(std::shared_ptr<AVAllocator> allocator,
                                                    int32_t capacity = 0, int32_t align = 0){
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(uint8_t *ptr, int32_t capacity, int32_t size){
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(MessageParcel &parcel, bool isSurfaceBuffer = false){
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(sptr<SurfaceBuffer> surfaceBuffer){
        return std::make_shared<AVMemory>();
    }
};
} // namespace Media
} // namespace OHOS
#endif // AVBUFFER_QUEUE_CONSUMER_MOCK_H