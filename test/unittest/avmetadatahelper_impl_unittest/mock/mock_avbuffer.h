/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_AVBUFFER_H
#define MOCK_AVBUFFER_H
 
#include "avmetadatahelper_impl.h"
#include "gmock/gmock.h"
#include "sync_fence.h"

namespace OHOS {
namespace Media {
class MockAVBuffer : public AVBuffer {
public:
    MockAVBuffer() = default;
    virtual ~MockAVBuffer() = default;
    MOCK_METHOD(const AVBufferConfig&, GetConfig, (), ());
    MOCK_METHOD(uint64_t, GetUniqueId, (), ());
    MOCK_METHOD(bool, WriteToMessageParcel, (MessageParcel& parcel), ());
    MOCK_METHOD(bool, ReadFromMessageParcel, (MessageParcel& parcel, bool isSurfaceBuffer), ());
    static std::shared_ptr<AVBuffer> CreateAVBuffer(const AVBufferConfig &config)
    {
        return std::make_shared<AVBuffer>();
    }
    static std::shared_ptr<AVBuffer> CreateAVBuffer(std::shared_ptr<AVAllocator> allocator, int32_t capacity = 0,
                                                    int32_t align = 0)
    {
        return std::make_shared<AVBuffer>();
    }
    static std::shared_ptr<AVBuffer> CreateAVBuffer(uint8_t *ptr, int32_t capacity, int32_t size = 0)
    {
        return std::make_shared<AVBuffer>();
    }
    static std::shared_ptr<AVBuffer> CreateAVBuffer(sptr<SurfaceBuffer> surfaceBuffer)
    {
        return std::make_shared<AVBuffer>();
    }
protected:
    MOCK_METHOD(Status, Init, (std::shared_ptr<AVAllocator> allocator, int32_t capacity, int32_t align), ());
    MOCK_METHOD(Status, Init, (uint8_t* ptr, int32_t capacity, int32_t size), ());
    MOCK_METHOD(Status, Init, (sptr<SurfaceBuffer> surfaceBuffer), ());
};

class MockAVMemory : public AVMemory {
public:
    MockAVMemory() = default;
    virtual ~MockAVMemory() = default;
    MOCK_METHOD(MemoryType, GetMemoryType, (), ());
    MOCK_METHOD(MemoryFlag, GetMemoryFlag, (), ());
    MOCK_METHOD(int32_t, GetCapacity, (), ());
    MOCK_METHOD(int32_t, GetSize, (), ());
    MOCK_METHOD(Status, SetSize, (int32_t size), ());
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

    static std::shared_ptr<AVMemory> CreateAVMemory(std::shared_ptr<AVAllocator> allocator,
                                                    int32_t capacity = 0, int32_t align = 0)
    {
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(uint8_t *ptr, int32_t capacity, int32_t size)
    {
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(MessageParcel &parcel, bool isSurfaceBuffer = false)
    {
        return std::make_shared<AVMemory>();
    }
    static std::shared_ptr<AVMemory> CreateAVMemory(sptr<SurfaceBuffer> surfaceBuffer)
    {
        return std::make_shared<AVMemory>();
    }
};

class MockSurfaceBuffer : public SurfaceBuffer {
public:
    MOCK_METHOD(int32_t, GetWidth, (), (const, override));
    MOCK_METHOD(int32_t, GetHeight, (), (const, override));
    MOCK_METHOD(int32_t, GetStride, (), (const, override));
    MOCK_METHOD(int32_t, GetFormat, (), (const, override));
    MOCK_METHOD(uint64_t, GetUsage, (), (const, override));
    MOCK_METHOD(uint64_t, GetPhyAddr, (), (const, override));
    MOCK_METHOD(int32_t, GetFileDescriptor, (), (const, override));
    MOCK_METHOD(uint32_t, GetSize, (), (const, override));
    MOCK_METHOD(GraphicColorGamut, GetSurfaceBufferColorGamut, (), (const, override));
    MOCK_METHOD(GraphicTransformType, GetSurfaceBufferTransform, (), (const, override));
    MOCK_METHOD(int32_t, GetSurfaceBufferWidth, (), (const, override));
    MOCK_METHOD(int32_t, GetSurfaceBufferHeight, (), (const, override));
    MOCK_METHOD(uint32_t, GetSeqNum, (), (const, override));
    MOCK_METHOD(sptr<BufferExtraData>, GetExtraData, (), (const, override));
    MOCK_METHOD(GSError, WriteToMessageParcel, (MessageParcel &parcel), (override));
    MOCK_METHOD(GSError, ReadFromMessageParcel, (MessageParcel &parcel, std::function<int(MessageParcel &,
        std::function<int(Parcel &)>readFdDefaultFunc)>readSafeFdFunc), (override));
    MOCK_METHOD(void, SetSurfaceBufferColorGamut, (const GraphicColorGamut& colorGamut), (override));
    MOCK_METHOD(void, SetSurfaceBufferTransform, (const GraphicTransformType& transform), (override));
    MOCK_METHOD(void, SetSurfaceBufferWidth, (int32_t width), (override));
    MOCK_METHOD(void, SetSurfaceBufferHeight, (int32_t width), (override));
    MOCK_METHOD(void, SetExtraData, (sptr<BufferExtraData> bedata), (override));
    MOCK_METHOD(void, SetBufferHandle, (BufferHandle *handle), (override));
    MOCK_METHOD(BufferHandle*, GetBufferHandle, (), (const, override));
    MOCK_METHOD(void*, GetVirAddr, (), (override));
    MOCK_METHOD(GSError, Alloc, (const BufferRequestConfig &config, const sptr<SurfaceBuffer>& previousBuffer),
        (override));
    MOCK_METHOD(GSError, Map, (), (override));
    MOCK_METHOD(GSError, Unmap, (), (override));
    MOCK_METHOD(GSError, FlushCache, (), (override));
    MOCK_METHOD(GSError, InvalidateCache, (), (override));
    MOCK_METHOD(GSError, SetMetadata, (uint32_t key, const std::vector<uint8_t>& value, bool enableCache), (override));
    MOCK_METHOD(GSError, GetMetadata, (uint32_t key, std::vector<uint8_t>& value), (override));
    MOCK_METHOD(GSError, ListMetadataKeys, (std::vector<uint32_t>& keys), (override));
    MOCK_METHOD(GSError, EraseMetadataKey, (uint32_t key), (override));
    MOCK_METHOD(GSError, GetPlanesInfo, (void **planesInfo), (override));
    MOCK_METHOD(void, SetCropMetadata, (const OHOS::Rect& crop), (override));
    MOCK_METHOD(bool, GetCropMetadata, (OHOS::Rect& crop), (override));
    MOCK_METHOD(OH_NativeBuffer*, SurfaceBufferToNativeBuffer, (), (override));
    MOCK_METHOD(BufferRequestConfig, GetBufferRequestConfig, (), (const, override));
    MOCK_METHOD(sptr<SyncFence>, GetSyncFence, (), (const, override));
    MOCK_METHOD(void, SetAndMergeSyncFence, (const sptr<SyncFence>& syncFence), (override));
};
}
}
#endif // MOCK_AVBUFFER_H