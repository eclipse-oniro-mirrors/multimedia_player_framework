/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef AVMETADATA_UNITTEST_H
#define AVMETADATA_UNITTEST_H

#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "avsharedmemory_ipc.h"
#include "avmetadatahelper_impl.h"
#include "sync_fence.h"

namespace OHOS {
namespace Media {
class AVMetadataUnittest : public testing::Test {
public:
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::shared_ptr<AVMetadataHelperImpl> avmetadataPtr_;
};
class MockPixelMap : public PixelMap {
public:
    MOCK_METHOD(int32_t, GetWidth, (), (override));
    MOCK_METHOD(int32_t, GetHeight, (), (override));
    MOCK_METHOD(PixelFormat, GetPixelFormat, (), (override));
    MOCK_METHOD(void*, GetFd, (), (const, override));
    MOCK_METHOD(AllocatorType, GetAllocatorType, (), (override));
    MOCK_METHOD(void, SetImageYUVInfo, (YUVDataInfo &yuvinfo), (override));
    MOCK_METHOD(void, scale, (float xAxis, float yAxis), (override));
};
class MockAVBuffer : public AVBuffer {
public:
    MOCK_METHOD(uint64_t, GetUniqueId, (), ());
};
class MockAVMemory : public AVMemory {
public:
    MOCK_METHOD(int32_t, GetSize, (), ());
    MOCK_METHOD(sptr<SurfaceBuffer>, GetSurfaceBuffer, (), ());
    MOCK_METHOD(uint8_t*, GetAddr, (), ());
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
#endif
