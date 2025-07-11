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
#ifndef AV_THUMBNAIL_GENERATOR_UNIT_TEST_H
#define AV_THUMBNAIL_GENERATOR_UNIT_TEST_H
 
#include <unordered_map>
#include <set>
#include <condition_variable>
#include <mutex>
#include <nocopyable.h>

#include "mock/avbuffer.h"
#include "mock/mock_avbuffer_queue.h"
#include "mock/mock_avbuffer_queue_consumer.h"
#include "mock/mock_avbuffer_queue_producer.h"
#include "mock/mock_avcodec_video_decoder.h"
#include "mock/avsharedmomorybase.h"
#include "mock/mock_media_demuxer.h"
#include "common/status.h"
#include "i_avmetadatahelper_service.h"
#include "pipeline/pipeline.h"
#include "video_decoder_adapter.h"
#include "av_thumbnail_generator.h"
#include "gtest/gtest.h"
 
namespace OHOS {
namespace Media {
namespace Test {
class AVThumbnailGeneratorUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
 
protected:
    std::shared_ptr<AVThumbnailGenerator> avThumbnailGenerator_{ nullptr };
    std::shared_ptr<MediaDemuxer> mediaDemuxer_{ nullptr };
    std::shared_ptr<MockMediaDemuxer> mockMediaDemuxer_{ nullptr };
    std::shared_ptr<Media::MockAVBufferQueue> mockInputBufferQueue_{ nullptr };
    sptr<Media::MockAVBufferQueueConsumer> mockInputBufferQueueConsumer_{ nullptr };
    sptr<Media::MockAVBufferQueueProducer> mockInputBufferQueueProducer_{ nullptr };
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
        std::function<int(Parcel &)>readFdDefaultFunc)>readSafeFdFunc),(override));
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
    MOCK_METHOD(void, SetCropMetadata, (const OHOS::Rect& crop), (override));
    MOCK_METHOD(bool, GetCropMetadata, (OHOS::Rect& crop), (override));
    MOCK_METHOD(OH_NativeBuffer*, SurfaceBufferToNativeBuffer, (), (override));
    MOCK_METHOD(BufferRequestConfig, GetBufferRequestConfig, (), (const, override));
};
}  // namespace Test
}  // namespace Media
}  // namespace OHOS
#endif  // AV_THUMBNAIL_GENERATOR_UNIT_TEST_H