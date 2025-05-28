/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "avmetadatahelper_impl_unit_test.h"

#include "buffer/avbuffer_common.h"
#include "common/media_source.h"
#include "ibuffer_consumer_listener.h"
#include "graphic_common_c.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_description.h"
#include "meta/meta.h"
#include "meta/meta_key.h"
#include "plugin/plugin_time.h"
#include "sync_fence.h"
#include "uri_helper.h"
#include "media_client.h"

#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "v1_0/buffer_handle_meta_key_type.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static MediaClient g_mediaClientInstance;
IMediaService &MediaServiceFactory::GetInstance()
{
    return g_mediaClientInstance;
}

MediaClient::MediaClient() noexcept {}

MediaClient::~MediaClient() {}

std::shared_ptr<IAVMetadataHelperService> MediaClient::CreateAVMetadataHelperService()
{
    return nullptr;
}

int32_t MediaClient::DestroyAVMetadataHelperService(std::shared_ptr<IAVMetadataHelperService> avMetadataHelper)
{
    return 0;
}

sptr<IStandardMonitorService> MediaClient::GetMonitorProxy()
{
    return nullptr;
}

bool MediaClient::CanKillMediaService()
{
    return false;
}

void MediaClient::ReleaseClientListener() {}

std::vector<pid_t> MediaClient::GetPlayerPids()
{
    std::vector<pid_t> ret;
    return ret;
}

namespace Test {
void AVMetadtahelperImplUnitTest::SetUpTestCase(void) {}

void AVMetadtahelperImplUnitTest::TearDownTestCase(void) {}

void AVMetadtahelperImplUnitTest::SetUp(void)
{
    helper_->ReportSceneCode(AV_META_SCENE_NORMAL);
    helper_->ReportSceneCode(AV_META_SCENE_CLONE);
    helper_ = std::make_shared<AVMetadataHelperImpl>();
}

void AVMetadtahelperImplUnitTest::TearDown(void)
{
    helper_ = nullptr;
}

/**
 * @tc.name: FreePixelMapData
 * @tc.desc: FreePixelMapData
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadtahelperImplUnitTest, FreePixelMapData, TestSize.Level1)
{
    PixelMapMemHolder *holder = new PixelMapMemHolder{ .isShmem = true, .shmem = nullptr, .heap = new uint8_t(0) };
    FreePixelMapData(nullptr, reinterpret_cast<void *>(holder), 0);
    ASSERT_EQ(holder->heap, nullptr);

    auto mem = AVSharedMemoryBase::CreateFromLocal(10, AVSharedMemory::Flags::FLAGS_READ_WRITE, "test");
    ASSERT_NE(mem, nullptr);
    holder = new PixelMapMemHolder{ .isShmem = true, .shmem = mem, .heap = nullptr };
    FreePixelMapData(nullptr, reinterpret_cast<void *>(holder), 0);
    ASSERT_EQ(holder->shmem, nullptr);

    mem = AVSharedMemoryBase::CreateFromLocal(10, AVSharedMemory::Flags::FLAGS_READ_WRITE, "test");
    ASSERT_NE(mem, nullptr);
    int32_t *tmpPtr = new int32_t(0);
    holder = new PixelMapMemHolder{ .isShmem = false, .shmem = mem, .heap = reinterpret_cast<uint8_t *>(tmpPtr) };
    FreePixelMapData(reinterpret_cast<void *>(tmpPtr), reinterpret_cast<void *>(holder), 0);
    ASSERT_NE(holder->shmem, nullptr);
    tmpPtr = nullptr;

    mem = AVSharedMemoryBase::CreateFromLocal(10, AVSharedMemory::Flags::FLAGS_READ_WRITE, "test");
    ASSERT_NE(mem, nullptr);
    tmpPtr = new int32_t(0);
    holder = new PixelMapMemHolder{ .isShmem = false, .shmem = mem, .heap = nullptr };
    FreePixelMapData(reinterpret_cast<void *>(tmpPtr), reinterpret_cast<void *>(holder), 0);
    ASSERT_NE(holder->shmem, nullptr);
    tmpPtr = nullptr;

    mem = AVSharedMemoryBase::CreateFromLocal(10, AVSharedMemory::Flags::FLAGS_READ_WRITE, "test");
    ASSERT_NE(mem, nullptr);
    tmpPtr = new int32_t(0);
    holder = new PixelMapMemHolder{ .isShmem = false, .shmem = mem, .heap = reinterpret_cast<uint8_t *>(tmpPtr) };
    FreePixelMapData(nullptr, reinterpret_cast<void *>(holder), 0);
    ASSERT_NE(holder->shmem, nullptr);
    tmpPtr = nullptr;

    mem = AVSharedMemoryBase::CreateFromLocal(10, AVSharedMemory::Flags::FLAGS_READ_WRITE, "test");
    ASSERT_NE(mem, nullptr);
    tmpPtr = new int32_t(0);
    holder = new PixelMapMemHolder{ .isShmem = false, .shmem = mem, .heap = nullptr };
    FreePixelMapData(nullptr, reinterpret_cast<void *>(holder), 0);
    ASSERT_NE(holder->shmem, nullptr);
    tmpPtr = nullptr;
}

/**
 * @tc.name: DumpPixelMap
 * @tc.desc: DumpPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadtahelperImplUnitTest, DumpPixelMap, TestSize.Level1)
{
    auto res = helper_->DumpPixelMap(true, nullptr, ".data");
    ASSERT_EQ(res, MSERR_INVALID_VAL);

    InitializationOptions opts;
    opts.size.width = 1;
    opts.size.height = 1;
    opts.pixelFormat = PixelFormat::NV12;
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    res = helper_->DumpPixelMap(true, pixelMap, ".data");
}

/**
 * @tc.name: DumpAVBuffer
 * @tc.desc: DumpAVBuffer
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadtahelperImplUnitTest, DumpAVBuffer, TestSize.Level1)
{
    auto res = helper_->DumpAVBuffer(true, nullptr, ".data");
    ASSERT_EQ(res, MSERR_INVALID_VAL);
}

/**
 * @tc.name: pixelFormatToString
 * @tc.desc: pixelFormatToString
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadtahelperImplUnitTest, pixelFormatToString, TestSize.Level1)
{
    auto res = helper_->pixelFormatToString(PixelFormat::RGB_565);
    ASSERT_EQ(res, "RGB_565");

    res = helper_->pixelFormatToString(PixelFormat::RGBA_8888);
    ASSERT_EQ(res, "RGBA_8888");

    res = helper_->pixelFormatToString(PixelFormat::RGB_888);
    ASSERT_EQ(res, "RGB_888");

    res = helper_->pixelFormatToString(PixelFormat::NV12);
    ASSERT_EQ(res, "NV12");

    res = helper_->pixelFormatToString(PixelFormat::YCBCR_P010);
    ASSERT_EQ(res, "YCBCR_P010");

    res = helper_->pixelFormatToString(PixelFormat::UNKNOWN);
    ASSERT_EQ(res, "UNKNOWN");
}

/**
 * @tc.name: SetPixelMapYuvInfo
 * @tc.desc: SetPixelMapYuvInfo
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadtahelperImplUnitTest, SetPixelMapYuvInfo, TestSize.Level1)
{
    InitializationOptions opts;
    opts.size.width = 1;
    opts.size.height = 1;
    opts.pixelFormat = PixelFormat::NV12;
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);

    AVMetadataHelperImpl::PixelMapInfo pixelMapInfo = { .pixelFormat = PixelFormat::NV12 };
    sptr<SurfaceBuffer> buffer = nullptr;
    helper_->SetPixelMapYuvInfo(buffer, pixelMap, pixelMapInfo, false);
    YUVDataInfo yuvInfo;
    pixelMap->GetImageYUVInfo(yuvInfo);
    ASSERT_EQ(yuvInfo.yWidth, 1);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS