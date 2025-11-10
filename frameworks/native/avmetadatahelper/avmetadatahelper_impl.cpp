/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "avmetadatahelper_impl.h"

#include <sys/stat.h>
#include <unistd.h>

#include "v1_0/hdr_static_metadata.h"
#include "v1_0/buffer_handle_meta_key_type.h"

#include "securec.h"
#include "image_source.h"
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"
#include "scope_guard.h"
#include "hisysevent.h"
#include "image_type.h"
#include "param_wrapper.h"
#include "hdr_type.h"
#include "metadata_convertor.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "MetaHelperImpl" };
constexpr int32_t SCENE_CODE_EFFECTIVE_DURATION_MS = 20000;
static constexpr char PERFORMANCE_STATS[] = "PERFORMANCE";
static std::atomic<uint32_t> concurrentWorkCount_ = 0;
static constexpr uint8_t HIGH_CONCRENT_WORK_NUM = 4;
static constexpr int32_t PLANE_Y = 0;
static constexpr int32_t PLANE_U = 1;
static constexpr uint8_t HDR_PIXEL_SIZE = 2;
static constexpr uint8_t SDR_PIXEL_SIZE = 1;
constexpr int32_t NUM_180 = 180;
static const std::string FILE_DIR_IN_THE_SANDBOX = "/data/storage/el2/base/files/";
const std::string DUMP_FILE_NAME_AVBUFFER = "_avbuffer.dat";
const std::string DUMP_FILE_NAME_PIXEMAP = "_pixelMap.dat";
const std::string DUMP_FILE_NAME_AFTER_SCLAE = "_afterScale.dat";
const std::string DUMP_FILE_NAME_AFTER_ROTATE = "_afterRotate.dat";

constexpr uint8_t COLORPRIMARIES_OFFSET = 0;
constexpr uint8_t TRANSFUNC_OFFSET = 8;
constexpr uint8_t MATRIX_OFFSET = 16;
constexpr uint8_t RANGE_OFFSET = 21;
constexpr uint16_t SURFACE_MAX_WIDTH = 7680;
constexpr uint16_t SURFACE_MAX_HEIGHT = 7680;
constexpr uint8_t MAX_BYTES_PER_PIXEL = 4;
constexpr uint16_t MAX_STRIDE = SURFACE_MAX_WIDTH * MAX_BYTES_PER_PIXEL;
}

namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
static constexpr uint8_t PIXEL_SIZE_HDR_YUV = 3;
static std::map<Scene, long> SCENE_CODE_MAP = { { Scene::AV_META_SCENE_CLONE, 1 },
                                                { Scene::AV_META_SCENE_BATCH_HANDLE, 2 } };
static std::map<Scene, int64_t> SCENE_TIMESTAMP_MAP = { { Scene::AV_META_SCENE_CLONE, 0 },
                                                        { Scene::AV_META_SCENE_BATCH_HANDLE, 0 } };
/*
 * CM_ColorSpaceType from
 * {@link ${system_general}/drivers/interface/display/graphic/common/v1_0/CMColorSpace.idl}
 *
 * ColorManager::ColorSpaceName from
 * {@link ${system_general}/foundation/graphic/graphic_2d/utils/color_manager/export/color_space.h}
 *
 * maps with #IsHdr()
 * {@link ${system_general}/foundation/multimedia/image_framework/frameworks/innerkitsimpl/common/src/pixel_map.cpp}
 */
static const std::unordered_map<unsigned int, ColorManager::ColorSpaceName> SDR_COLORSPACE_MAP = {
    { CM_BT601_EBU_FULL, ColorManager::ColorSpaceName::BT601_EBU },
    { CM_BT601_EBU_LIMIT, ColorManager::ColorSpaceName::BT601_EBU_LIMIT },
    { CM_BT601_SMPTE_C_FULL, ColorManager::ColorSpaceName::BT601_SMPTE_C },
    { CM_BT601_SMPTE_C_LIMIT, ColorManager::ColorSpaceName::BT601_SMPTE_C_LIMIT },
    { CM_BT709_FULL, ColorManager::ColorSpaceName::BT709 },
    { CM_BT709_LIMIT, ColorManager::ColorSpaceName::BT709_LIMIT },
    { CM_SRGB_FULL, ColorManager::ColorSpaceName::SRGB },
    { CM_SRGB_LIMIT, ColorManager::ColorSpaceName::SRGB_LIMIT },
    { CM_P3_FULL, ColorManager::ColorSpaceName::DISPLAY_P3 },
    { CM_P3_LIMIT, ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT },
    { CM_P3_HLG_FULL, ColorManager::ColorSpaceName::P3_HLG },
    { CM_P3_HLG_LIMIT, ColorManager::ColorSpaceName::P3_HLG_LIMIT },
    { CM_P3_PQ_FULL, ColorManager::ColorSpaceName::P3_PQ_LIMIT },
    { CM_P3_PQ_LIMIT, ColorManager::ColorSpaceName::P3_PQ_LIMIT },
    { CM_ADOBERGB_FULL, ColorManager::ColorSpaceName::ADOBE_RGB },
    { CM_ADOBERGB_LIMIT, ColorManager::ColorSpaceName::ADOBE_RGB_LIMIT },
    { CM_LINEAR_SRGB, ColorManager::ColorSpaceName::LINEAR_SRGB },
    { CM_LINEAR_BT709, ColorManager::ColorSpaceName::LINEAR_BT709 },
    { CM_LINEAR_P3, ColorManager::ColorSpaceName::LINEAR_P3 },
    { CM_LINEAR_BT2020, ColorManager::ColorSpaceName::LINEAR_BT2020 },

    // sdr pixelMap can use BT2020 color space, but hdr can't use color space except BT2020
    { CM_BT2020_HLG_FULL, ColorManager::ColorSpaceName::BT2020_HLG },
    { CM_BT2020_PQ_FULL, ColorManager::ColorSpaceName::BT2020_PQ },
    { CM_BT2020_HLG_LIMIT, ColorManager::ColorSpaceName::BT2020_HLG_LIMIT },
    { CM_BT2020_PQ_LIMIT, ColorManager::ColorSpaceName::BT2020_PQ_LIMIT },
};

static const std::unordered_map<unsigned int, ColorManager::ColorSpaceName> HDR_COLORSPACE_MAP = {
    { CM_BT2020_HLG_FULL, ColorManager::ColorSpaceName::BT2020_HLG },
    { CM_BT2020_PQ_FULL, ColorManager::ColorSpaceName::BT2020_PQ },
    { CM_BT2020_HLG_LIMIT, ColorManager::ColorSpaceName::BT2020_HLG_LIMIT },
    { CM_BT2020_PQ_LIMIT, ColorManager::ColorSpaceName::BT2020_PQ_LIMIT },
};

static const std::unordered_map<int32_t, std::pair<bool, bool>> VIDEOORIENTATIONTYPE_FLIP_MAP = {
    { Plugins::VideoOrientationType::FLIP_H, {true, false} },
    { Plugins::VideoOrientationType::FLIP_V, {false, true} },
    { Plugins::VideoOrientationType::FLIP_H_ROT90, {true, false} },
    { Plugins::VideoOrientationType::FLIP_V_ROT90, {false, true} },
};

static const std::unordered_map<int32_t, int32_t> VIDEOORIENTATIONTYPE_ROTATION_MAP = {
    { Plugins::VideoOrientationType::FLIP_H, 0 },
    { Plugins::VideoOrientationType::FLIP_V, 0 },
    { Plugins::VideoOrientationType::FLIP_H_ROT90, 270 },
    { Plugins::VideoOrientationType::FLIP_V_ROT90, 270 },
};

struct PixelMapMemHolder {
    bool isShmem;
    std::shared_ptr<AVSharedMemory> shmem;
    uint8_t *heap;
};

struct AVBufferHolder {
    std::shared_ptr<AVBuffer> buffer;
};

static void FreePixelMapData(void *addr, void *context, uint32_t size)
{
    (void)size;

    MEDIA_LOGD("free pixel map data");

    CHECK_AND_RETURN_LOG(context != nullptr, "context is nullptr");
    PixelMapMemHolder *holder = reinterpret_cast<PixelMapMemHolder *>(context);
    if (holder->isShmem) {
        if (holder->shmem == nullptr) {
            MEDIA_LOGE("shmem is nullptr");
        }
        holder->shmem = nullptr;
        holder->heap = nullptr;
    } else {
        if (holder->heap == nullptr || holder->heap != addr) {
            MEDIA_LOGE("heap is invalid");
        } else {
            delete [] holder->heap;
            holder->heap = nullptr;
        }
    }
    delete holder;
}

static void FreeAvBufferData(void *addr, void *context, uint32_t size)
{
    (void)addr;
    (void)size;
    CHECK_AND_RETURN_LOG(context != nullptr, "context is nullptr");
    AVBufferHolder *holder = reinterpret_cast<AVBufferHolder *>(context);
    delete holder;
}

static void FreeSurfaceBuffer(void *addr, void *context, uint32_t size)
{
    (void)addr;
    (void)size;
    CHECK_AND_RETURN_LOG(context != nullptr, "context is nullptr");
    void* nativeBuffer = context;
    RefBase *ref = reinterpret_cast<RefBase *>(nativeBuffer);
    ref->DecStrongRef(ref);
}

static PixelMapMemHolder *CreatePixelMapData(const std::shared_ptr<AVSharedMemory> &mem, const OutputFrame &frame)
{
    PixelMapMemHolder *holder = new (std::nothrow) PixelMapMemHolder;
    CHECK_AND_RETURN_RET_LOG(holder != nullptr, nullptr, "alloc pixelmap mem holder failed");

    ON_SCOPE_EXIT(0) {
        delete holder;
    };

    CHECK_AND_RETURN_RET_LOG(frame.width_ > 0 && frame.width_ <= SURFACE_MAX_WIDTH, nullptr, "width info wrong");
    CHECK_AND_RETURN_RET_LOG(frame.height_ > 0 && frame.height_ <= SURFACE_MAX_HEIGHT, nullptr, "height info wrong");
    CHECK_AND_RETURN_RET_LOG(frame.bytesPerPixel_ > 0 && frame.bytesPerPixel_ <= MAX_BYTES_PER_PIXEL, nullptr,
        "bytesPerPixel info wrong");
    CHECK_AND_RETURN_RET_LOG(frame.stride_ > 0 && frame.stride_ <= MAX_STRIDE, nullptr, "stride info wrong");
    int32_t minStride = frame.width_ * frame.bytesPerPixel_;
    CHECK_AND_RETURN_RET_LOG(minStride <= frame.stride_, nullptr, "stride info wrong");

    if (frame.stride_ == minStride) {
        CANCEL_SCOPE_EXIT_GUARD(0);
        holder->isShmem = true;
        holder->shmem = mem;
        holder->heap = frame.GetFlattenedData();
        return holder;
    }

    static constexpr int64_t maxAllowedSize = 100 * 1024 * 1024;
    int64_t memSize = static_cast<int64_t>(minStride) * frame.height_;
    CHECK_AND_RETURN_RET_LOG(memSize <= maxAllowedSize, nullptr, "alloc heap size too large");

    uint8_t *heap = new (std::nothrow) uint8_t[memSize];
    CHECK_AND_RETURN_RET_LOG(heap != nullptr, nullptr, "alloc heap failed");

    ON_SCOPE_EXIT(1) {
        delete [] heap;
    };

    uint8_t *currDstPos = heap;
    uint8_t *currSrcPos = frame.GetFlattenedData();
    for (int32_t row = 0; row < frame.height_; ++row) {
        errno_t rc = memcpy_s(currDstPos, static_cast<size_t>(memSize), currSrcPos, static_cast<size_t>(minStride));
        CHECK_AND_RETURN_RET_LOG(rc == EOK, nullptr, "memcpy_s failed");

        currDstPos += minStride;
        currSrcPos += frame.stride_;
        memSize -= minStride;
    }

    holder->isShmem = false;
    holder->heap = heap;

    CANCEL_SCOPE_EXIT_GUARD(0);
    CANCEL_SCOPE_EXIT_GUARD(1);
    return holder;
}

static AVBufferHolder *CreateAVBufferHolder(const std::shared_ptr<AVBuffer> &avBuffer)
{
    CHECK_AND_RETURN_RET(avBuffer != nullptr && avBuffer->memory_ != nullptr, nullptr);
    AVBufferHolder *holder = new (std::nothrow) AVBufferHolder;
    CHECK_AND_RETURN_RET_LOG(holder != nullptr, nullptr, "alloc avBuffer holder failed");
    holder->buffer = avBuffer;
    return holder;
}

static std::shared_ptr<PixelMap> CreatePixelMap(const std::shared_ptr<AVSharedMemory> &mem, PixelFormat color,
    int32_t &rotation)
{
    CHECK_AND_RETURN_RET_LOG(mem != nullptr, nullptr, "Fetch frame failed");
    CHECK_AND_RETURN_RET_LOG(mem->GetBase() != nullptr, nullptr, "Addr is nullptr");
    CHECK_AND_RETURN_RET_LOG(mem->GetSize() > 0, nullptr, "size is incorrect");
    CHECK_AND_RETURN_RET_LOG(static_cast<uint32_t>(mem->GetSize()) >= sizeof(OutputFrame),
                             nullptr, "size is incorrect");

    OutputFrame *frame = reinterpret_cast<OutputFrame *>(mem->GetBase());
    MEDIA_LOGD("width: %{public}d, stride : %{public}d, height: %{public}d, size: %{public}d, format: %{public}d",
        frame->width_, frame->stride_, frame->height_, frame->size_, color);

    rotation = frame->rotation_;
    InitializationOptions opts;
    opts.size.width = frame->width_;
    opts.size.height = frame->height_;
    opts.pixelFormat = color;
    opts.editable = true;
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(opts);

    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "pixelMap create failed");
    CHECK_AND_RETURN_RET_LOG(pixelMap->GetByteCount() <= frame->size_, nullptr, "Size inconsistent !");

    PixelMapMemHolder *holder = CreatePixelMapData(mem, *frame);
    CHECK_AND_RETURN_RET_LOG(holder != nullptr, nullptr, "create pixel map data failed");

    pixelMap->SetPixelsAddr(holder->heap, holder, static_cast<uint32_t>(pixelMap->GetByteCount()),
        AllocatorType::CUSTOM_ALLOC, FreePixelMapData);
    return pixelMap;
}

int32_t AVMetadataHelperImpl::SaveDataToFile(const std::string &fileName, const char *data, const size_t &totalSize)
{
    CHECK_AND_RETURN_RET_LOG(data != nullptr, MSERR_INVALID_VAL, "data is nullptr");
    auto rootPath = FILE_DIR_IN_THE_SANDBOX;
    auto fullPath = rootPath + fileName;
    char realPath[PATH_MAX] = { 0x00 };
    CHECK_AND_RETURN_RET((fullPath.length() < PATH_MAX) && (realpath(rootPath.c_str(), realPath) != nullptr),
                         MSERR_INVALID_VAL);
    std::string verifiedPath(realPath);
    std::ofstream outFile(verifiedPath.append("/" + fileName), std::ofstream::out);
    if (!outFile.is_open()) {
        MEDIA_LOGW("SaveDataToFile write error, path=%{public}s", verifiedPath.c_str());
        return MSERR_UNKNOWN;
    }

    outFile.write(data, totalSize);
    return MSERR_OK;
}

void AVMetadataHelperImpl::InitDumpFlag()
{
    const std::string dumpTag = "sys.media.avmetadatahelper.dump.enable";
    std::string dumpEnable;
    int32_t dumpRes = OHOS::system::GetStringParameter(dumpTag, dumpEnable, "false");
    isDump_ = (dumpEnable == "true");
    MEDIA_LOGD("get dump flag, dumpRes: %{public}d, isDump_: %{public}d", dumpRes, isDump_);
}

int32_t AVMetadataHelperImpl::DumpPixelMap(bool isDump, std::shared_ptr<PixelMap> pixelMap,
                                           const std::string &fileNameSuffix)
{
    if (!isDump) {
        return MSERR_INVALID_VAL;
    }
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, MSERR_INVALID_VAL, "invalid pixelMap");
    std::string width = std::to_string(pixelMap->GetWidth());
    std::string height = std::to_string(pixelMap->GetHeight());
    std::string pixelFormat = pixelFormatToString(pixelMap->GetPixelFormat());
    auto fileName = GetLocalTime() + "_" + width + "_" + height + "_" + pixelFormat + fileNameSuffix;
    if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        auto surfaceBuffer = static_cast<SurfaceBuffer*>(pixelMap->GetFd());
        CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, MSERR_INVALID_VAL, "invalid surface buffer");
        return SaveDataToFile(fileName,
                              reinterpret_cast<const char *>(surfaceBuffer->GetVirAddr()),
                              surfaceBuffer->GetSize());
    }
    return SaveDataToFile(fileName,
                          reinterpret_cast<const char *>(pixelMap->GetPixels()),
                          pixelMap->GetByteCount());
}

int32_t AVMetadataHelperImpl::DumpAVBuffer(bool isDump, const std::shared_ptr<AVBuffer> &frameBuffer,
                                           const std::string &fileNameSuffix)
{
    if (!isDump) {
        return MSERR_INVALID_VAL;
    }
    bool isValid = frameBuffer != nullptr && frameBuffer->meta_ != nullptr && frameBuffer->memory_ != nullptr;
    CHECK_AND_RETURN_RET_LOG(isValid, MSERR_INVALID_VAL, "invalid frame buffer");
    auto bufferMeta = frameBuffer->meta_;
    int32_t width = 0;
    int32_t height = 0;
    bool isHdr = false;
    bufferMeta->Get<Tag::VIDEO_WIDTH>(width);
    bufferMeta->Get<Tag::VIDEO_HEIGHT>(height);
    bufferMeta->Get<Tag::VIDEO_IS_HDR_VIVID>(isHdr);
    std::string widthStr = std::to_string(width);
    std::string heightStr = std::to_string(height);
    std::string pixelFormat = isHdr ? pixelFormatToString(PixelFormat::YCBCR_P010):
                              pixelFormatToString(PixelFormat::NV12);
    auto fileName = GetLocalTime() + "_" + widthStr + "_" + heightStr + "_" + pixelFormat + fileNameSuffix;
    auto surfaceBuffer = frameBuffer->memory_->GetSurfaceBuffer();
    if (surfaceBuffer == nullptr) {
        return SaveDataToFile(fileName,
                              reinterpret_cast<const char *>(frameBuffer->memory_->GetAddr()),
                              frameBuffer->memory_->GetSize());
    }
    return SaveDataToFile(fileName,
                          reinterpret_cast<const char *>(surfaceBuffer->GetVirAddr()),
                          surfaceBuffer->GetSize());
}

std::string AVMetadataHelperImpl::pixelFormatToString(PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case PixelFormat::RGB_565:
            return "RGB_565";
        case PixelFormat::RGBA_8888:
            return "RGBA_8888";
        case PixelFormat::RGB_888:
            return "RGB_888";
        case PixelFormat::NV12:
            return "NV12";
        case PixelFormat::YCBCR_P010:
            return "YCBCR_P010";
        default:
            return "UNKNOWN";
    }
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::CreatePixelMapYuv(const std::shared_ptr<AVBuffer> &frameBuffer,
                                                                  PixelMapInfo &pixelMapInfo)
{
    bool isValid = frameBuffer != nullptr && frameBuffer->meta_ != nullptr && frameBuffer->memory_ != nullptr;
    CHECK_AND_RETURN_RET_LOG(isValid, nullptr, "invalid frame buffer");
    auto bufferMeta = frameBuffer->meta_;

    int32_t width = 0;
    auto hasProperty = bufferMeta->Get<Tag::VIDEO_WIDTH>(width);
    CHECK_AND_RETURN_RET_LOG(hasProperty, nullptr, "invalid width");
    int32_t height = 0;
    hasProperty = bufferMeta->Get<Tag::VIDEO_HEIGHT>(height);
    CHECK_AND_RETURN_RET_LOG(hasProperty, nullptr, "invalid height");

    Plugins::VideoRotation rotation = Plugins::VideoRotation::VIDEO_ROTATION_0;
    bufferMeta->Get<Tag::VIDEO_ROTATION>(rotation);
    pixelMapInfo.rotation = static_cast<int32_t>(rotation);

    Plugins::VideoOrientationType orientation = Plugins::VideoOrientationType::ROTATE_NONE;
    bufferMeta->Get<Tag::VIDEO_ORIENTATION_TYPE>(orientation);
    pixelMapInfo.orientation = static_cast<int32_t>(orientation);

    bufferMeta->Get<Tag::VIDEO_IS_HDR_VIVID>(pixelMapInfo.isHdr);

    if (pixelMapInfo.pixelFormat == PixelFormat::UNKNOWN) {
        pixelMapInfo.pixelFormat = pixelMapInfo.isHdr ? PixelFormat::YCBCR_P010 : PixelFormat::NV12;
    }

    if (frameBuffer->memory_->GetSize() != 0 && frameBuffer->memory_->GetSurfaceBuffer() == nullptr) {
        InitializationOptions options = { .size = { .width = width, .height = height },
                                          .pixelFormat = PixelFormat::NV12 };
        return CreatePixelMapFromAVShareMemory(frameBuffer, pixelMapInfo, options);
    }

    auto surfaceBuffer = frameBuffer->memory_->GetSurfaceBuffer();
    CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, nullptr, "srcSurfaceBuffer is nullptr");

    pixelMapInfo.width = width;
    pixelMapInfo.height = height;
    int32_t outputHeight = height;
    bufferMeta->Get<Tag::VIDEO_SLICE_HEIGHT>(outputHeight);
    pixelMapInfo.outputHeight = outputHeight;
    MEDIA_LOGD("pixelMapInfo.outputHeight = %{public}d", pixelMapInfo.outputHeight);

    return CreatePixelMapFromSurfaceBuffer(surfaceBuffer, pixelMapInfo);
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::CreatePixelMapFromAVShareMemory(const std::shared_ptr<AVBuffer>
                                                                                &frameBuffer,
                                                                                PixelMapInfo &pixelMapInfo,
                                                                                InitializationOptions &options)
{
    bool isValid = frameBuffer != nullptr && frameBuffer->memory_ != nullptr;
    CHECK_AND_RETURN_RET_LOG(isValid, nullptr, "invalid frame buffer");
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(options);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Create pixelMap failed");
    AVBufferHolder *holder = CreateAVBufferHolder(frameBuffer);
    CHECK_AND_RETURN_RET_LOG(holder != nullptr, nullptr, "Create buffer holder failed");
    uint8_t *pixelAddr = frameBuffer->memory_->GetAddr();
    pixelMap->SetPixelsAddr(pixelAddr, holder, pixelMap->GetByteCount(),
                            AllocatorType::CUSTOM_ALLOC, FreeAvBufferData);
    const InitializationOptions opts = { .size = { .width = pixelMap->GetWidth(),
                                                   .height = pixelMap->GetHeight() },
                                         .srcPixelFormat = PixelFormat::NV12,
                                         .pixelFormat = pixelMapInfo.pixelFormat };
    pixelMap = PixelMap::Create(reinterpret_cast<const uint32_t *>(pixelMap->GetPixels()),
                                pixelMap->GetByteCount(), opts);
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    SetPixelMapYuvInfo(surfaceBuffer, pixelMap, pixelMapInfo, false);
    return pixelMap;
}

void AVMetadataHelperImpl::FormatColorSpaceInfo(CM_ColorSpaceInfo &colorSpaceInfo)
{
    switch (colorSpaceInfo.primaries) {
        case CM_ColorPrimaries::COLORPRIMARIES_P3_D65:
            if (colorSpaceInfo.matrix == CM_Matrix::MATRIX_BT601_P) {
                colorSpaceInfo.matrix = CM_Matrix::MATRIX_P3; // MATRIX_P3 equals MATRIX_BT601_P and MATRIX_BT601_N
            }
            break;
        case CM_ColorPrimaries::COLORPRIMARIES_BT601_P:
            if (colorSpaceInfo.matrix == CM_Matrix::MATRIX_BT601_N || colorSpaceInfo.matrix == CM_Matrix::MATRIX_P3) {
                colorSpaceInfo.matrix = CM_Matrix::MATRIX_BT601_P; // MATRIX_P3 equals MATRIX_BT601_P and MATRIX_BT601_N
            }
            break;
        default:
            break;
    }
}

Status AVMetadataHelperImpl::GetColorSpace(sptr<SurfaceBuffer> &surfaceBuffer, PixelMapInfo &pixelMapInfo)
{
    std::vector<uint8_t> colorSpaceInfoVec;
    if (surfaceBuffer->GetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec) != GSERROR_OK) {
        MEDIA_LOGW("cant find colorSpace");
        return Status::ERROR_UNKNOWN;
    }
    CHECK_AND_RETURN_RET_LOG(!colorSpaceInfoVec.empty(), Status::ERROR_UNKNOWN, "colorSpaceInfoVec is empty");
    auto outColor = reinterpret_cast<CM_ColorSpaceInfo *>(colorSpaceInfoVec.data());
    CHECK_AND_RETURN_RET_LOG(outColor != nullptr, Status::ERROR_UNKNOWN, "colorSpaceInfoVec init failed");
    auto colorSpaceInfo = outColor[0];
    FormatColorSpaceInfo(colorSpaceInfo);
    pixelMapInfo.srcRange = colorSpaceInfo.range == CM_Range::RANGE_FULL ? 1 : 0;
    auto type = ((static_cast<unsigned int>(colorSpaceInfo.primaries) << COLORPRIMARIES_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.transfunc) << TRANSFUNC_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.matrix) << MATRIX_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.range) << RANGE_OFFSET));
    pixelMapInfo.primaries = colorSpaceInfo.primaries;
    MEDIA_LOGI("colorSpaceType is %{public}u", type);
    if (pixelMapInfo.isHdr) {
        auto it = HDR_COLORSPACE_MAP.find(type);
        CHECK_AND_RETURN_RET_LOG(it != HDR_COLORSPACE_MAP.end(), Status::ERROR_UNKNOWN,
            "can't find mapped colorSpace name in hdr map");
        MEDIA_LOGI("video is hdr, colorspace info is [%{public}d, %{public}d]", it->first, it->second);
        pixelMapInfo.colorSpaceName = it->second;
        return Status::OK;
    }
    auto it = SDR_COLORSPACE_MAP.find(type);
    CHECK_AND_RETURN_RET_LOG(it != SDR_COLORSPACE_MAP.end(), Status::ERROR_UNKNOWN,
        "can't find mapped colorSpace name in sdr map");
    MEDIA_LOGI("video is sdr, colorspace info is [%{public}d, %{public}d]", it->first, it->second);
    pixelMapInfo.colorSpaceName = it->second;
    return Status::OK;
}

Status AVMetadataHelperImpl::GetColorSpaceWithDefaultValue(sptr<SurfaceBuffer> &surfaceBuffer,
                                                           PixelMapInfo &pixelMapInfo)
{
    std::vector<uint8_t> colorSpaceInfoVec;
    if (surfaceBuffer->GetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec) != GSERROR_OK) {
        MEDIA_LOGW("cant find colorSpace");
        return Status::ERROR_UNKNOWN;
    }
    CHECK_AND_RETURN_RET_LOG(!colorSpaceInfoVec.empty(), Status::ERROR_UNKNOWN, "colorSpaceInfoVec is empty");
    auto outColor = reinterpret_cast<CM_ColorSpaceInfo *>(colorSpaceInfoVec.data());
    CHECK_AND_RETURN_RET_LOG(outColor != nullptr, Status::ERROR_UNKNOWN, "colorSpaceInfoVec init failed");
    auto colorSpaceInfo = outColor[0];
    FormatColorSpaceInfo(colorSpaceInfo);
    pixelMapInfo.srcRange = colorSpaceInfo.range == CM_Range::RANGE_FULL ? 1 : 0;
    auto type = ((static_cast<unsigned int>(colorSpaceInfo.primaries) << COLORPRIMARIES_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.transfunc) << TRANSFUNC_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.matrix) << MATRIX_OFFSET) +
                 (static_cast<unsigned int>(colorSpaceInfo.range) << RANGE_OFFSET));
    pixelMapInfo.primaries = colorSpaceInfo.primaries;
    MEDIA_LOGI("colorSpaceTypeWithDefaultValue is %{public}u", type);

    // using SDR_COLORSPACE_MAP for colorspace query when convertColorSpace_ is false
    // do not distinguish between SDR and HDR
    auto it = SDR_COLORSPACE_MAP.find(type);
    CHECK_AND_RETURN_RET_LOG(it != SDR_COLORSPACE_MAP.end(), Status::ERROR_UNKNOWN,
        "can't find mapped colorSpace name in colorSpace map");
    MEDIA_LOGI("colorSpaceWithDefaultValue info is [%{public}d, %{public}d]", it->first, it->second);
    pixelMapInfo.colorSpaceName = it->second;
    return Status::OK;
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::CreatePixelMapFromSurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer,
                                                                                PixelMapInfo &pixelMapInfo)
{
    CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, nullptr, "surfaceBuffer is nullptr");
    auto getColorSpaceInfoRes = convertColorSpace_ ? GetColorSpace(surfaceBuffer, pixelMapInfo) :
        GetColorSpaceWithDefaultValue(surfaceBuffer, pixelMapInfo);
    InitializationOptions options = { .size = { .width = pixelMapInfo.width, .height = pixelMapInfo.height } };
    bool isHdr = pixelMapInfo.isHdr;
    options.srcPixelFormat = isHdr ? PixelFormat::YCBCR_P010 : PixelFormat::NV12;
    options.pixelFormat = isHdr ? PixelFormat::YCBCR_P010 : PixelFormat::NV12;
    options.useDMA = isHdr;
    bool needModifyStride = false;
    options.convertColorSpace.srcRange = pixelMapInfo.srcRange;
    int32_t colorLength = pixelMapInfo.width * pixelMapInfo.height * PIXEL_SIZE_HDR_YUV;
    colorLength = isHdr ? colorLength : colorLength / HDR_PIXEL_SIZE;
    std::shared_ptr<PixelMap> pixelMap;

    if (!options.useDMA) {
        pixelMap = PixelMap::Create(options);
        CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Create pixelMap failed");
        auto ret = CopySurfaceBufferToPixelMap(surfaceBuffer, pixelMap, pixelMapInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "CopySurfaceBufferToPixelMap failed");
        options.pixelFormat = pixelMapInfo.pixelFormat;
        int32_t primaries = pixelMapInfo.primaries;
        options.convertColorSpace.srcYuvConversion = primaries == CM_ColorPrimaries::COLORPRIMARIES_BT709 ?
            YuvConversion::BT709 : YuvConversion::BT601;
        options.convertColorSpace.dstYuvConversion = primaries == CM_ColorPrimaries::COLORPRIMARIES_BT709 ?
            YuvConversion::BT709 : YuvConversion::BT601;
        MEDIA_LOGD("conversion: %{public}d", options.convertColorSpace.srcYuvConversion);
        pixelMap = PixelMap::Create(reinterpret_cast<const uint32_t *>(pixelMap->GetPixels()),
                                    pixelMap->GetByteCount(), options);
        CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Create non-DMA pixelMap failed");
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
            getColorSpaceInfoRes == Status::OK ? pixelMapInfo.colorSpaceName : ColorManager::SRGB));
    } else {
        pixelMap = PixelMap::Create(reinterpret_cast<const uint32_t *>(surfaceBuffer->GetVirAddr()),
                                    static_cast<uint32_t>(colorLength), options);
        CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Create DMA pixelMap failed");
        void* nativeBuffer = surfaceBuffer.GetRefPtr();
        RefBase *ref = reinterpret_cast<RefBase *>(nativeBuffer);
        ref->IncStrongRef(ref);
        if (isHdr) {
            pixelMap->SetHdrType(ImageHdrType::HDR_VIVID_SINGLE);
            pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
                getColorSpaceInfoRes == Status::OK ? pixelMapInfo.colorSpaceName : ColorManager::BT2020_HLG));
        }
        pixelMap->SetPixelsAddr(surfaceBuffer->GetVirAddr(), surfaceBuffer.GetRefPtr(), surfaceBuffer->GetSize(),
                                AllocatorType::DMA_ALLOC, FreeSurfaceBuffer);
        needModifyStride = true;
    }
    
    SetPixelMapYuvInfo(surfaceBuffer, pixelMap, pixelMapInfo, needModifyStride);

    return pixelMap;
}

int32_t AVMetadataHelperImpl::CopySurfaceBufferToPixelMap(sptr<SurfaceBuffer> &surfaceBuffer,
                                                          std::shared_ptr<PixelMap> pixelMap,
                                                          PixelMapInfo &pixelMapInfo)
{
    CHECK_AND_RETURN_RET(surfaceBuffer != nullptr && pixelMap != nullptr, MSERR_INVALID_VAL);
    int32_t width = surfaceBuffer->GetWidth();
    int32_t height = surfaceBuffer->GetHeight();
    int32_t stride = surfaceBuffer->GetStride();

    CHECK_AND_RETURN_RET(width > 0 && height > 0 && stride > 0, MSERR_INVALID_VAL);
    CHECK_AND_RETURN_RET(pixelMapInfo.outputHeight > 0, MSERR_INVALID_VAL);

    static int32_t uvDivBase = 2;
    CHECK_AND_RETURN_RET(INT64_MAX - (static_cast<int64_t>(stride) * pixelMapInfo.outputHeight)
        >= static_cast<int64_t>(stride) * height / uvDivBase, MSERR_INVALID_VAL);
    int64_t copySrcSize = std::max(static_cast<int64_t>(stride) * height,
        static_cast<int64_t>(stride) * pixelMapInfo.outputHeight + static_cast<int64_t>(stride) * height / uvDivBase);
    CHECK_AND_RETURN_RET(static_cast<int64_t>(surfaceBuffer->GetSize()) >= copySrcSize, MSERR_INVALID_VAL);
 
    CHECK_AND_RETURN_RET(INT64_MAX - (static_cast<int64_t>(width) * height) >=
        static_cast<int64_t>(width) * height / uvDivBase, MSERR_INVALID_VAL);
    int64_t copyDstSize = static_cast<int64_t>(width) * height + static_cast<int64_t>(width) * height / uvDivBase;
    CHECK_AND_RETURN_RET(static_cast<int64_t>(pixelMap->GetCapacity()) >= copyDstSize, MSERR_INVALID_VAL);

    uint8_t *srcPtr = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr());
    uint8_t *dstPtr = const_cast<uint8_t *>(pixelMap->GetPixels());
        // copy src Y component to dst
    int32_t lineByteCount = width;
    for (int32_t y = 0; y < height; y++) {
        auto ret = memcpy_s(dstPtr, lineByteCount, srcPtr, lineByteCount);
        TRUE_LOG(ret != EOK, MEDIA_LOGW, "Memcpy Y component failed.");
        srcPtr += stride;
        dstPtr += lineByteCount;
    }
    
    int64_t yOffset = static_cast<int64_t>(stride) * pixelMapInfo.outputHeight;
    CHECK_AND_RETURN_RET(yOffset > 0, MSERR_INVALID_VAL);
    CHECK_AND_RETURN_RET(yOffset < static_cast<int64_t>(surfaceBuffer->GetSize()), MSERR_INVALID_VAL);
    srcPtr = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + yOffset;
 
    // copy src UV component to dst, height(UV) = height(Y) / 2
    for (int32_t uv = 0; uv < height / 2; uv++) {
        auto ret = memcpy_s(dstPtr, lineByteCount, srcPtr, lineByteCount);
        TRUE_LOG(ret != EOK, MEDIA_LOGW, "Memcpy UV component failed.");
        srcPtr += stride;
        dstPtr += lineByteCount;
    }
    return MSERR_OK;
}

void AVMetadataHelperImpl::SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer, std::shared_ptr<PixelMap> pixelMap,
                                              PixelMapInfo &pixelMapInfo, bool needModifyStride)
{
    CHECK_AND_RETURN_LOG(pixelMap != nullptr, "invalid pixelMap");
    uint8_t ratio = pixelMapInfo.isHdr ? HDR_PIXEL_SIZE : SDR_PIXEL_SIZE;
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    YUVDataInfo yuvDataInfo = { .yWidth = srcWidth,
                                .yHeight = srcHeight,
                                .uvWidth = srcWidth / 2,
                                .uvHeight = srcHeight / 2,
                                .yStride = srcWidth,
                                .uvStride = srcWidth,
                                .uvOffset = srcWidth * srcHeight};

    if (surfaceBuffer == nullptr || !needModifyStride) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return;
    }
    
    yuvDataInfo.yStride = planes->planes[PLANE_Y].columnStride / ratio;
    yuvDataInfo.uvStride = planes->planes[PLANE_U].columnStride / ratio;
    yuvDataInfo.yOffset = planes->planes[PLANE_Y].offset / ratio;
    yuvDataInfo.uvOffset = planes->planes[PLANE_U].offset / ratio;

    pixelMap->SetImageYUVInfo(yuvDataInfo);
}

std::shared_ptr<AVMetadataHelper> AVMetadataHelperFactory::CreateAVMetadataHelper()
{
    std::shared_ptr<AVMetadataHelperImpl> impl = std::make_shared<AVMetadataHelperImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new AVMetadataHelperImpl");

    int32_t ret = impl->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init AVMetadataHelperImpl");

    return impl;
}

int32_t AVMetadataHelperImpl::Init()
{
    avMetadataHelperService_ = MediaServiceFactory::GetInstance().CreateAVMetadataHelperService();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_NO_MEMORY,
        "failed to create avmetadatahelper service");
    InitDumpFlag();
    return MSERR_OK;
}

AVMetadataHelperImpl::AVMetadataHelperImpl()
{
    MEDIA_LOGD("AVMetadataHelperImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVMetadataHelperImpl::~AVMetadataHelperImpl()
{
    if (avMetadataHelperService_ != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyAVMetadataHelperService(avMetadataHelperService_);
        avMetadataHelperService_ = nullptr;
    }
    MEDIA_LOGD("AVMetadataHelperImpl:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t AVMetadataHelperImpl::SetHelperCallback(const std::shared_ptr<HelperCallback> &callback)
{
    MEDIA_LOGD("AVMetadataHelperImpl:0x%{public}06" PRIXPTR " SetHelperCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_SERVICE_DIED,
        "metadata helper service does not exist..");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    return avMetadataHelperService_->SetHelperCallback(callback);
}

void AVMetadataHelperImpl::SetScene(Scene scene)
{
    ReportSceneCode(scene);
}

void AVMetadataHelperImpl::ReportSceneCode(Scene scene)
{
    if (scene != Scene::AV_META_SCENE_CLONE && scene != Scene::AV_META_SCENE_BATCH_HANDLE) {
        return;
    }
    if (scene == Scene::AV_META_SCENE_BATCH_HANDLE && concurrentWorkCount_ < HIGH_CONCRENT_WORK_NUM) {
        return;
    }
    auto sceneCode = SCENE_CODE_MAP[scene];
    auto lastTsp = SCENE_TIMESTAMP_MAP[scene];
    auto now =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    auto duration = now - std::chrono::milliseconds(lastTsp);
    if (duration < std::chrono::milliseconds(SCENE_CODE_EFFECTIVE_DURATION_MS)) {
        return;
    }
    SCENE_TIMESTAMP_MAP[scene] = now.count();
    MEDIA_LOGI("Report scene code %{public}ld", sceneCode);
    int32_t ret = HiSysEventWrite(
        PERFORMANCE_STATS, "CPU_SCENE_ENTRY", OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "PACKAGE_NAME",
        "media_service", "SCENE_ID", std::to_string(sceneCode).c_str(), "HAPPEN_TIME", now.count());
    if (ret != MSERR_OK) {
        MEDIA_LOGW("report error");
    }
}

int32_t AVMetadataHelperImpl::SetSource(const std::string &uri, int32_t usage)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_NO_MEMORY,
        "avmetadatahelper service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), MSERR_INVALID_VAL, "uri is empty.");

    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);
    auto res = avMetadataHelperService_->SetSource(uri, usage);
    concurrentWorkCount_--;
    return res;
}

int32_t AVMetadataHelperImpl::SetAVMetadataCaller(AVMetadataCaller caller)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_NO_MEMORY,
        "avmetadatahelper service does not exist..");
    return avMetadataHelperService_->SetAVMetadataCaller(caller);
}

int32_t AVMetadataHelperImpl::SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_NO_MEMORY,
        "avmetadatahelper service does not exist..");
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), MSERR_INVALID_VAL, "uri is empty.");
    CHECK_AND_RETURN_RET_LOG((uri.find("http://") == 0 || uri.find("https://") == 0),
        MSERR_INVALID_VAL, "uri is error.");
    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);
    auto res = avMetadataHelperService_->SetUrlSource(uri, header);
    concurrentWorkCount_--;
    return res;
}

int32_t AVMetadataHelperImpl::SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, MSERR_NO_MEMORY,
        "avmetadatahelper service does not exist..");
    MEDIA_LOGI("Set file source fd: %{public}d, offset: %{public}" PRIu64 ", size: %{public}" PRIu64,
        fd, offset, size);
    CHECK_AND_RETURN_RET_LOG(fd > 0 && offset >= 0 && size >= -1, MSERR_INVALID_VAL,
        "invalid param");

    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);
    auto res = avMetadataHelperService_->SetSource(fd, offset, size, usage);
    concurrentWorkCount_--;
    return res;
}

int32_t AVMetadataHelperImpl::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    MEDIA_LOGD("AVMetadataHelperImpl:0x%{public}06" PRIXPTR " SetSource in(dataSrc)", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(dataSrc != nullptr, MSERR_INVALID_VAL, "failed to create data source");

    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);
    auto res = avMetadataHelperService_->SetSource(dataSrc);
    concurrentWorkCount_--;
    return res;
}

std::string AVMetadataHelperImpl::ResolveMetadata(int32_t key)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, "",
        "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->ResolveMetadata(key);
    concurrentWorkCount_--;
    return res;
}

std::unordered_map<int32_t, std::string> AVMetadataHelperImpl::ResolveMetadata()
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, {},
        "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->ResolveMetadata();
    concurrentWorkCount_--;
    return res;
}

std::shared_ptr<Meta> AVMetadataHelperImpl::GetAVMetadata()
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, nullptr,
        "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->GetAVMetadata();
    concurrentWorkCount_--;
    return res;
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperImpl::FetchArtPicture()
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, nullptr,
        "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->FetchArtPicture();
    concurrentWorkCount_--;
    return res;
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::FetchFrameAtTime(
    int64_t timeUs, int32_t option, const PixelMapParams &param)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, nullptr,
        "avmetadatahelper service does not exist.");

    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);

    OutputConfiguration config;
    config.colorFormat = param.colorFormat;
    config.dstHeight = param.dstHeight;
    config.dstWidth = param.dstWidth;

    auto mem = avMetadataHelperService_->FetchFrameAtTime(timeUs, option, config);
    auto pixelMap = CreatePixelMap(mem, PixelFormat::NV12, rotation_);

    concurrentWorkCount_--;

    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "pixelMap does not exist.");
 
    const InitializationOptions opts = { .size = { .width = pixelMap->GetWidth(), .height = pixelMap->GetHeight() },
                                         .srcPixelFormat = PixelFormat::NV12 };
    pixelMap =
        PixelMap::Create(reinterpret_cast<const uint32_t *>(pixelMap->GetPixels()), pixelMap->GetByteCount(), opts);
    if (pixelMap == nullptr) {
        return nullptr;
    }
    if (rotation_ > 0) {
        pixelMap->rotate(rotation_);
    }
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    bool needScale = (param.dstWidth > 0 && param.dstHeight > 0) &&
                     (param.dstWidth <= srcWidth && param.dstHeight <= srcHeight) &&
                     (param.dstWidth < srcWidth || param.dstHeight < srcHeight) && srcWidth > 0 && srcHeight > 0;
    if (needScale) {
        pixelMap->scale((1.0f * param.dstWidth) / srcWidth, (1.0f * param.dstHeight) / srcHeight);
    }
    return pixelMap;
}

void AVMetadataHelperImpl::ScalePixelMapWithEqualRatio(
    std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info, const PixelMapParams &param)
{
    CHECK_AND_RETURN_LOG(pixelMap != nullptr, "pixelMap is nullptr");
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    int32_t dstWidth = info.rotation % NUM_180 == 0 ? param.dstWidth : param.dstHeight;
    int32_t dstHeight = info.rotation % NUM_180 == 0 ? param.dstHeight : param.dstWidth;

    bool needScale = (dstWidth > 0 || dstHeight > 0) && (srcWidth > 0 && srcHeight > 0) &&
        (dstWidth <= srcWidth && dstHeight <= srcHeight) && (dstWidth < srcWidth || dstHeight < srcHeight);
    CHECK_AND_RETURN(needScale);

    float widthFactor = dstWidth > 0 ? (1.0f * dstWidth) / srcWidth : 1.0f;
    float heightFactor = dstHeight > 0 ? (1.0f * dstHeight) / srcHeight : 1.0f;

    if (dstWidth == 0) {
        widthFactor = heightFactor;
    } else if (dstHeight == 0) {
        heightFactor = widthFactor;
    }
    pixelMap->scale(widthFactor, heightFactor, AntiAliasingOption::LOW);
    MEDIA_LOGI("srcWidth: %{public}d, srcHeight : %{public}d, dstWidth: %{public}d, dstHeight: %{public}d,"
        "widthFactor: %{public}f, HeightFactor: %{public}f, finalWidth: %{public}d, finalHeight : %{public}d",
        srcWidth, srcHeight, dstWidth, dstHeight, widthFactor, heightFactor,
        pixelMap->GetWidth(), pixelMap->GetHeight());
}

void AVMetadataHelperImpl::ScalePixelMap(
    std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info, const PixelMapParams &param)
{
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    int32_t dstWidth = info.rotation % NUM_180 == 0 ? param.dstWidth : param.dstHeight;
    int32_t dstHeight = info.rotation % NUM_180 == 0 ? param.dstHeight : param.dstWidth;
    bool needScale = (dstWidth > 0 && dstHeight > 0) &&
                     (dstWidth <= srcWidth && dstHeight <= srcHeight) &&
                     (dstWidth < srcWidth || dstHeight < srcHeight) && srcWidth > 0 && srcHeight > 0;
    CHECK_AND_RETURN(needScale);
    pixelMap->scale((1.0f * dstWidth) / srcWidth, (1.0f * dstHeight) / srcHeight, AntiAliasingOption::LOW);
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::FetchFrameYuv(int64_t timeUs, int32_t option,
                                                              const PixelMapParams &param)
{
    return FetchFrameBase(timeUs, option, param, FrameScaleMode::NORMAL_RATIO);
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::FetchScaledFrameYuv(int64_t timeUs, int32_t option,
                                                                    const PixelMapParams &param)
{
    return FetchFrameBase(timeUs, option, param, FrameScaleMode::ASPECT_RATIO);
}

std::shared_ptr<PixelMap> AVMetadataHelperImpl::FetchFrameBase(int64_t timeUs, int32_t option,
                                                               const PixelMapParams &param, int32_t scaleMode)
{
    std::shared_ptr<IAVMetadataHelperService> avMetadataHelperService = avMetadataHelperService_;
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService != nullptr, nullptr, "avmetadatahelper service does not exist.");

    concurrentWorkCount_++;
    ReportSceneCode(AV_META_SCENE_BATCH_HANDLE);
    OutputConfiguration config = { .dstWidth = param.dstWidth,
                                   .dstHeight = param.dstHeight,
                                   .colorFormat = param.colorFormat };
    auto frameBuffer = avMetadataHelperService->FetchFrameYuv(timeUs, option, config);
    CHECK_AND_RETURN_RET(frameBuffer != nullptr && frameBuffer->memory_ != nullptr, nullptr);
    concurrentWorkCount_--;
    
    DumpAVBuffer(isDump_, frameBuffer, DUMP_FILE_NAME_AVBUFFER);

    PixelMapInfo pixelMapInfo = { .pixelFormat = param.colorFormat };
    convertColorSpace_ = param.convertColorSpace;
    auto pixelMap = CreatePixelMapYuv(frameBuffer, pixelMapInfo);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "convert to pixelMap failed");

    DumpPixelMap(isDump_, pixelMap, DUMP_FILE_NAME_PIXEMAP);

    ScalePixelMapByMode(pixelMap, pixelMapInfo, param, scaleMode);

    DumpPixelMap(isDump_, pixelMap, DUMP_FILE_NAME_AFTER_SCLAE);

    MEDIA_LOGI("Rotation is %{public}d, orientation is %{public}d", pixelMapInfo.rotation, pixelMapInfo.orientation);
    if (param.isSupportFlip && VIDEOORIENTATIONTYPE_ROTATION_MAP.count(pixelMapInfo.orientation) > 0) {
        MEDIA_LOGI("Support flip");
        auto itFlip = VIDEOORIENTATIONTYPE_FLIP_MAP.find(pixelMapInfo.orientation);
        CHECK_AND_RETURN_RET_LOG(itFlip != VIDEOORIENTATIONTYPE_FLIP_MAP.end(), nullptr,
            "can't find mapped orientation name in VIDEOORIENTATIONTYPE_FLIP_MAP");
        pixelMap->flip(itFlip->second.first, itFlip->second.second);
        auto itRotate = VIDEOORIENTATIONTYPE_ROTATION_MAP.find(pixelMapInfo.orientation);
        CHECK_AND_RETURN_RET_LOG(itRotate != VIDEOORIENTATIONTYPE_ROTATION_MAP.end(), nullptr,
            "can't find mapped orientation name in VIDEOORIENTATIONTYPE_ROTATION_MAP");
        pixelMap->rotate(itRotate->second);
    } else if (pixelMapInfo.rotation > 0) {
        MEDIA_LOGI("Not support flip");
        pixelMap->rotate(pixelMapInfo.rotation);
    }

    MEDIA_LOGI("final colorSpace %{public}u", pixelMap->InnerGetGrColorSpace().GetColorSpaceName());

    DumpPixelMap(isDump_, pixelMap, DUMP_FILE_NAME_AFTER_ROTATE);
    return pixelMap;
}

void AVMetadataHelperImpl::ScalePixelMapByMode(std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info,
                                               const PixelMapParams &param, int32_t scaleMode)
{
    CHECK_AND_RETURN_LOG(pixelMap != nullptr, "pixelMap is nullptr");
    switch (scaleMode) {
        case FrameScaleMode::NORMAL_RATIO:
            ScalePixelMap(pixelMap, info, param);
            break;
        case FrameScaleMode::ASPECT_RATIO:
            ScalePixelMapWithEqualRatio(pixelMap, info, param);
            break;
        default:
            break;
    }
}

int32_t AVMetadataHelperImpl::GetTimeByFrameIndex(uint32_t index, uint64_t &time)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, 0, "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->GetTimeByFrameIndex(index, time);
    concurrentWorkCount_--;
    return res;
}

int32_t AVMetadataHelperImpl::GetFrameIndexByTime(uint64_t time, uint32_t &index)
{
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperService_ != nullptr, 0, "avmetadatahelper service does not exist.");
    concurrentWorkCount_++;
    auto res = avMetadataHelperService_->GetFrameIndexByTime(time, index);
    concurrentWorkCount_--;
    return res;
}

void AVMetadataHelperImpl::Release()
{
    std::lock_guard<std::mutex> lock(releaseMutex_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Release", FAKE_POINTER(this));
    CHECK_AND_RETURN_LOG(avMetadataHelperService_ != nullptr, "avmetadatahelper service does not exist.");
    avMetadataHelperService_->Release();
    (void)MediaServiceFactory::GetInstance().DestroyAVMetadataHelperService(avMetadataHelperService_);
    avMetadataHelperService_ = nullptr;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Release out", FAKE_POINTER(this));
}
} // namespace Media
} // namespace OHOS
