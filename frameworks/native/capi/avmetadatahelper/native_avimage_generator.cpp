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

#include "media_log.h"
#include "media_errors.h"
#include "native_mfmagic.h"
#include "native_player_magic.h"
#include "avimage_generator.h"
#include "pixelmap_native.h"
#include "pixelmap_native_impl.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "NativeAVImageGenerator" };
    constexpr int32_t DEFAULT_WIDTH = -1;
    constexpr int32_t DEFAULT_HEIGHT = -1;
}

using namespace OHOS::Media;

struct AVImageGeneratorObject : public OH_AVImageGenerator {
    explicit AVImageGeneratorObject(const std::shared_ptr<AVMetadataHelper> &aVMetadataHelper)
        : aVMetadataHelper_(aVMetadataHelper) {}
    ~AVImageGeneratorObject() = default;

    const std::shared_ptr<AVMetadataHelper> aVMetadataHelper_ = nullptr;
    std::atomic<HelperState> state_ = HelperState::HELPER_STATE_IDLE;
};

OH_AVImageGenerator* OH_AVImageGenerator_Create(void)
{
    std::shared_ptr<AVMetadataHelper> aVMetadataHelper =  AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(aVMetadataHelper != nullptr, nullptr,
                             "failed to AVMetadataHelperFactory::CreateAVMetadataHelper");

    struct AVImageGeneratorObject *object = new(std::nothrow) AVImageGeneratorObject(aVMetadataHelper);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new AVImageGeneratorObject");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVImageGenerator_Create", FAKE_POINTER(object));

    return object;
}

OH_AVErrCode OH_AVImageGenerator_SetFDSource(OH_AVImageGenerator* generator, int32_t fd, int64_t offset, int64_t size)
{
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, AV_ERR_INVALID_VAL, "input aVImageGenerator is nullptr");
    struct AVImageGeneratorObject *generatorObj = reinterpret_cast<AVImageGeneratorObject *>(generator);
    CHECK_AND_RETURN_RET_LOG(generatorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");
    
    CHECK_AND_RETURN_RET_LOG(fd >= 0, AV_ERR_INVALID_VAL, "fd is invalid");

    CHECK_AND_RETURN_RET_LOG(generatorObj->state_ == HelperState::HELPER_STATE_IDLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Has set source once, unsupport set again");
    
    int32_t ret = generatorObj->aVMetadataHelper_->SetSource(fd, offset, size);
    generatorObj->state_ = ret == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret == MSERR_NO_MEMORY ? AV_ERR_NO_MEMORY : AV_ERR_INVALID_VAL,
                             "aVImageGenerator setFdSource failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVImageGenerator_FetchFrameByTime(OH_AVImageGenerator* generator,
    int64_t timeUs, OH_AVImageGenerator_QueryOptions options, OH_PixelmapNative** pixelMap)
{
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, AV_ERR_INVALID_VAL, "input aVImageGenerator is nullptr");
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, AV_ERR_INVALID_VAL, "input pixelMap is nullptr");
    struct AVImageGeneratorObject *generatorObj = reinterpret_cast<AVImageGeneratorObject *>(generator);
    CHECK_AND_RETURN_RET_LOG(generatorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(generatorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchFrame.");
    
    PixelMapParams param = {
        .dstWidth = DEFAULT_WIDTH,
        .dstHeight = DEFAULT_HEIGHT,
        .colorFormat = PixelFormat::UNKNOWN,
    };
    auto pixelMapInner = generatorObj->aVMetadataHelper_->FetchFrameYuv(timeUs, static_cast<int32_t>(options), param);
    CHECK_AND_RETURN_RET_LOG(pixelMapInner != nullptr, AV_ERR_UNSUPPORTED_FORMAT, "aVImageGenerator FetchFrame failed");

    *pixelMap = new(std::nothrow) OH_PixelmapNative(pixelMapInner);
    CHECK_AND_RETURN_RET_LOG(*pixelMap != nullptr, AV_ERR_NO_MEMORY, "create OH_PixelmapNative failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVImageGenerator_Release(OH_AVImageGenerator* generator)
{
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, AV_ERR_INVALID_VAL, "input aVImageGenerator is nullptr");
    struct AVImageGeneratorObject *generatorObj = reinterpret_cast<AVImageGeneratorObject *>(generator);
    CHECK_AND_RETURN_RET_LOG(generatorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");
    generatorObj->aVMetadataHelper_->Release();
    delete generatorObj;
    return AV_ERR_OK;
}