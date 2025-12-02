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

#include "avimagegenerator_taihe.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "fd_utils.h"
#include "pixel_map_taihe.h"

using namespace ANI::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVImageGeneratorTaihe"};
}
namespace ANI::Media {

AVImageGeneratorImpl::AVImageGeneratorImpl() {}

AVImageGeneratorImpl::AVImageGeneratorImpl(std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper)
{
    helper_ = avMetadataHelper;
}

optional<AVFileDescriptor> AVImageGeneratorImpl::GetFdSrc()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::get fd");
    MEDIA_LOGI("GetFdSrc In");
    AVFileDescriptor fdSrc;
    fdSrc.fd = fileDescriptor_.fd;
    fdSrc.offset = optional<int64_t>(std::in_place_t{}, fileDescriptor_.offset);
    fdSrc.length = optional<int64_t>(std::in_place_t{}, fileDescriptor_.length);
    MEDIA_LOGI("GetFdSrc Out");
    return optional<AVFileDescriptor>(std::in_place_t{}, fdSrc);
}

void AVImageGeneratorImpl::SetFdSrc(optional_view<AVFileDescriptor> fdSrc)
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::set fd");
    MEDIA_LOGI("SetFdSrc In");

    CHECK_AND_RETURN_LOG(state_ == OHOS::Media::HelperState::HELPER_STATE_IDLE,
        "Has set source once, unsupport set again");
    CHECK_AND_RETURN_LOG(helper_ != nullptr, "Invalid AVImageGenerator.");

    if (fdSrc.has_value()) {
        fileDescriptor_.fd = fdSrc.value().fd;
        if (fdSrc.value().offset.has_value()) {
            fileDescriptor_.offset = fdSrc.value().offset.value();
        }
        if (fdSrc.value().length.has_value()) {
            fileDescriptor_.length = fdSrc.value().length.value();
        }
    }
#ifdef __linux__
    FILE *reopenFile = nullptr;
    auto res = ANI::Media::FdUtils::ReOpenFd(fileDescriptor_.fd, reopenFile);
    fileDescriptor_.fd = res == OHOS::Media::MSERR_OK ? fileno(reopenFile) : fileDescriptor_.fd;
    res = helper_->SetSource(fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    if (reopenFile != nullptr) {
        fclose(reopenFile);
    }
#else
    auto res = helper_->SetSource(fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
#endif
    state_ = res == OHOS::Media::MSERR_OK ?
        OHOS::Media::HelperState::HELPER_STATE_RUNNABLE : OHOS::Media::HelperState::HELPER_ERROR;
    MEDIA_LOGI("SetFdSrc Out");
    return;
}

optional<::ohos::multimedia::image::image::PixelMap> AVImageGeneratorImpl::FetchFrameByTimeSync(int64_t timeUs,
    AVImageQueryOptions options, PixelMapParams const& param)
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::FetchFrameByTimeSync");
    MEDIA_LOGI("FetchFrameByTimeSync  in");
    AVImageGeneratorImpl *taihe = this;
    if (taihe->state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "Current state is not runnable, can't fetchFrame.");
        return optional<::ohos::multimedia::image::image::PixelMap>(std::nullopt);
    }
    OHOS::Media::PixelMapParams pixelMapParams;
    if (param.height.has_value()) {
        pixelMapParams.dstHeight = param.height.value();
    }
    if (param.width.has_value()) {
        pixelMapParams.dstWidth = param.width.value();
    }
    OHOS::Media::PixelFormat colorFormat = OHOS::Media::PixelFormat::RGBA_8888;
    if (param.colorFormat.has_value()) {
        int32_t formatVal = static_cast<int32_t>(param.colorFormat.value());
        colorFormat = static_cast<OHOS::Media::PixelFormat>(formatVal);
        if (colorFormat != OHOS::Media::PixelFormat::RGB_565 && colorFormat !=
            OHOS::Media::PixelFormat::RGB_888 &&
            colorFormat != OHOS::Media::PixelFormat::RGBA_8888) {
            set_business_error(OHOS::Media::MSERR_INVALID_VAL, "formatVal is invalid");
            return optional<::ohos::multimedia::image::image::PixelMap>(std::nullopt);
        }
    }
    pixelMapParams.colorFormat = colorFormat;
    auto pixelMap = helper_->FetchFrameYuv(timeUs, options.get_value(), pixelMapParams);
    MEDIA_LOGI("FetchFrameByTimeSync Out");
    return optional<::ohos::multimedia::image::image::PixelMap>(std::in_place_t{},
        Image::PixelMapImpl::CreatePixelMap(pixelMap));
}

optional<::ohos::multimedia::image::image::PixelMap> AVImageGeneratorImpl::FetchScaledFrameByTimeSync(
    int64_t timeUs, AVImageQueryOptions options, optional_view<OutputSize> param)
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::FetchScaledFrameByTimeSync");
    MEDIA_LOGI("FetchScaledFrameByTimeSync  in");
    AVImageGeneratorImpl *taihe = this;
    if (taihe->state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "Current state is not runnable, can't fetchFrame.");
        return optional<::ohos::multimedia::image::image::PixelMap>(std::nullopt);
    }
    OHOS::Media::PixelMapParams pixelMapParams;
    if (param.has_value()) {
        if (param->height.has_value()) {
            pixelMapParams.dstHeight = param->height.value();
        }
        if (param->width.has_value()) {
            pixelMapParams.dstWidth = param->width.value();
        }
    }

    OHOS::Media::PixelFormat colorFormat = OHOS::Media::PixelFormat::UNKNOWN;
    pixelMapParams.colorFormat = colorFormat;
    auto pixelMap = helper_->FetchScaledFrameYuv(timeUs, options.get_value(), pixelMapParams);
    MEDIA_LOGI("FetchScaledFrameByTimeSync Out");
    return optional<::ohos::multimedia::image::image::PixelMap>(std::in_place_t{},
        Image::PixelMapImpl::CreatePixelMap(pixelMap));
}

void AVImageGeneratorImpl::ReleaseSync()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::ReleaseSync");
    MEDIA_LOGI("ReleaseSync In");
    if (state_ == OHOS::Media::HelperState::HELPER_STATE_RELEASED) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("AVImageGenerator is nullptr");
    } else {
        helper_->Release();
    }
    MEDIA_LOGI("ReleaseSync Out");
}

optional<AVImageGenerator> CreateAVImageGeneratorSync()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::CreateAVImageGeneratorSync");
    MEDIA_LOGI("TaiheCreateAVImageGenerator In");
    std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper =
        OHOS::Media::AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, optional<AVImageGenerator>(std::nullopt),
        "failed to CreateMetadataHelper");
    auto res = make_holder<AVImageGeneratorImpl, AVImageGenerator>(avMetadataHelper);
    return optional<AVImageGenerator>(std::in_place, res);
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVImageGeneratorSync(CreateAVImageGeneratorSync);