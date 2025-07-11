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

using namespace ANI::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVImageGeneratorTaihe"};
}
namespace ANI::Media {

AVImageGeneratorImpl::AVImageGeneratorImpl() {}

AVImageGeneratorImpl::AVImageGeneratorImpl(AVImageGeneratorImpl *obj)
{
    if (obj != nullptr) {
        helper_ = obj->helper_;
    }
}

optional<AVFileDescriptor> AVImageGeneratorImpl::GetFdSrc()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::get fd");
    AVFileDescriptor fdSrc;
    fdSrc.fd = fileDescriptor_.fd;
    fdSrc.offset = optional<int64_t>(std::in_place_t{}, fileDescriptor_.offset);
    fdSrc.length = optional<int64_t>(std::in_place_t{}, fileDescriptor_.length);
    return optional<AVFileDescriptor>(std::in_place_t{}, fdSrc);
}

void AVImageGeneratorImpl::SetFdSrc(optional_view<AVFileDescriptor> fdSrc)
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::set fd");
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_IDLE) {
        MEDIA_LOGE("Has set source once, unsupport set again");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("Invalid AVImageGenerator.");
        return;
    }
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
    return;
}

void AVImageGeneratorImpl::ReleaseSync()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::ReleaseSync");
    if (helper_ == nullptr) {
        MEDIA_LOGE("AVMetadataExtractorTaihe. is nullptr");
    } else {
        helper_->Release();
    }
}

AVImageGenerator CreateAVImageGeneratorSync()
{
    OHOS::Media::MediaTrace trace("AVImageGeneratorTaihe::CreateAVImageGeneratorSync");
    AVImageGeneratorImpl *extractor = new AVImageGeneratorImpl();
    std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper =
        OHOS::Media::AVMetadataHelperFactory::CreateAVMetadataHelper();
    extractor->helper_ = avMetadataHelper;
    CHECK_AND_RETURN_RET_LOG(extractor->helper_ != nullptr,
        (make_holder<AVImageGeneratorImpl, AVImageGenerator>(nullptr)), "failed to CreateMetadataHelper");
    return make_holder<AVImageGeneratorImpl, AVImageGenerator>(extractor);
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVImageGeneratorSync(CreateAVImageGeneratorSync);