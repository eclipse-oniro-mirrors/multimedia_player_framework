/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cj_avimagegenerator.h"
#include "media_log.h"
#include "pixel_map_impl.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "CJAVImageGeneratorImpl" };
}

namespace OHOS {
namespace Media {

CJAVImageGeneratorImpl::CJAVImageGeneratorImpl()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

sptr<CJAVImageGeneratorImpl> CJAVImageGeneratorImpl::Create()
{
    auto instance = FFI::FFIData::Create<CJAVImageGeneratorImpl>();
    if (instance == nullptr) {
        MEDIA_LOGE("Failed to new CJAVImageGeneratorImpl");
        return nullptr;
    }
    instance->helper_ = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (instance->helper_ == nullptr) {
        MEDIA_LOGE("Failed to CreateMetadataHelper");
        FFI::FFIData::Release(instance->GetID());
        return nullptr;
    }
    return instance;
}

int64_t CJAVImageGeneratorImpl::FetchFrameAtTime(int64_t timeUs, int32_t option, CPixelMapParams param)
{
    if (state_ != HelperState::HELPER_STATE_RUNNABLE) {
        MEDIA_LOGE("Current state is not runnable, can't fetchFrame.");
        return 0;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("helper_ is nullptr!");
        return -1;
    }
    auto pixelMap = helper_->FetchFrameYuv(
        timeUs, option, PixelMapParams{param.width, param.height, PixelFormat::RGBA_8888});
    auto result = FFI::FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (result == nullptr) {
        return 0;
    }
    return result->GetID();
}

int32_t CJAVImageGeneratorImpl::SetAVFileDescriptor(CAVFileDescriptor file)
{
    fileDescriptor_.fd = file.fd;
    fileDescriptor_.offset = file.offset;
    fileDescriptor_.length = file.length;
    MEDIA_LOGD("get fd argument, fd = %{public}d, offset = %{public}" PRIi64 ", size = %{public}" PRIi64 "",
        fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    if (helper_ == nullptr) {
        MEDIA_LOGE("helper_ is nullptr!");
        return -1;
    }
    auto res = helper_->SetSource(fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    return MSERR_OK;
}

int32_t CJAVImageGeneratorImpl::GetAVFileDescriptor(CAVFileDescriptor* data)
{
    if (data == nullptr) {
        return MSERR_INVALID_VAL;
    }
    data->fd = fileDescriptor_.fd;
    data->offset = fileDescriptor_.offset;
    data->length = fileDescriptor_.length;
    return MSERR_OK;
}

void CJAVImageGeneratorImpl::Release()
{
    if (state_ == HelperState::HELPER_STATE_RELEASED) {
        MEDIA_LOGE("Has released once, can't release again.");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("helper_ is nullptr!");
        return;
    }
    helper_->Release();
}

} // namespace Media
} // namespace OHOS
