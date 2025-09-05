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

#include "metadatahelper_ffi.h"
#include "cj_avimagegenerator.h"

namespace OHOS {
namespace Media {
extern "C" {

FFI_EXPORT int64_t FfiCreateAVImageGenerator()
{
    auto instance = CJAVImageGeneratorImpl::Create();
    if (instance == nullptr) {
        return 0;
    }
    return instance->GetID();
}

FFI_EXPORT int32_t FfiAVImageGeneratorGetFdSrc(int64_t id, CAVFileDescriptor* fd)
{
    auto instance = FFI::FFIData::GetData<CJAVImageGeneratorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->GetAVFileDescriptor(fd);
}

FFI_EXPORT int32_t FfiAVImageGeneratorSetFdSrc(int64_t id, CAVFileDescriptor fd)
{
    auto instance = FFI::FFIData::GetData<CJAVImageGeneratorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->SetAVFileDescriptor(fd);
}

FFI_EXPORT int64_t FfiFetchFrameByTime(int64_t id, int64_t timeUs, int32_t option, CPixelMapParams param)
{
    auto instance = FFI::FFIData::GetData<CJAVImageGeneratorImpl>(id);
    if (instance == nullptr) {
        return 0;
    }
    return instance->FetchFrameAtTime(timeUs, option, param);
}

FFI_EXPORT int32_t FfiAVImageGeneratorRelease(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CJAVImageGeneratorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    instance->Release();
    return MSERR_OK;
}

FFI_EXPORT int64_t FfiCreateAVMetadataExtractor()
{
    auto instance = CJAVMetadataExtractorImpl::Create();
    if (instance == nullptr) {
        return 0;
    }
    return instance->GetID();
}

FFI_EXPORT int32_t FfiFetchMetadata(int64_t id, CAVMetadata* data)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->FetchMetadata(data);
}

FFI_EXPORT int64_t FfiFetchAlbumCover(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return 0;
    }
    return instance->FetchAlbumCover();
}

FFI_EXPORT int32_t FfiAVMetadataExtractorGetFdSrc(int64_t id, CAVFileDescriptor* fd)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->GetAVFileDescriptor(fd);
}

FFI_EXPORT int32_t FfiAVMetadataExtractorSetFdSrc(int64_t id, CAVFileDescriptor fd)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->SetAVFileDescriptor(fd);
}

FFI_EXPORT int32_t FfiAVMetadataExtractorGetDataSrc(int64_t id, CAVDataSrcDescriptor* data)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->GetAVDataSrcDescriptor(data);
}

FFI_EXPORT int32_t FfiAVMetadataExtractorSetDataSrc(int64_t id, CAVDataSrcDescriptor data)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    return instance->SetAVDataSrcDescriptor(data);
}

FFI_EXPORT int64_t FfiAVMetadataExtractorFetchFrameByTime(
    int64_t id, int64_t timeUs, int32_t option, CPixelMapParams param)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return 0;
    }
    return instance->FetchFrameByTime(timeUs, option, param);
}

FFI_EXPORT int32_t FfiAVMetadataExtractorRelease(int64_t id)
{
    auto instance = FFI::FFIData::GetData<CJAVMetadataExtractorImpl>(id);
    if (instance == nullptr) {
        return MSERR_UNKNOWN;
    }
    instance->Release();
    return MSERR_OK;
}
}
} // namespace Media
} // namespace OHOS
