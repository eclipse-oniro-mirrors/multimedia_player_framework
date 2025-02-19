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

#ifndef METADATAHELPER_FFI_H
#define METADATAHELPER_FFI_H
#include "cj_avimagegenerator.h"
#include "cj_avmetadataextractor.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "metadatahelper_util.h"

namespace OHOS {
namespace Media {
extern "C" {
FFI_EXPORT int64_t FfiCreateAVImageGenerator();
FFI_EXPORT int32_t FfiAVImageGeneratorGetFdSrc(int64_t id, CAVFileDescriptor* fd);
FFI_EXPORT int32_t FfiAVImageGeneratorSetFdSrc(int64_t id, CAVFileDescriptor fd);
FFI_EXPORT int64_t FfiFetchFrameByTime(int64_t id, int64_t timeUs, int32_t option, CPixelMapParams param);
FFI_EXPORT int32_t FfiAVImageGeneratorRelease(int64_t id);

FFI_EXPORT int64_t FfiCreateAVMetadataExtractor();
FFI_EXPORT int32_t FfiFetchMetadata(int64_t id, CAVMetadata* data);
FFI_EXPORT int64_t FfiFetchAlbumCover(int64_t id);
FFI_EXPORT int32_t FfiAVMetadataExtractorGetFdSrc(int64_t id, CAVFileDescriptor* fd);
FFI_EXPORT int32_t FfiAVMetadataExtractorSetFdSrc(int64_t id, CAVFileDescriptor fd);
FFI_EXPORT int32_t FfiAVMetadataExtractorGetDataSrc(int64_t id, CAVDataSrcDescriptor* data);
FFI_EXPORT int32_t FfiAVMetadataExtractorSetDataSrc(int64_t id, CAVDataSrcDescriptor data);
FFI_EXPORT int32_t FfiAVMetadataExtractorRelease(int64_t id);
}
} // namespace Media
} // namespace OHOS
#endif // METADATAHELPER_FFI_H
