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

#ifndef CJ_AVMETADATAEXTRACTOR_H
#define CJ_AVMETADATAEXTRACTOR_H

#include <cstdint>
#include <memory>
#include "avmetadatahelper.h"
#include "cj_helperdatasourcecallback.h"
#include "ffi_remote_data.h"
#include "image_source.h"
#include "media_core.h"
#include "metadatahelper_util.h"

namespace OHOS {
namespace Media {

class FFI_EXPORT CJAVMetadataExtractorImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(CJAVMetadataExtractorImpl, OHOS::FFI::FFIData)
public:
    static sptr<CJAVMetadataExtractorImpl> Create();
    CJAVMetadataExtractorImpl();
    ~CJAVMetadataExtractorImpl();
    int32_t FetchMetadata(CAVMetadata* data);
    int64_t FetchAlbumCover();
    int32_t SetAVFileDescriptor(CAVFileDescriptor file);
    int32_t GetAVFileDescriptor(CAVFileDescriptor* file);
    int32_t SetAVDataSrcDescriptor(CAVDataSrcDescriptor data);
    int32_t GetAVDataSrcDescriptor(CAVDataSrcDescriptor* data);
    int64_t FetchFrameByTime(int64_t timeUs, int32_t option, const CPixelMapParams& param);
    void Release();
private:
    std::shared_ptr<AVMetadataHelper> helper_ = nullptr;
    std::shared_ptr<CJHelperDataSourceCallback> dataSrcCb_ = nullptr;
    CAVFileDescriptor fileDescriptor_ = { .fd = 0, .offset = 0, .length = -1 };
    CAVDataSrcDescriptor dataSrcDescriptor_ = { .fileSize = 0, .callback = 0 };
    std::atomic<HelperState> state_ = HelperState::HELPER_STATE_IDLE;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_AVMETADATAEXTRACTOR_H
