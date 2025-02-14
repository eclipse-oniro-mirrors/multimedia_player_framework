/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SOURCE_FFI_H
#define MEDIA_SOURCE_FFI_H

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "player.h"

namespace OHOS {
namespace Media {

struct Header {
    char *key;
    char *value;
};

struct ArrHeaders {
    Header *headers;
    int64_t size;
};

class CJMediaSource : public OHOS::FFI::FFIData {
    DECL_TYPE(CJMediaSource, OHOS::FFI::FFIData)
public:
    CJMediaSource(std::string sourceUrl, std::map<std::string, std::string> sourceHeader);
    ~CJMediaSource() = default;

    std::shared_ptr<AVMediaSource> mediaSource{nullptr};
};
extern "C" {
// MediaSource
FFI_EXPORT int64_t FfiMediaCreateMediaSourceWithUrl(char *url, ArrHeaders headers, int32_t *errCode);
} // extern "C"
} // namespace Media
} // namespace OHOS
#endif