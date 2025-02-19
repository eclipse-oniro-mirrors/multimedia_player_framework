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

#include "media_source_ffi.h"
#include "cj_avplayer_utils.h"
#include "player.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
std::map<std::string, std::string> ConvertArrHeaders(ArrHeaders &headers)
{
    std::map<std::string, std::string> mapHeaders;
    for (int64_t i = 0; i < headers.size; i++) {
        auto key = std::string(headers.headers[i].key);
        auto value = std::string(headers.headers[i].value);
        mapHeaders.insert({key, value});
    }
    return mapHeaders;
}

extern "C" {
int64_t FfiMediaCreateMediaSourceWithUrl(char *url, ArrHeaders headers, int32_t *errCode)
{
    auto mediaSrcImpl = FFIData::Create<CJMediaSource>(std::string(url), ConvertArrHeaders(headers));
    if (mediaSrcImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return INVALID_ID;
    }
    return mediaSrcImpl->GetID();
}
} // extern "C"

CJMediaSource::CJMediaSource(std::string sourceUrl, std::map<std::string, std::string> sourceHeader)
{
    AVMediaSource mediaSrc(sourceUrl, sourceHeader);
    mediaSource = std::make_shared<AVMediaSource>(mediaSrc);
}
} // namespace Media
} // namespace OHOS