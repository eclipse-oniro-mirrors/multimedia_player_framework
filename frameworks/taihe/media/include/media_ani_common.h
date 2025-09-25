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
#ifndef MEDIA_ANI_COMMON_H
#define MEDIA_ANI_COMMON_H

#include "common_taihe.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "meta/format.h"

namespace ANI {
namespace Media {

struct DataSrcDescriptor {
    int64_t fileSize = 0;
    std::shared_ptr<uintptr_t> callback = nullptr;
};

struct AVPlayMediaStreamTmp {
    std::string url;
    uint32_t width;
    uint32_t height;
    uint32_t bitrate;
};

class AVMediaSourceTmp {
public:
    AVMediaSourceTmp() = default;
    ~AVMediaSourceTmp()
    {
        header.clear();
    }

    void SetMimeType(const std::string& mimeType)
    {
        mimeType_ = mimeType;
    }

    std::string GetMimeType() const
    {
        return mimeType_;
    }

    void AddAVPlayMediaStreamTmp(const AVPlayMediaStreamTmp& avPlayMediaStreamTmp)
    {
        mediaStreamVec_.push_back(avPlayMediaStreamTmp);
    }
 
    const std::vector<AVPlayMediaStreamTmp>& getAVPlayMediaStreamTmpList()
    {
        return mediaStreamVec_;
    }

    std::map<std::string, std::string> header;
    std::string url {};
    std::string mimeType_ {};
private:
    std::vector<AVPlayMediaStreamTmp> mediaStreamVec_;
};
}
}
#endif // MEDIA_ANI_COMMON_H