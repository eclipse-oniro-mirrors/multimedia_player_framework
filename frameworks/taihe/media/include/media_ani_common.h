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

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "meta/format.h"

namespace ANI {
namespace Media {

struct AutoRef {
    AutoRef(ani_env *env, std::shared_ptr<uintptr_t> callback)
        : env_(env)
    {
        if (callback != nullptr) {
            callbackRef_ = callback;
        }
    }
    ~AutoRef()
    {
        env_ = nullptr;
        callbackRef_ = nullptr;
    }
    ani_env* env_ = nullptr;
    std::shared_ptr<uintptr_t> callbackRef_;
};

struct DataSrcDescriptor {
    int64_t fileSize = 0;
    std::shared_ptr<uintptr_t> callback = nullptr;
};

}
}
#endif // MEDIA_ANI_COMMON_H