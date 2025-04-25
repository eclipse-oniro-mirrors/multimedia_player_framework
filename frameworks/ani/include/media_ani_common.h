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
#ifndef FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_COMMON_H
#define FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_COMMON_H

#include "ani.h"
#include "media_log.h"
#include "meta/format.h"

namespace OHOS {
namespace Media {

struct AutoRef {
    AutoRef(ani_env *env, ani_ref cb)
        : env_(env), cb_(cb)
    {
    }
    ~AutoRef()
    {
        if (env_ != nullptr && cb_ != nullptr) {
            env_->GlobalReference_Delete(cb_);
        }
    }
    ani_env *env_;
    ani_ref cb_;
};

struct AVDataSrcDescriptor {
    int64_t fileSize = 0;
    ani_ref callback = nullptr;
};

class CommonAni {
public:
    static bool SetPropertyInt32(ani_env *env, ani_object &recordObject, ani_method setMethod,
        const std::string &key, int32_t value);
    static bool SetPropertyString(ani_env *env, ani_object &recordObject, ani_method setMethod,
        const std::string &key, const std::string &value);
    static ani_object CreateFormatBuffer(ani_env *env, Format &format);
};

}
}
#endif // FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_COMMON_H