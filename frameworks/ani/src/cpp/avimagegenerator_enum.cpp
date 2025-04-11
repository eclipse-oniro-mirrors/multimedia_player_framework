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
#include <map>
#include "avimagegenerator_enum.h"
#include "media_log.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "AVImageGeneratorAni" };
}

namespace OHOS {
namespace Media {
ani_status AVImageGeneratorEnumAni::EnumGetValueInt32(ani_env *env, ani_enum_item enumItem, int32_t &value)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");
    ani_int aniInt = 0;
    ani_status status = env->EnumItem_GetValue_Int(enumItem, &aniInt);
    if (status != ANI_OK) {
        MEDIA_LOGE("EnumItem_GetValue_Int failed");
        return status;
    }
    value = static_cast<int32_t>(aniInt);
    return ANI_OK;
}
}
}