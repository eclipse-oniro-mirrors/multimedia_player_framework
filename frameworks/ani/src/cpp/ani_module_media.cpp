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
#include "avimagegenerator_ani.h"
#include "avplayer_ani.h"
#include "media_ani_utils.h"

using namespace OHOS::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "AVImageGeneratorAni" };
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        return (ani_status)ANI_ERROR;
    }

    static const char *staticClassName = "@ohos.multimedia.media.media";
    ani_namespace staticNs;
    if (ANI_OK != env->FindNamespace(staticClassName, &staticNs)) {
        MEDIA_LOGE("Not found %{public}s", staticClassName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"createAVPlayerAsync", nullptr,
            reinterpret_cast<void *>(AVPlayerAni::Constructor)},
        ani_native_function {"createAVImageGeneratorAsync", nullptr,
            reinterpret_cast<void *>(AVImageGeneratorAni::Constructor)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(staticNs, staticMethods.data(), staticMethods.size())) {
        MEDIA_LOGE("Cannot bind native methods to %{public}s", staticClassName);
        return ANI_ERROR;
    };

    ani_status status = AVImageGeneratorAni::AVImageGeneratorInit(env);
    if (status != ANI_OK) {
        MEDIA_LOGE("AVImageGenerator Init Failed");
        return status;
    }
    status = AVPlayerAni::AVPlayerAniInit(env);
    if (status != ANI_OK) {
        MEDIA_LOGE("AVPlayer Init Failed");
        return status;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}
