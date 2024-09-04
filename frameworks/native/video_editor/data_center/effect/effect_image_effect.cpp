/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "data_center/effect/effect_image_effect.h"
#include "render/graphics/graphics_render_info.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "DataCenter"};
}

namespace OHOS {
namespace Media {

EffectImageEffect::EffectImageEffect(uint64_t id, const std::string& description)
    : Effect(id, EffectType::IMAGE_EFFECT), description_(description)
{
}

VEFError EffectImageEffect::Init()
{
#ifdef IMAGE_EFFECT_SUPPORT
    OH_ImageEffect* imageEffect = OH_ImageEffect_Restore(description_.c_str());
    if (imageEffect == nullptr) {
        MEDIA_LOGE("OH_ImageEffect_Restore failed.");
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("OH_ImageEffect_Restore finish.");
    imageEffectHandler_ = std::shared_ptr<OH_ImageEffect>(imageEffect, [](OH_ImageEffect *imageEffect) {
        auto ret = OH_ImageEffect_Release(imageEffect);
        if (ret != EFFECT_SUCCESS) {
            MEDIA_LOGE("OH_ImageEffect_Release failed, ret = %{public}d.", ret);
        }
    });
    return VEFError::ERR_OK;
#else
    MEDIA_LOGE("image effect is not supported.");
    return VEFError::ERR_EFFECT_IS_NOT_SUPPORTED;
#endif
}

std::shared_ptr<EffectRenderInfo> EffectImageEffect::GetRenderInfo() const
{
    auto info = std::make_shared<EffectRenderInfo>();
    info->id = id_;
    info->type = EffectType::IMAGE_EFFECT;
#ifdef IMAGE_EFFECT_SUPPORT
    info->imageEffect = this->imageEffectHandler_;
#endif
    return info;
}

} // namespace Media
} // namespace OHOS
