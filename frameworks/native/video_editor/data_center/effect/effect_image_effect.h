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

#ifndef OH_VEF_EFFECT_IMAGE_EFFECT_H
#define OH_VEF_EFFECT_IMAGE_EFFECT_H

#include <memory>
#include <string>
#ifdef IMAGE_EFFECT_SUPPORT
#include "image_effect.h"
#endif
#include "data_center/effect/effect.h"
namespace OHOS {
namespace Media {

class EffectImageEffect : public Effect {
public:
    EffectImageEffect(uint64_t id, const std::string& description);
    ~EffectImageEffect() override = default;
    VEFError Init() override;
    std::shared_ptr<EffectRenderInfo> GetRenderInfo() const override;
private:
    std::string description_;
#ifdef IMAGE_EFFECT_SUPPORT
    std::shared_ptr<OH_ImageEffect> imageEffectHandler_ { nullptr };
#endif
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_EFFECT_IMAGE_EFFECT_H
