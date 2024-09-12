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

#ifndef OH_VEF_GRAPHICS_RENDER_INFO_H
#define OH_VEF_GRAPHICS_RENDER_INFO_H

#include <vector>
#include <memory>
#ifdef IMAGE_EFFECT_SUPPORT
#include "image_effect.h"
#endif

namespace OHOS {
namespace Media {

struct EffectRenderInfo {
    uint64_t id = 0;
    EffectType type = EffectType::UNKNOWN;
#ifdef IMAGE_EFFECT_SUPPORT
    std::shared_ptr<OH_ImageEffect> imageEffect;
#endif
};

class GraphicsRenderInfo {
public:
    GraphicsRenderInfo() = default;
    ~GraphicsRenderInfo() = default;
public:
    std::vector<std::shared_ptr<EffectRenderInfo>> effectInfoList_;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_GRAPHICS_RENDER_INFO_H
