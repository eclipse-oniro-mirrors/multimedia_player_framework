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

#ifndef OH_VEF_EFFECT_BASE_H
#define OH_VEF_EFFECT_BASE_H

#include <memory>
#include "video_editor.h"

namespace OHOS {
namespace Media {

enum class EffectType : uint32_t {
    IMAGE_EFFECT,
    UNKNOWN
};

struct EffectRenderInfo;

class Effect {
public:
    virtual ~Effect() = default;
    Effect(uint64_t id, EffectType type);

public:
    uint64_t GetId() const;
    EffectType GetType() const;

    virtual VEFError Init() = 0;

    virtual std::shared_ptr<EffectRenderInfo> GetRenderInfo() const = 0;
protected:
    uint64_t id_{ 0 };
    EffectType type_{ EffectType::UNKNOWN };
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_EFFECT_BASE_H
