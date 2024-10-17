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

#ifndef OH_VEF_EFFECT_FACTORY_H
#define OH_VEF_EFFECT_FACTORY_H

#include <memory>
#include "data_center/effect/effect.h"

namespace OHOS {
namespace Media {

class EffectFactory {
public:
    static std::shared_ptr<Effect> CreateEffect(const std::string& description);

private:
    static EffectType ParseEffectType(const std::string& description);

private:
    static std::atomic<uint64_t> id_;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_EFFECT_FACTORY_H
