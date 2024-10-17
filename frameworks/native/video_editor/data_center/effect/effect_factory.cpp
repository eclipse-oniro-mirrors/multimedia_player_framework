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
#include "data_center/effect/effect.h"
#include "data_center/effect/effect_factory.h"
#include "data_center/effect/effect_image_effect.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "DataCenter"};
}

std::atomic<uint64_t> EffectFactory::id_ = 1;

std::shared_ptr<Effect> EffectFactory::CreateEffect(const std::string& description)
{
    EffectType type = ParseEffectType(description);
    std::shared_ptr<Effect> result = nullptr;
    switch (type) {
        case EffectType::IMAGE_EFFECT: {
            auto effect = std::make_shared<EffectImageEffect>(id_.fetch_add(1), description);
            auto err = effect->Init();
            if (err != VEFError::ERR_OK) {
                MEDIA_LOGE("init effect[%{public}" PRIu64 "] failed, error: %{public}d", effect->GetId(), err);
            } else {
                result = effect;
                MEDIA_LOGI("init effect[%{public}" PRIu64 "] success.", effect->GetId());
            }
        }
            break;
        default:
            MEDIA_LOGE("unsupported effect type: %{public}u", type);
            break;
    }
    return result;
}

EffectType EffectFactory::ParseEffectType(const std::string& description)
{
    if (description.empty()) {
        MEDIA_LOGE("effect desc is empty.");
        return EffectType::UNKNOWN;
    }
    // currently, only IMAGE_EFFECT is supported.
    return EffectType::IMAGE_EFFECT;
}

} // namespace Media
} // namespace OHOS