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

#include "tone_haptics_settings_taihe.h"
#include "media_log.h"

using namespace ANI::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "ToneHapticsSettingsNapi"};
constexpr int INVALID_TONE_HAPTICS_TYPE = -1;
}

namespace ANI::Media {
ToneHapticsSettingsTaihe::ToneHapticsSettingsTaihe() {}

ToneHapticsSettingsTaihe::~ToneHapticsSettingsTaihe() = default;

ToneHapticsSettings ToneHapticsSettingsTaihe::NewInstance(const OHOS::Media::ToneHapticsSettings &toneHapticsSettings)
{
    ToneHapticsSettings settings = {
        .mode = ToneHapticsMode::from_value(INVALID_TONE_HAPTICS_TYPE),
        .hapticsUri = optional<string>(std::in_place_t{}, ""),
    };
    std::unique_ptr<ToneHapticsSettingsTaihe> obj = std::make_unique<ToneHapticsSettingsTaihe>();
    CHECK_AND_RETURN_RET_LOG(obj != nullptr, settings, "obj is nullptr");
    obj->toneHapticsSettings_ = toneHapticsSettings;
    settings.mode = ToneHapticsMode::from_value(static_cast<int32_t>(toneHapticsSettings.mode));
    settings.hapticsUri = optional<string>(std::in_place_t{}, toneHapticsSettings.hapticsUri);
    return settings;
}
} // namespace ANI::Media