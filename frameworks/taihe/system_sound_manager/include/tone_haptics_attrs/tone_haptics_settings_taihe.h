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

#ifndef TONE_HAPTICS_SETTINGS_TAIHE_H
#define TONE_HAPTICS_SETTINGS_TAIHE_H

#include "ohos.multimedia.systemSoundManager.proj.hpp"
#include "ohos.multimedia.systemSoundManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "tone_haptics_attrs.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::systemSoundManager;

class ToneHapticsSettingsTaihe {
public:
    ToneHapticsSettingsTaihe();
    ~ToneHapticsSettingsTaihe();

    static ToneHapticsSettings NewInstance(const OHOS::Media::ToneHapticsSettings &toneHapticsSettings);

private:
    OHOS::Media::ToneHapticsSettings toneHapticsSettings_;
};
} // namespace ANI::Media
#endif // TONE_HAPTICS_SETTINGS_TAIHE_H