/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TONE_HAPTICS_ATTRS_TAIHE_H
#define TONE_HAPTICS_ATTRS_TAIHE_H

#include <memory>

#include "ohos.multimedia.systemSoundManager.proj.hpp"
#include "ohos.multimedia.systemSoundManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "tone_haptics_attrs.h"

namespace ANI::Media {
static const std::string TONE_HAPTICS_ATTRS_TAIHE_CLASS_NAME = "ToneHapticsAttrs";

class ToneHapticsAttrsImpl {
public:
    ToneHapticsAttrsImpl();
    ToneHapticsAttrsImpl(std::shared_ptr<OHOS::Media::ToneHapticsAttrs> &nativeToneHapticsAttrs);
    bool VerifySelfSystemPermission();

    ::taihe::string GetUri();
    ::taihe::string GetTitle();
    ::taihe::string GetFileName();
    ::taihe::string GetGentleUri();
    ::taihe::string GetGentleTitle();
    ::taihe::string GetGentleFileName();

private:
    bool CheckNativeToneHapticsAttrs();
    bool CheckPermission();
    std::shared_ptr<OHOS::Media::ToneHapticsAttrs> toneHapticsAttrs_;
};
} // namespace ANI::Media
#endif // TONE_HAPTICS_ATTRS_TAIHE_H