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

#ifndef TONE_ATTRS_TAIHE_H
#define TONE_ATTRS_TAIHE_H

#include <map>
#include "ohos.multimedia.systemSoundManager.proj.hpp"
#include "ohos.multimedia.systemSoundManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "tone_attrs.h"

namespace ANI::Media {
using WeakToneAttrsTaihe = ::ohos::multimedia::systemSoundManager::weak::ToneAttrs;
static const std::string TONE_ATTRS_TAIHE_CLASS_NAME = "ToneAttrs";

class ToneAttrsImpl {
public:
    ToneAttrsImpl();
    ToneAttrsImpl(std::shared_ptr<OHOS::Media::ToneAttrs>& nativeToneAttrs);
    std::shared_ptr<OHOS::Media::ToneAttrs> GetToneAttrs();

    int64_t GetImplPtr();

    bool VerifySelfSystemPermission();

    ::taihe::string GetTitle();
    void SetTitle(::taihe::string_view title);
    ::taihe::string GetFileName();
    void SetFileName(::taihe::string_view name);
    ::taihe::string GetUri();
    ::ohos::multimedia::systemSoundManager::ToneCustomizedType GetCustomizedType();
    void SetCategory(int64_t category);
    int64_t GetCategory();
    void SetMediaType(::ohos::multimedia::systemSoundManager::MediaType type);
    ::ohos::multimedia::systemSoundManager::MediaType GetMediaType();

    bool CheckNativeToneAttrs();
    bool CheckPermission();

    std::shared_ptr<OHOS::Media::ToneAttrs> toneAttrs_;
};
} // namespace ANI::Media
#endif // TONE_ATTRS_TAIHE_H
