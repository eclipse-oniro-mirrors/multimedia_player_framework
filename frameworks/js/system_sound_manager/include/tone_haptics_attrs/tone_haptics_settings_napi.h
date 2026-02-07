/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TONE_HAPTICS_SETTINGS_NAPI_H
#define TONE_HAPTICS_SETTINGS_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "tone_haptics_attrs.h"

namespace OHOS {
namespace Media {
extern const std::string TONE_HAPTICS_SETTINGS_NAPI_CLASS_NAME;

class ToneHapticsSettingsNapi {
public:
    ToneHapticsSettingsNapi();
    ~ToneHapticsSettingsNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, const ToneHapticsSettings &toneHapticsSettings, napi_value &out);

private:
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static napi_value GetMode(napi_env env, napi_callback_info info);
    static napi_value SetMode(napi_env env, napi_callback_info info);
    static napi_value GetHapticsUri(napi_env env, napi_callback_info info);
    static napi_value SetHapticsUri(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;

    ToneHapticsSettings toneHapticsSettings_;
    napi_env env_;
};
} // namespace Media
} // namespace OHOS
#endif // TONE_HAPTICS_SETTINGS_NAPI_H