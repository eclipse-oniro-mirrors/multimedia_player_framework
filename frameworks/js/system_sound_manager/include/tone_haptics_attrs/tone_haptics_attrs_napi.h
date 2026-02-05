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

#ifndef TONE_HAPTICS_ATTRS_NAPI_H
#define TONE_HAPTICS_ATTRS_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "tone_haptics_attrs.h"

#include <memory>

namespace OHOS {
namespace Media {
extern const std::string TONE_HAPTICS_ATTRS_NAPI_CLASS_NAME;

class ToneHapticsAttrsNapi {
public:
    ToneHapticsAttrsNapi();
    ~ToneHapticsAttrsNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, std::shared_ptr<ToneHapticsAttrs> &nativeToneAttrs, napi_value &out);

private:
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value Construct(napi_env env, napi_callback_info info);

    static napi_value ThrowErrorAndReturn(napi_env env, const std::string &errMsg, int32_t errCode);
    static bool VerifySelfSystemPermission();

    static napi_value GetUri(napi_env env, napi_callback_info info);
    static napi_value GetTitle(napi_env env, napi_callback_info info);
    static napi_value GetFileName(napi_env env, napi_callback_info info);
    static napi_value GetGentleUri(napi_env env, napi_callback_info info);
    static napi_value GetGentleTitle(napi_env env, napi_callback_info info);
    static napi_value GetGentleFileName(napi_env env, napi_callback_info info);

    napi_env env_;
    std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs_;
    static thread_local napi_ref sConstructor_;
};
} // namespace Media
} // namespace OHOS
#endif // TONE_HAPTICS_ATTRS_NAPI_H