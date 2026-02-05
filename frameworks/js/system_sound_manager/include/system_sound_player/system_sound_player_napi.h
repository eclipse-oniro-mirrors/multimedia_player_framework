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

#ifndef SYSTEM_SOUND_PLAYER_NAPI_H
#define SYSTEM_SOUND_PLAYER_NAPI_H

#include "system_sound_player.h"

#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
extern const std::string g_SYSTEM_SOUND_PLAYER_NAPI_CLASS_NAME;

class SystemSoundPlayerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateSystemSoundPlayerNapiInstance(napi_env env,
        std::shared_ptr<SystemSoundPlayer> systemSoundPlayer);
    SystemSoundPlayerNapi();
    ~SystemSoundPlayerNapi();

private:
    static napi_status DefineStaticProperties(napi_env env, napi_value exports);
    static napi_status DefineClassProperties(napi_env env, napi_value &ctorObj);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize_hint);

    static napi_value ThrowErrorAndReturn(napi_env env, const std::string& napiMessage, int32_t napiCode);
    static napi_value AsyncThrowErrorAndReturn(napi_env env, const std::string& napiMessage, int32_t napiCode);

    static bool IsSystemSoundTypeValid(int32_t systemSoundType);

    static napi_value Load(napi_env env, napi_callback_info info);
    static napi_value Play(napi_env env, napi_callback_info info);
    static napi_value Unload(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static void AsyncLoad(napi_env env, void *data);
    static void AsyncPlay(napi_env env, void *data);
    static void AsyncUnload(napi_env env, void *data);
    static void AsyncRelease(napi_env env, void *data);
    static void CommonAsyncComplete(napi_env env, napi_status status, void* data);

    static thread_local napi_ref g_constructor;
    static thread_local napi_ref g_systemSoundType;
    static std::shared_ptr<SystemSoundPlayer> g_systemSoundPlayer;

    napi_env env_;
    std::shared_ptr<SystemSoundPlayer> systemSoundPlayer_ = nullptr;
};

struct SystemSoundPlayerAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    int32_t errCode;
    std::string errMessage;
    SystemSoundPlayerNapi *objectInfo;
    int32_t systemSoundType;
};
} // namespace Media
} // namespace OHOS
#endif //SYSTEM_SOUND_PLAYER_NAPI_H