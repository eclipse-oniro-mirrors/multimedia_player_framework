/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SYSTEM_TONE_NAPI_H
#define SYSTEM_TONE_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "media_errors.h"
#include "system_sound_log.h"
#include "system_tone_options_napi.h"
#include "system_tone_player.h"
#include "system_tone_callback_napi.h"

namespace OHOS {
namespace Media {
extern const std::string SYSTEM_TONE_PLAYER_NAPI_CLASS_NAME;

class SystemTonePlayerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value GetSystemTonePlayerInstance(napi_env env, std::shared_ptr<SystemTonePlayer> &systemTonePlayer);

    SystemTonePlayerNapi();
    ~SystemTonePlayerNapi();

private:
    static void SystemTonePlayerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value SystemTonePlayerNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value GetTitle(napi_env env, napi_callback_info info);
    static napi_value Prepare(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value SetAudioVolumeScale(napi_env env, napi_callback_info info);
    static napi_value GetAudioVolumeScale(napi_env env, napi_callback_info info);
    static napi_value GetSupportedHapticsFeatures(napi_env env, napi_callback_info info);
    static napi_value SetHapticsFeature(napi_env env, napi_callback_info info);
    static napi_value GetHapticsFeature(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static void AsyncStart(napi_env env, void *data);
    static void AsyncStop(napi_env env, void *data);
    static void AsyncRelease(napi_env env, void *data);

    static void CommonAsyncCallbackComplete(napi_env env, napi_status status, void* data);
    static void GetTitleAsyncCallbackComplete(napi_env env, napi_status status, void *data);
    static void StartAsyncCallbackComplete(napi_env env, napi_status status, void *data);
    static bool VerifySelfSystemPermission();
    static napi_value ThrowErrorAndReturn(napi_env env, int32_t errCode, const std::string &errMsg);
    static napi_value RegisterCallback(napi_env env, napi_value jsThis, napi_value *argv, const std::string &cbName);
    static napi_value RegisterSystemTonePlayerCallback(napi_env env, napi_value *argv, const std::string &cbName,
        SystemTonePlayerNapi *systemTonePlayerNapi);
    static napi_value UnregisterCallback(napi_env env, napi_value jsThis, const std::string &cbName,
        const napi_value &callback);
    static void UnregisterSystemTonePlayerCallback(napi_env env, SystemTonePlayerNapi *systemTonePlayerNapi,
        const std::string &cbName, const napi_value &callback);

    napi_env env_;
    std::shared_ptr<SystemTonePlayer> systemTonePlayer_;
    std::shared_ptr<SystemTonePlayerFinishedAndErrorCallback> callbackNapi_ = nullptr;

    static thread_local napi_ref sConstructor_;
    static std::shared_ptr<SystemTonePlayer> sSystemTonePlayer_;
};

struct SystemTonePlayerAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    SystemTonePlayerNapi *objectInfo;
    std::string title;
    int32_t streamID;
    SystemToneOptions systemToneOptions {false, false};
    float volume;
    std::vector<ToneHapticsFeature> toneHapticsFeatures;
    ToneHapticsFeature toneHapticsFeature;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_TONE_NAPI_H