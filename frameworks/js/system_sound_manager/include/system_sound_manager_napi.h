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

#ifndef SYSTEM_SOUND_MNGR_NAPI_H
#define SYSTEM_SOUND_MNGR_NAPI_H

#include "system_sound_manager.h"

#include "ringtone_player_napi.h"
#include "system_tone_player_napi.h"
#include "tone_attrs_napi.h"
#include "tone_haptics_attrs_napi.h"
#include "tone_haptics_settings_napi.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"
#include "ability.h"

namespace OHOS {
namespace Media {
static const std::string SYSTEM_SND_MNGR_NAPI_CLASS_NAME = "SystemSoundManager";

static const std::map<std::string, RingtoneType> ringtoneTypeMap = {
    {"RINGTONE_TYPE_DEFAULT", RINGTONE_TYPE_SIM_CARD_0}, // deprecated
    {"RINGTONE_TYPE_MULTISIM", RINGTONE_TYPE_SIM_CARD_1}, // deprecated
    {"RINGTONE_TYPE_SIM_CARD_0", RINGTONE_TYPE_SIM_CARD_0},
    {"RINGTONE_TYPE_SIM_CARD_1", RINGTONE_TYPE_SIM_CARD_1}
};

static const std::map<std::string, SystemToneType> systemToneTypeMap = {
    {"SYSTEM_TONE_TYPE_SIM_CARD_0", SYSTEM_TONE_TYPE_SIM_CARD_0},
    {"SYSTEM_TONE_TYPE_SIM_CARD_1", SYSTEM_TONE_TYPE_SIM_CARD_1},
    {"SYSTEM_TONE_TYPE_NOTIFICATION", SYSTEM_TONE_TYPE_NOTIFICATION}
};

static const std::map<std::string, ToneHapticsType> toneHapticsTypeMap = {
    {"CALL_SIM_CARD_0", CALL_SIM_CARD_0},
    {"CALL_SIM_CARD_1", CALL_SIM_CARD_1},
    {"TEXT_MESSAGE_SIM_CARD_0", TEXT_MESSAGE_SIM_CARD_0},
    {"TEXT_MESSAGE_SIM_CARD_1", TEXT_MESSAGE_SIM_CARD_1},
    {"NOTIFICATION", NOTIFICATION},
};

static const std::map<std::string, ToneCustomizedType> toneCustomizedTypeMap = {
    {"PRE_INSTALLED", PRE_INSTALLED},
    {"CUSTOMISED",  CUSTOMISED}
};

static const std::map<std::string, ToneHapticsMode> toneHapticsModeMap = {
    {"NONE", NONE},
    {"SYNC", SYNC},
    {"NON_SYNC", NON_SYNC},
};

class SystemSoundManagerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

    SystemSoundManagerNapi();
    ~SystemSoundManagerNapi();

private:
    static napi_status DefineClassProperties(napi_env env, napi_value &ctorObj);
    static napi_status DefineStaticProperties(napi_env env, napi_value exports);
    static void Destructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static napi_value CreateCustomizedToneAttrs(napi_env env, napi_callback_info info);
    static napi_value GetSystemSoundManager(napi_env env, napi_callback_info info);
    static napi_status AddNamedProperty(napi_env env, napi_value object, const std::string name, int32_t enumValue);
    static napi_value CreateRingtoneTypeObject(napi_env env);
    static napi_value CreateSystemToneTypeObject(napi_env env);
    static napi_value CreateToneCustomizedTypeObject(napi_env env);
    static napi_value CreateToneCategoryRingtoneObject(napi_env env);
    static napi_value CreateToneCategoryTextMessageObject(napi_env env);
    static napi_value CreateToneCategoryNotificationObject(napi_env env);
    static napi_value CreateToneCategoryAlarmObject(napi_env env);
    static napi_value CreateToneHapticsTypeObject(napi_env env);
    static napi_value CreateToneHapticsModeObject(napi_env env);
    static std::shared_ptr<AbilityRuntime::Context> GetAbilityContext(napi_env env, napi_value contextArg);
    static bool VerifySelfSystemPermission();
    static bool VerifyRingtonePermission();

    static napi_value SetRingtoneUri(napi_env env, napi_callback_info info);
    static void AsyncSetRingtoneUri(napi_env env, void *data);
    static napi_value GetRingtoneUri(napi_env env, napi_callback_info info);
    static void AsyncGetRingtoneUri(napi_env env, void *data);
    static napi_value GetDefaultRingtoneAttrs(napi_env env, napi_callback_info info);
    static void AsyncGetDefaultRingtoneAttrs(napi_env env, void *data);
    static napi_value GetRingtoneAttrList(napi_env env, napi_callback_info info);
    static void AsyncGetRingtoneAttrList(napi_env env, void *data);
    static napi_value GetRingtonePlayer(napi_env env, napi_callback_info info);
    static void AsyncGetRingtonePlayer(napi_env env, void *data);

    static napi_value SetSystemToneUri(napi_env env, napi_callback_info info);
    static void AsyncSetSystemToneUri(napi_env env, void *data);
    static napi_value GetSystemToneUri(napi_env env, napi_callback_info info);
    static void AsyncGetSystemToneUri(napi_env env, void *data);
    static napi_value GetDefaultSystemToneAttrs(napi_env env, napi_callback_info info);
    static void AsyncGetDefaultSystemToneAttrs(napi_env env, void *data);
    static napi_value GetSystemToneAttrList(napi_env env, napi_callback_info info);
    static void AsyncGetSystemToneAttrList(napi_env env, void *data);
    static napi_value GetSystemTonePlayer(napi_env env, napi_callback_info info);
    static void AsyncGetSystemTonePlayer(napi_env env, void *data);

    static napi_value SetAlarmToneUri(napi_env env, napi_callback_info info);
    static void AsyncSetAlarmToneUri(napi_env env, void *data);
    static napi_value GetAlarmToneUri(napi_env env, napi_callback_info info);
    static void AsyncGetAlarmToneUri(napi_env env, void *data);
    static napi_value GetDefaultAlarmToneAttrs(napi_env env, napi_callback_info info);
    static void AsyncGetDefaultAlarmToneAttrs(napi_env env, void *data);
    static napi_value GetAlarmToneAttrList(napi_env env, napi_callback_info info);
    static void AsyncGetAlarmToneAttrList(napi_env env, void *data);

    static void SetSystemSoundUriAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static void GetSystemSoundUriAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static void GetDefaultAttrsAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static void GetToneAttrsListAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static void GetRingtonePlayerAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static void GetSystemTonePlayerAsyncCallbackComp(napi_env env, napi_status status, void* data);

    static napi_value OpenAlarmTone(napi_env env, napi_callback_info info);
    static void AsyncOpenAlarmTone(napi_env env, void *data);
    static void OpenAlarmToneAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static napi_value Close(napi_env env, napi_callback_info info);
    static void AsyncClose(napi_env env, void *data);
    static void CloseAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static napi_value AddCustomizedTone(napi_env env, napi_callback_info info);
    static void AsyncAddCustomizedTone(napi_env env, void *data);
    static void AddCustomizedToneAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static napi_value RemoveCustomizedTone(napi_env env, napi_callback_info info);
    static void AsyncRemoveCustomizedTone(napi_env env, void *data);
    static void RemoveCustomizedToneAsyncCallbackComp(napi_env env, napi_status status, void* data);
    static napi_value ThrowErrorAndReturn(napi_env env, const std::string& napiMessage, int32_t napiCode);
    static napi_value AsyncThrowErrorAndReturn(napi_env env, const std::string& napiMessage, int32_t napiCode);

    static napi_value GetToneHapticsSettings(napi_env env, napi_callback_info info);
    static void AsyncGetToneHapticsSettings(napi_env env, void *data);
    static void GetToneHapticsSettingsAsyncCallbackComp(napi_env env, napi_status status, void *data);
    static napi_value SetToneHapticsSettings(napi_env env, napi_callback_info info);
    static void AsyncSetToneHapticsSettings(napi_env env, void *data);
    static void SetToneHapticsSettingsAsyncCallbackComp(napi_env env, napi_status status, void *data);
    static napi_value GetToneHapticsList(napi_env env, napi_callback_info info);
    static void AsyncGetToneHapticsList(napi_env env, void *data);
    static void GetToneHapticsListAsyncCallbackComp(napi_env env, napi_status status, void *data);
    static napi_value GetHapticsAttrsSyncedWithTone(napi_env env, napi_callback_info info);
    static void AsyncGetHapticsAttrsSyncedWithTone(napi_env env, void *data);
    static void GetHapticsAttrsSyncedWithToneAsyncCallbackComp(napi_env env, napi_status status, void *data);
    static napi_value OpenToneHaptics(napi_env env, napi_callback_info info);
    static void AsyncOpenToneHaptics(napi_env env, void *data);
    static void OpenToneHapticsAsyncCallbackComp(napi_env env, napi_status status, void *data);
    static void GetToneHapticsSettingsToEnv(const napi_env &env, const napi_value &argv,
        ToneHapticsSettings &toneHapticsSettings);
    static std::string ExtractStringToEnv(const napi_env &env, const napi_value &argv);

    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref ringtoneType_;
    static thread_local napi_ref systemToneType_;
    static thread_local napi_ref toneCustomizedType_;
    static thread_local napi_ref toneHapticsMode_;

    napi_env env_;

    std::shared_ptr<SystemSoundManager> sysSoundMgrClient_ = nullptr;
};

struct SystemSoundManagerAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    SystemSoundManagerNapi *objectInfo;
    std::shared_ptr<AbilityRuntime::Context> abilityContext_;
    std::string uri;
    std::shared_ptr<RingtonePlayer> ringtonePlayer;
    int32_t ringtoneType;
    std::shared_ptr<SystemTonePlayer> systemTonePlayer;
    int32_t systemToneType;
    std::shared_ptr<ToneAttrsNapi> toneAttrsNapi;
    std::shared_ptr<ToneAttrs> toneAttrs;
    std::vector<std::shared_ptr<ToneAttrs>> toneAttrsArray;
    std::string externalUri;
    int32_t fd;
    int32_t offset = 0;
    int32_t length = 0;
    int32_t result;
    int32_t errCode;
    std::string errMessage;
    bool isSynced;
    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
    std::string toneUri;
    std::string hapticsUri;
    int32_t toneHapticsType;
    ToneHapticsSettings toneHapticsSettings;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_SOUND_MNGR_NAPI_H