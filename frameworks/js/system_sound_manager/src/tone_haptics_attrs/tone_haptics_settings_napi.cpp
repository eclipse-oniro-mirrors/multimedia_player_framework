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

#include "tone_haptics_settings_napi.h"
#include "media_log.h"

using namespace std;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "ToneHapticsSettingsNapi"};
}

namespace OHOS {
namespace Media {
const std::string TONE_HAPTICS_SETTINGS_NAPI_CLASS_NAME = "ToneHapticsSettings";

thread_local napi_ref ToneHapticsSettingsNapi::sConstructor_ = nullptr;

ToneHapticsSettingsNapi::ToneHapticsSettingsNapi() : env_(nullptr) {}

ToneHapticsSettingsNapi::~ToneHapticsSettingsNapi() = default;

napi_value ToneHapticsSettingsNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value constructor;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_property_descriptor tone_haptics_settings_properties[] = {
        DECLARE_NAPI_GETTER_SETTER("mode", GetMode, SetMode),
        DECLARE_NAPI_GETTER_SETTER("hapticsUri", GetHapticsUri, SetHapticsUri)
    };

    status = napi_define_class(env, TONE_HAPTICS_SETTINGS_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Construct,
        nullptr, sizeof(tone_haptics_settings_properties) / sizeof(tone_haptics_settings_properties[0]),
        tone_haptics_settings_properties, &constructor);
    if (status != napi_ok) {
        return result;
    }

    status = napi_create_reference(env, constructor, 1, &sConstructor_);
    if (status == napi_ok) {
        status = napi_set_named_property(env, exports, TONE_HAPTICS_SETTINGS_NAPI_CLASS_NAME.c_str(), constructor);
        if (status == napi_ok) {
            return exports;
        }
    }

    MEDIA_LOGE("Failure in ToneHapticsSettingsNapi::Init()");
    return result;
}

napi_value ToneHapticsSettingsNapi::Construct(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsThis = nullptr;
    size_t argCount = 0;

    status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status == napi_ok) {
        unique_ptr<ToneHapticsSettingsNapi> obj = make_unique<ToneHapticsSettingsNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            status = napi_wrap(env, jsThis, static_cast<void*>(obj.get()), ToneHapticsSettingsNapi::Destructor,
                nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return jsThis;
            }
        }
    }

    MEDIA_LOGE("Failed in ToneHapticsSettingsNapi::Construct()!");
    napi_get_undefined(env, &jsThis);
    return jsThis;
}

void ToneHapticsSettingsNapi::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    if (nativeObject != nullptr) {
        auto obj = static_cast<ToneHapticsSettingsNapi*>(nativeObject);
        delete obj;
        obj = nullptr;
    }
}

napi_status ToneHapticsSettingsNapi::NewInstance(napi_env env, const ToneHapticsSettings &toneHapticsSettings,
    napi_value &out)
{
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, sConstructor_, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);

    ToneHapticsSettingsNapi* toneHapticsSettingsNapi{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&toneHapticsSettingsNapi)),
        napi_generic_failure);
    CHECK_AND_RETURN_RET_LOG(toneHapticsSettingsNapi != nullptr, napi_invalid_arg,
        "toneHapticsSettingsNapi is nullptr");

    toneHapticsSettingsNapi->toneHapticsSettings_ = toneHapticsSettings;
    out = instance;
    return napi_ok;
}

napi_value ToneHapticsSettingsNapi::GetMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    ToneHapticsSettingsNapi *toneHapticsSettingsNapi = nullptr;
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr) {
        MEDIA_LOGE("GetMode: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&toneHapticsSettingsNapi);
    if (status != napi_ok || toneHapticsSettingsNapi == nullptr) {
        MEDIA_LOGE("GetMode: failed for napi_unwrap");
        return jsResult;
    }

    status = napi_create_int32(env, static_cast<int32_t>(toneHapticsSettingsNapi->toneHapticsSettings_.mode),
        &jsResult);
    if (status != napi_ok) {
        MEDIA_LOGE("GetMode: failed for napi_create_int32");
        return jsResult;
    }
    return jsResult;
}

napi_value ToneHapticsSettingsNapi::SetMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    ToneHapticsSettingsNapi *toneHapticsSettingsNapi = nullptr;
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    int32_t mode = 0;
    napi_value jsResult = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr || argc < 1) {
        MEDIA_LOGE("SetMode: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&toneHapticsSettingsNapi);
    if (status != napi_ok || toneHapticsSettingsNapi == nullptr) {
        MEDIA_LOGE("SetMode: failed for napi_unwrap");
        return jsResult;
    }

    status = napi_typeof(env, args[0], &valueType);
    if (status != napi_ok || valueType != napi_number) {
        MEDIA_LOGE("SetMode: failed for wrong data type");
        return jsResult;
    }

    status = napi_get_value_int32(env, args[0], &mode);
    if (status != napi_ok) {
        MEDIA_LOGE("SetMode: failed for napi_get_value_int32");
        return jsResult;
    }

    toneHapticsSettingsNapi->toneHapticsSettings_.mode = static_cast<ToneHapticsMode>(mode);
    return jsResult;
}

napi_value ToneHapticsSettingsNapi::GetHapticsUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    ToneHapticsSettingsNapi *toneHapticsSettingsNapi = nullptr;
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr) {
        MEDIA_LOGE("GetHapticsUri: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&toneHapticsSettingsNapi);
    if (status != napi_ok || toneHapticsSettingsNapi == nullptr) {
        MEDIA_LOGE("GetHapticsUri: failed for napi_unwrap");
        return jsResult;
    }

    string &hapticsUri = toneHapticsSettingsNapi->toneHapticsSettings_.hapticsUri;
    status = napi_create_string_utf8(env, hapticsUri.c_str(), hapticsUri.size(), &jsResult);
    if (status != napi_ok) {
        MEDIA_LOGE("GetHapticsUri: failed for napi_create_string_utf8");
        return jsResult;
    }
    return jsResult;
}

napi_value ToneHapticsSettingsNapi::SetHapticsUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    ToneHapticsSettingsNapi *toneHapticsSettingsNapi = nullptr;
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    char buffer[1024] = {0};
    size_t res = 0;
    napi_value jsResult = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr || argc < 1) {
        MEDIA_LOGE("SetHapticsUri: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&toneHapticsSettingsNapi);
    if (status != napi_ok || toneHapticsSettingsNapi == nullptr) {
        MEDIA_LOGE("SetHapticsUri: failed for napi_unwrap");
        return jsResult;
    }

    status = napi_typeof(env, args[0], &valueType);
    if (status != napi_ok || valueType != napi_string) {
        MEDIA_LOGE("SetHapticsUri: failed for wrong data type");
        return jsResult;
    }

    status = napi_get_value_string_utf8(env, args[0], buffer, sizeof(buffer), &res);
    if (status != napi_ok) {
        MEDIA_LOGE("SetHapticsUri: failed for napi_get_value_int32");
        return jsResult;
    }

    toneHapticsSettingsNapi->toneHapticsSettings_.hapticsUri = std::string(buffer);
    return jsResult;
}
}  // namespace Media
}  // namespace OHOS
