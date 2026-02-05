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

#include "tone_haptics_attrs_napi.h"

#include "media_log.h"
#include "common_napi.h"

#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ringtone_common_napi.h"

using OHOS::Security::AccessToken::AccessTokenKit;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "ToneHapticsAttrsNapi"};
}

namespace OHOS {
namespace Media {

const std::string TONE_HAPTICS_ATTRS_NAPI_CLASS_NAME = "ToneHapticsAttrs";

thread_local napi_ref ToneHapticsAttrsNapi::sConstructor_ = nullptr;

ToneHapticsAttrsNapi::ToneHapticsAttrsNapi() : env_(nullptr) {}

ToneHapticsAttrsNapi::~ToneHapticsAttrsNapi() = default;

napi_value ToneHapticsAttrsNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor tone_haptics_attrs_prop[] = {
        DECLARE_NAPI_FUNCTION("getUri", GetUri),
        DECLARE_NAPI_FUNCTION("getTitle", GetTitle),
        DECLARE_NAPI_FUNCTION("getFileName", GetFileName),
        DECLARE_NAPI_FUNCTION("getGentleUri", GetGentleUri),
        DECLARE_NAPI_FUNCTION("getGentleTitle", GetGentleTitle),
        DECLARE_NAPI_FUNCTION("getGentleFileName", GetGentleFileName),
    };

    status = napi_define_class(env, TONE_HAPTICS_ATTRS_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
        Construct, nullptr, sizeof(tone_haptics_attrs_prop) / sizeof(tone_haptics_attrs_prop[0]),
        tone_haptics_attrs_prop, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, TONE_HAPTICS_ATTRS_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

napi_value ToneHapticsAttrsNapi::Construct(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsThis = nullptr;
    napi_value thisVar = nullptr;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ToneHapticsAttrsNapi> obj = std::make_unique<ToneHapticsAttrsNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            status = napi_wrap(env, thisVar, static_cast<void*>(obj.get()), ToneHapticsAttrsNapi::Destructor,
                nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            }
        }
    }
    MEDIA_LOGE("Failed in ToneHapticsAttrsNapi::Construct()!");
    napi_get_undefined(env, &jsThis);
    return jsThis;
}

void ToneHapticsAttrsNapi::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    if (nativeObject != nullptr) {
        delete reinterpret_cast<ToneHapticsAttrsNapi*>(nativeObject);
    }
}

napi_status ToneHapticsAttrsNapi::NewInstance(napi_env env, std::shared_ptr<ToneHapticsAttrs> &nativeToneHapticsAttrs,
    napi_value &out)
{
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, sConstructor_, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);

    ToneHapticsAttrsNapi* toneHapticsAttrsNapi{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&toneHapticsAttrsNapi)),
        napi_generic_failure);
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, napi_invalid_arg, "toneHapticsAttrsNapi is nullptr");

    toneHapticsAttrsNapi->toneHapticsAttrs_ = std::move(nativeToneHapticsAttrs);
    out = instance;
    return napi_ok;
}

napi_value ToneHapticsAttrsNapi::ThrowErrorAndReturn(napi_env env, const std::string &errMsg, int32_t errCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value errVal = nullptr;
    napi_value errNameVal = nullptr;
    napi_value result{};
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &errVal);
    napi_create_int32(env, errCode, &code);
    napi_set_named_property(env, errVal, "code", code);
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &errNameVal);
    napi_set_named_property(env, errVal, "BusinessError", errNameVal);
    napi_throw(env, errVal);
    napi_get_undefined(env, &result);
    return result;
}

bool ToneHapticsAttrsNapi::VerifySelfSystemPermission()
{
    Security::AccessToken::FullTokenID selfTokenID = IPCSkeleton::GetSelfTokenID();
    auto tokenTypeFlag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<uint32_t>(selfTokenID));
    if (tokenTypeFlag == Security::AccessToken::TOKEN_NATIVE ||
        tokenTypeFlag == Security::AccessToken::TOKEN_SHELL ||
        Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID)) {
        return true;
    }
    return false;
}

napi_value ToneHapticsAttrsNapi::GetUri(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    napi_create_string_utf8(env, toneHapticsAttrsNapi->toneHapticsAttrs_->GetUri().c_str(),
        NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value ToneHapticsAttrsNapi::GetTitle(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    napi_create_string_utf8(env, toneHapticsAttrsNapi->toneHapticsAttrs_->GetTitle().c_str(),
        NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value ToneHapticsAttrsNapi::GetFileName(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    napi_create_string_utf8(env, toneHapticsAttrsNapi->toneHapticsAttrs_->GetFileName().c_str(),
        NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value ToneHapticsAttrsNapi::GetGentleUri(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    std::string gentleUri = toneHapticsAttrsNapi->toneHapticsAttrs_->GetGentleUri();
    if (!gentleUri.empty()) {
        napi_create_string_utf8(env, gentleUri.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value ToneHapticsAttrsNapi::GetGentleTitle(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    std::string gentleTitle = toneHapticsAttrsNapi->toneHapticsAttrs_->GetGentleTitle();
    if (!gentleTitle.empty()) {
        napi_create_string_utf8(env, gentleTitle.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value ToneHapticsAttrsNapi::GetGentleFileName(napi_env env, napi_callback_info info)
{
    ToneHapticsAttrsNapi *toneHapticsAttrsNapi = nullptr;
    napi_value jsThis = nullptr;
    size_t argc = 0;
    CHECK_AND_RETURN_RET_LOG(VerifySelfSystemPermission(),
        ThrowErrorAndReturn(env, NAPI_ERR_PERMISSION_DENIED_INFO, NAPI_ERR_PERMISSION_DENIED),
        "No system permission");

    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG((status == napi_ok) && (jsThis != nullptr), nullptr, "jsThis is nullptr");
    napi_unwrap(env, jsThis, reinterpret_cast<void**>(&toneHapticsAttrsNapi));
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi != nullptr, nullptr, "toneAttrsNapi is nullptr");
    CHECK_AND_RETURN_RET_LOG(toneHapticsAttrsNapi->toneHapticsAttrs_ != nullptr, nullptr,
        "toneHapticsAttrs_ is nullptr");
    napi_value result;
    std::string gentleFileName = toneHapticsAttrsNapi->toneHapticsAttrs_->GetGentleFileName();
    if (!gentleFileName.empty()) {
        napi_create_string_utf8(env, gentleFileName.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

} // namespace Media
} // namespace OHOS