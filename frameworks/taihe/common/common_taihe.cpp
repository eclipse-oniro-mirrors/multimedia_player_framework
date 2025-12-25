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

#include "common_taihe.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "media_log.h"
#include "tokenid_kit.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CommonTaihe"};

constexpr char CLASS_NAME_BUSINESSERROR[] = "@ohos.base.BusinessError";
constexpr char CLASS_NAME_INTERRUPTEVENT[] = "@ohos.multimedia.audio._taihe_InterruptEvent_inner";
constexpr char CLASS_NAME_INTERRUPTTYPE[] = "@ohos.multimedia.audio._taihe_InterruptType_inner";
constexpr char CLASS_NAME_INTERRUPTHINT[] = "@ohos.multimedia.audio._taihe_InterruptHint_inner";
constexpr char CLASS_NAME_INTERRUPTFORCETYPE[] = "@ohos.multimedia.audio._taihe_InterruptForceType_inner";
constexpr char CLASS_NAME_AUDIORENDERERINFO[] = "@ohos.multimedia.audio.audio._taihe_AudioRendererInfo_inner";
constexpr char CLASS_NAME_STREAMUSAGE[] = "@ohos.multimedia.audio.audio.StreamUsage";
constexpr char CLASS_NAME_VOLUMEMODE[] = "@ohos.multimedia.audio.audio.AudioVolumeMode";

static const std::map<OHOS::AudioStandard::InterruptType, int32_t> ANI_INTERRUPTTYPE_INDEX_MAP = {
    {OHOS::AudioStandard::InterruptType::INTERRUPT_TYPE_BEGIN, 1},
    {OHOS::AudioStandard::InterruptType::INTERRUPT_TYPE_END, 2},
};

static const std::map<OHOS::AudioStandard::InterruptHint, int32_t> ANI_INTERRUPTHINT_INDEX_MAP = {
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_NONE, 0},
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_RESUME, 1},
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE, 2},
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_STOP, 3},
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_DUCK, 4},
    {OHOS::AudioStandard::InterruptHint::INTERRUPT_HINT_UNDUCK, 5},
};

static const std::map<OHOS::AudioStandard::InterruptForceType, int32_t> ANI_INTERRUPTFORCETYPE_INDEX_MAP = {
    {OHOS::AudioStandard::InterruptForceType::INTERRUPT_FORCE, 0},
    {OHOS::AudioStandard::InterruptForceType::INTERRUPT_SHARE, 1},
};

static const std::map<OHOS::AudioStandard::StreamUsage, int32_t> ANI_STREAMUSAGE_INDEX_MAP = {
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN, 0},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MUSIC, 1},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION, 2},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VOICE_ASSISTANT, 3},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_ALARM, 4},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MESSAGE, 5},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE, 6},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION, 7},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_ACCESSIBILITY, 8},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_SYSTEM, 9},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MOVIE, 10},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_GAME, 11},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_AUDIOBOOK, 12},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_NAVIGATION, 13},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_DTMF, 14},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_ENFORCED_TONE, 15},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_ULTRASONIC, 16},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION, 17},
    { OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VOICE_CALL_ASSISTANT, 18},
};
}

namespace ANI::Media {

void CommonTaihe::ThrowError(const std::string &errMessage)
{
    MEDIA_LOGE("CommonTaihe: errMsg: %{public}s", errMessage.c_str());
    taihe::set_error(errMessage);
}

void CommonTaihe::ThrowError(int32_t code, const std::string &errMessage)
{
    MEDIA_LOGE("CommonTaihe: errCode: %{public}d errMsg: %{public}s", code, errMessage.c_str());
    taihe::set_business_error(code, errMessage);
}

bool CommonTaihe::VerifySelfSystemPermission()
{
    OHOS::Security::AccessToken::FullTokenID selfTokenID = OHOS::IPCSkeleton::GetSelfTokenID();
    auto tokenTypeFlag =
        OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<uint32_t>(selfTokenID));
    if (tokenTypeFlag == OHOS::Security::AccessToken::TOKEN_NATIVE ||
        tokenTypeFlag == OHOS::Security::AccessToken::TOKEN_SHELL ||
        OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID)) {
        return true;
    }
    return false;
}

bool CommonTaihe::VerifyRingtonePermission()
{
    OHOS::Security::AccessToken::FullTokenID selfTokenID = OHOS::IPCSkeleton::GetSelfTokenID();
    if (OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        selfTokenID, "ohos.permission.WRITE_RINGTONE")) {
        return false;
    }
    return true;
}

ani_object CommonTaihe::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env != nullptr, err, "Invalid env");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindClass(CLASS_NAME_BUSINESSERROR, &cls), err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Class_FindMethod(cls, "<ctor>", ":", &ctor), err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_New(cls, ctor, &error), err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_AND_RETURN_RET_LOG(
        ANI_OK == env->Object_SetPropertyByName_Int(error, "code", static_cast<ani_int>(code)), err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->String_NewUTF8(message.c_str(), message.size(), &messageRef), err,
        "new message string failed");
    CHECK_AND_RETURN_RET_LOG(
        ANI_OK == env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)), err,
        "set property BusinessError.message failed");
    return error;
}

uintptr_t CommonTaihe::GetUndefinedPtr(ani_env *env)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, 0, "Invalid env");
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    ani_object undefinedObj = static_cast<ani_object>(undefinedRef);
    return reinterpret_cast<uintptr_t>(undefinedObj);
}

ani_status CommonTaihe::EnumGetValueInt32(ani_env *env, ani_enum_item enumItem, int32_t &value)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    ani_int aniInt {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->EnumItem_GetValue_Int(enumItem, &aniInt), ANI_ERROR,
        "EnumItem_GetValue_Int failed");
    value = static_cast<int32_t>(aniInt);
    return ANI_OK;
}

ani_status CommonTaihe::ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptType value,
    ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_INTERRUPTTYPE_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_INTERRUPTTYPE_INDEX_MAP.end(), ANI_INVALID_ARGS,
        "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);

    ani_enum aniEnum {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(CLASS_NAME_INTERRUPTTYPE, &aniEnum),
        ANI_ERROR, "Find Enum Fail");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        ANI_ERROR, "Find Enum item Fail");
    return ANI_OK;
}

ani_status CommonTaihe::ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptForceType value,
    ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_INTERRUPTFORCETYPE_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_INTERRUPTFORCETYPE_INDEX_MAP.end(),
        ANI_INVALID_ARGS, "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);

    ani_enum aniEnum {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(CLASS_NAME_INTERRUPTFORCETYPE, &aniEnum),
        ANI_ERROR, "Find Enum Fail");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        ANI_ERROR, "Find Enum item Fail");
    return ANI_OK;
}

ani_status CommonTaihe::ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptHint value,
    ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_INTERRUPTHINT_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_INTERRUPTHINT_INDEX_MAP.end(), ANI_INVALID_ARGS,
        "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);

    ani_enum aniEnum {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(CLASS_NAME_INTERRUPTHINT, &aniEnum),
        ANI_ERROR, "Find Enum Fail");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        ANI_ERROR, "Find Enum item Fail");
    return ANI_OK;
}

ani_object CommonTaihe::ToAudioStandardInterruptEvent(ani_env *env,
    const OHOS::AudioStandard::InterruptEvent &interruptEvent)
{
    ani_object interruptEventObj {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env != nullptr, interruptEventObj, "Invalid env");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindClass(CLASS_NAME_INTERRUPTEVENT, &cls), interruptEventObj,
        "find class %{public}s failed", CLASS_NAME_INTERRUPTEVENT);
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Class_FindMethod(cls, "<ctor>", ":", &ctor), interruptEventObj,
        "find method AudioStandardInterruptEvent constructor failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_New(cls, ctor, &interruptEventObj), interruptEventObj,
        "new object %{public}s failed", CLASS_NAME_INTERRUPTEVENT);

    ani_enum_item eventType {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == ToAniEnum(env, interruptEvent.eventType, eventType), interruptEventObj,
        "convert InterruptType to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Ref(interruptEventObj, "eventType",
        static_cast<ani_ref>(eventType)), interruptEventObj, "set property InterruptEvent.eventType failed");

    ani_enum_item forceType {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == ToAniEnum(env, interruptEvent.forceType, forceType), interruptEventObj,
        "convert InterruptForceType to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Ref(interruptEventObj, "forceType",
        static_cast<ani_ref>(forceType)), interruptEventObj, "set property InterruptEvent.forceType failed");
    
    ani_enum_item hintType {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == ToAniEnum(env, interruptEvent.hintType, hintType), interruptEventObj,
        "convert InterruptHint to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Ref(interruptEventObj, "hintType",
        static_cast<ani_ref>(hintType)), interruptEventObj, "set property InterruptEvent.hintType failed");
    return interruptEventObj;
}

ani_status CommonTaihe::ToAniEnum(ani_env *env, OHOS::AudioStandard::StreamUsage value,
    ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_STREAMUSAGE_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_STREAMUSAGE_INDEX_MAP.end(), ANI_INVALID_ARGS,
        "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);

    ani_enum aniEnum {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(CLASS_NAME_STREAMUSAGE, &aniEnum),
        ANI_ERROR, "Find Enum Fail");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        ANI_ERROR, "Find Enum item Fail");
    return ANI_OK;
}

ani_status CommonTaihe::VolumeModeToAniEnum(ani_env *env, int32_t value,
    ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");
    ani_int enumIndex = value;
    ani_enum aniEnum {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindEnum(CLASS_NAME_VOLUMEMODE, &aniEnum),
        ANI_ERROR, "Find Enum Fail");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        ANI_ERROR, "Find Enum item Fail");
    return ANI_OK;
}

ani_object CommonTaihe::CreateAudioRendererInfo(ani_env *env,
    std::unique_ptr<OHOS::AudioStandard::AudioRendererInfo> &audioRendererInfo)
{
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "ani_env is nullptr");
    CHECK_AND_RETURN_RET_LOG(env->FindClass(CLASS_NAME_AUDIORENDERERINFO, &cls) == ANI_OK, nullptr,
        "Failed to find class: %{public}s", CLASS_NAME_AUDIORENDERERINFO);
    ani_method ctorMethod {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) == ANI_OK, nullptr,
        "Failed to find method: <ctor>");

    ani_object aniObject {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctorMethod, &aniObject) == ANI_OK, aniObject,
        "new object %{public}s failed", CLASS_NAME_AUDIORENDERERINFO);

    ani_enum_item volumeMode {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == VolumeModeToAniEnum(env, audioRendererInfo->volumeMode, volumeMode), aniObject,
        "convert volumeMode to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Ref(aniObject, "volumeMode",
        static_cast<ani_ref>(volumeMode)), aniObject, "set property volumeMode failed");

    ani_enum_item streamUsage {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == ToAniEnum(env, audioRendererInfo->streamUsage, streamUsage), aniObject,
        "convert streamUsage to aniEnumItem failed");
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Ref(aniObject, "usage",
        static_cast<ani_ref>(streamUsage)), aniObject, "set property streamUsage failed");

    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_SetPropertyByName_Int(aniObject, "rendererFlags",
        (ani_int)audioRendererInfo->rendererFlags), aniObject, "set property rendererFlags failed");
    return aniObject;
}

ani_status CommonTaihe::ToAniLongObject(ani_env *env, int64_t src, ani_object &aniObj)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");
    static const char *className = "std.core.BigInt";

    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->FindClass(className, &cls), ANI_ERROR, "Failed to find class");

    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Class_FindMethod(cls, "<ctor>", "l:", &ctor), ANI_ERROR,
        "Failed to find class");

    CHECK_AND_RETURN_RET_LOG(ANI_OK == env->Object_New(cls, ctor, &aniObj, static_cast<ani_long>(src)), ANI_ERROR,
        "Failed to new Long object");

    return ANI_OK;
}

} // namespace ANI::Media