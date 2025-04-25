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
#include "media_ani_common.h"
#include "media_ani_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CommonAni"};
}

namespace OHOS {
namespace Media {

bool CommonAni::SetPropertyInt32(ani_env *env, ani_object &recordObject, ani_method setMethod,
    const std::string &key, int32_t value)
{
    CHECK_AND_RETURN_RET_LOG(recordObject != nullptr, false, "recordObject is nullptr");

    ani_string inputKey{};
    MediaAniUtils::ToAniString(env, key, inputKey);

    ani_object inputValue = nullptr;
    MediaAniUtils::ToAniNumberObject(env, value, inputValue);

    return env->Object_CallMethod_Void(recordObject, setMethod, inputKey, inputValue) == ANI_OK;
}

bool CommonAni::SetPropertyString(ani_env *env, ani_object &recordObject, ani_method setMethod,
    const std::string &key, const std::string &value)
{
    CHECK_AND_RETURN_RET_LOG(recordObject != nullptr, false, "recordObject is nullptr");

    ani_string inputKey{};
    MediaAniUtils::ToAniString(env, key, inputKey);

    ani_string inputValue{};
    MediaAniUtils::ToAniString(env, value, inputValue);

    return env->Object_CallMethod_Void(recordObject, setMethod, inputKey,
        reinterpret_cast<ani_object>(inputValue)) == ANI_OK;
}

ani_object CommonAni::CreateFormatBuffer(ani_env *env, Format &format)
{
    int32_t intValue = 0;
    std::string strValue;

    ani_class cls {};
    ani_method mapCtor {};
    ani_object mapObject {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass("Lescompat/Record;", &cls) == ANI_OK, nullptr,
        "Can't find Lescompat/Record");
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", "Lstd/core/Object;:V", &mapCtor) == ANI_OK,
        nullptr, "Can't find method <ctor> in Lescompat/Record");
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, mapCtor, &mapObject, nullptr) == ANI_OK, nullptr, "New Map failed");

    ani_method setMethod {};
    if (env->Class_FindMethod(cls, "$_set", "Lstd/core/Object;Lstd/core/Object;:V", &setMethod) != ANI_OK) {
        return mapObject;
    }
    for (auto &iter : format.GetFormatMap()) {
        switch (format.GetValueType(std::string_view(iter.first))) {
            case FORMAT_TYPE_INT32:
                if (format.GetIntValue(iter.first, intValue)) {
                    CHECK_AND_RETURN_RET(SetPropertyInt32(env, mapObject, setMethod, iter.first, intValue), nullptr);
                }
                break;
            case FORMAT_TYPE_INT64:
                int64_t longValue;
                if (format.GetLongValue(iter.first, longValue) &&
                    longValue >= INT32_MIN && longValue <= INT32_MAX) {
                    intValue = static_cast<int32_t>(longValue);
                    CHECK_AND_RETURN_RET(SetPropertyInt32(env, mapObject, setMethod, iter.first, intValue), nullptr);
                }
                break;
            case FORMAT_TYPE_DOUBLE:
                double doubleValue;
                if (format.GetDoubleValue(iter.first, doubleValue) &&
                    doubleValue >= INT32_MIN && doubleValue <= INT32_MAX) {
                    intValue = static_cast<int32_t>(doubleValue);
                    CHECK_AND_RETURN_RET(SetPropertyInt32(env, mapObject, setMethod, iter.first, intValue), nullptr);
                }
                break;
            case FORMAT_TYPE_STRING:
                if (format.GetStringValue(iter.first, strValue)) {
                    CHECK_AND_RETURN_RET(SetPropertyString(env, mapObject, setMethod, iter.first, strValue), nullptr);
                }
                break;
            default:
                MEDIA_LOGE("format key: %{public}s", iter.first.c_str());
                break;
        }
    }
    return mapObject;
}
}
}