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

#include "media_ani_utils.h"
namespace OHOS {
namespace Media {

static const std::map<AudioStandard::InterruptMode, int32_t> ANI_INTERRUPTMODE_INDEX_MAP = {
    {AudioStandard::InterruptMode::SHARE_MODE, 0},
    {AudioStandard::InterruptMode::INDEPENDENT_MODE, 1},
};

ani_boolean MediaAniUtils::isArray(ani_env *env, ani_object object)
{
    ani_boolean isArray = ANI_FALSE;
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_COND_RET(ANI_OK == env->FindClass(className.c_str(), &cls), isArray, "Can't find Lescompat/Array.");

    ani_static_method static_method {};
    CHECK_COND_RET(ANI_OK == env->Class_FindStaticMethod(cls, "isArray", nullptr, &static_method), isArray,
        "Can't find method isArray in Lescompat/Array.");

    CHECK_COND_RET(ANI_OK == env->Class_CallStaticMethod_Boolean(cls, static_method, &isArray, object),
        isArray, "Call method isArray failed.");
    return isArray;
}

ani_boolean MediaAniUtils::isUndefined(ani_env *env, ani_object object)
{
    ani_boolean isUndefined = ANI_TRUE;
    CHECK_COND_RET(ANI_OK == env->Reference_IsUndefined(object, &isUndefined), ANI_TRUE,
        "Call Reference_IsUndefined failed.");
    return isUndefined;
}

ani_status MediaAniUtils::GetString(ani_env *env, ani_string arg, std::string &str)
{
    CHECK_COND_RET(arg != nullptr, ANI_INVALID_ARGS, "GetString invalid arg");

    ani_size srcSize = 0;
    CHECK_STATUS_RET(env->String_GetUTF8Size(arg, &srcSize), "String_GetUTF8Size failed");

    std::vector<char> buffer(srcSize + 1);
    ani_size dstSize = 0;
    CHECK_STATUS_RET(env->String_GetUTF8SubString(arg, 0, srcSize, buffer.data(), buffer.size(), &dstSize),
        "String_GetUTF8SubString failed");

    str.assign(buffer.data(), dstSize);
    return ANI_OK;
}

ani_status MediaAniUtils::GetString(ani_env *env, ani_object arg, std::string &str)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    return GetString(env, static_cast<ani_string>(arg), str);
}

ani_status MediaAniUtils::ToAniInt32Array(ani_env *env, const std::vector<int32_t> &array, ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); i++) {
        ani_int aniInt = static_cast<ani_int>(array[i]);
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, aniInt),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaAniUtils::GetDouble(ani_env *env, ani_double arg, double &value)
{
    value = static_cast<double>(arg);
    return ANI_OK;
}

ani_status MediaAniUtils::GetFloat(ani_env *env, ani_float arg, float &value)
{
    value = static_cast<float>(arg);
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniFloatArray(ani_env *env, const std::vector<float> &array, ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); i++) {
        ani_float aniFloat = static_cast<ani_float>(array[i]);
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, aniFloat),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniInt(ani_env *env, const std::int32_t &int32, ani_int &aniInt)
{
    aniInt = static_cast<ani_int>(int32);
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniLong(ani_env *env, const std::int64_t &int64, ani_long &aniLong)
{
    aniLong = static_cast<ani_long>(int64);
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniDouble(ani_env *env, const double &arg, ani_double &aniDouble)
{
    aniDouble = static_cast<ani_double>(arg);
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniString(ani_env *env, const std::string &str, ani_string &aniStr)
{
    CHECK_STATUS_RET(env->String_NewUTF8(str.c_str(), str.size(), &aniStr), "String_NewUTF8 failed");
    return ANI_OK;
}

ani_status MediaAniUtils::ToAniNumberObject(ani_env *env, int32_t src, ani_object &aniObj)
{
    static const char *className = "Lstd/core/Double;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);

    ani_method ctor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "D:V", &ctor), "Failed to find method: ctor");

    CHECK_STATUS_RET(env->Object_New(cls, ctor, &aniObj, static_cast<ani_double>(src)), "New number Object Fail");
    return ANI_OK;
}

ani_status MediaAniUtils::ParseAVDataSrcDescriptor(
    ani_env *env, ani_object src, AVDataSrcDescriptor &dataSrcDescriptor)
{
    static const char *className = "L@ohos/multimedia/media/media/AVDataSrcDescriptorHandle;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);
    ani_method fileSizeGetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<get>fileSize", nullptr, &fileSizeGetter),
        "Failed to find method: <get>fileSize");
    ani_double fileSize {};
    CHECK_STATUS_RET(env->Object_CallMethod_Double(src, fileSizeGetter, &fileSize), "<get>fileSize fail");
    dataSrcDescriptor.fileSize = static_cast<int32_t>(fileSize);
    ani_method callbackGetter {};
    ani_ref objectGRef;
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<get>callback", nullptr, &callbackGetter),
        "Failed to find method: <get>callback");
    CHECK_STATUS_RET(env->Object_CallMethod_Ref(src, callbackGetter, &objectGRef), "<get>callback fail"); 
    env->GlobalReference_Create(objectGRef, &dataSrcDescriptor.callback);
    return ANI_OK;
}

ani_object MediaAniUtils::CreateAVDataSrcDescriptor(ani_env *env, AVDataSrcDescriptor &dataSrcDescriptor)
{
    static const char *className = "L@ohos/multimedia/media/media/AVDataSrcDescriptorHandle;";
    ani_class cls {};
    CHECK_COND_RET(env->FindClass(className, &cls) == ANI_OK, nullptr,
        "Failed to find class: %{public}s", className);
    ani_method ctorMethod {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK, nullptr,
        "Failed to find method: <ctor>");
    ani_object aniObject {};
    CHECK_COND_RET(env->Object_New(cls, ctorMethod, &aniObject) == ANI_OK, nullptr, "Call method <ctor> failed.");

    ani_method fileSizeSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>fileSize", nullptr, &fileSizeSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>fileSize");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, fileSizeSetter,
        (ani_double)dataSrcDescriptor.fileSize) == ANI_OK, nullptr, "<set>fileSize fail");
    ani_method callbackSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>callback", nullptr, &callbackSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>callback");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, callbackSetter, dataSrcDescriptor.callback) == ANI_OK,
        nullptr, "<set>callback fail");
    return aniObject;
}

ani_status MediaAniUtils::ParseAudioRendererInfo(ani_env *env, ani_object src,
    AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    static const char *className = "L@ohos/multimedia/media/audio/AudioRendererInfo";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);
    ani_method contentGetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<get>content", nullptr, &contentGetter),
        "Failed to find method: <get>content");
    ani_int content {};
    CHECK_STATUS_RET(env->Object_CallMethod_Int(src, contentGetter, &content), "<get>content fail");
    audioRendererInfo.contentType = static_cast<AudioStandard::ContentType>(content);

    ani_method usageGetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<get>usage", nullptr, &usageGetter),
        "Failed to find method: <get>usage");
    ani_int usage {};
    CHECK_STATUS_RET(env->Object_CallMethod_Int(src, usageGetter, &usage), "<get>usage fail");
    audioRendererInfo.streamUsage = static_cast<AudioStandard::StreamUsage>(usage);

    ani_method rendererFlagsGetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<get>rendererFlags", nullptr, &rendererFlagsGetter),
        "Failed to find method: <get>rendererFlags");
    ani_int rendererFlags {};
    CHECK_STATUS_RET(env->Object_CallMethod_Int(src, rendererFlagsGetter, &rendererFlags), "<get>rendererFlags fail");
    audioRendererInfo.rendererFlags = static_cast<int32_t>(rendererFlags);
    return ANI_OK;
}

ani_object MediaAniUtils::CreateAudioRendererInfo(ani_env *env, AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    static const char *className = "L@ohos/multimedia/media/audio/AudioRendererInfo";
    ani_class cls {};
    CHECK_COND_RET(env->FindClass(className, &cls) == ANI_OK, nullptr,
        "Failed to find class: %{public}s", className);
    ani_method ctorMethod {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK, nullptr,
        "Failed to find method: <ctor>");
    ani_object aniObject {};
    CHECK_COND_RET(env->Object_New(cls, ctorMethod, &aniObject) == ANI_OK, nullptr, "Call method <ctor> failed.");

    ani_method contentSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>content", nullptr, &contentSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>content");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, contentSetter,
        (ani_int)audioRendererInfo.contentType) == ANI_OK, nullptr, "<set>fileSize fail");

    ani_method usageSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>usage", nullptr, &usageSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>usage");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, usageSetter,
        (ani_int)audioRendererInfo.streamUsage) == ANI_OK, nullptr, "<set>fileSize fail");

    ani_method rendererFlagsSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>rendererFlags", nullptr, &rendererFlagsSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>rendererFlags");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, rendererFlagsSetter,
        (ani_int)audioRendererInfo.rendererFlags) == ANI_OK, nullptr, "<set>fileSize fail");
    return aniObject;
}

ani_status MediaAniUtils::ToAniEnum(ani_env *env, AudioStandard::InterruptMode value, ani_enum_item &aniEnumItem)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_INTERRUPTMODE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_INTERRUPTMODE_INDEX_MAP.end(), ANI_INVALID_ARGS, "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);
    static const char *className = "L@ohos/multimedia/audio/audio/InterruptMode;";
    ani_enum aniEnum {};
    CHECK_STATUS_RET(env->FindEnum(className, &aniEnum), "Find Enum Fail");
    CHECK_STATUS_RET(env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem), "Find Enum item Fail");
    return ANI_OK;
}

ani_status MediaAniUtils::GetObjectArray(ani_env *env, ani_object arg, std::vector<ani_object> &array)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    CHECK_COND_RET(isArray(env, arg) == ANI_TRUE, ANI_ERROR, "invalid parameter.");

    ani_double length;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(arg, "length", &length),
        "Call method <get>length failed.");

    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref value {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(arg, "$_get", "I:Lstd/core/Object;", &value, i),
            "Call method $_get failed.");
        array.emplace_back(static_cast<ani_object>(value));
    }
    return ANI_OK;
}

ani_status MediaAniUtils::GetProperty(ani_env *env, ani_object arg, const std::string &propName,
    std::string &propValue)
{
    ani_object propObj;
    CHECK_STATUS_RET(GetProperty(env, arg, propName, propObj), "GetProperty failed.");
    CHECK_STATUS_RET(GetString(env, propObj, propValue), "GetString failed.");
    return ANI_OK;
}

ani_status MediaAniUtils::GetProperty(ani_env *env, ani_object arg, const std::string &propName, ani_object &propObj)
{
    ani_ref propRef;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Ref(arg, propName.c_str(), &propRef),
        "Object_GetPropertyByName_Ref failed.");
    propObj = static_cast<ani_object>(propRef);
    return ANI_OK;
}

void MediaAniUtils::CreateError(ani_env *env, int32_t errCode, const std::string &errMsg, ani_object &errorObj)
{
    static const std::string className = "L@ohos/multimedia/media/MediaAniError;";
    ani_class cls;
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Can't find class %{public}s", className.c_str());
        return;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>","DLstd/core/String;:V", &ctor)) {
        ANI_ERR_LOG("Can't find <ctor> from class %{public}s", className.c_str());
        return;
    }
    ani_string error_msg;
    if (ANI_OK != MediaAniUtils::ToAniString(env, errMsg, error_msg)) {
        ANI_ERR_LOG("Call ToAniString function failed.");
        return;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &errorObj, (ani_double)errCode, error_msg)) {
        ANI_ERR_LOG("New MediaLibraryAniError object failed.");
        return;
    }
    return;
}

ani_object MediaAniUtils::CreateAVFdSrcDescriptor(ani_env *env, AVFileDescriptor &fdSrcDescriptor)
{
    static const char *className = "L@ohos/multimedia/media/media/AVFileDescriptorHandle;";
    ani_class cls {};
    CHECK_COND_RET(env->FindClass(className, &cls) == ANI_OK, nullptr,
        "Failed to find class: %{public}s", className);
    ani_method ctorMethod {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK, nullptr,
        "Failed to find method: <ctor>");
    ani_object aniObject {};
    CHECK_COND_RET(env->Object_New(cls, ctorMethod, &aniObject) == ANI_OK, nullptr, "Call method <ctor> failed.");

    ani_method fdSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>fd", nullptr, &fdSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>fd");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, fdSetter, (ani_int)fdSrcDescriptor.fd) == ANI_OK, nullptr,
        "<set>fd fail");
    ani_method offSetSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>offset", nullptr, &offSetSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>offSetSetter");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, offSetSetter, (ani_int)fdSrcDescriptor.offset) == ANI_OK,
        nullptr, "<set>offset fail");
    ani_method lengthSetter {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "<set>length", nullptr, &lengthSetter) == ANI_OK, nullptr,
        "Failed to find method: <set>lengthSetter");
    CHECK_COND_RET(env->Object_CallMethod_Void(aniObject, lengthSetter, (ani_int)fdSrcDescriptor.length) == ANI_OK,
        nullptr, "<set>length fail");
    return aniObject;
}

}
}
