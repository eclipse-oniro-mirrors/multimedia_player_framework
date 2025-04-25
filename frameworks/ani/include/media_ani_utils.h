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
#ifndef FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_UTILS_H
#define FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_UTILS_H

#include "media_log.h"
#include "ani.h"
#include "audio_info.h"
#include "string"
#include "media_ani_common.h"
#include "media_core.h"

namespace OHOS {
namespace Media {
class MediaAniUtils {
public:
    static ani_boolean isArray(ani_env *env, ani_object object);
    static ani_boolean isUndefined(ani_env *env, ani_object object);
    static ani_status GetString(ani_env *env, ani_string arg, std::string &str);
    static ani_status GetString(ani_env *env, ani_object arg, std::string &str);
    static ani_status ToAniInt32Array(ani_env *env, const std::vector<int32_t> &array,
        ani_object &aniArray);
    static ani_status ToAniInt(ani_env *env, const std::int32_t &int32, ani_int &aniInt);
    static ani_status ToAniLong(ani_env *env, const std::int64_t &int64, ani_long &aniLong);
    static ani_status ToAniDouble(ani_env *env, const double &arg, ani_double &aniDouble);
    static ani_status GetFloat(ani_env *env, ani_float arg, float &value);
    static ani_status GetDouble(ani_env *env, ani_double arg, double &value);
    static ani_status ToAniFloatArray(ani_env *env, const std::vector<float> &array,
        ani_object &aniArray);
    static ani_status ToAniString(ani_env *env, const std::string &str, ani_string &aniStr);
    static ani_status ToAniNumberObject(ani_env *env, int32_t src, ani_object &aniObj);
    static ani_status ParseAVDataSrcDescriptor(ani_env *env, ani_object src, AVDataSrcDescriptor &dataSrcDescriptor);
    static ani_object CreateAVDataSrcDescriptor(ani_env *env, AVDataSrcDescriptor &dataSrcDescriptor);
    static ani_status ParseAudioRendererInfo(ani_env *env, ani_object src,
        AudioStandard::AudioRendererInfo &dataSrcDescriptor);
    static ani_object CreateAudioRendererInfo(ani_env *env, AudioStandard::AudioRendererInfo &audioRendererInfo);
    static ani_status ToAniEnum(ani_env *env, AudioStandard::InterruptMode value, ani_enum_item &aniEnumItem);
    static ani_status GetObjectArray(ani_env *env, ani_object arg, std::vector<ani_object> &array);

    static ani_status GetProperty(ani_env *env, ani_object arg, const std::string &propName, std::string &propValue);
    static ani_status GetProperty(ani_env *env, ani_object arg, const std::string &propName, ani_object &propObj);
    static void CreateError(ani_env *env, int32_t errCode, const std::string &errMsg, ani_object &errorObj);
    static ani_object CreateAVFdSrcDescriptor(ani_env *env, AVFileDescriptor &fdSrcDescriptor);
};

}
}
#endif // FRAMEWORKS_ANI_INCLUDE_MEDIA_ANI_UTILS_H