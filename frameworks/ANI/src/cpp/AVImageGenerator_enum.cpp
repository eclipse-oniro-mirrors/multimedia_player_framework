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
#include <map>
#include "AVImageGenerator_enum.h"
#include "media_ani_log.h"

namespace OHOS {
namespace Media {

static const std::map<AVEnumTypeInt32, std::string> AVENUM_TYPE_MAP_INT32 = {
    {AVEnumTypeInt32::AVImageQueryOptions, "LAVImageGenerator_enum/#AVImageQueryOptions;"},
    {AVEnumTypeInt32::PixelFormat, "LAVImageGenerator_enum/#PixelFormat;"},
    {AVEnumTypeInt32::PlaybackSpeed, "LAVImageGenerator_enum/#PlaybackSpeed;"},
    {AVEnumTypeInt32::SeekMode, "LAVImageGenerator_enum/#SeekMode;"},
};

ani_status AVImageGeneratorEnumAni::EnumGetValueInt32(ani_env *env, ani_enum_item enumItem, int32_t &value)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "Invalid env");
    ani_int aniInt {};
    CHECK_STATUS_RET(env->EnumItem_GetValue_Int(enumItem, &aniInt), "EnumItem_GetValue_Int failed");
    CHECK_STATUS_RET(AVImageGeneratorEnumAni::GetInt32(env, aniInt, value), "GetInt32 failed");
    return ANI_OK;
}

ani_status AVImageGeneratorEnumAni::GetInt32(ani_env *env, ani_int arg, int32_t &value)
{
    value = static_cast<int32_t>(arg);
    return ANI_OK;
}
}
}