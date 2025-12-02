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
#ifndef MEDIA_TAIHE_UTILS_H
#define MEDIA_TAIHE_UTILS_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "ohos.multimedia.audio.proj.hpp"
#include "ohos.multimedia.audio.impl.hpp"
#include "audio_info.h"
#include "taihe/runtime.hpp"
#include "audio_effect.h"
#include "audio_device_descriptor.h"
#include "meta/format.h"
#include "image_source.h"
#include "recorder.h"

namespace ANI {
namespace Media {
using namespace taihe;
using namespace ohos::multimedia::media;

constexpr char CLASS_NAME_BUSINESSERROR[] = "@ohos.base.BusinessError";
constexpr char CLASS_NAME_ERRORINFO[] = "multimedia.soundPool._taihe_ErrorInfo_inject";
constexpr char ENUM_NAME_ERRORTYPE[] = "multimedia.soundPool.ErrorType";
class MediaTaiheUtils {
public:
    static string ToTaiheString(const std::string &src);
    static void ThrowExceptionError(const std::string errMsg);
    template <typename EnumType>
    static bool GetEnumKeyByValue(int32_t value, typename EnumType::key_t &key);
    template <typename EnumTypeString>
    static bool GetEnumKeyByStringValue(::taihe::string_view value, typename EnumTypeString::key_t &key);
    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);
    static ani_string ToAniString(ani_env *env, const std::string &str);
    static uintptr_t GetUndefined(ani_env* env);
    static map<string, MediaDescriptionValue> CreateFormatBuffer(OHOS::Media::Format &format);
    static map<string, PlaybackInfoValue> CreateFormatBufferByRef(OHOS::Media::Format &format);
    static bool IsSystemApp();
    static bool SystemPermission();
    static int32_t MapExtensionNameToOutputFormat(const std::string &extension, OHOS::Media::OutputFormatType &type);
    static int32_t MapMimeToAudioCodecFormat(const std::string &mime, OHOS::Media::AudioCodecFormat &codecFormat);
    static int32_t MapMimeToVideoCodecFormat(const std::string &mime, OHOS::Media::VideoCodecFormat &codecFormat);
};
}
}
#endif // MEDIA_TAIHE_UTILS_H
