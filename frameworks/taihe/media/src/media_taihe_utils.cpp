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

#include "avcodec_info.h"
#include "media_taihe_utils.h"
#include "media_log.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "MediaTaiheUtils"};
}

namespace ANI {
namespace Media {

static const std::map<OHOS::AudioStandard::InterruptMode, int32_t> TAIHE_INTERRUPTMODE_INDEX_MAP = {
    {OHOS::AudioStandard::InterruptMode::SHARE_MODE, 0},
    {OHOS::AudioStandard::InterruptMode::INDEPENDENT_MODE, 1},
};

const std::map<std::string, OHOS::Media::OutputFormatType> g_extensionToOutputFormat = {
    { "mp4", OHOS::Media::OutputFormatType::FORMAT_MPEG_4 },
    { "m4a", OHOS::Media::OutputFormatType::FORMAT_M4A },
};

const std::map<std::string_view, int32_t> g_mimeStrToCodecFormat = {
    { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC, OHOS::Media::AudioCodecFormat::AAC_LC },
    { OHOS::MediaAVCodec::CodecMimeType::VIDEO_AVC, OHOS::Media::VideoCodecFormat::H264 },
    { OHOS::MediaAVCodec::CodecMimeType::VIDEO_MPEG4, OHOS::Media::VideoCodecFormat::MPEG4 },
};

void MediaTaiheUtils::ThrowExceptionError(const std::string errMsg)
{
    MEDIA_LOGE("errMsg: %{public}s", errMsg.c_str());
    taihe::set_error(errMsg);
}

string MediaTaiheUtils::ToTaiheString(const std::string &src)
{
    return ::taihe::string(src);
}

template <typename EnumType>
bool MediaTaiheUtils::GetEnumKeyByValue(int32_t value, typename EnumType::key_t &key)
{
    for (size_t index = 0; index < std::size(EnumType::table); ++index) {
        if (EnumType::table[index] == value) {
            key = static_cast<typename EnumType::key_t>(index);
            return true;
        }
    }
    return false;
}

template <typename EnumTypeString>
bool MediaTaiheUtils::GetEnumKeyByStringValue(::taihe::string_view value, typename EnumTypeString::key_t &key)
{
    for (size_t index = 0; index < std::size(EnumTypeString::table); ++index) {
        if (EnumTypeString::table[index] == value) {
            key = static_cast<typename EnumTypeString::key_t>(index);
            return true;
        }
    }
    return false;
}

template
bool MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(::taihe::string_view value,
    typename ohos::multimedia::media::CodecMimeType::key_t &key);

template
bool MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::ContainerFormatType>(::taihe::string_view value,
    typename ohos::multimedia::media::ContainerFormatType::key_t &key);

template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEncodingType>(int32_t value,
    typename ohos::multimedia::audio::AudioEncodingType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceType>(int32_t value,
    typename ohos::multimedia::audio::DeviceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceRole>(int32_t value,
    typename ohos::multimedia::audio::DeviceRole::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::SourceType>(int32_t value,
    typename ohos::multimedia::audio::SourceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioState>(int32_t value,
    typename ohos::multimedia::audio::AudioState::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::StreamUsage>(int32_t value,
    typename ohos::multimedia::audio::StreamUsage::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioVolumeMode>(int32_t value,
    typename ohos::multimedia::audio::AudioVolumeMode::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::HdrType>(int32_t value,
    typename ohos::multimedia::media::HdrType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::AudioSourceType>(int32_t value,
    typename ohos::multimedia::media::AudioSourceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::VideoSourceType>(int32_t value,
    typename ohos::multimedia::media::VideoSourceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::MetaSourceType>(int32_t value,
    typename ohos::multimedia::media::MetaSourceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::FileGenerationMode>(int32_t value,
    typename ohos::multimedia::media::FileGenerationMode::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<VideoScaleType>(int32_t value, typename VideoScaleType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<StateChangeReason>(int32_t value, typename StateChangeReason::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<BufferingInfoType>(int32_t value, typename BufferingInfoType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEffectMode>(int32_t value,
    typename ohos::multimedia::audio::AudioEffectMode::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::InterruptType>(int32_t value,
    typename ohos::multimedia::audio::InterruptType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::InterruptForceType>(int32_t value,
    typename ohos::multimedia::audio::InterruptForceType::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::InterruptHint>(int32_t value,
    typename ohos::multimedia::audio::InterruptHint::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioStreamDeviceChangeReason>(int32_t value,
    typename ohos::multimedia::audio::AudioStreamDeviceChangeReason::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::InterruptMode>(int32_t value,
    typename ohos::multimedia::audio::InterruptMode::key_t &key);
template
bool MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::AVMetricsEventType>(int32_t value,
    typename ohos::multimedia::media::AVMetricsEventType::key_t &key);


ani_object MediaTaiheUtils::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass(CLASS_NAME_BUSINESSERROR, &cls) == ANI_OK, err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", ":", &ctor) == ANI_OK, err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &error) == ANI_OK, err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Int(error, "code", static_cast<ani_int>(code)) == ANI_OK, err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_AND_RETURN_RET_LOG(env->String_NewUTF8(message.c_str(), message.size(), &messageRef) == ANI_OK, err,
        "new message string failed");
    CHECK_AND_RETURN_RET_LOG(
        env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)) == ANI_OK, err,
        "set property BusinessError.message failed");
    return error;
}

ani_string MediaTaiheUtils::ToAniString(ani_env *env, const std::string &str)
{
    ani_string aniString;
    if (env->String_NewUTF8(str.c_str(), str.size(), &aniString) != ANI_OK) {
        printf("String_NewUTF8 failed");
    }
    return aniString;
}

uintptr_t MediaTaiheUtils::GetUndefined(ani_env* env)
{
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    ani_object undefinedObject = static_cast<ani_object>(undefinedRef);
    return reinterpret_cast<uintptr_t>(undefinedObject);
}

map<string, MediaDescriptionValue> MediaTaiheUtils::CreateFormatBuffer(OHOS::Media::Format &format)
{
    int32_t intValue = 0;
    std::string strValue;
    map<string, MediaDescriptionValue> description;

    for (auto &iter : format.GetFormatMap()) {
        switch (format.GetValueType(std::string_view(iter.first))) {
            case OHOS::Media::FORMAT_TYPE_INT32:
                if (format.GetIntValue(iter.first, intValue)) {
                    description.emplace(iter.first, MediaDescriptionValue::make_type_int(intValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_INT64:
                int64_t longValue;
                if (format.GetLongValue(iter.first, longValue) &&
                    longValue >= INT32_MIN && longValue <= INT32_MAX) {
                    intValue = static_cast<int32_t>(longValue);
                    description.emplace(iter.first, MediaDescriptionValue::make_type_int(intValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_DOUBLE:
                double doubleValue;
                if (format.GetDoubleValue(iter.first, doubleValue) &&
                    doubleValue >= INT32_MIN && doubleValue <= INT32_MAX) {
                    intValue = static_cast<int32_t>(doubleValue);
                    description.emplace(iter.first, MediaDescriptionValue::make_type_int(intValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_STRING:
                if (format.GetStringValue(iter.first, strValue)) {
                    description.emplace(iter.first, MediaDescriptionValue::make_type_string(strValue));
                }
                break;
            default:
                MEDIA_LOGE("format key: %{public}s", iter.first.c_str());
                break;
        }
    }
    return description;
}

map<string, PlaybackInfoValue> MediaTaiheUtils::CreateFormatBufferByRef(OHOS::Media::Format &format)
{
    int32_t intValue = 0;
    int64_t longValue = 0;
    std::string strValue = "";
    map<string, PlaybackInfoValue> playbackInfo;

    for (auto &iter : format.GetFormatMap()) {
        switch (format.GetValueType(std::string_view(iter.first))) {
            case OHOS::Media::FORMAT_TYPE_INT32:
                if (format.GetIntValue(iter.first, intValue)) {
                    playbackInfo.emplace(iter.first, PlaybackInfoValue::make_type_int(intValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_INT64:
                if (format.GetLongValue(iter.first, longValue)) {
                    playbackInfo.emplace(iter.first, PlaybackInfoValue::make_type_int(longValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_STRING:
                if (format.GetStringValue(iter.first, strValue)) {
                    playbackInfo.emplace(iter.first, PlaybackInfoValue::make_type_string(strValue));
                }
                break;
            default:
                MEDIA_LOGE("format key: %{public}s", iter.first.c_str());
                break;
        }
    }
    return playbackInfo;
}

map<::ohos::multimedia::media::PlaybackMetricsKey, PlaybackMetricsValue> MediaTaiheUtils::CreateFormatResult(
    OHOS::Media::Format &format)
{
    int32_t intValue = 0;
    uint32_t uintValue = 0;
    int64_t longValue = 0;
    std::string strValue = "";
    map<::ohos::multimedia::media::PlaybackMetricsKey, PlaybackMetricsValue> playbackMetrics;

    for (auto &iter : format.GetFormatMap()) {
        taihe::string playbackMetricsType = MediaTaiheUtils::ToTaiheString(iter.first);
        ohos::multimedia::media::PlaybackMetricsKey::key_t playbackMetricsKey;
        MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::PlaybackMetricsKey>(
            playbackMetricsType, playbackMetricsKey);
        switch (format.GetValueType(std::string_view(iter.first))) {
            case OHOS::Media::FORMAT_TYPE_INT32:
                if (format.GetIntValue(iter.first, intValue)) {
                    playbackMetrics.emplace(playbackMetricsKey, PlaybackMetricsValue::make_type_int(intValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_UINT32:
                if (format.GetUintValue(iter.first, uintValue)) {
                    playbackMetrics.emplace(playbackMetricsKey, PlaybackMetricsValue::make_type_int(uintValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_INT64:
                if (format.GetLongValue(iter.first, longValue)) {
                    playbackMetrics.emplace(playbackMetricsKey, PlaybackMetricsValue::make_type_int(longValue));
                }
                break;
            case OHOS::Media::FORMAT_TYPE_STRING:
                if (format.GetStringValue(iter.first, strValue)) {
                    playbackMetrics.emplace(playbackMetricsKey, PlaybackMetricsValue::make_type_string(strValue));
                }
                break;
            default:
                MEDIA_LOGE("format key: %{public}s", iter.first.c_str());
                break;
        }
    }
    return playbackMetrics;
}

bool MediaTaiheUtils::IsSystemApp()
{
    uint64_t accessTokenIDEx = OHOS::IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx);
    return isSystemApp;
}

bool MediaTaiheUtils::SystemPermission()
{
    auto tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE ||
        tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        return true;
    }
    return IsSystemApp();
}

int32_t MediaTaiheUtils::MapExtensionNameToOutputFormat(const std::string &extension,
    OHOS::Media::OutputFormatType &type)
{
    auto iter = g_extensionToOutputFormat.find(extension);
    if (iter != g_extensionToOutputFormat.end()) {
        type = iter->second;
    }
    return OHOS::Media::MSERR_INVALID_VAL;
}

int32_t MediaTaiheUtils::MapMimeToAudioCodecFormat(const std::string &mime, OHOS::Media::AudioCodecFormat &codecFormat)
{
    auto iter = g_mimeStrToCodecFormat.find(mime);
    if (iter != g_mimeStrToCodecFormat.end()) {
        codecFormat = static_cast<OHOS::Media::AudioCodecFormat>(iter->second);
    }
    return OHOS::Media::MSERR_INVALID_VAL;
}

int32_t MediaTaiheUtils::MapMimeToVideoCodecFormat(const std::string &mime, OHOS::Media::VideoCodecFormat &codecFormat)
{
    auto iter = g_mimeStrToCodecFormat.find(mime);
    if (iter != g_mimeStrToCodecFormat.end()) {
        codecFormat = static_cast<OHOS::Media::VideoCodecFormat>(iter->second);
    }
    return OHOS::Media::MSERR_INVALID_VAL;
}
}
}
