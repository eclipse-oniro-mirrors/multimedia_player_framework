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

#include "system_sound_manager_impl.h"

#include <fstream>
#include <nativetoken_kit.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "directory_ex.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "ringtone_proxy_uri.h"

#include "config_policy_utils.h"
#include "file_ex.h"
#include "nlohmann/json.hpp"

#include "system_sound_log.h"
#include "media_errors.h"
#include "ringtone_player_impl.h"
#include "vibrate_type.h"
#include "os_account_manager.h"
#include "system_tone_player_impl.h"
#include "parameter.h"
#include "string_ex.h"
#include "parameters.h"
#include "system_sound_manager_utils.h"

using namespace std;
using namespace nlohmann;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::DataShare;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundManagerImpl"};
}

namespace OHOS {
namespace Media {
const std::string FDHEAD = "fd://";
const std::string RING_TONE = "ring_tone";
const std::string SYSTEM_TONE = "system_tone";
const std::string DEFAULT_SYSTEM_SOUND_PATH = "resource/media/audio/";
const std::string DEFAULT_RINGTONE_URI_JSON = "ringtone_incall.json";
const std::string DEFAULT_RINGTONE_PATH = "ringtones/";
const std::string DEFAULT_SYSTEM_TONE_URI_JSON = "ringtone_sms-notification.json";
const std::string DEFAULT_SYSTEM_TONE_PATH = "notifications/";
const std::string EXT_SERVICE_AUDIO = "const.mulitimedia.service_audio";
const int STORAGE_MANAGER_MANAGER_ID = 5003;
const int UNSUPPORTED_ERROR = -5;
const int INVALID_FD = -1;
const int32_t NOT_ENOUGH_ROM = -234;
const int32_t VIDEOS_NUM_EXCEEDS_SPECIFICATION = -235;
const int32_t FILE_EXIST = -17;
const int32_t MAX_VECTOR_LENGTH = 1024;
const off_t MAX_FILE_SIZE_1G = 1024 * 1024 * 1024;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;
#ifdef SUPPORT_VIBRATOR
const int OPERATION_ERROR = -4;
#endif
const int IO_ERROR = -3;
const int TYPEERROR = -2;
const int ERROR = -1;
const int SUCCESS = 0;
const int32_t EXT_PROXY_UID = 1000;
const int32_t EXT_PROXY_SID = 66849;
const int32_t CMD_SET_EXT_RINGTONE_URI = 6;

enum ExtToneType : int32_t {
    EXT_TYPE_RINGTONE_ONE = 1,
    EXT_TYPE_NOTIFICATION = 2,
    EXT_TYPE_ALARMTONE = 4,
    EXT_TYPE_RINGTONE_TWO = 8,
    EXT_TYPE_MESSAGETONE_ONE = 16,
    EXT_TYPE_MESSAGETONE_TWO = 32,
};

// tone haptics default setting
static const char PARAM_HAPTICS_SETTING_RINGTONE_CARD_ONE[] = "const.multimedia.haptics_ringtone_sim_card_0_haptics";
static const char PARAM_HAPTICS_SETTING_RINGTONE_CARD_TWO[] = "const.multimedia.haptics_ringtone_sim_card_1_haptics";
static const char PARAM_HAPTICS_SETTING_SHOT_CARD_ONE[] = "const.multimedia.haptics_system_tone_sim_card_0_haptics";
static const char PARAM_HAPTICS_SETTING_SHOT_CARD_TWO[] = "const.multimedia.haptics_system_tone_sim_card_1_haptics";
static const char PARAM_HAPTICS_SETTING_NOTIFICATIONTONE[] = "const.multimedia.notification_tone_haptics";
static const int32_t SYSPARA_SIZE = 128;

const char RINGTONE_PARAMETER_SCANNER_FIRST_KEY[] = "ringtone.scanner.first";
const int32_t RINGTONEPARA_SIZE = 64;

std::shared_ptr<SystemSoundManager> SystemSoundManagerFactory::systemSoundManager_ = nullptr;
std::mutex SystemSoundManagerFactory::systemSoundManagerMutex_;
std::unordered_map<RingtoneType, RingToneType> ringtoneTypeMap_;
std::unordered_map<int32_t, ToneCustomizedType> sourceTypeMap_;
std::unordered_map<SystemToneType, int32_t> systemTypeMap_;
std::unordered_map<SystemToneType, ShotToneType> shotToneTypeMap_;
std::unordered_map<ToneHapticsMode, VibratePlayMode> hapticsModeMap_;
std::unordered_map<ToneHapticsType, std::pair<int32_t, int32_t>> hapticsTypeWhereArgsMap_;
std::unordered_map<int32_t, std::unordered_map<HapticsStyle, int32_t>> hapticsStyleMap_;
std::unordered_map<RingtoneType, DefaultSystemToneType> defaultoneTypeMap_;
std::unordered_map<SystemToneType, int32_t> defaultsystemTypeMap_;
Uri RINGTONEURI(RINGTONE_PATH_URI);
Uri VIBRATEURI(VIBRATE_PATH_URI);
Uri SIMCARDSETTINGURI(SIMCARD_SETTING_PATH_URI);
vector<string> COLUMNS = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}, {RINGTONE_COLUMN_DISPLAY_NAME},
    {RINGTONE_COLUMN_TITLE}, {RINGTONE_COLUMN_TONE_TYPE}, {RINGTONE_COLUMN_MEDIA_TYPE}, {RINGTONE_COLUMN_SOURCE_TYPE},
    {RINGTONE_COLUMN_SHOT_TONE_TYPE}, {RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE},
    {RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_RING_TONE_TYPE},
    {RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_ALARM_TONE_TYPE},
    {RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE}};
vector<string> JOIN_COLUMNS = {{RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA},
    {RINGTONE_TABLE + "." + RINGTONE_COLUMN_DISPLAY_NAME}, {RINGTONE_COLUMN_TITLE},
    {RINGTONE_COLUMN_TONE_TYPE}, {RINGTONE_COLUMN_SOURCE_TYPE}, {RINGTONE_COLUMN_SHOT_TONE_TYPE},
    {RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE},
    {RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE}, {RINGTONE_TABLE + "." + RINGTONE_COLUMN_RING_TONE_TYPE},
    {RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_ALARM_TONE_TYPE},
    {RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE}};
vector<string> SETTING_TABLE_COLUMNS = {{SIMCARD_SETTING_COLUMN_MODE}, {SIMCARD_SETTING_COLUMN_TONE_FILE},
    {SIMCARD_SETTING_COLUMN_RINGTONE_TYPE}, {SIMCARD_SETTING_COLUMN_VIBRATE_FILE},
    {SIMCARD_SETTING_COLUMN_VIBRATE_MODE}, {SIMCARD_SETTING_COLUMN_RING_MODE}};
vector<string> VIBRATE_TABLE_COLUMNS = {{VIBRATE_COLUMN_VIBRATE_ID}, {VIBRATE_COLUMN_DATA}, {VIBRATE_COLUMN_SIZE},
    {VIBRATE_COLUMN_DISPLAY_NAME}, {VIBRATE_COLUMN_TITLE}, {VIBRATE_COLUMN_DISPLAY_LANGUAGE},
    {VIBRATE_COLUMN_VIBRATE_TYPE}, {VIBRATE_COLUMN_SOURCE_TYPE}, {VIBRATE_COLUMN_DATE_ADDED},
    {VIBRATE_COLUMN_DATE_MODIFIED}, {VIBRATE_COLUMN_DATE_TAKEN}, {VIBRATE_COLUMN_PLAY_MODE}};
std::vector<std::string> RINGTONETYPE = {{RINGTONE_CONTAINER_TYPE_MP3}, {RINGTONE_CONTAINER_TYPE_OGG},
    {RINGTONE_CONTAINER_TYPE_AC3}, {RINGTONE_CONTAINER_TYPE_AAC}, {RINGTONE_CONTAINER_TYPE_FLAC},
    {RINGTONE_CONTAINER_TYPE_WAV}, {RINGTONE_CONTAINER_TYPE_VIDEO_MP4}};

std::shared_ptr<SystemSoundManager> SystemSoundManagerFactory::CreateSystemSoundManager()
{
    std::lock_guard<std::mutex> lock(systemSoundManagerMutex_);
    if (systemSoundManager_ == nullptr) {
        systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    }
    CHECK_AND_RETURN_RET_LOG(systemSoundManager_ != nullptr, nullptr, "Failed to create sound manager object");
    return systemSoundManager_;
}

SystemSoundManagerImpl::SystemSoundManagerImpl()
{
    InitDefaultUriMap();
    InitRingerMode();
    InitMap();
    InitDefaultToneHapticsMap();
}

SystemSoundManagerImpl::~SystemSoundManagerImpl()
{
    if (audioGroupManager_ != nullptr) {
        (void)audioGroupManager_->UnsetRingerModeCallback(getpid(), ringerModeCallback_);
        ringerModeCallback_ = nullptr;
        audioGroupManager_ = nullptr;
    }
}

void SystemSoundManagerImpl::InitMap(void)
{
    ringtoneTypeMap_[RINGTONE_TYPE_SIM_CARD_0] = RING_TONE_TYPE_SIM_CARD_1;
    ringtoneTypeMap_[RINGTONE_TYPE_SIM_CARD_1] = RING_TONE_TYPE_SIM_CARD_2;
    sourceTypeMap_[SOURCE_TYPE_PRESET] = PRE_INSTALLED;
    sourceTypeMap_[SOURCE_TYPE_CUSTOMISED] = CUSTOMISED;
    systemTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_0] = SHOT_TONE_TYPE_SIM_CARD_1;
    systemTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_1] = SHOT_TONE_TYPE_SIM_CARD_2;
    systemTypeMap_[SYSTEM_TONE_TYPE_NOTIFICATION] = NOTIFICATION_TONE_TYPE;
    shotToneTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_0] = SHOT_TONE_TYPE_SIM_CARD_1;
    shotToneTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_1] = SHOT_TONE_TYPE_SIM_CARD_2;
    defaultoneTypeMap_[RINGTONE_TYPE_SIM_CARD_0] = DEFAULT_RING_TYPE_SIM_CARD_1;
    defaultoneTypeMap_[RINGTONE_TYPE_SIM_CARD_1] = DEFAULT_RING_TYPE_SIM_CARD_2;
    defaultsystemTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_0] = DEFAULT_SHOT_TYPE_SIM_CARD_1;
    defaultsystemTypeMap_[SYSTEM_TONE_TYPE_SIM_CARD_1] = DEFAULT_SHOT_TYPE_SIM_CARD_2;
    defaultsystemTypeMap_[SYSTEM_TONE_TYPE_NOTIFICATION] = DEFAULT_NOTIFICATION_TYPE;
    hapticsModeMap_[NONE] = VIBRATE_PLAYMODE_NONE;
    hapticsModeMap_[SYNC] = VIBRATE_PLAYMODE_SYNC;
    hapticsModeMap_[NON_SYNC] = VIBRATE_PLAYMODE_CLASSIC;
    hapticsTypeWhereArgsMap_ = {
        {ToneHapticsType::CALL_SIM_CARD_0, {RING_TONE_TYPE_SIM_CARD_1, TONE_SETTING_TYPE_RINGTONE}},
        {ToneHapticsType::CALL_SIM_CARD_1, {RING_TONE_TYPE_SIM_CARD_2, TONE_SETTING_TYPE_RINGTONE}},
        {ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0, {RING_TONE_TYPE_SIM_CARD_1, TONE_SETTING_TYPE_SHOT}},
        {ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1, {RING_TONE_TYPE_SIM_CARD_2, TONE_SETTING_TYPE_SHOT}},
        {ToneHapticsType::NOTIFICATION, {RING_TONE_TYPE_SIM_CARD_BOTH, TONE_SETTING_TYPE_NOTIFICATION}},
    };
    hapticsStyleMap_[VIBRATE_TYPE_STANDARD] = {
        {HAPTICS_STYLE_GENTLE, VIBRATE_TYPE_GENTLE},
    };
    hapticsStyleMap_[VIBRATE_TYPE_SALARM] = {
        {HAPTICS_STYLE_GENTLE, VIBRATE_TYPE_GALARM},
    };
    hapticsStyleMap_[VIBRATE_TYPE_SRINGTONE] = {
        {HAPTICS_STYLE_GENTLE, VIBRATE_TYPE_GRINGTONE},
    };
    hapticsStyleMap_[VIBRATE_TYPE_SNOTIFICATION] = {
        {HAPTICS_STYLE_GENTLE, VIBRATE_TYPE_GNOTIFICATION},
    };
}

void SystemSoundManagerImpl::InitRingerMode(void)
{
    audioGroupManager_ = AudioStandard::AudioSystemManager::GetInstance()->
        GetGroupManager(AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager_ == nullptr) {
        MEDIA_LOGE("InitRingerMode: audioGroupManager_ is nullptr");
        return;
    }
    ringerMode_ = audioGroupManager_->GetRingerMode();

    ringerModeCallback_ = std::make_shared<RingerModeCallbackImpl>(*this);
    audioGroupManager_->SetRingerModeCallback(getpid(), ringerModeCallback_);
}

bool SystemSoundManagerImpl::IsRingtoneTypeValid(RingtoneType ringtongType)
{
    switch (ringtongType) {
        case RINGTONE_TYPE_SIM_CARD_0:
        case RINGTONE_TYPE_SIM_CARD_1:
            return true;
        default:
            MEDIA_LOGE("IsRingtoneTypeValid: ringtongType %{public}d is unavailable", ringtongType);
            return false;
    }
}

bool SystemSoundManagerImpl::IsSystemToneTypeValid(SystemToneType systemToneType)
{
    switch (systemToneType) {
        case SYSTEM_TONE_TYPE_SIM_CARD_0:
        case SYSTEM_TONE_TYPE_SIM_CARD_1:
        case SYSTEM_TONE_TYPE_NOTIFICATION:
            return true;
        default:
            MEDIA_LOGE("IsSystemToneTypeValid: systemToneType %{public}d is unavailable", systemToneType);
            return false;
    }
}

bool SystemSoundManagerImpl::IsSystemToneType(const unique_ptr<RingtoneAsset> &ringtoneAsset,
    const SystemToneType &systemToneType)
{
    CHECK_AND_RETURN_RET_LOG(ringtoneAsset != nullptr, false, "Invalid ringtone asset.");
    return (systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_TYPE_NOTIFICATION != ringtoneAsset->GetToneType() :
        TONE_TYPE_SHOT != ringtoneAsset->GetToneType());
}

bool SystemSoundManagerImpl::IsToneHapticsTypeValid(ToneHapticsType toneHapticsType)
{
    switch (toneHapticsType) {
        case ToneHapticsType::CALL_SIM_CARD_0 :
        case ToneHapticsType::CALL_SIM_CARD_1 :
        case ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0 :
        case ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1 :
        case ToneHapticsType::NOTIFICATION :
            return true;
        default:
            MEDIA_LOGE("IsToneHapticsTypeValid: toneHapticsType %{public}d is unavailable", toneHapticsType);
            return false;
    }
}

void SystemSoundManagerImpl::InitDefaultUriMap()
{
    systemSoundPath_ = GetFullPath(DEFAULT_SYSTEM_SOUND_PATH);

    std::string ringtoneJsonPath = systemSoundPath_ + DEFAULT_RINGTONE_URI_JSON;
    InitDefaultRingtoneUriMap(ringtoneJsonPath);

    std::string systemToneJsonPath = systemSoundPath_ + DEFAULT_SYSTEM_TONE_URI_JSON;
    InitDefaultSystemToneUriMap(systemToneJsonPath);
}

void SystemSoundManagerImpl::InitDefaultRingtoneUriMap(const std::string &ringtoneJsonPath)
{
    std::lock_guard<std::mutex> lock(uriMutex_);

    std::string jsonValue = GetJsonValue(ringtoneJsonPath);
    nlohmann::json ringtoneJson = json::parse(jsonValue, nullptr, false);
    if (ringtoneJson.is_discarded()) {
        MEDIA_LOGE("ringtoneJson parsing is false !");
        return;
    }
    if (ringtoneJson.contains("preset_ringtone_sim1") && ringtoneJson["preset_ringtone_sim1"].is_string()) {
        std::string defaultRingtoneName = ringtoneJson["preset_ringtone_sim1"];
        defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_0] =
            systemSoundPath_ + DEFAULT_RINGTONE_PATH + defaultRingtoneName + ".ogg";
        MEDIA_LOGI("preset_ringtone_sim1 is [%{public}s]", defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_0].c_str());
    } else {
        defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_0] = "";
        MEDIA_LOGW("InitDefaultRingtoneUriMap: failed to load uri of preset_ringtone_sim1");
    }
    if (ringtoneJson.contains("preset_ringtone_sim2") && ringtoneJson["preset_ringtone_sim2"].is_string()) {
        std::string defaultRingtoneName = ringtoneJson["preset_ringtone_sim2"];
        defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_1] =
            systemSoundPath_ + DEFAULT_RINGTONE_PATH + defaultRingtoneName + ".ogg";
        MEDIA_LOGI("preset_ringtone_sim1 is [%{public}s]", defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_1].c_str());
    } else {
        defaultRingtoneUriMap_[RINGTONE_TYPE_SIM_CARD_1] = "";
        MEDIA_LOGW("InitDefaultRingtoneUriMap: failed to load uri of preset_ringtone_sim2");
    }
}

std::string SystemSoundManagerImpl::GetDefaultRingtoneUri(RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    if (defaultRingtoneUriMap_.count(ringtoneType) == 0) {
        MEDIA_LOGE("Failed to GetDefaultRingtoneUri: invalid ringtone type %{public}d", ringtoneType);
        return "";
    }
    return defaultRingtoneUriMap_[ringtoneType];
}

std::string SystemSoundManagerImpl::GetDefaultSystemToneUri(SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    if (defaultSystemToneUriMap_.count(systemToneType) == 0) {
        MEDIA_LOGE("Failed to GetDefaultRingtoneUri: invalid system tone type %{public}d", systemToneType);
        return "";
    }
    return defaultSystemToneUriMap_[systemToneType];
}

void SystemSoundManagerImpl::InitDefaultSystemToneUriMap(const std::string &systemToneJsonPath)
{
    std::lock_guard<std::mutex> lock(uriMutex_);

    std::string jsonValue = GetJsonValue(systemToneJsonPath);
    nlohmann::json systemToneJson = json::parse(jsonValue, nullptr, false);
    if (systemToneJson.is_discarded()) {
        MEDIA_LOGE("systemToneJson parsing is false !");
        return;
    }
    if (systemToneJson.contains("preset_ringtone_sms") && systemToneJson["preset_ringtone_sms"].is_string()) {
        std::string defaultSystemToneName = systemToneJson["preset_ringtone_sms"];
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_SIM_CARD_0] =
            systemSoundPath_ + DEFAULT_SYSTEM_TONE_PATH + defaultSystemToneName + ".ogg";
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_SIM_CARD_1] =
            systemSoundPath_ + DEFAULT_SYSTEM_TONE_PATH + defaultSystemToneName + ".ogg";
        MEDIA_LOGI("preset_ringtone_sms is [%{public}s]",
            defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_SIM_CARD_0].c_str());
    } else {
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_SIM_CARD_0] = "";
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_SIM_CARD_1] = "";
        MEDIA_LOGW("InitDefaultSystemToneUriMap: failed to load uri of preset_ringtone_sms");
    }
    if (systemToneJson.contains("preset_ringtone_notification") &&
        systemToneJson["preset_ringtone_notification"].is_string()) {
        std::string defaultSystemToneName = systemToneJson["preset_ringtone_notification"];
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_NOTIFICATION] =
            systemSoundPath_ + DEFAULT_SYSTEM_TONE_PATH + defaultSystemToneName + ".ogg";
        MEDIA_LOGI("preset_ringtone_notification is [%{public}s]",
            defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_NOTIFICATION].c_str());
    } else {
        defaultSystemToneUriMap_[SYSTEM_TONE_TYPE_NOTIFICATION] = "";
        MEDIA_LOGW("InitDefaultSystemToneUriMap: failed to load uri of preset_ringtone_notification");
    }
}

void SystemSoundManagerImpl::ReadDefaultToneHaptics(const char *paramName, ToneHapticsType toneHapticsType)
{
    char paramValue[SYSPARA_SIZE] = {0};
    GetParameter(paramName, "", paramValue, SYSPARA_SIZE);
    if (strcmp(paramValue, "")) {
        defaultToneHapticsUriMap_.insert(make_pair(toneHapticsType, string(paramValue)));
        MEDIA_LOGI("ReadDefaultToneHaptics: tone [%{public}d] haptics is [%{public}s]", toneHapticsType, paramValue);
    } else {
        MEDIA_LOGW("ReadDefaultToneHaptics: failed to load uri of [%{public}s]", paramName);
    }
}

void SystemSoundManagerImpl::InitDefaultToneHapticsMap()
{
    ReadDefaultToneHaptics(PARAM_HAPTICS_SETTING_RINGTONE_CARD_ONE, ToneHapticsType::CALL_SIM_CARD_0);
    ReadDefaultToneHaptics(PARAM_HAPTICS_SETTING_RINGTONE_CARD_TWO, ToneHapticsType::CALL_SIM_CARD_1);
    ReadDefaultToneHaptics(PARAM_HAPTICS_SETTING_SHOT_CARD_ONE, ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0);
    ReadDefaultToneHaptics(PARAM_HAPTICS_SETTING_SHOT_CARD_TWO, ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1);
    ReadDefaultToneHaptics(PARAM_HAPTICS_SETTING_NOTIFICATIONTONE, ToneHapticsType::NOTIFICATION);
}

std::string SystemSoundManagerImpl::GetFullPath(const std::string &originalUri)
{
    char buf[MAX_PATH_LEN];
    char *path = GetOneCfgFile(originalUri.c_str(), buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        MEDIA_LOGE("GetOneCfgFile for %{public}s failed.", originalUri.c_str());
        return "";
    }
    std::string filePath = path;
    MEDIA_LOGI("GetFullPath for [%{public}s], result: [%{public}s]", originalUri.c_str(), filePath.c_str());
    return filePath;
}

std::string SystemSoundManagerImpl::GetJsonValue(const std::string &jsonPath)
{
    std::string jsonValue = "";
    ifstream file(jsonPath.c_str());
    if (!file.is_open()) {
        MEDIA_LOGI("file not open! try open first ! ");
        file.open(jsonPath.c_str(), ios::app);
        if (!file.is_open()) {
            MEDIA_LOGE("open file again fail !");
            return "";
        }
    }
    file.seekg(0, ios::end);

    const long maxFileLength = 32 * 1024 * 1024; // max size of the json file
    const long fileLength = file.tellg();
    if (fileLength > maxFileLength) {
        MEDIA_LOGE("invalid file length(%{public}ld)!", fileLength);
        return "";
    }

    jsonValue.clear();
    file.seekg(0, ios::beg);
    copy(istreambuf_iterator<char>(file), istreambuf_iterator<char>(), back_inserter(jsonValue));
    return jsonValue;
}

int32_t SystemSoundManagerImpl::WriteUriToDatabase(const std::string &key, const std::string &uri)
{
    int32_t result = AudioStandard::AudioSystemManager::GetInstance()->SetSystemSoundUri(key, uri);
    MEDIA_LOGI("WriteUriToDatabase: key: %{public}s, uri: %{public}s, result: %{public}d",
        key.c_str(), uri.c_str(), result);
    return result;
}

std::string SystemSoundManagerImpl::GetUriFromDatabase(const std::string &key)
{
    std::string uri = AudioStandard::AudioSystemManager::GetInstance()->GetSystemSoundUri(key);

    MEDIA_LOGI("GetUriFromDatabase: key [%{public}s], uri [%{public}s]", key.c_str(), uri.c_str());
    return uri;
}

std::string SystemSoundManagerImpl::GetKeyForDatabase(const std::string &systemSoundType, int32_t type)
{
    if (systemSoundType == RING_TONE) {
        switch (static_cast<RingtoneType>(type)) {
            case RINGTONE_TYPE_SIM_CARD_0:
                return "ringtone_for_sim_card_0";
            case RINGTONE_TYPE_SIM_CARD_1:
                return "ringtone_for_sim_card_1";
            default:
                MEDIA_LOGE("GetKeyForDatabase: ringtoneType %{public}d is unavailable", type);
                return "";
        }
    } else if (systemSoundType == SYSTEM_TONE) {
        switch (static_cast<SystemToneType>(type)) {
            case SYSTEM_TONE_TYPE_SIM_CARD_0:
                return "system_tone_for_sim_card_0";
            case SYSTEM_TONE_TYPE_SIM_CARD_1:
                return "system_tone_for_sim_card_1";
            case SYSTEM_TONE_TYPE_NOTIFICATION:
                return "system_tone_for_notification";
            default:
                MEDIA_LOGE("GetKeyForDatabase: systemToneType %{public}d is unavailable", type);
                return "";
        }
    } else {
        MEDIA_LOGE("GetKeyForDatabase: systemSoundType %{public}s is unavailable", systemSoundType.c_str());
        return "";
    }
}

int32_t SystemSoundManagerImpl::UpdateRingtoneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const int32_t &toneId, RingtoneType ringtoneType, const int32_t &num)
{
    RingToneType type = RING_TONE_TYPE_SIM_CARD_1;
    DataSharePredicates updateOnlyPredicates;
    DataShareValuesBucket updateOnlyValuesBucket;
    updateOnlyPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    updateOnlyPredicates.SetWhereArgs({to_string(ringtoneTypeMap_[ringtoneType]),
        to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOnlyValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_TYPE, RING_TONE_TYPE_NOT);
    updateOnlyValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOnlyPredicates, updateOnlyValuesBucket);

    DataSharePredicates updateBothPredicates;
    DataShareValuesBucket updateBothValuesBucket;
    if (ringtoneTypeMap_[ringtoneType] == RING_TONE_TYPE_SIM_CARD_1) {
        type = RING_TONE_TYPE_SIM_CARD_2;
    }
    updateBothPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    updateBothPredicates.SetWhereArgs({to_string(RING_TONE_TYPE_SIM_CARD_BOTH),
        to_string(SOURCE_TYPE_CUSTOMISED)});
    updateBothValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_TYPE, type);
    dataShareHelper->Update(RINGTONEURI, updateBothPredicates, updateBothValuesBucket);

    DataSharePredicates updatePredicates;
    DataShareValuesBucket updateValuesBucket;
    if (((num == RING_TONE_TYPE_SIM_CARD_1 || num == RING_TONE_TYPE_SIM_CARD_BOTH) &&
        (ringtoneTypeMap_[ringtoneType] == RING_TONE_TYPE_SIM_CARD_2)) ||
        ((num == RING_TONE_TYPE_SIM_CARD_2 || num == RING_TONE_TYPE_SIM_CARD_BOTH) &&
        (ringtoneTypeMap_[ringtoneType] == RING_TONE_TYPE_SIM_CARD_1))) {
        type = RING_TONE_TYPE_SIM_CARD_BOTH;
    } else {
        type = ringtoneTypeMap_[ringtoneType];
    }
    updatePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
    updatePredicates.SetWhereArgs({to_string(toneId)});
    updateValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_TYPE, type);
    updateValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE, SOURCE_TYPE_CUSTOMISED);
    return dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
}

int32_t SystemSoundManagerImpl::SetNoRingToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    RingtoneType ringtoneType)
{
    MEDIA_LOGI("Set no audio uri for system tone type %{public}d", ringtoneType);
    int32_t result = 0;
    // Removes the flag for the current system tone uri.
    result += RemoveSourceTypeForRingTone(dataShareHelper, ringtoneType, SOURCE_TYPE_CUSTOMISED);
    // Removes the flag for the preset system tone uri.
    result += RemoveSourceTypeForRingTone(dataShareHelper, ringtoneType, SOURCE_TYPE_PRESET);
    return result;
}

int32_t SystemSoundManagerImpl::RemoveSourceTypeForRingTone(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, RingtoneType ringtoneType, SourceType sourceType)
{
    int32_t result = 0;
    switch (ringtoneType) {
        case RINGTONE_TYPE_SIM_CARD_0:
        case RINGTONE_TYPE_SIM_CARD_1: {
            // SIM_CARD_0 or SIM_CARD_1
            DataSharePredicates updateOnlyPredicates;
            DataShareValuesBucket updateOnlyValuesBucket;
            updateOnlyPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
                RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
            updateOnlyPredicates.SetWhereArgs({to_string(ringtoneTypeMap_[ringtoneType]), to_string(sourceType)});
            updateOnlyValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_TYPE, RING_TONE_TYPE_NOT);
            updateOnlyValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
            result += dataShareHelper->Update(RINGTONEURI, updateOnlyPredicates, updateOnlyValuesBucket);
            // both SIM_CARD_0 and SIM_CARD_1
            DataSharePredicates updateBothPredicates;
            DataShareValuesBucket updateBothValuesBucket;
            RingToneType type = RING_TONE_TYPE_SIM_CARD_1;
            if (ringtoneTypeMap_[ringtoneType] == RING_TONE_TYPE_SIM_CARD_1) {
                type = RING_TONE_TYPE_SIM_CARD_2;
            }
            updateBothPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
                RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
            updateBothPredicates.SetWhereArgs({to_string(RING_TONE_TYPE_SIM_CARD_BOTH), to_string(sourceType)});
            updateBothValuesBucket.Put(RINGTONE_COLUMN_RING_TONE_TYPE, type);
            result += dataShareHelper->Update(RINGTONEURI, updateBothPredicates, updateBothValuesBucket);
            MEDIA_LOGI("The ring0 tone type [%{public}d] is invalid!", ringtoneType);
            break;
        }
        default:
            MEDIA_LOGE("The ring1 tone type [%{public}d] is invalid!", ringtoneType);
            break;
    }
    return result;
}

int32_t SystemSoundManagerImpl::SetRingtoneUri(const shared_ptr<Context> &context, const string &uri,
    RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType), MSERR_INVALID_VAL, "Invalid ringtone type");

    MEDIA_LOGI("SetRingtoneUri: ringtoneType %{public}d, uri %{public}s", ringtoneType, uri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed, datashare or library error.");

    if (uri == NO_RING_SOUND) {
        int32_t changedRows = SetNoRingToneUri(dataShareHelper, ringtoneType);
        MEDIA_LOGI("SetNoRingToneUri result: changedRows %{public}d", changedRows);
        dataShareHelper->Release();
        return SUCCESS;
    }

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        resultSetByUri == nullptr ? : resultSetByUri->Close();
        dataShareHelper->Release();
        MEDIA_LOGE("Failed to find the uri in ringtone library!");
        return ERROR;
    }
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, TONE_TYPE_RINGTONE);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (uri != ringtoneAsset->GetPath())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        int32_t changedRows = UpdateRingtoneUri(dataShareHelper, ringtoneAsset->GetId(),
            ringtoneType, ringtoneAsset->GetRingtoneType());
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), ringtoneType, TONE_TYPE_RINGTONE, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetRingtoneUriByType(const DatabaseTool &databaseTool, const std::string &type)
{
    ToneAttrs toneAttrs = GetRingtoneAttrsByType(databaseTool, type);
    return toneAttrs.GetUri();
}

ToneAttrs SystemSoundManagerImpl::GetRingtoneAttrsByType(const DatabaseTool &databaseTool, const std::string &type)
{
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE };
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("GetRingtoneAttrsByType: the database tool is not ready!");
        return toneAttrs;
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_CUSTOMISED)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("GetRingtoneAttrsByType: dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        MEDIA_LOGE("GetRingtoneAttrsByType: results is nullptr!");
        return toneAttrs;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        toneAttrs.SetUri(ringtoneAsset->GetPath());
        toneAttrs.SetTitle(ringtoneAsset->GetTitle());
        toneAttrs.SetFileName(ringtoneAsset->GetDisplayName());
        toneAttrs.SetCategory(ringtoneAsset->GetToneType());
        if (ringtoneAsset->GetMediaType() == RINGTONE_MEDIA_TYPE_VIDEO) {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_VID);
        } else {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_AUD);
        }
    }
    resultSet == nullptr ? : resultSet->Close();
    return toneAttrs;
}

std::string SystemSoundManagerImpl::GetPresetRingToneUriByType(const DatabaseTool &databaseTool,
    const std::string &type)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_PRESET)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

ToneAttrs SystemSoundManagerImpl::GetPresetRingToneAttrByType(const DatabaseTool &databaseTool,
    const std::string &type)
{
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE };
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("GetPresetRingToneAttrByType: The database tool is not ready!");
        return toneAttrs;
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_PRESET)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("GetPresetRingToneAttrByType: dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        MEDIA_LOGE("GetPresetRingToneAttrByType: query failed, ringtone library error!");
        return toneAttrs;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        toneAttrs.SetUri(ringtoneAsset->GetPath());
        toneAttrs.SetTitle(ringtoneAsset->GetTitle());
        toneAttrs.SetFileName(ringtoneAsset->GetDisplayName());
        toneAttrs.SetCategory(ringtoneAsset->GetToneType());
        if (ringtoneAsset->GetMediaType() == RINGTONE_MEDIA_TYPE_VIDEO) {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_VID);
        } else {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_AUD);
        }
    }
    resultSet == nullptr ? : resultSet->Close();
    return toneAttrs;
}

std::string SystemSoundManagerImpl::GetRingtoneUri(const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    ToneAttrs toneAttrs = GetCurrentRingtoneAttribute(ringtoneType);
    return toneAttrs.GetUri();
}

ToneAttrs SystemSoundManagerImpl::GetCurrentRingtoneAttribute(RingtoneType ringtoneType)
{
    MEDIA_LOGI("GetCurrentRingtoneAttribute: Start, ringtoneType: %{public}d", ringtoneType);
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE };
    if (!IsRingtoneTypeValid(ringtoneType)) {
        MEDIA_LOGE("GetCurrentRingtoneAttribute: Invalid ringtone type!");
        return toneAttrs;
    }

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    bool isProxy = (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED &&
        SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) &&
        SystemSoundManagerUtils::CheckCurrentUser()) ? true : false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = isProxy ?
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID) :
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        MEDIA_LOGE("GetCurrentRingtoneAttribute: Failed to CreateDataShareHelper!");
        return toneAttrs;
    }
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    toneAttrs = GetRingtoneAttrs(databaseTool, ringtoneType);
    dataShareHelper->Release();
    MEDIA_LOGI("Finish to get ringtone attrs: type %{public}d, mediaType %{public}d, uri: %{public}s",
        ringtoneType, toneAttrs.GetMediaType(), toneAttrs.GetUri().c_str());
    return toneAttrs;
}

std::string SystemSoundManagerImpl::GetRingtoneUri(const DatabaseTool &databaseTool, RingtoneType ringtoneType)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("GetRingtoneUri: The database tool is not ready!");
        return "";
    }

    std::string ringtoneUri = "";
    switch (ringtoneType) {
        case RINGTONE_TYPE_SIM_CARD_0:
        case RINGTONE_TYPE_SIM_CARD_1:
            ringtoneUri = GetRingtoneUriByType(databaseTool, to_string(ringtoneTypeMap_[ringtoneType]));
            if (ringtoneUri.empty()) {
                ringtoneUri = GetRingtoneUriByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            if (ringtoneUri.empty()) {
                ringtoneUri = GetPresetRingToneUriByType(databaseTool, to_string(ringtoneTypeMap_[ringtoneType]));
            }
            if (ringtoneUri.empty()) {
                ringtoneUri = GetPresetRingToneUriByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            break;
        default:
            break;
    }
    if (ringtoneUri.empty()) {
        MEDIA_LOGI("GetRingtoneUri: No ring tone uri for type %{public}d. Return NO_RING_SOUND", ringtoneType);
        return NO_RING_SOUND;
    }
    return ringtoneUri;
}

ToneAttrs SystemSoundManagerImpl::GetRingtoneAttrs(const DatabaseTool &databaseTool, RingtoneType ringtoneType)
{
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE };
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("GetRingtoneAttrs: The database tool is not ready!");
        return toneAttrs;
    }

    switch (ringtoneType) {
        case RINGTONE_TYPE_SIM_CARD_0:
        case RINGTONE_TYPE_SIM_CARD_1:
            toneAttrs = GetRingtoneAttrsByType(databaseTool, to_string(ringtoneTypeMap_[ringtoneType]));
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetRingtoneAttrsByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetPresetRingToneAttrByType(databaseTool, to_string(ringtoneTypeMap_[ringtoneType]));
            }
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetPresetRingToneAttrByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            break;
        default:
            break;
    }
    if (toneAttrs.GetUri().empty()) {
        MEDIA_LOGI("GetRingtoneAttrs: No ring tone uri for type %{public}d. Return NO_RING_SOUND", ringtoneType);
        toneAttrs.SetUri(NO_RING_SOUND);
    }
    return toneAttrs;
}

std::string SystemSoundManagerImpl::GetRingtoneTitle(const std::string &ringtoneUri)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::string ringtoneTitle = "";
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ringtoneUri,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, ringtoneUri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri != nullptr) {
        ringtoneTitle = ringtoneAssetByUri->GetTitle();
    }
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    dataShareHelper->Release();
    return ringtoneTitle;
}

std::shared_ptr<RingtonePlayer> SystemSoundManagerImpl::GetRingtonePlayer(const shared_ptr<Context> &context,
    RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType), nullptr, "invalid ringtone type");
    MEDIA_LOGI("GetRingtonePlayer: for ringtoneType %{public}d", ringtoneType);

    std::shared_ptr<RingtonePlayer> ringtonePlayer = std::make_shared<RingtonePlayerImpl>(context, *this, ringtoneType);
    CHECK_AND_RETURN_RET_LOG(ringtonePlayer != nullptr, nullptr,
        "Failed to create ringtone player object");
    return ringtonePlayer;
}

std::shared_ptr<RingtonePlayer> SystemSoundManagerImpl::GetSpecificRingTonePlayer(
    const shared_ptr<Context> &context, const RingtoneType ringtoneType, string &ringtoneUri)
{
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType), nullptr, "invalid ringtone type");
    MEDIA_LOGI("GetSpecificRingTonePlayer: for ringtoneType %{public}d", ringtoneType);

    if (ringtoneUri.empty()) {
        // ringtoneUri is empty. Use current ringtone uri.
        std::shared_ptr<RingtonePlayer> ringtonePlayer =
            std::make_shared<RingtonePlayerImpl>(context, *this, ringtoneType);
        CHECK_AND_RETURN_RET_LOG(ringtonePlayer != nullptr, nullptr,
            "Failed to create ringtone player object");
        return ringtonePlayer;
    }
    std::shared_ptr<RingtonePlayer> ringtonePlayer = std::make_shared<RingtonePlayerImpl>(context,
        *this, ringtoneType, ringtoneUri);
    CHECK_AND_RETURN_RET_LOG(ringtonePlayer != nullptr, nullptr,
        "Failed to create ringtone player object");
    return ringtonePlayer;
}

std::shared_ptr<SystemTonePlayer> SystemSoundManagerImpl::GetSystemTonePlayer(
    const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType), nullptr, "invalid system tone type");
    MEDIA_LOGI("GetSystemTonePlayer: for systemToneType %{public}d", systemToneType);

    std::shared_ptr<SystemTonePlayer> systemTonePlayer =
        std::make_shared<SystemTonePlayerImpl>(context, *this, systemToneType);
    CHECK_AND_RETURN_RET_LOG(systemTonePlayer != nullptr, nullptr,
        "Failed to create system tone player object");
    return systemTonePlayer;
}

int32_t SystemSoundManagerImpl::UpdateShotToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const int32_t &toneId, SystemToneType systemToneType, const int32_t &num)
{
    ShotToneType type = SHOT_TONE_TYPE_SIM_CARD_1;
    DataSharePredicates updateOnlyPredicates;
    DataShareValuesBucket updateOnlyValuesBucket;
    updateOnlyPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
    updateOnlyPredicates.SetWhereArgs({to_string(systemTypeMap_[systemToneType]),
        to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOnlyValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_TYPE, RING_TONE_TYPE_NOT);
    updateOnlyValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOnlyPredicates, updateOnlyValuesBucket);

    DataSharePredicates updateBothPredicates;
    DataShareValuesBucket updateBothValuesBucket;
    if (systemTypeMap_[systemToneType] == SHOT_TONE_TYPE_SIM_CARD_1) {
        type = SHOT_TONE_TYPE_SIM_CARD_2;
    }
    updateBothPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
    updateBothPredicates.SetWhereArgs({to_string(SHOT_TONE_TYPE_SIM_CARD_BOTH),
        to_string(SOURCE_TYPE_CUSTOMISED)});
    updateBothValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_TYPE, type);
    dataShareHelper->Update(RINGTONEURI, updateBothPredicates, updateBothValuesBucket);

    DataSharePredicates updatePredicates;
    DataShareValuesBucket updateValuesBucket;
    if (((num == SHOT_TONE_TYPE_SIM_CARD_1 || num == RING_TONE_TYPE_SIM_CARD_BOTH) &&
        (systemTypeMap_[systemToneType] == SHOT_TONE_TYPE_SIM_CARD_2)) ||
        ((num == SHOT_TONE_TYPE_SIM_CARD_2 || num == RING_TONE_TYPE_SIM_CARD_BOTH) &&
        (systemTypeMap_[systemToneType] == SHOT_TONE_TYPE_SIM_CARD_1))) {
        type = SHOT_TONE_TYPE_SIM_CARD_BOTH;
    } else {
        type = shotToneTypeMap_[systemToneType];
    }
    updatePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
    updatePredicates.SetWhereArgs({to_string(toneId)});
    updateValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_TYPE, type);
    updateValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE, SOURCE_TYPE_CUSTOMISED);
    return dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
}

int32_t SystemSoundManagerImpl::UpdateNotificatioToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const int32_t &toneId)
{
    DataSharePredicates updateOldPredicates;
    DataShareValuesBucket updateOldValuesBucket;
    updateOldPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
    updateOldPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, NOTIFICATION_TONE_TYPE_NOT);
    updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOldPredicates, updateOldValuesBucket);

    DataSharePredicates updatePredicates;
    DataShareValuesBucket updateValuesBucket;
    updatePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
    updatePredicates.SetWhereArgs({to_string(toneId)});
    updateValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, NOTIFICATION_TONE_TYPE);
    updateValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE, SOURCE_TYPE_CUSTOMISED);
    return dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
}

int32_t SystemSoundManagerImpl::SetNoSystemToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    SystemToneType systemToneType)
{
    int32_t result = 0;
    // Removes the flag for the current system tone uri.
    result += RemoveSourceTypeForSystemTone(dataShareHelper, systemToneType, SOURCE_TYPE_CUSTOMISED);
    // Removes the flag for the preset system tone uri.
    result += RemoveSourceTypeForSystemTone(dataShareHelper, systemToneType, SOURCE_TYPE_PRESET);
    MEDIA_LOGI("Set no audio uri for system tone type %{public}d. changedRows %{public}d", systemToneType, result);
    return result;
}

int32_t SystemSoundManagerImpl::RemoveSourceTypeForSystemTone(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, SystemToneType systemToneType, SourceType sourceType)
{
    int32_t result = 0;
    switch (systemToneType) {
        case SYSTEM_TONE_TYPE_SIM_CARD_0:
        case SYSTEM_TONE_TYPE_SIM_CARD_1: {
            // SIM_CARD_0 or SIM_CARD_1
            DataSharePredicates updateOnlyPredicates;
            DataShareValuesBucket updateOnlyValuesBucket;
            updateOnlyPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
                RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
            updateOnlyPredicates.SetWhereArgs({to_string(systemTypeMap_[systemToneType]), to_string(sourceType)});
            updateOnlyValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_TYPE, RING_TONE_TYPE_NOT);
            updateOnlyValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
            result += dataShareHelper->Update(RINGTONEURI, updateOnlyPredicates, updateOnlyValuesBucket);
            // both SIM_CARD_0 and SIM_CARD_1
            DataSharePredicates updateBothPredicates;
            DataShareValuesBucket updateBothValuesBucket;
            ShotToneType type = SHOT_TONE_TYPE_SIM_CARD_1;
            if (systemTypeMap_[systemToneType] == SHOT_TONE_TYPE_SIM_CARD_1) {
                type = SHOT_TONE_TYPE_SIM_CARD_2;
            }
            updateBothPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
                RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
            updateBothPredicates.SetWhereArgs({to_string(SHOT_TONE_TYPE_SIM_CARD_BOTH), to_string(sourceType)});
            updateBothValuesBucket.Put(RINGTONE_COLUMN_SHOT_TONE_TYPE, type);
            result += dataShareHelper->Update(RINGTONEURI, updateBothPredicates, updateBothValuesBucket);
            break;
        }
        case SYSTEM_TONE_TYPE_NOTIFICATION: {
            DataSharePredicates updateOldPredicates;
            DataShareValuesBucket updateOldValuesBucket;
            updateOldPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
                RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
            updateOldPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(sourceType)});
            updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, NOTIFICATION_TONE_TYPE_NOT);
            updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
            result += dataShareHelper->Update(RINGTONEURI, updateOldPredicates, updateOldValuesBucket);
            break;
        }
        default:
            MEDIA_LOGE("The system tone type [%{public}d] is invalid!", systemToneType);
            break;
    }
    return result;
}

int32_t SystemSoundManagerImpl::SetSystemToneUri(const shared_ptr<Context> &context, const string &uri,
    SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType), MSERR_INVALID_VAL, "Invalid system tone type");

    MEDIA_LOGI("SetSystemToneUri: systemToneType %{public}d, uri %{public}s", systemToneType, uri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed.");

    if (uri == NO_SYSTEM_SOUND) {
        (void)SetNoSystemToneUri(dataShareHelper, systemToneType);
        dataShareHelper->Release();
        return SUCCESS;
    }

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        resultSetByUri == nullptr ? : resultSetByUri->Close();
        dataShareHelper->Release();
        MEDIA_LOGE("Failed to find the uri in ringtone library!");
        return ERROR;
    }
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, TONE_TYPE_NOTIFICATION);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (uri != ringtoneAsset->GetPath())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        int32_t changedRows = 0;
        if (systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION) {
            changedRows = UpdateNotificatioToneUri(dataShareHelper, ringtoneAsset->GetId());
        } else {
            changedRows = UpdateShotToneUri(dataShareHelper, ringtoneAsset->GetId(),
                systemToneType, ringtoneAsset->GetShottoneType());
        }
        resultSet == nullptr ? : resultSet->Close();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), systemToneType, TONE_TYPE_NOTIFICATION, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetShotToneUriByType(const DatabaseTool &databaseTool, const std::string &type)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_CUSTOMISED)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetPresetShotToneUriByType(const DatabaseTool &databaseTool,
    const std::string &type)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_PRESET)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetNotificationToneUriByType(const DatabaseTool &databaseTool)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(SOURCE_TYPE_CUSTOMISED)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetPresetNotificationToneUri(const DatabaseTool &databaseTool)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string uri = "";
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(SOURCE_TYPE_PRESET)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    SystemToneType systemToneType)
{
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType), "", "Invalid system tone type");
    std::string systemToneUri = "";

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    bool isProxy = (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED &&
        SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) &&
        SystemSoundManagerUtils::CheckCurrentUser()) ? true : false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = isProxy ?
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID) :
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    systemToneUri = GetSystemToneUri(databaseTool, systemToneType);
    dataShareHelper->Release();
    MEDIA_LOGI("Finish to get system tone uri: type %{public}d, uri %{public}s", systemToneType, systemToneUri.c_str());
    return systemToneUri;
}

std::string SystemSoundManagerImpl::GetSystemToneUri(const DatabaseTool &databaseTool, SystemToneType systemToneType)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string systemToneUri = "";
    switch (systemToneType) {
        case SYSTEM_TONE_TYPE_SIM_CARD_0:
        case SYSTEM_TONE_TYPE_SIM_CARD_1:
            systemToneUri = GetShotToneUriByType(databaseTool, to_string(systemTypeMap_[systemToneType]));
            if (systemToneUri.empty()) {
                systemToneUri = GetShotToneUriByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            if (systemToneUri.empty()) {
                systemToneUri = GetPresetShotToneUriByType(databaseTool, to_string(systemTypeMap_[systemToneType]));
            }
            if (systemToneUri.empty()) {
                systemToneUri = GetPresetShotToneUriByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            break;
        case SYSTEM_TONE_TYPE_NOTIFICATION:
            systemToneUri = GetNotificationToneUriByType(databaseTool);
            if (systemToneUri.empty()) {
                systemToneUri = GetPresetNotificationToneUri(databaseTool);
            }
            break;
        default:
            break;
    }
    if (systemToneUri.empty()) {
        MEDIA_LOGI("No system tone uri for type %{public}d. Return NO_SYSTEM_SOUND", systemToneType);
        return NO_SYSTEM_SOUND;
    }
    return systemToneUri;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultRingtoneAttrs(
    const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    MEDIA_LOGI("GetDefaultRingtoneAttrs : Enter the getDefaultRingtoneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType),  nullptr, "Invalid ringtone type");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    ringtoneAttrs_ = nullptr;
    std::vector<std::string> onClause;
    onClause.push_back(RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID + "=" +
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_TONE_ID);
    queryPredicates.InnerJoin(PRELOAD_CONFIG_TABLE)->On(onClause)->EqualTo(
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_RING_TONE_TYPE, defaultoneTypeMap_[ringtoneType]);
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, JOIN_COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetDefaultRingtoneAttrs: errCode:%{public}d, result :%{public}d ", errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Invalid dataShare.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, JOIN_COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "single sim card failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (TONE_TYPE_RINGTONE != ringtoneAsset->GetToneType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        ringtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(), ringtoneAsset->GetDisplayName(),
            ringtoneAsset->GetPath(), sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_RINGTONE);
        MEDIA_LOGI("RingtoneAttrs_ :  Title = %{public}s", ringtoneAsset->GetTitle().c_str());
    } else {
        MEDIA_LOGE("GetDefaultRingtoneAttrs: no single card default ringtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return ringtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetRingtoneAttrList(
    const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType)
{
    MEDIA_LOGI("GetRingtoneAttrList : Enter the getRingtoneAttrList interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    ringtoneAttrsArray_.clear();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ringtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_RINGTONE));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetRingtoneAttrList:errCode:%{public}d, result :%{public}d ", errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED  ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ringtoneAttrsArray_,
            "Invalid dataShare, datashare or ringtone library error.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ringtoneAttrsArray_, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while (ringtoneAsset != nullptr) {
        ringtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_RINGTONE);
        ringtoneAttrsArray_.push_back(ringtoneAttrs_);
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAttrsArray_.empty()) {
        MEDIA_LOGE("GetRingtoneAttrList: no ringtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return ringtoneAttrsArray_;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultSystemToneAttrs(
    const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType)
{
    MEDIA_LOGI("GetDefaultSystemToneAttrs : Enter the getDefaultSystemToneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType),  nullptr, "Invalid systemtone type");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");
    std::string ringToneType = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE : RINGTONE_COLUMN_SHOT_TONE_TYPE;
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    systemtoneAttrs_ = nullptr;
    std::vector<std::string> onClause;
    onClause.push_back(RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID + "=" +
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_TONE_ID);
    queryPredicates.InnerJoin(PRELOAD_CONFIG_TABLE)->On(onClause)->EqualTo(
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_RING_TONE_TYPE, defaultsystemTypeMap_[systemToneType]);
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, JOIN_COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Invalid dataShare.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, JOIN_COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query single systemtone failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && IsSystemToneType(ringtoneAsset, systemToneType)) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        systemtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(), ringtoneAsset->GetDisplayName(),
        ringtoneAsset->GetPath(), sourceTypeMap_[ringtoneAsset->GetSourceType()], category);
    } else {
        MEDIA_LOGE("GetDefaultSystemToneAttrs: no single default systemtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return systemtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetSystemToneAttrList(
    const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    systemtoneAttrsArray_.clear();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, systemtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_NOTIFICATION));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetSystemToneAttrList: errCode:%{public}d, result :%{public}d ", errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, systemtoneAttrsArray_,
            "Invalid dataShare, datashare or ringtone library error.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, systemtoneAttrsArray_, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while (ringtoneAsset != nullptr) {
        systemtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], category);
        systemtoneAttrsArray_.push_back(systemtoneAttrs_);
        ringtoneAsset = results->GetNextObject();
    }
    if (systemtoneAttrsArray_.empty()) {
        MEDIA_LOGE("GetSystemToneAttrList: no systemtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return systemtoneAttrsArray_;
}

int32_t SystemSoundManagerImpl::SetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &uri)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    MEDIA_LOGI("SetAlarmToneUri: alarm type %{public}d",
        SystemSoundManagerUtils::GetTypeForSystemSoundUri(uri));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        MEDIA_LOGE("Failed to find uri in ringtone library. The input uri is invalid!");
        resultSetByUri == nullptr ? : resultSetByUri->Close();
        dataShareHelper->Release();
        return ERROR;
    }
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, TONE_TYPE_ALARM);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (uri != ringtoneAsset->GetPath())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        int32_t changedRows = UpdataeAlarmToneUri(dataShareHelper, ringtoneAsset->GetId());
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), TONE_TYPE_ALARM, TONE_TYPE_ALARM, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    MEDIA_LOGE("Failed to find uri in ringtone library!");
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

int32_t SystemSoundManagerImpl::UpdataeAlarmToneUri(
    const std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const int32_t ringtoneAssetId)
{
    DataSharePredicates updateOldPredicates;
    DataShareValuesBucket updateOldValuesBucket;
    updateOldPredicates.SetWhereClause(RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE + " = ? ");
    updateOldPredicates.SetWhereArgs({to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOldValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_TYPE, ALARM_TONE_TYPE_NOT);
    updateOldValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOldPredicates, updateOldValuesBucket);
    DataSharePredicates updatePredicates;
    DataShareValuesBucket updateValuesBucket;
    updatePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
    updatePredicates.SetWhereArgs({to_string(ringtoneAssetId)});
    updateValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_TYPE, ALARM_TONE_TYPE);
    updateValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE, SOURCE_TYPE_CUSTOMISED);
    int32_t changedRows = dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
    MEDIA_LOGI("UpdataeAlarmToneUri: result(changedRows) %{public}d", changedRows);
    return changedRows;
}

std::string SystemSoundManagerImpl::GetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context)
{
    int32_t count = 2;
    std::string alarmToneUri = "";
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmToneUri,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_ALARM_TONE_TYPE, to_string(ALARM_TONE_TYPE));
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetAlarmToneUri:errCode:%{public}d, result :%{public}d", errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmToneUri, "Invalid dataShare.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, alarmToneUri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (SOURCE_TYPE_CUSTOMISED !=
        ringtoneAsset->GetAlarmtoneSourceType()) && (results->GetCount() == count)) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        alarmToneUri = ringtoneAsset->GetPath();
        MEDIA_LOGI("GetAlarmToneUri: alarm type %{public}d",
            SystemSoundManagerUtils::GetTypeForSystemSoundUri(alarmToneUri));
    } else {
        MEDIA_LOGE("GetAlarmToneUri: no alarmtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return alarmToneUri;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultAlarmToneAttrs(
    const std::shared_ptr<AbilityRuntime::Context> &context)
{
    MEDIA_LOGI("GetDefaultAlarmToneAttrs : Enter the getDefaultAlarmToneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    alarmtoneAttrs_ = nullptr;
    std::vector<std::string> onClause;
    onClause.push_back(RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID + "=" +
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_TONE_ID);
    queryPredicates.InnerJoin(PRELOAD_CONFIG_TABLE)->On(onClause)->EqualTo(
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_RING_TONE_TYPE, DEFAULT_ALARM_TYPE);
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, JOIN_COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetDefaultAlarmToneAttrs:errCode:%{public}d, result :%{public}d ",  errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Invalid dataShare,");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, JOIN_COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (TONE_TYPE_ALARM != ringtoneAsset->GetToneType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        alarmtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(), ringtoneAsset->GetDisplayName(),
            ringtoneAsset->GetPath(), sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_ALARM);
        MEDIA_LOGI("AlarmtoneAttrs_ :Title = %{public}s", ringtoneAsset->GetTitle().c_str());
    } else {
        MEDIA_LOGE("GetDefaultAlarmToneAttrs: no default alarmtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return alarmtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetAlarmToneAttrList
    (const std::shared_ptr<AbilityRuntime::Context> &context)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    alarmtoneAttrsArray_.clear();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_ALARM));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, COLUMNS, &businessError);
    int32_t errCode = businessError.GetCode();
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("GetAlarmToneAttrList: errCode:%{public}d, result :%{public}d ",  errCode, result);
    if (errCode != 0 || result != Security::AccessToken::PermissionState::PERMISSION_GRANTED ||
        !SystemSoundManagerUtils::GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) ||
        !SystemSoundManagerUtils::CheckCurrentUser()) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmtoneAttrsArray_,
            "Invalid dataShare, datashare or ringtone library error.");
        resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, alarmtoneAttrsArray_, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while (ringtoneAsset != nullptr) {
        alarmtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_ALARM);
        alarmtoneAttrsArray_.push_back(alarmtoneAttrs_);
        ringtoneAsset = results->GetNextObject();
    }
    if (alarmtoneAttrsArray_.empty()) {
        MEDIA_LOGE("GetAlarmToneAttrList: no alarmtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return alarmtoneAttrsArray_;
}

int32_t SystemSoundManagerImpl::OpenAlarmTone(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &uri)
{
    return OpenToneUri(context, uri, TONE_TYPE_ALARM);
}

int32_t SystemSoundManagerImpl::OpenToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &uri, int32_t toneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed, datashare or library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        MEDIA_LOGE("OpenToneUri: tone of uri is not in the ringtone library!");
        resultSetByUri == nullptr ? : resultSetByUri->Close();
        dataShareHelper->Release();
        return ERROR;
    }
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, toneType);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (uri != ringtoneAsset->GetPath())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        Uri ofUri(uriStr);
        int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        return fd > 0 ? fd : ERROR;
    }
    MEDIA_LOGE("OpenTone: tone of uri failed!");
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::vector<std::tuple<std::string, int64_t, SystemSoundError>> SystemSoundManagerImpl::OpenToneList(
    const std::vector<std::string> &uriList, SystemSoundError &errCode)
{
    MEDIA_LOGI("OpenToneList: Start, size: %{public}zu", uriList.size());
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::vector<std::tuple<std::string, int64_t, SystemSoundError>> resultOfOpenList;
    if (uriList.size() > MAX_VECTOR_LENGTH) {
        errCode = ERROR_INVALID_PARAM;
        return resultOfOpenList;
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        MEDIA_LOGE("OpenToneList: Create dataShare failed, datashare or library error!");
        errCode = ERROR_IO;
        return resultOfOpenList;
    }
    for (uint32_t i = 0; i < uriList.size(); i++) {
        std::tuple<string, int64_t, SystemSoundError> resultOfOpen = std::make_tuple(uriList[i], INVALID_FD, ERROR_IO);
        OpenOneFile(dataShareHelper, uriList[i], resultOfOpen);
        resultOfOpenList.push_back(resultOfOpen);
    }
    dataShareHelper->Release();
    errCode = ERROR_OK;
    return resultOfOpenList;
}

void SystemSoundManagerImpl::OpenOneFile(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const std::string &uri, std::tuple<std::string, int64_t, SystemSoundError> &resultOfOpen)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        MEDIA_LOGE("OpenOneFile: Query failed, ringtone library error!");
        return;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (uri != ringtoneAsset->GetPath())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        Uri ofUri(uriStr);
        int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
        resultSet == nullptr ? : resultSet->Close();
        if (fd > 0) {
            std::get<PARAM1>(resultOfOpen) = fd;
            std::get<PARAM2>(resultOfOpen) = ERROR_OK;
        } else {
            MEDIA_LOGE("OpenOneFile: OpenFile failed, uri: %{public}s.", uri.c_str());
        }
        return;
    }
    MEDIA_LOGE("OpenOneFile: ringtoneAsset is nullptr, uri: %{public}s.", uri.c_str());
    resultSet == nullptr ? : resultSet->Close();
}

int32_t SystemSoundManagerImpl::Close(const int32_t &fd)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    return close(fd);
}

std::string SystemSoundManagerImpl::AddCustomizedToneByExternalUri(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<ToneAttrs> &toneAttrs,
    const std::string &externalUri)
{
    MEDIA_LOGI("AddCustomizedToneByExternalUri: Start, externalUri: %{public}s", externalUri.c_str());
    std::string fdHead = "fd://";
    std::string srcPath = externalUri;
    int32_t srcFd = -1;
    if (srcPath.find(fdHead) != std::string::npos) {
        StrToInt(srcPath.substr(fdHead.size()), srcFd);
    } else {
        srcFd = open(srcPath.c_str(), O_RDONLY);
    }
    if (srcFd < 0) {
        MEDIA_LOGE("AddCustomizedToneByExternalUri: fd open error is %{public}s", strerror(errno));
        fdHead.clear();
        return fdHead;
    }
    return AddCustomizedToneByFd(context, toneAttrs, srcFd);
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFd(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd)
{
    MEDIA_LOGI("AddCustomizedToneByFd: Start.");
    return AddCustomizedToneByFdAndOffset(context, toneAttrs, fd, 0, INT_MAX);
}

void SystemSoundManagerImpl::GetCustomizedTone(const std::shared_ptr<ToneAttrs> &toneAttrs)
{
    displayName_ = toneAttrs->GetFileName();
    mimeType_ = "";
    for (const auto& type : RINGTONETYPE) {
        size_t found = displayName_.find("." + type);
        if (found != std::string::npos) {
            mimeType_ = type;
        }
    }
    if (mimeType_.empty()) {
        mimeType_ = RINGTONE_CONTAINER_TYPE_OGG;
        displayName_ = displayName_ + ".ogg";
    }
}

int32_t SystemSoundManagerImpl::AddCustomizedTone(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const std::shared_ptr<ToneAttrs> &toneAttrs)
{
    MEDIA_LOGI("AddCustomizedTone: Start.");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Invalid dataShareHelper.");
    int32_t category = -1;
    category = toneAttrs->GetCategory();
    GetCustomizedTone(toneAttrs);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(RINGTONE_COLUMN_DISPLAY_NAME, static_cast<string>(displayName_));
    valuesBucket.Put(RINGTONE_COLUMN_TITLE, static_cast<string>(toneAttrs->GetTitle()));
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_AUD) {
        valuesBucket.Put(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_AUDIO));
    } else if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        valuesBucket.Put(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_VIDEO));
    }
    valuesBucket.Put(RINGTONE_COLUMN_MIME_TYPE, static_cast<string>(mimeType_));
    valuesBucket.Put(RINGTONE_COLUMN_SOURCE_TYPE, static_cast<int>(SOURCE_TYPE_CUSTOMISED));
    switch (category) {
        case TONE_CATEGORY_RINGTONE:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_RINGTONE_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_RINGTONE));
            break;
        case TONE_CATEGORY_TEXT_MESSAGE:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_NOTIFICATIONS_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_NOTIFICATION));
            break;
        case TONE_CATEGORY_NOTIFICATION:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_NOTIFICATIONS_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_NOTIFICATION));
            break;
        case TONE_CATEGORY_ALARM:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_ALARM_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_ALARM));
            break;
        case TONE_CATEGORY_CONTACTS:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_CONTACTS_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_CONTACTS));
            MEDIA_LOGI("displayName : %{public}s", displayName_.c_str());
            break;
        default:
            break;
    }
    valuesBucket.Put(RINGTONE_COLUMN_DATA, static_cast<string>(toneAttrs->GetUri()));
    int32_t result = dataShareHelper->Insert(RINGTONEURI, valuesBucket);
    MEDIA_LOGI("AddCustomizedTone, result : %{public}d", result);
    return result;
}

bool SystemSoundManagerImpl::DeleteCustomizedTone(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const std::shared_ptr<ToneAttrs> &toneAttrs)
{
    MEDIA_LOGI("DeleteCustomizedTone: Start.");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Invalid dataShareHelper.");
    int32_t category = -1;
    category = toneAttrs->GetCategory();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(RINGTONE_COLUMN_DISPLAY_NAME, static_cast<string>(displayName_));
    predicates.EqualTo(RINGTONE_COLUMN_TITLE, static_cast<string>(toneAttrs->GetTitle()));
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_AUD) {
        predicates.EqualTo(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_AUDIO));
    } else if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        predicates.EqualTo(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_VIDEO));
    }
    predicates.EqualTo(RINGTONE_COLUMN_MIME_TYPE, static_cast<string>(mimeType_));
    predicates.EqualTo(RINGTONE_COLUMN_SOURCE_TYPE, static_cast<int>(SOURCE_TYPE_CUSTOMISED));
    switch (category) {
        case TONE_CATEGORY_RINGTONE:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_RINGTONE));
            break;
        case TONE_CATEGORY_TEXT_MESSAGE:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_NOTIFICATION));
            break;
        case TONE_CATEGORY_NOTIFICATION:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_NOTIFICATION));
            break;
        case TONE_CATEGORY_ALARM:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_ALARM));
            break;
        case TONE_CATEGORY_CONTACTS:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_CONTACTS));
            break;
        default:
            break;
    }
    predicates.EqualTo(RINGTONE_COLUMN_DATA, static_cast<string>(toneAttrs->GetUri()));
    bool result = (dataShareHelper->Delete(RINGTONEURI, predicates) > 0);
    MEDIA_LOGI("DeleteCustomizedTone: displayName : %{public}s, result: %{public}d", displayName_.c_str(), result);
    return result;
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<ToneAttrs> &toneAttrs,
    const int32_t &fd, const int32_t &offset, const int32_t &length)
{
    MEDIA_LOGI("AddCustomizedToneByFdAndOffset: Start.");
    std::string result = "TYPEERROR";
    if (toneAttrs->GetCustomizedType() != CUSTOMISED) {
        MEDIA_LOGE("AddCustomizedToneByFdAndOffset: The ringtone is not customized!");
        return result;
    }
    off_t fileSize = 0;
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        fileSize = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        if (fileSize > MAX_FILE_SIZE_1G) {
            MEDIA_LOGE("AddCustomizedToneByFdAndOffset: The file size exceeds 1G.");
            return FILE_SIZE_EXCEEDS_LIMIT;
        }
    }
    std::lock_guard<std::mutex> lock(uriMutex_);
    int32_t srcFd = fd;
    off_t lseekResult = lseek(srcFd, offset, SEEK_SET);
    if (srcFd < 0 || lseekResult == -1) {
        MEDIA_LOGE("AddCustomizedToneByFdAndOffset: fd is error");
        result.clear();
        return result;
    }
    MediaTrace::TraceBegin("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        MEDIA_LOGE("AddCustomizedToneByFdAndOffset: Create dataShare failed, datashare or ringtone library error.");
        result.clear();
        return result;
    }
    int32_t sert = AddCustomizedTone(dataShareHelper, toneAttrs);
    if (sert < 0) {
        dataShareHelper->Release();
        SendCustomizedToneEvent(true, toneAttrs, fileSize, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        if (sert == VIDEOS_NUM_EXCEEDS_SPECIFICATION) {
            return FILE_COUNT_EXCEEDS_LIMIT;
        } else if (sert == NOT_ENOUGH_ROM) {
            return ROM_IS_INSUFFICIENT;
        } else if (sert == FILE_EXIST) {
            return toneAttrs->GetUri();
        }
    }
    std::string dstPath = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(sert);
    ParamsForWriteFile paramsForWriteFile = { dstPath, fileSize, srcFd, length };
    return CustomizedToneWriteFile(context, dataShareHelper, toneAttrs, paramsForWriteFile);
}

std::string SystemSoundManagerImpl::CustomizedToneWriteFile(const std::shared_ptr<AbilityRuntime::Context> &context,
    std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper, const std::shared_ptr<ToneAttrs> &toneAttrs,
    ParamsForWriteFile &paramsForWriteFile)
{
    MEDIA_LOGI("CustomizedToneWriteFile: Start.");
    Uri ofUri(paramsForWriteFile.dstPath);
    int32_t dstFd = dataShareHelper->OpenFile(ofUri, "rw");
    if (dstFd < 0) {
        MEDIA_LOGE("CustomizedToneWriteFile: Open error is %{public}s", strerror(errno));
        DeleteCustomizedTone(dataShareHelper, toneAttrs);
        dataShareHelper->Release();
        SendCustomizedToneEvent(true, toneAttrs, paramsForWriteFile.fileSize, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        return "";
    }
    MEDIA_LOGI("CustomizedToneWriteFile: OpenFile success, begin write file.");
    char buffer[4096];
    int32_t len = paramsForWriteFile.length;
    memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    int32_t bytesRead = 0;
    while ((bytesRead = read(paramsForWriteFile.srcFd, buffer, sizeof(buffer))) > 0 && len > 0) {
        int32_t bytesWritten = write(dstFd, buffer, (bytesRead < len) ? bytesRead : len);
        memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
        if (bytesWritten == -1) {
            break;
        }
        len -= bytesWritten;
    }
    MEDIA_LOGI("CustomizedToneWriteFile: Write file end.");
    close(dstFd);
    dataShareHelper->Release();
    SendCustomizedToneEvent(true, toneAttrs, paramsForWriteFile.fileSize, mimeType_, SUCCESS);
    MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
    return toneAttrs->GetUri();
}

int32_t SystemSoundManagerImpl::RemoveCustomizedTone(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri)
{
    MEDIA_LOGI("RemoveCustomizedTone: uri %{public}s", uri.c_str());
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "RemoveCustomizedTone: Create dataShare failed, datashare or ringtone library error.");
    std::tuple<string, int64_t, SystemSoundError> resultOfOpen = std::make_tuple(uri, INVALID_FD, ERROR_IO);
    OpenOneFile(dataShareHelper, uri, resultOfOpen);
    int64_t srcFd = std::get<PARAM1>(resultOfOpen);
    off_t fileSize = 0;
    if (srcFd < 0) {
        MEDIA_LOGE("RemoveCustomizedTone: fd open error is %{public}s", strerror(errno));
    } else {
        fileSize = lseek(srcFd, 0, SEEK_END);
        close(srcFd);
    }
    return DoRemove(dataShareHelper, uri, fileSize);
}

int32_t SystemSoundManagerImpl::DoRemove(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const std::string &uri, off_t fileSize)
{
    std::shared_ptr<ToneAttrs> toneAttrs =
        std::make_shared<ToneAttrs>("", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    int32_t changedRows = TYPEERROR;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "DoRemove: Query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    std::string mimeType = "";
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("DoRemove: Tone of uri is not in the ringtone library!");
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        SendCustomizedToneEvent(false, toneAttrs, fileSize, mimeType, ERROR);
        return ERROR;
    }
    while ((ringtoneAsset != nullptr) &&
        (SOURCE_TYPE_CUSTOMISED != ringtoneAsset->GetSourceType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        toneAttrs->SetCategory(ringtoneAsset->GetToneType());
        if (ringtoneAsset->GetMediaType() == RINGTONE_MEDIA_TYPE_VIDEO) {
            toneAttrs->SetMediaType(ToneMediaType::MEDIA_TYPE_VID);
        } else {
            toneAttrs->SetMediaType(ToneMediaType::MEDIA_TYPE_AUD);
        }
        mimeType = ringtoneAsset->GetMimeType();
        DataShare::DataSharePredicates deletePredicates;
        deletePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
        deletePredicates.SetWhereArgs({to_string(ringtoneAsset->GetId())});
        changedRows = dataShareHelper->Delete(RINGTONEURI, deletePredicates);
    } else {
        MEDIA_LOGE("DoRemove: the ringtone is not customized!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    SendCustomizedToneEvent(false, toneAttrs, fileSize, mimeType, SUCCESS);
    return changedRows;
}

std::vector<std::pair<std::string, SystemSoundError>> SystemSoundManagerImpl::RemoveCustomizedToneList(
    const std::vector<std::string> &uriList, SystemSoundError &errCode)
{
    MEDIA_LOGI("RemoveCustomizedToneList: Start, size: %{public}zu.", uriList.size());
    std::vector<std::pair<std::string, SystemSoundError>> removeResults;
    if (uriList.size() > MAX_VECTOR_LENGTH) {
        errCode = ERROR_INVALID_PARAM;
        return removeResults;
    }
    std::shared_ptr<AbilityRuntime::Context> context;
    for (uint32_t i = 0; i < uriList.size(); i++) {
        int32_t result = RemoveCustomizedTone(context, uriList[i]);
        if (result > 0) {
            std::pair<std::string, SystemSoundError> resultPair(uriList[i], ERROR_OK);
            removeResults.push_back(resultPair);
        } else {
            MEDIA_LOGE("RemoveCustomizedToneList: err, uri: %{public}s.", uriList[i].c_str());
            std::pair<std::string, SystemSoundError> resultPair(uriList[i], ERROR_IO);
            removeResults.push_back(resultPair);
        }
    }
    errCode = ERROR_OK;
    return removeResults;
}

int32_t SystemSoundManagerImpl::SetRingerMode(const AudioStandard::AudioRingerMode &ringerMode)
{
    ringerMode_.store(ringerMode);
    return MSERR_OK;
}

AudioStandard::AudioRingerMode SystemSoundManagerImpl::GetRingerMode() const
{
    return ringerMode_.load();
}

bool SystemSoundManagerImpl::ConvertToRingtoneType(ToneHapticsType toneHapticsType, RingtoneType &ringtoneType)
{
    switch (toneHapticsType) {
        case ToneHapticsType::CALL_SIM_CARD_0 :
            ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
            return true;
        case ToneHapticsType::CALL_SIM_CARD_1 :
            ringtoneType = RINGTONE_TYPE_SIM_CARD_1;
            return true;
        default:
            return false;
    }
}

bool SystemSoundManagerImpl::ConvertToSystemToneType(ToneHapticsType toneHapticsType, SystemToneType &systemToneType)
{
    switch (toneHapticsType) {
        case ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0 :
            systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
            return true;
        case ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1 :
            systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_1;
            return true;
        case ToneHapticsType::NOTIFICATION :
            systemToneType = SYSTEM_TONE_TYPE_NOTIFICATION;
            return true;
        default:
            return false;
    }
}

ToneHapticsMode SystemSoundManagerImpl::IntToToneHapticsMode(int32_t value)
{
    switch (value) {
        case NONE:
            return NONE;
        case SYNC:
            return SYNC;
        case NON_SYNC:
            return NON_SYNC;
        default:
            return NONE;
    }
}

std::string SystemSoundManagerImpl::GetCurrentToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    ToneHapticsType toneHapticsType)
{
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    bool isProxy = (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED) ? true : false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = isProxy ?
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID) :
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};

    std::string currentToneUri = GetCurrentToneUri(databaseTool, toneHapticsType);
    dataShareHelper->Release();
    return currentToneUri;
}

std::string SystemSoundManagerImpl::GetCurrentToneUri(const DatabaseTool &databaseTool, ToneHapticsType toneHapticsType)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string currentToneUri = "";
    RingtoneType ringtoneType;
    SystemToneType systemToneType;
    if (ConvertToRingtoneType(toneHapticsType, ringtoneType)) {
        currentToneUri = GetRingtoneUri(databaseTool, ringtoneType);
    } else if (ConvertToSystemToneType(toneHapticsType, systemToneType)) {
        currentToneUri = GetSystemToneUri(databaseTool, systemToneType);
    } else {
        MEDIA_LOGE("Invalid tone haptics type");
    }
    return currentToneUri;
}

int32_t SystemSoundManagerImpl::UpdateToneHapticsSettings(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
    MEDIA_LOGI("UpdateToneHapticsSettings: toneUri[%{public}s], mode[%{public}d], hapticsUri[%{public}s]",
        toneUri.c_str(), settings.mode, settings.hapticsUri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_ = dataShareHelper;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_MODE, hapticsTypeWhereArgsMap_[toneHapticsType].first);
    queryPredicates.And();
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE, hapticsTypeWhereArgsMap_[toneHapticsType].second);

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_TONE_FILE, toneUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_FILE, settings.hapticsUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_RING_MODE, to_string(hapticsModeMap_[settings.mode]));
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_MODE, to_string(VIBRATE_TYPE_STANDARD));

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t ret =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    if (ret != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        dataShareHelper_ = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, IO_ERROR, "Invalid dataShare,");
        int32_t result = dataShareHelper_->Update(SIMCARDSETTINGURI, queryPredicates, valuesBucket);
        if (result > 0) {
            return SUCCESS;
        } else {
            MEDIA_LOGE("UpdateToneHapticsSettings: update haptics settings fail");
        }
        valuesBucket.Put(SIMCARD_SETTING_COLUMN_MODE, to_string(hapticsTypeWhereArgsMap_[toneHapticsType].first));
        valuesBucket.Put(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE,
            to_string(hapticsTypeWhereArgsMap_[toneHapticsType].second));
        result = dataShareHelper_->Insert(SIMCARDSETTINGURI, valuesBucket);
        if (result <= 0) {
            MEDIA_LOGE("UpdateToneHapticsSettings: insert haptics settings fail");
        }
        return result > 0 ? SUCCESS : IO_ERROR;
    } else {
        Uri SIMCARDSETTINGURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_SIMCARD_SETTING + "&user=" +
            std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
        int32_t result = dataShareHelper_->Update(SIMCARDSETTINGURI_PROXY, queryPredicates, valuesBucket);
        if (result > 0) {
            return SUCCESS;
        }
        valuesBucket.Put(SIMCARD_SETTING_COLUMN_MODE, to_string(hapticsTypeWhereArgsMap_[toneHapticsType].first));
        valuesBucket.Put(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE,
            to_string(hapticsTypeWhereArgsMap_[toneHapticsType].second));
        result = dataShareHelper_->Insert(SIMCARDSETTINGURI_PROXY, valuesBucket);
        if (result <= 0) {
            MEDIA_LOGE("UpdateToneHapticsSettings: insert haptics settings fail");
        }
        return result > 0 ? SUCCESS : IO_ERROR;
    }
}

std::unique_ptr<SimcardSettingAsset> SystemSoundManagerImpl::GetSimcardSettingAssetByToneHapticsType(
    const DatabaseTool &databaseTool, ToneHapticsType toneHapticsType)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_MODE, hapticsTypeWhereArgsMap_[toneHapticsType].first);
    queryPredicates.And();
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE, hapticsTypeWhereArgsMap_[toneHapticsType].second);

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_SIMCARD_SETTING +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = SIMCARD_SETTING_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri,
        queryPredicates, SETTING_TABLE_COLUMNS, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<SimcardSettingAsset>>(move(resultSet));
    unique_ptr<SimcardSettingAsset> simcardSettingAsset = results->GetFirstObject();
    return simcardSettingAsset;
}

std::string SystemSoundManagerImpl::GetToneSyncedHapticsUri(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const std::string &toneUri)
{
    std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
    int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, dataShareHelper, toneHapticsAttrs);
    if (result == SUCCESS && toneHapticsAttrs) {
        return toneHapticsAttrs->GetUri();
    }
    return "";
}

std::string SystemSoundManagerImpl::GetDefaultNonSyncedHapticsUri(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, ToneHapticsType toneHapticsType)
{
    MEDIA_LOGD("GetDefaultNonSyncedHapticsUri: toneHapticsType %{public}d", toneHapticsType);
    auto toneHapticsItem = defaultToneHapticsUriMap_.find(toneHapticsType);
    if (toneHapticsItem == defaultToneHapticsUriMap_.end()) {
        MEDIA_LOGE("GetDefaultNonSyncedHapticsUri: get type %{public}d defaultTone haptics fail", toneHapticsType);
        return "";
    }

    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
        "Create dataShare failed, datashare or ringtone library error.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME, toneHapticsItem->second);
    queryPredicatesByUri.And();
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_STANDARD);
    Uri VIBRATEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSetByUri = dataShareHelper->Query(VIBRATEURI_PROXY, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
        &businessError);
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("systemsoundmanagerimpl result :%{public}d ",  result);
    if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
            "Invalid dataShare, datashare or ringtone library error.");
        resultSetByUri = dataShareHelper->Query(VIBRATEURI, queryPredicatesByUri,
            VIBRATE_TABLE_COLUMNS, &businessError);
    }
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    if (vibrateAssetByUri == nullptr) {
        MEDIA_LOGE("GetDefaultNonSyncedHapticsUri: no non_sync vibration called %{public}s",
            toneHapticsItem->second.c_str());
        return "";
    }

    string hapticsUri = vibrateAssetByUri->GetPath();
    MEDIA_LOGI("GetDefaultNonSyncedHapticsUri: toneHapticsType %{public}d default haptics %{public}s",
        toneHapticsType, hapticsUri.c_str());
    return hapticsUri;
}

std::string SystemSoundManagerImpl::GetFirstNonSyncedHapticsUri()
{
    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = GetToneHapticsList(nullptr, false, toneHapticsAttrsArray);
    if (result == SUCCESS && !toneHapticsAttrsArray.empty()) {
        return toneHapticsAttrsArray[0]->GetUri();
    }
    return "";
}

int32_t SystemSoundManagerImpl::GetDefaultToneHapticsSettings(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const std::string &currentToneUri,
    ToneHapticsType toneHapticsType, ToneHapticsSettings &settings)
{
    settings.hapticsUri = GetToneSyncedHapticsUri(dataShareHelper, currentToneUri);
    if (!settings.hapticsUri.empty()) {
        settings.mode = ToneHapticsMode::SYNC;
        return SUCCESS;
    }
    settings.hapticsUri = GetDefaultNonSyncedHapticsUri(dataShareHelper, toneHapticsType);
    if (!settings.hapticsUri.empty()) {
        settings.mode = ToneHapticsMode::NON_SYNC;
        return SUCCESS;
    }
    settings.hapticsUri = GetFirstNonSyncedHapticsUri();
    if (!settings.hapticsUri.empty()) {
        settings.mode = ToneHapticsMode::NON_SYNC;
        return SUCCESS;
    }
    return IO_ERROR;
}

int32_t SystemSoundManagerImpl::GetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
    ToneHapticsType toneHapticsType, ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    CHECK_AND_RETURN_RET_LOG(IsToneHapticsTypeValid(toneHapticsType), IO_ERROR, "Invalid tone haptics type");

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    bool isProxy = (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED) ? true : false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = isProxy ?
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID) :
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};

    string currentToneUri = GetCurrentToneUri(databaseTool, toneHapticsType);

    result = GetToneHapticsSettings(databaseTool, currentToneUri, toneHapticsType, settings);
    dataShareHelper->Release();
    return result;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::GetToneHapticsSettings(const DatabaseTool &databaseTool, const std::string &toneUri,
    ToneHapticsType toneHapticsType, ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return IO_ERROR;
    }
    if (toneUri.empty() || !IsToneHapticsTypeValid(toneHapticsType)) {
        MEDIA_LOGE("GetToneHapticsSettings: param fail");
        return IO_ERROR;
    }

    std::lock_guard<std::mutex> lock(toneHapticsMutex_);
    MEDIA_LOGI("GetToneHapticsSettings: toneUri %{public}s toneHapticsType %{public}d", toneUri.c_str(),
        toneHapticsType);

    int32_t result = SUCCESS;
    auto simcardSettingAsset = GetSimcardSettingAssetByToneHapticsType(databaseTool, toneHapticsType);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = databaseTool.dataShareHelper;
    if (simcardSettingAsset == nullptr || simcardSettingAsset->GetToneFile().empty()) {
        result = GetDefaultToneHapticsSettings(dataShareHelper, toneUri, toneHapticsType, settings);
        if (result != SUCCESS) {
            MEDIA_LOGE("GetToneHapticsSettings: get defaultTone haptics settings fail");
        }
        return result;
    }

    if (toneUri == simcardSettingAsset->GetToneFile()) {
        settings.hapticsUri = simcardSettingAsset->GetVibrateFile();
        settings.mode = IntToToneHapticsMode(simcardSettingAsset->GetRingMode());
        return SUCCESS;
    }

    if (simcardSettingAsset->GetRingMode() != VIBRATE_PLAYMODE_SYNC) {
        settings.hapticsUri = simcardSettingAsset->GetVibrateFile();
        settings.mode = IntToToneHapticsMode(simcardSettingAsset->GetRingMode());
    } else {
        result = GetDefaultToneHapticsSettings(dataShareHelper, toneUri, toneHapticsType, settings);
    }
    if (result == SUCCESS) {
        MEDIA_LOGE("GetDefaultToneHapticsSettings: get defaultTone haptics settings success");
    } else {
        MEDIA_LOGE("GetToneHapticsSettings: get defaultTone haptics settings fail");
    }
    return result;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::SetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
    ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    CHECK_AND_RETURN_RET_LOG(IsToneHapticsTypeValid(toneHapticsType), OPERATION_ERROR, "Invalid tone haptics type");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    string currentToneUri = GetCurrentToneUri(context, toneHapticsType);

    int32_t res = SetToneHapticsSettings(dataShareHelper, currentToneUri, toneHapticsType, settings);
    dataShareHelper->Release();
    return res;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::SetToneHapticsSettings(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    std::lock_guard<std::mutex> lock(toneHapticsMutex_);
    MEDIA_LOGI("SetToneHapticsSettings: toneUri %{public}s type %{public}d hapticsUri %{public}s mode %{public}d",
        toneUri.c_str(), toneHapticsType, settings.hapticsUri.c_str(), settings.mode);
    if (dataShareHelper == nullptr || toneUri.empty() || !IsToneHapticsTypeValid(toneHapticsType)) {
        MEDIA_LOGE("SetToneHapticsSettings: param fail");
        return IO_ERROR;
    }

    ToneHapticsSettings updateSettings = settings;
    if (updateSettings.mode == ToneHapticsMode::NON_SYNC) {
        DataShare::DatashareBusinessError businessError;
        DataShare::DataSharePredicates queryPredicatesByUri;
        queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, updateSettings.hapticsUri);
        queryPredicatesByUri.And();
        queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_PLAY_MODE, hapticsModeMap_[updateSettings.mode]);
        Uri VIBRATEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES + "&user=" +
            std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
        auto resultSetByUri = dataShareHelper->Query(VIBRATEURI_PROXY, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
            &businessError);
        Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
        int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
        if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
            std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
                SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
            CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR, "Invalid dataShare");
        resultSetByUri = dataShareHelper->Query(VIBRATEURI, queryPredicatesByUri,
            VIBRATE_TABLE_COLUMNS, &businessError);
        }
        auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
        unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
        CHECK_AND_RETURN_RET_LOG(vibrateAssetByUri != nullptr, OPERATION_ERROR,
            "SetToneHapticsSettings: vibration of uri is not in the ringtone library!");
    } else if (settings.mode == ToneHapticsMode::SYNC) {
        std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
        int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, dataShareHelper, toneHapticsAttrs);
        if (result != SUCCESS) {
            return result;
        }
        updateSettings.hapticsUri = toneHapticsAttrs->GetUri();
    }

    int32_t res = UpdateToneHapticsSettings(dataShareHelper, toneUri, toneHapticsType, updateSettings);
    if (res != SUCCESS) {
        MEDIA_LOGE("SetToneHapticsSettings: set tone haptics settings fail!");
    }
    return res;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::GetToneHapticsList(const std::shared_ptr<AbilityRuntime::Context> &context,
    bool isSynced, std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray)
{
#ifdef SUPPORT_VIBRATOR
    MEDIA_LOGI("GetToneHapticsList: get vibration list, type : %{public}s.", isSynced ? "sync" : "non sync");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.BeginWrap();
    queryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_STANDARD);
    queryPredicates.Or();
    queryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_SALARM);
    queryPredicates.Or();
    queryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_SRINGTONE);
    queryPredicates.Or();
    queryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_SNOTIFICATION);
    queryPredicates.EndWrap();
    queryPredicates.And();
    queryPredicates.EqualTo(VIBRATE_COLUMN_PLAY_MODE,
        std::to_string(isSynced ? VIBRATE_PLAYMODE_SYNC : VIBRATE_PLAYMODE_CLASSIC));
    Uri VIBRATEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto resultSet = dataShareHelper->Query(VIBRATEURI_PROXY, queryPredicates, VIBRATE_TABLE_COLUMNS, &businessError);
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR, "Invalid dataShare,");
        resultSet = dataShareHelper->Query(VIBRATEURI, queryPredicates, VIBRATE_TABLE_COLUMNS, &businessError);
    }
    auto results = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSet));

    toneHapticsAttrsArray.clear();
    unique_ptr<VibrateAsset> vibrateAsset = results->GetFirstObject();
    if (vibrateAsset == nullptr) {
        MEDIA_LOGE("GetToneHapticsList: get %{public}s vibration list fail!", isSynced ? "sync" : "non sync");
    } else {
        while (vibrateAsset != nullptr) {
            auto toneHapticsAttrs = std::make_shared<ToneHapticsAttrs>(vibrateAsset->GetTitle(),
                vibrateAsset->GetDisplayName(), vibrateAsset->GetPath());
            toneHapticsAttrsArray.push_back(toneHapticsAttrs);
            vibrateAsset = results->GetNextObject();
        }
    }

    dataShareHelper->Release();
    return toneHapticsAttrsArray.empty() ? IO_ERROR : SUCCESS;
#endif
    return UNSUPPORTED_ERROR;
}

std::string SystemSoundManagerImpl::ConvertToHapticsFileName(const std::string &fileName)
{
    size_t dotPos = fileName.find_last_of('.');
    if (dotPos != std::string::npos) {
        std::string baseName = fileName.substr(0, dotPos);
        return baseName + ".json";
    } else {
        return fileName + ".json";
    }
}

std::unique_ptr<RingtoneAsset> SystemSoundManagerImpl::IsPresetRingtone(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const std::string &toneUri)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, toneUri);
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("the Permissions result :%{public}d ", result);
    if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Invalid dataShare.");
        auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
        auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
        unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
        if (ringtoneAsset == nullptr) {
            MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] inexistence in the ringtone library!", toneUri.c_str());
            return nullptr;
        }
        if (ringtoneAsset->GetSourceType() != SOURCE_TYPE_PRESET) {
            MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] is not system prefabrication!", toneUri.c_str());
            return nullptr;
        }
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        return ringtoneAsset;
    } else {
        Uri RINGTONEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
            std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
        auto resultSet = dataShareHelper->Query(RINGTONEURI_PROXY, queryPredicates, COLUMNS, &businessError);
        auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
        unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
        if (ringtoneAsset == nullptr) {
            MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] inexistence in the ringtone library!", toneUri.c_str());
            return nullptr;
        }
        if (ringtoneAsset->GetSourceType() != SOURCE_TYPE_PRESET) {
            MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] is not system prefabrication!", toneUri.c_str());
            return nullptr;
        }
        return ringtoneAsset;
    }
}

int SystemSoundManagerImpl::GetStandardVibrateType(int toneType)
{
    switch (toneType) {
        case TONE_TYPE_ALARM:
            return VIBRATE_TYPE_SALARM;
        case TONE_TYPE_RINGTONE:
            return VIBRATE_TYPE_SRINGTONE;
        case TONE_TYPE_NOTIFICATION:
            return VIBRATE_TYPE_SNOTIFICATION;
        default:
            return VIBRATE_TYPE_STANDARD;
    }
}

int32_t SystemSoundManagerImpl::GetHapticsAttrsSyncedWithTone(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &toneUri, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs)
{
#ifdef SUPPORT_VIBRATOR
    CHECK_AND_RETURN_RET_LOG(!toneUri.empty(), OPERATION_ERROR, "Invalid toneUri");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, dataShareHelper, toneHapticsAttrs);
    dataShareHelper->Release();
    return result;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::GetHapticsAttrsSyncedWithTone(const std::string &toneUri,
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs)
{
#ifdef SUPPORT_VIBRATOR
    MEDIA_LOGI("GetHapticsAttrsSyncedWithTone: get %{public}s sync vibration.", toneUri.c_str());
    if (dataShareHelper == nullptr || toneUri.empty()) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: param fail");
        return IO_ERROR;
    }

    unique_ptr<RingtoneAsset> ringtoneAsset = IsPresetRingtone(dataShareHelper, toneUri);
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not presetRingtone!", toneUri.c_str());
        return OPERATION_ERROR;
    }

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates vibrateQueryPredicates;
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME,
        ConvertToHapticsFileName(ringtoneAsset->GetDisplayName()));
    vibrateQueryPredicates.And();
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE,
        GetStandardVibrateType(ringtoneAsset->GetToneType()));
    vibrateQueryPredicates.And();
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_PLAY_MODE, VIBRATE_PLAYMODE_SYNC);
    Uri VIBRATEURI_PROXY(RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()));
    auto vibrateResultSet = dataShareHelper->Query(VIBRATEURI_PROXY, vibrateQueryPredicates, VIBRATE_TABLE_COLUMNS,
        &businessError);
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    MEDIA_LOGI("systemsoundmanagerimpl  result :%{public}d ",  result);
    if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        dataShareHelper = SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
            "Invalid dataShare, datashare or ringtone library error.");
        vibrateResultSet = dataShareHelper->Query(VIBRATEURI, vibrateQueryPredicates,
            VIBRATE_TABLE_COLUMNS, &businessError);
    }
    auto vibrateResults = make_unique<RingtoneFetchResult<VibrateAsset>>(move(vibrateResultSet));

    unique_ptr<VibrateAsset> vibrateAsset = vibrateResults->GetFirstObject();
    if (vibrateAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not sync vibration!", toneUri.c_str());
        return IO_ERROR;
    }

    toneHapticsAttrs = std::make_shared<ToneHapticsAttrs>(vibrateAsset->GetTitle(), vibrateAsset->GetDisplayName(),
        vibrateAsset->GetPath());
    return SUCCESS;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::OpenToneHaptics(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &hapticsUri)
{
#ifdef SUPPORT_VIBRATOR
    CHECK_AND_RETURN_RET_LOG(!hapticsUri.empty(), OPERATION_ERROR, "Invalid hapticsUri");
    MEDIA_LOGI("OpenToneHaptics: open %{public}s vibration.", hapticsUri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, hapticsUri);
    auto resultSetByUri = dataShareHelper->Query(VIBRATEURI, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
        &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    if (vibrateAssetByUri == nullptr) {
        MEDIA_LOGE("OpenToneHaptics: vibration of uri is not in the ringtone library!");
        dataShareHelper->Release();
        return OPERATION_ERROR;
    }

    string uriStr = VIBRATE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(vibrateAssetByUri->GetId());
    Uri ofUri(uriStr);
    int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
    dataShareHelper->Release();
    return fd > 0 ? fd : IO_ERROR;
#endif
    return UNSUPPORTED_ERROR;
}

bool SystemSoundManagerImpl::GetVibrateTypeByStyle(int standardVibrateType, HapticsStyle hapticsStyle,
    int &vibrateType)
{
    auto standardVibrateTypeEntry = hapticsStyleMap_.find(standardVibrateType);
    if (standardVibrateTypeEntry == hapticsStyleMap_.end()) {
        MEDIA_LOGE("GetVibrateType: input type [%{public}d] is not standardVibrateType!", standardVibrateType);
        return false;
    }
    auto hapticsStyleEntry = standardVibrateTypeEntry->second.find(hapticsStyle);
    if (hapticsStyleEntry == standardVibrateTypeEntry->second.end()) {
        MEDIA_LOGE("GetVibrateType: not have %{public}d haptics Style", hapticsStyle);
        return false;
    }
    vibrateType = hapticsStyleEntry->second;
    MEDIA_LOGI("GetVibrateType: standard %{public}d, style %{public}d, vibrateType %{public}d",
        standardVibrateType, hapticsStyle, vibrateType);
    return true;
}

std::string SystemSoundManagerImpl::GetHapticsUriByStyle(const DatabaseTool &databaseTool,
    const std::string &standardHapticsUri, HapticsStyle hapticsStyle)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }
    if (standardHapticsUri.empty()) {
        MEDIA_LOGE("The standardHapticsUri is empty!");
        return "";
    }
    MEDIA_LOGI("GetHapticsUriByStyle: standardHapticsUri %{public}s, style %{public}d", standardHapticsUri.c_str(),
        hapticsStyle);
    std::string vibrateFilesUri = "";
    if (databaseTool.isProxy) {
        vibrateFilesUri = RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        vibrateFilesUri = VIBRATE_PATH_URI;
    }
    Uri queryUri(vibrateFilesUri);

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, standardHapticsUri);
    auto resultSetByUri = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByUri,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByUri != nullptr, "", "vibrateAssetByUri is nullptr.");
    int vibrateType = 0;
    bool getResult = GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(), hapticsStyle, vibrateType);
    resultSetByUri == nullptr ? : resultSetByUri->Close();
    if (!getResult) {
        return "";
    }

    DataShare::DataSharePredicates queryPredicatesByDisplayName;
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME, vibrateAssetByUri->GetDisplayName());
    queryPredicatesByDisplayName.And();
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_PLAY_MODE, vibrateAssetByUri->GetPlayMode());
    queryPredicatesByDisplayName.And();
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, vibrateType);
    auto resultSetByDisplayName = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByDisplayName,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto resultsByDisplayName = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByDisplayName));
    unique_ptr<VibrateAsset> vibrateAssetByDisplayName = resultsByDisplayName->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByDisplayName != nullptr, "", "vibrateAssetByDisplayName is nullptr.");

    std::string hapticsUri = vibrateAssetByDisplayName->GetPath();
    resultSetByDisplayName == nullptr ? : resultSetByDisplayName->Close();
    MEDIA_LOGI("get style vibration %{public}s!", hapticsUri.c_str());
    return hapticsUri;
}

void SystemSoundManagerImpl::SetExtRingtoneUri(const std::string &uri, const std::string &title,
    int32_t ringType, int32_t toneType, int32_t changedRows)
{
    if (changedRows <= 0) {
        MEDIA_LOGE("Failed to Set Uri.");
        return;
    }

    int32_t ringtoneType = -1;
    if (toneType == TONE_TYPE_ALARM) {
        ringtoneType = EXT_TYPE_ALARMTONE;
    } else if (toneType == TONE_TYPE_RINGTONE) {
        ringtoneType = (ringType == RINGTONE_TYPE_SIM_CARD_0) ? EXT_TYPE_RINGTONE_ONE : EXT_TYPE_RINGTONE_TWO;
    } else if (toneType == TONE_TYPE_NOTIFICATION) {
        ringtoneType = (ringType == SYSTEM_TONE_TYPE_NOTIFICATION) ? EXT_TYPE_NOTIFICATION :
            (ringType == SYSTEM_TONE_TYPE_SIM_CARD_0) ? EXT_TYPE_MESSAGETONE_ONE : EXT_TYPE_MESSAGETONE_TWO;
    }

    if (ringtoneType < 0) {
        MEDIA_LOGE("ringtoneType error.");
        return;
    }

    (void)SetExtRingToneUri(uri, title, ringtoneType);
}

int32_t SystemSoundManagerImpl::SetExtRingToneUri(const std::string &uri, const std::string &title, int32_t toneType)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    CHECK_AND_RETURN_RET_LOG(callingUid != EXT_PROXY_UID, SUCCESS, "Calling from EXT, not need running.");

    std::string serviceAudio = OHOS::system::GetParameter(EXT_SERVICE_AUDIO, "");
    CHECK_AND_RETURN_RET_LOG(serviceAudio != "", ERROR, "The EXT is null.");
    MEDIA_LOGI("SetExtRingToneUri: toneType %{public}d, title %{public}s, uri %{public}s",
        toneType, title.c_str(), uri.c_str());

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, ERROR, "SystemAbilityManager init failed.");
    sptr<IRemoteObject> object = samgr->CheckSystemAbility(EXT_PROXY_SID);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, ERROR, "object is nullptr.");

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(Str8ToStr16(serviceAudio)), ERROR, "write desc failed.");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(uri), ERROR, "write uri failed.");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(title), ERROR, "write title failed.");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(toneType), ERROR, "write toneType failed.");

    int32_t ret = 0;
    ret = object->SendRequest(CMD_SET_EXT_RINGTONE_URI, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR, "request failed, error code:%{public}d", ret);

    ret = reply.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(ret == SUCCESS, ERROR, "reply failed, error code:%{public}d", ret);
    MEDIA_LOGI("SetExtRingToneUri Success.");
    return SUCCESS;
}

std::string SystemSoundManagerImpl::OpenAudioUri(const DatabaseTool &databaseTool, const std::string &audioUri)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    if (SystemSoundManagerUtils::VerifyCustomPath(audioUri)) {
        MEDIA_LOGI("The audio uri is custom path.");
        return OpenCustomAudioUri(audioUri);
    }

    std::string newAudioUri = audioUri;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    vector<string> columns = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, audioUri);

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, columns, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());

    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("The ringtoneAsset is nullptr!");
        return newAudioUri;
    }
    int32_t fd  = 0;
    if (databaseTool.isProxy) {
        std::string absFilePath;
        PathToRealPath(audioUri, absFilePath);
        fd = open(absFilePath.c_str(), O_RDONLY);
    } else {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        Uri ofUri(uriStr);
        fd = databaseTool.dataShareHelper->OpenFile(ofUri, "r");
    }
    resultSet == nullptr ? : resultSet->Close();

    if (fd > 0) {
        newAudioUri = FDHEAD + to_string(fd);
    }
    MEDIA_LOGI("OpenAudioUri result: newAudioUri is %{public}s", newAudioUri.c_str());
    return newAudioUri;
}

std::string SystemSoundManagerImpl::OpenCustomAudioUri(const std::string &customAudioUri)
{
    std::string newAudioUri = customAudioUri;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    vector<string> columns = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, customAudioUri);

    Uri ringtonePathUri(RINGTONE_PATH_URI);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, newAudioUri, "Invalid dataShare");
    auto resultSet = dataShareHelper->Query(ringtonePathUri, queryPredicates, columns, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    int32_t fd = 0;
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        MEDIA_LOGD("OpenCustomAudioUri: uri is %{public}s", uriStr.c_str());
        Uri ofUri(uriStr);
        fd = dataShareHelper->OpenFile(ofUri, "r");
        resultSet == nullptr ? : resultSet->Close();
    }
    dataShareHelper->Release();
    if (fd > 0) {
        newAudioUri = FDHEAD + to_string(fd);
    }
    MEDIA_LOGI("OpenCustomAudioUri: newAudioUri is %{public}s", newAudioUri.c_str());
    return newAudioUri;
}

std::string SystemSoundManagerImpl::OpenHapticsUri(const DatabaseTool &databaseTool, const std::string &hapticsUri)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return "";
    }

    std::string newHapticsUri = hapticsUri;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    vector<string> columns = {{VIBRATE_COLUMN_VIBRATE_ID}, {VIBRATE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, hapticsUri);

    std::string vibrateFilesUri = "";
    if (databaseTool.isProxy) {
        vibrateFilesUri = RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        vibrateFilesUri = VIBRATE_PATH_URI;
    }
    Uri queryUri(vibrateFilesUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, columns, &businessError);
    MEDIA_LOGI("dataShareHelper->Query: errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSet));
    unique_ptr<VibrateAsset> vibrateAssetByUri = results->GetFirstObject();
    if (vibrateAssetByUri == nullptr) {
        MEDIA_LOGE("The vibrateAssetByUri is nullptr!");
        return newHapticsUri;
    }
    int32_t fd = 0;
    if (databaseTool.isProxy) {
        std::string absFilePath;
        PathToRealPath(hapticsUri, absFilePath);
        fd = open(absFilePath.c_str(), O_RDONLY);
    } else {
        string uriStr = VIBRATE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(vibrateAssetByUri->GetId());
        MEDIA_LOGD("OpenHapticsUri: uri is %{public}s", uriStr.c_str());
        Uri ofUri(uriStr);
        fd = databaseTool.dataShareHelper->OpenFile(ofUri, "r");
    }
    resultSet == nullptr ? : resultSet->Close();
    if (fd > 0) {
        newHapticsUri = FDHEAD + to_string(fd);
    }
    MEDIA_LOGI("OpenHapticsUri result: newHapticsUri is %{public}s", newHapticsUri.c_str());
    return newHapticsUri;
}

void SystemSoundManagerImpl::SendCustomizedToneEvent(bool flag, const std::shared_ptr<ToneAttrs> &toneAttrs,
    off_t fileSize, std::string mimeType, int result)
{
    MEDIA_LOGI("SendCustomizedToneEvent start.");
    auto now = std::chrono::system_clock::now();
    time_t rawtime = std::chrono::system_clock::to_time_t(now);
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::ModuleId::AUDIO, Media::MediaMonitor::EventId::ADD_REMOVE_CUSTOMIZED_TONE,
        Media::MediaMonitor::EventType::BEHAVIOR_EVENT);
    bean->Add("ADD_REMOVE_OPERATION", static_cast<int32_t>(flag));
    bean->Add("APP_NAME", GetBundleName());
    bean->Add("FILE_SIZE", static_cast<uint64_t>(fileSize));
    bean->Add("RINGTONE_CATEGORY", toneAttrs->GetCategory());
    bean->Add("MEDIA_TYPE", static_cast<int32_t>(toneAttrs->GetMediaType()));
    bean->Add("MIME_TYPE", mimeType);
    bean->Add("TIMESTAMP", static_cast<uint64_t>(rawtime));
    bean->Add("RESULT", static_cast<int32_t>(result));
    Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
}

std::string SystemSoundManagerImpl::GetBundleName()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_LOGE("Get ability manager failed.");
        return "";
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_LOGE("object is NULL.");
        return "";
    }
    sptr<AppExecFwk::IBundleMgr> bms = iface_cast<AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_LOGE("bundle manager service is NULL.");
        return "";
    }
    std::string bundleName;
    if (bms->GetNameForUid(getuid(), bundleName)) {
        MEDIA_LOGE("get bundle name error.");
        return "";
    }
    MEDIA_LOGI("GetBundleName: bundleName is %{public}s", bundleName.c_str());
    return bundleName;
}
} // namesapce Media
} // namespace OHOS
