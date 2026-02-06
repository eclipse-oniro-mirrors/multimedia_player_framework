/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "config_policy_utils.h"
#include "file_ex.h"
#include "nlohmann/json.hpp"
#include <nativetoken_kit.h>
#include "directory_ex.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "ringtone_proxy_uri.h"
#include "ringtone_check_utils.h"

#include "system_sound_log.h"
#include "media_errors.h"
#include "ringtone_player_impl.h"
#include "vibrate_type.h"
#include "os_account_manager.h"
#include "system_tone_player_impl.h"
#include "parameter.h"
#include "system_sound_manager_utils.h"
#include "string_ex.h"
#include "parameters.h"

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
const std::string FIX_MP4 = ".mp4";
const int STORAGE_MANAGER_MANAGER_ID = 5003;
const int UNSUPPORTED_ERROR = -5;
const int INVALID_FD = -1;
const int32_t NOT_ENOUGH_ROM = -234;
const int32_t VIDEOS_NUM_EXCEEDS_SPECIFICATION = -235;
const int32_t FILE_EXIST = -17;
const int32_t MAX_VECTOR_LENGTH = 1024;
const off_t MAX_FILE_SIZE_200M = 200 * 1024 * 1024;
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
const int32_t INVALID_DATASHARE = -2;
const int32_t OPEN_FAILED = -3;
const int32_t QUERY_FAILED = -4;

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


std::shared_ptr<SystemSoundManager> SystemSoundManagerFactory::systemSoundManager_ = nullptr;
std::mutex SystemSoundManagerFactory::systemSoundManagerMutex_;
std::unordered_map<RingtoneType, RingToneType> ringtoneTypeMap_;
std::unordered_map<int32_t, ToneCustomizedType> sourceTypeMap_;
std::unordered_map<SystemToneType, int32_t> systemTypeMap_;
std::unordered_map<SystemToneType, ShotToneType> shotToneTypeMap_;
std::unordered_map<RingtoneType, DefaultSystemToneType> defaultoneTypeMap_;
std::unordered_map<SystemToneType, int32_t> defaultsystemTypeMap_;
std::unordered_map<ToneHapticsMode, VibratePlayMode> hapticsModeMap_;
std::unordered_map<ToneHapticsType, std::pair<int32_t, int32_t>> hapticsTypeWhereArgsMap_;
std::unordered_map<int32_t, std::unordered_map<HapticsStyle, int32_t>> hapticsStyleMap_;
Uri RINGTONEURI(RINGTONE_PATH_URI);
Uri VIBRATEURI(VIBRATE_PATH_URI);
Uri SIMCARDSETTINGURI(SIMCARD_SETTING_PATH_URI);
vector<string> COLUMNS = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}, {RINGTONE_COLUMN_DISPLAY_NAME},
    {RINGTONE_COLUMN_TITLE}, {RINGTONE_COLUMN_TONE_TYPE}, {RINGTONE_COLUMN_MEDIA_TYPE}, {RINGTONE_COLUMN_SOURCE_TYPE},
    {RINGTONE_COLUMN_SHOT_TONE_TYPE}, {RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE},
    {RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_RING_TONE_TYPE},
    {RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_ALARM_TONE_TYPE},
    {RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_MIME_TYPE}};
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
    {RINGTONE_CONTAINER_TYPE_WAV}, {RINGTONE_CONTAINER_TYPE_VIDEO_MP4}, {RINGTONE_CONTAINER_TYPE_3GA},
    {RINGTONE_CONTAINER_TYPE_A52}, {RINGTONE_CONTAINER_TYPE_AMR}, {RINGTONE_CONTAINER_TYPE_IMY},
    {RINGTONE_CONTAINER_TYPE_RTTTL}, {RINGTONE_CONTAINER_TYPE_XMF}, {RINGTONE_CONTAINER_TYPE_RTX},
    {RINGTONE_CONTAINER_TYPE_MXMF}, {RINGTONE_CONTAINER_TYPE_M4A}, {RINGTONE_CONTAINER_TYPE_M4B},
    {RINGTONE_CONTAINER_TYPE_M4P}, {RINGTONE_CONTAINER_TYPE_F4A}, {RINGTONE_CONTAINER_TYPE_F4B},
    {RINGTONE_CONTAINER_TYPE_F4P}, {RINGTONE_CONTAINER_TYPE_M3U}, {RINGTONE_CONTAINER_TYPE_SMF},
    {RINGTONE_CONTAINER_TYPE_MKA}, {RINGTONE_CONTAINER_TYPE_RA}, {RINGTONE_CONTAINER_TYPE_ADTS},
    {RINGTONE_CONTAINER_TYPE_ADT}, {RINGTONE_CONTAINER_TYPE_SND}, {RINGTONE_CONTAINER_TYPE_MP2},
    {RINGTONE_CONTAINER_TYPE_MP1}, {RINGTONE_CONTAINER_TYPE_MPA}, {RINGTONE_CONTAINER_TYPE_MPA},
    {RINGTONE_CONTAINER_TYPE_M4R}};

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

int32_t SystemSoundManagerImpl::UpdateToneTypeUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const UpdateToneTypeParams &params)
{
    // Step 1: Clear old type mark for current type
    DataSharePredicates updateOnlyPredicates;
    DataShareValuesBucket updateOnlyValuesBucket;
    updateOnlyPredicates.SetWhereClause(params.typeColumnName + " = ? AND " +
        params.sourceTypeColumnName + " = ? ");
    updateOnlyPredicates.SetWhereArgs({to_string(params.currentType), to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOnlyValuesBucket.Put(params.typeColumnName, params.notType);
    updateOnlyValuesBucket.Put(params.sourceTypeColumnName, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOnlyPredicates, updateOnlyValuesBucket);

    // Step 2: Update BOTH type to alternate type
    DataSharePredicates updateBothPredicates;
    DataShareValuesBucket updateBothValuesBucket;
    int32_t alternateType = (params.currentType == RING_TONE_TYPE_SIM_CARD_1 ||
        params.currentType == SHOT_TONE_TYPE_SIM_CARD_1) ?
        RING_TONE_TYPE_SIM_CARD_2 : RING_TONE_TYPE_SIM_CARD_1;
    updateBothPredicates.SetWhereClause(params.typeColumnName + " = ? AND " +
        params.sourceTypeColumnName + " = ? ");
    updateBothPredicates.SetWhereArgs({to_string(params.simCardBoth), to_string(SOURCE_TYPE_CUSTOMISED)});
    updateBothValuesBucket.Put(params.typeColumnName, alternateType);
    dataShareHelper->Update(RINGTONEURI, updateBothPredicates, updateBothValuesBucket);

    // Step 3: Determine final type and update
    int32_t finalType = params.currentType;
    // Check if current type is SIM_CARD_1 (ring: SIM1, shot: SIM1)
    bool isCurrentSimCard1 = (params.currentType == RING_TONE_TYPE_SIM_CARD_1 ||
        params.currentType == SHOT_TONE_TYPE_SIM_CARD_1);
    // Check if current type is SIM_CARD_2 (ring: SIM2, shot: SIM2)
    bool isCurrentSimCard2 = (params.currentType == RING_TONE_TYPE_SIM_CARD_2 ||
        params.currentType == SHOT_TONE_TYPE_SIM_CARD_2);
    // Check if asset type is SIM_CARD_1 (ring: SIM1, shot: SIM1)
    bool isAssetSimCard1 = (params.shotToneType == RING_TONE_TYPE_SIM_CARD_1 ||
        params.shotToneType == SHOT_TONE_TYPE_SIM_CARD_1);
    // Check if asset type is SIM_CARD_2 (ring: SIM2, shot: SIM2)
    bool isAssetSimCard2 = (params.shotToneType == RING_TONE_TYPE_SIM_CARD_2 ||
        params.shotToneType == SHOT_TONE_TYPE_SIM_CARD_2);
    bool isAssetBoth = (params.shotToneType == RING_TONE_TYPE_SIM_CARD_BOTH);

    // If asset supports SIM1 (or Both) and current is SIM2, or asset supports SIM2 (or Both)
    // and current is SIM1, set to BOTH type
    if ((isAssetSimCard1 || isAssetBoth) && isCurrentSimCard2) {
        finalType = params.simCardBoth;
    } else if ((isAssetSimCard2 || isAssetBoth) && isCurrentSimCard1) {
        finalType = params.simCardBoth;
    }

    DataSharePredicates updatePredicates;
    DataShareValuesBucket updateValuesBucket;
    updatePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
    updatePredicates.SetWhereArgs({to_string(params.toneId)});
    updateValuesBucket.Put(params.typeColumnName, finalType);
    updateValuesBucket.Put(params.sourceTypeColumnName, SOURCE_TYPE_CUSTOMISED);
    return dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
}

int32_t SystemSoundManagerImpl::UpdateRingtoneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const int32_t &toneId, RingtoneType ringtoneType, const int32_t &shotToneType)
{
    UpdateToneTypeParams params = {
        toneId,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        ringtoneTypeMap_[ringtoneType],
        shotToneType
    };
    return UpdateToneTypeUri(dataShareHelper, params);
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

    HILOG_COMM_INFO("SetRingtoneUri: ringtoneType %{public}d, uri %{public}s", ringtoneType, uri.c_str());
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
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        if (resultsByUri != nullptr) resultsByUri->Close();
        dataShareHelper->Release();
        MEDIA_LOGE("Failed to find the uri in ringtone library!");
        return ERROR;
    }
    if (resultsByUri != nullptr) resultsByUri->Close();
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
        if (results != nullptr) results->Close();
        dataShareHelper->Release();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), ringtoneType, TONE_TYPE_RINGTONE, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetRingtoneUriByType(const DatabaseTool &databaseTool, const std::string &type)
{
    ToneAttrs toneAttrs = GetRingtoneAttrsByType(databaseTool, type);
    return toneAttrs.GetUri();
}

ToneAttrs SystemSoundManagerImpl::QueryToneAttrsByType(const DatabaseTool &databaseTool,
    const std::string &typeColumnName, const std::string &typeColumnValue,
    SourceType sourceType, int32_t defaultCategory)
{
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, defaultCategory };
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("QueryToneAttrsByType: the database tool is not ready!");
        return toneAttrs;
    }

    std::string sourceTypeColumnName = "";
    if (typeColumnName == RINGTONE_COLUMN_RING_TONE_TYPE) {
        sourceTypeColumnName = RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE;
    } else if (typeColumnName == RINGTONE_COLUMN_SHOT_TONE_TYPE) {
        sourceTypeColumnName = RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE;
    } else if (typeColumnName == RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE) {
        sourceTypeColumnName = RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE;
    } else {
        MEDIA_LOGE("QueryToneAttrsByType: invalid type column name!");
        return toneAttrs;
    }

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(typeColumnName + " = ? AND " + sourceTypeColumnName + " = ? ");
    queryPredicates.SetWhereArgs({typeColumnValue, to_string(sourceType)});

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    MEDIA_LOGI("QueryToneAttrsByType: Query errCode %{public}d", businessError.GetCode());
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, toneAttrs, "QueryToneAttrsByType: results is nullptr!");
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
    if (results != nullptr) results->Close();
    return toneAttrs;
}

ToneAttrs SystemSoundManagerImpl::GetRingtoneAttrsByType(const DatabaseTool &databaseTool, const std::string &type)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_RING_TONE_TYPE, type,
        SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
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
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    if (results != nullptr) results->Close();
    return uri;
}

ToneAttrs SystemSoundManagerImpl::GetPresetRingToneAttrByType(const DatabaseTool &databaseTool,
    const std::string &type)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_RING_TONE_TYPE, type,
        SOURCE_TYPE_PRESET, TONE_CATEGORY_RINGTONE);
}

std::string SystemSoundManagerImpl::GetRingtoneUri(const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    ToneAttrs toneAttrs = GetCurrentRingtoneAttribute(ringtoneType);
    return toneAttrs.GetUri();
}

ToneAttrs SystemSoundManagerImpl::GetCurrentRingtoneAttribute(RingtoneType ringtoneType)
{
    HILOG_COMM_INFO("GetCurrentRingtoneAttribute: Start, ringtoneType: %{public}d", ringtoneType);
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_RINGTONE };
    if (!IsRingtoneTypeValid(ringtoneType)) {
        MEDIA_LOGE("GetCurrentRingtoneAttribute: Invalid ringtone type!");
        return toneAttrs;
    }

    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
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
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, ringtoneTitle, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri != nullptr) {
        ringtoneTitle = ringtoneAssetByUri->GetTitle();
    }
    if (resultsByUri != nullptr) resultsByUri->Close();
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
    const int32_t &toneId, SystemToneType systemToneType, const int32_t &shotToneType)
{
    UpdateToneTypeParams params = {
        toneId,
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        SHOT_TONE_TYPE_SIM_CARD_BOTH,
        shotToneTypeMap_[systemToneType],
        shotToneType
    };
    return UpdateToneTypeUri(dataShareHelper, params);
}

int32_t SystemSoundManagerImpl::UpdateNotificatioToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const int32_t &toneId)
{
    // Clear old notification tone type mark
    DataSharePredicates updateOldPredicates;
    DataShareValuesBucket updateOldValuesBucket;
    updateOldPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
    updateOldPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(SOURCE_TYPE_CUSTOMISED)});
    updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, NOTIFICATION_TONE_TYPE_NOT);
    updateOldValuesBucket.Put(RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE, SOURCE_TYPE_INVALID);
    dataShareHelper->Update(RINGTONEURI, updateOldPredicates, updateOldValuesBucket);

    // Set new notification tone type
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

    HILOG_COMM_INFO("SetSystemToneUri: systemToneType %{public}d, uri %{public}s", systemToneType, uri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed.");

    if (uri == NO_SYSTEM_SOUND) {
        (void)SetNoSystemToneUri(dataShareHelper, systemToneType);
        dataShareHelper->Release();
        return SUCCESS;
    }
    int32_t result = SetSystemToneUri(dataShareHelper, uri, systemToneType);
    dataShareHelper->Release();
    return result;
}

int32_t SystemSoundManagerImpl::SetSystemToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const string &uri, SystemToneType systemToneType)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        if (resultsByUri != nullptr) resultsByUri->Close();
        dataShareHelper->Release();
        MEDIA_LOGE("Failed to find the uri in ringtone library!");
        return ERROR;
    }
    if (resultsByUri != nullptr) resultsByUri->Close();
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
        if (results != nullptr) results->Close();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), systemToneType, TONE_TYPE_NOTIFICATION, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    if (results != nullptr) results->Close();
    return TYPEERROR;
}

ToneAttrs SystemSoundManagerImpl::GetShotToneAttrsByType(const DatabaseTool &databaseTool, const std::string &type)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_SHOT_TONE_TYPE, type,
        SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_TEXT_MESSAGE);
}

ToneAttrs SystemSoundManagerImpl::GetPresetShotToneAttrsByType(const DatabaseTool &databaseTool,
    const std::string &type)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_SHOT_TONE_TYPE, type,
        SOURCE_TYPE_PRESET, TONE_CATEGORY_TEXT_MESSAGE);
}

ToneAttrs SystemSoundManagerImpl::GetNotificationToneAttrsByType(const DatabaseTool &databaseTool)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE,
        to_string(NOTIFICATION_TONE_TYPE), SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_NOTIFICATION);
}

ToneAttrs SystemSoundManagerImpl::GetPresetNotificationToneAttrs(const DatabaseTool &databaseTool)
{
    return QueryToneAttrsByType(databaseTool, RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE,
        to_string(NOTIFICATION_TONE_TYPE), SOURCE_TYPE_PRESET, TONE_CATEGORY_NOTIFICATION);
}

std::string SystemSoundManagerImpl::GetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    SystemToneType systemToneType)
{
    MEDIA_LOGI("Enter the GetSystemToneUri interface.");
    ToneAttrs toneAttrs = GetSystemToneAttrs(systemToneType);
    return toneAttrs.GetUri();
}

ToneAttrs SystemSoundManagerImpl::GetSystemToneAttrs(SystemToneType systemToneType)
{
    MEDIA_LOGI("GetSystemToneAttrs: Start, systemToneType: %{public}d", systemToneType);
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, category };
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType), toneAttrs, "Invalid system tone type");

    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, toneAttrs,
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    toneAttrs = GetSystemToneAttrs(databaseTool, systemToneType);
    dataShareHelper->Release();
    MEDIA_LOGI("Finish to get system tone uri: type %{public}d, uri %{public}s", systemToneType,
        toneAttrs.GetUri().c_str());
    return toneAttrs;
}

ToneAttrs SystemSoundManagerImpl::GetSystemToneAttrs(const DatabaseTool &databaseTool, SystemToneType systemToneType)
{
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, category};
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return toneAttrs;
    }

    switch (systemToneType) {
        case SYSTEM_TONE_TYPE_SIM_CARD_0:
        case SYSTEM_TONE_TYPE_SIM_CARD_1:
            toneAttrs = GetShotToneAttrsByType(databaseTool, to_string(systemTypeMap_[systemToneType]));
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetShotToneAttrsByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetPresetShotToneAttrsByType(databaseTool, to_string(systemTypeMap_[systemToneType]));
            }
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetPresetShotToneAttrsByType(databaseTool, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            break;
        case SYSTEM_TONE_TYPE_NOTIFICATION:
            toneAttrs = GetNotificationToneAttrsByType(databaseTool);
            if (toneAttrs.GetUri().empty()) {
                toneAttrs = GetNotificationToneAttrsByType(databaseTool);
            }
            break;
        default:
            break;
    }
    if (toneAttrs.GetUri().empty()) {
        MEDIA_LOGI("GetSystemToneAttrs: No system tone uri for type %{public}d. Return NO_SYSTEM_SOUND",
            systemToneType);
        toneAttrs.SetUri(NO_SYSTEM_SOUND);
    }
    return toneAttrs;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultRingtoneAttrs(
    const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    MEDIA_LOGI("GetDefaultRingtoneAttrs : Enter the getDefaultRingtoneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType),  nullptr, "Invalid ringtone type");
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    ringtoneAttrs_ = nullptr;
    std::vector<std::string> onClause;
    onClause.push_back(RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID + "=" +
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_TONE_ID);
    queryPredicates.InnerJoin(PRELOAD_CONFIG_TABLE)->On(onClause)->EqualTo(
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_RING_TONE_TYPE, defaultoneTypeMap_[ringtoneType]);
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, JOIN_COLUMNS, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "query failed.");
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
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return ringtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetRingtoneAttrList(
    const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType)
{
    MEDIA_LOGI("GetRingtoneAttrList : Enter the getRingtoneAttrList interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    ringtoneAttrsArray_.clear();
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ringtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_RINGTONE));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, COLUMNS, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, ringtoneAttrsArray_, "query failed.");
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
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return ringtoneAttrsArray_;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultSystemToneAttrs(
    const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType)
{
    MEDIA_LOGI("GetDefaultSystemToneAttrs : Enter the getDefaultSystemToneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType),  nullptr, "Invalid systemtone type");
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
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
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, JOIN_COLUMNS, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "query failed.");
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
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return systemtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetSystemToneAttrList(
    const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    systemtoneAttrsArray_.clear();
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, systemtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_NOTIFICATION));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, COLUMNS, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, systemtoneAttrsArray_, "query failed.");
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
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return systemtoneAttrsArray_;
}

int32_t SystemSoundManagerImpl::SetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &uri)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    MEDIA_LOGI("SetAlarmToneUri: Alarm type %{public}d", SystemSoundManagerUtils::GetTypeForSystemSoundUri(uri));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Create dataShare failed.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        MEDIA_LOGE("Failed to find uri in ringtone library. The input uri is invalid!");
        if (resultsByUri != nullptr) resultsByUri->Close();
        dataShareHelper->Release();
        return ERROR;
    }
    if (resultsByUri != nullptr) resultsByUri->Close();
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
        if (results != nullptr) results->Close();
        dataShareHelper->Release();
        SetExtRingtoneUri(uri, ringtoneAsset->GetTitle(), TONE_TYPE_ALARM, TONE_TYPE_ALARM, changedRows);
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    MEDIA_LOGE("Failed to find uri in ringtone library!");
    if (results != nullptr) results->Close();
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
    MEDIA_LOGI("Enter the GetAlarmToneUri interface.");
    ToneAttrs toneAttrs = GetAlarmToneAttrs(context);
    std::string alarmToneUri = toneAttrs.GetUri();
    MEDIA_LOGI("GetAlarmToneUri: alarm type %{public}d",
        SystemSoundManagerUtils::GetTypeForSystemSoundUri(alarmToneUri));
    return alarmToneUri;
}

ToneAttrs SystemSoundManagerImpl::GetAlarmToneAttrs(const std::shared_ptr<AbilityRuntime::Context> &context)
{
    MEDIA_LOGI("GetAlarmToneAttrs: Start.");
    std::lock_guard<std::mutex> lock(uriMutex_);
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_ALARM };
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, toneAttrs,
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    toneAttrs = GetAlarmToneAttrs(databaseTool);
    MEDIA_LOGI("GetAlarmToneUri: alarm uri %{public}s", toneAttrs.GetUri().c_str());
    dataShareHelper->Release();
    return toneAttrs;
}

ToneAttrs SystemSoundManagerImpl::GetAlarmToneAttrs(const DatabaseTool &databaseTool)
{
    int32_t count = 2;
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_ALARM };
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return toneAttrs;
    }
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_ALARM_TONE_TYPE, to_string(ALARM_TONE_TYPE));
    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, toneAttrs, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (SOURCE_TYPE_CUSTOMISED !=
        ringtoneAsset->GetAlarmtoneSourceType()) && (results->GetCount() == count)) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        toneAttrs.SetCategory(ringtoneAsset->GetToneType());
        toneAttrs.SetFileName(ringtoneAsset->GetDisplayName());
        toneAttrs.SetTitle(ringtoneAsset->GetTitle());
        toneAttrs.SetUri(ringtoneAsset->GetPath());
        if (ringtoneAsset->GetMediaType() == RINGTONE_MEDIA_TYPE_VIDEO) {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_VID);
        } else {
            toneAttrs.SetMediaType(ToneMediaType::MEDIA_TYPE_AUD);
        }
    } else {
        MEDIA_LOGE("GetAlarmToneAttrs: no alarmtone in the ringtone library!");
    }
    if (results != nullptr) results->Close();
    return toneAttrs;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultAlarmToneAttrs(
    const std::shared_ptr<AbilityRuntime::Context> &context)
{
    MEDIA_LOGI("GetDefaultAlarmToneAttrs : Enter the getDefaultAlarmToneAttrs interface");
    std::lock_guard<std::mutex> lock(uriMutex_);
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "Create dataShare failed.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    alarmtoneAttrs_ = nullptr;
    std::vector<std::string> onClause;
    onClause.push_back(RINGTONE_TABLE + "." + RINGTONE_COLUMN_TONE_ID + "=" +
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_TONE_ID);
    queryPredicates.InnerJoin(PRELOAD_CONFIG_TABLE)->On(onClause)->EqualTo(
        PRELOAD_CONFIG_TABLE + "." + PRELOAD_CONFIG_COLUMN_RING_TONE_TYPE, DEFAULT_ALARM_TYPE);

    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, JOIN_COLUMNS, &businessError);

    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "query failed.");
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
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    return alarmtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetAlarmToneAttrList
    (const std::shared_ptr<AbilityRuntime::Context> &context)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    alarmtoneAttrsArray_.clear();
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmtoneAttrsArray_, "Create dataShare failed.");
    
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_ALARM));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : RINGTONE_PATH_URI;
    Uri QUERYURI(queryUri);
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, COLUMNS, &businessError);

    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, alarmtoneAttrsArray_, "query failed.");
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
    if (results != nullptr) results->Close();
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
    MEDIA_LOGI("Enter the OpenToneUri interface.");
    std::lock_guard<std::mutex> lock(uriMutex_);
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    if (dataShareHelper == nullptr) {
        SendPlaybackFailedEvent(INVALID_DATASHARE);
        MEDIA_LOGE("Failed to CreateDataShareHelper! datashare or ringtone library error.");
        return ERROR;
    }
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    std::string newAudioUri = RingtoneCheckUtils::GetCustomRingtoneCurrentPath(uri);
    int32_t ret = OpenToneUri(databaseTool, newAudioUri, toneType);
    MEDIA_LOGI("Open tone uri: open result : %{public}d, type %{public}d, newAudioUri %{public}s,",
        ret, toneType, newAudioUri.c_str());
    dataShareHelper->Release();
    return ret;
}

int32_t SystemSoundManagerImpl::OpenToneUri(const DatabaseTool &databaseTool,
    const std::string &uri, int32_t toneType)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        SendPlaybackFailedEvent(INVALID_DATASHARE);
        return ERROR;
    }
    if (SystemSoundManagerUtils::VerifyCustomPath(uri)) {
        MEDIA_LOGI("The audio uri is custom path.");
        return OpenCustomToneUri(uri, toneType);
    }
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    std::vector<std::string> args = {uri, to_string(toneType)};
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_DATA + " = ? AND " + RINGTONE_COLUMN_TONE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs(args);
    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        SendPlaybackFailedEvent(QUERY_FAILED);
        MEDIA_LOGE("query failed, ringtone library error.");
        return ERROR;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("OpenTone: tone of uri failed!");
        if (results != nullptr) results->Close();
        return TYPEERROR;
    }
    int32_t toneId = ringtoneAsset->GetId();
    int32_t fd  = OpenToneFile(databaseTool, uri, toneType, toneId);
    if (results != nullptr) results->Close();
    return fd;
}

int32_t SystemSoundManagerImpl::OpenToneFile(const DatabaseTool &databaseTool,
    const std::string &uri, int32_t toneType, int32_t toneId)
{
    int32_t fd = 0;
    if (databaseTool.isProxy) {
        std::string absFilePath;
        PathToRealPath(uri, absFilePath);
        fd = open(absFilePath.c_str(), O_RDONLY);
    } else {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(toneId);
        Uri ofUri(uriStr);
        fd = databaseTool.dataShareHelper->OpenFile(ofUri, "r");
    }
    if (fd < 0) {
        SendPlaybackFailedEvent(OPEN_FAILED);
        MEDIA_LOGE("query failed, ringtone library error.");
        return ERROR;
    }
    return fd;
}

int32_t SystemSoundManagerImpl::OpenCustomToneUri(const std::string &customAudioUri, int32_t toneType)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    std::vector<std::string> args = {customAudioUri, to_string(toneType)};
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_DATA + " = ? AND " + RINGTONE_COLUMN_TONE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs(args);
    Uri ringtonePathUri(RINGTONE_PATH_URI);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        SendPlaybackFailedEvent(INVALID_DATASHARE);
        MEDIA_LOGE("Invalid dataShare.");
        return ERROR;
    }
    auto resultSet = dataShareHelper->Query(ringtonePathUri, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        SendPlaybackFailedEvent(QUERY_FAILED);
        MEDIA_LOGE("query failed, ringtone library error.");
        return ERROR;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        Uri ofUri(uriStr);
        int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
        if (results != nullptr) results->Close();
        dataShareHelper->Release();
        if (fd < 0) {
            SendPlaybackFailedEvent(OPEN_FAILED);
            return ERROR;
        }
        return fd;
    }
    MEDIA_LOGE("Open custom audio uri failed!");
    SendPlaybackFailedEvent(QUERY_FAILED);
    if (results != nullptr) results->Close();
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
        if (results != nullptr) results->Close();
        if (fd > 0) {
            std::get<PARAM1>(resultOfOpen) = fd;
            std::get<PARAM2>(resultOfOpen) = ERROR_OK;
        } else {
            MEDIA_LOGE("OpenOneFile: OpenFile failed, uri: %{public}s.", uri.c_str());
        }
        return;
    }
    MEDIA_LOGE("OpenOneFile: ringtoneAsset is nullptr, uri: %{public}s.", uri.c_str());
    if (results != nullptr) results->Close();
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
    bool needToCloseSrcFd = false;
    if (srcPath.find(fdHead) != std::string::npos) {
        StrToInt(srcPath.substr(fdHead.size()), srcFd);
    } else {
        srcFd = open(srcPath.c_str(), O_RDONLY);
        needToCloseSrcFd = (srcFd != -1);
    }
    if (srcFd < 0) {
        MEDIA_LOGE("AddCustomizedToneByExternalUri: fd open error is %{public}s", strerror(errno));
        fdHead.clear();
        return fdHead;
    }
    std::string result = AddCustomizedToneByFd(context, toneAttrs, srcFd);
    if (needToCloseSrcFd) {
        MEDIA_LOGI("Close src fd.");
        close(srcFd);
    }
    return result;
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFd(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd)
{
    MEDIA_LOGI("AddCustomizedToneByFd: Start.");
    ParamsForAddCustomizedTone paramsForAddCustomizedTone = { "", fd, INT_MAX, 0, false };
    return AddCustomizedToneByFdAndOffset(context, toneAttrs, paramsForAddCustomizedTone);
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
    const std::shared_ptr<ToneAttrs> &toneAttrs, int32_t &length)
{
    MEDIA_LOGI("AddCustomizedTone: Start.");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Invalid dataShareHelper.");
    int32_t category = -1;
    category = toneAttrs->GetCategory();
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(RINGTONE_COLUMN_DISPLAY_NAME, static_cast<string>(displayName_));
    valuesBucket.Put(RINGTONE_COLUMN_TITLE, static_cast<string>(toneAttrs->GetTitle()));
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_AUD) {
        valuesBucket.Put(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_AUDIO));
    } else if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        valuesBucket.Put(RINGTONE_COLUMN_MEDIA_TYPE, static_cast<int>(RINGTONE_MEDIA_TYPE_VIDEO));
    }
    valuesBucket.Put(RINGTONE_COLUMN_SIZE, static_cast<int>(length));
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
        case TONE_CATEGORY_NOTIFICATION_APP:
            toneAttrs->SetUri(RINGTONE_CUSTOMIZED_APP_NOTIFICATIONS_PATH + RINGTONE_SLASH_CHAR + displayName_);
            valuesBucket.Put(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_APP_NOTIFICATION));
            break;
        default:
            break;
    }
    valuesBucket.Put(RINGTONE_COLUMN_DATA, static_cast<string>(toneAttrs->GetUri()));
    int32_t result = dataShareHelper->Insert(RINGTONEURI, valuesBucket);
    HILOG_COMM_INFO("AddCustomizedTone, result : %{public}d", result);
    return result;
}

bool SystemSoundManagerImpl::DeleteCustomizedTone(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const std::shared_ptr<ToneAttrs> &toneAttrs, int32_t &length)
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
    predicates.EqualTo(RINGTONE_COLUMN_SIZE, static_cast<int>(length));
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
        case TONE_CATEGORY_NOTIFICATION_APP:
            predicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, static_cast<int>(TONE_TYPE_APP_NOTIFICATION));
            break;
        default:
            break;
    }
    predicates.EqualTo(RINGTONE_COLUMN_DATA, static_cast<string>(toneAttrs->GetUri()));
    bool result = (dataShareHelper->Delete(RINGTONEURI, predicates) > 0);
    HILOG_COMM_INFO("DeleteCustomizedTone: displayName : %{public}s, result: %{public}d", displayName_.c_str(), result);
    return result;
}

std::string SystemSoundManagerImpl::AddCustomizedToneCheck(const std::shared_ptr<ToneAttrs> &toneAttrs,
    const int32_t &length)
{
    std::string result = "TYPEERROR";
    if (toneAttrs == nullptr) {
        MEDIA_LOGE("AddCustomizedToneCheck: The toneAttrs is nullptr!");
        return result;
    }
    GetCustomizedTone(toneAttrs);
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        if (length > MAX_FILE_SIZE_200M) {
            MEDIA_LOGE("AddCustomizedToneCheck: The file size exceeds 200M.");
            return FILE_SIZE_EXCEEDS_LIMIT;
        }
    }
    if (toneAttrs->GetCustomizedType() != CUSTOMISED) {
        MEDIA_LOGE("AddCustomizedToneCheck: The ringtone is not customized!");
        return result;
    }
    if (toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        std::string fileName = toneAttrs->GetFileName();
        if (fileName.length() <= FIX_MP4.length()) {
            MEDIA_LOGE("AddCustomizedToneCheck: fileName length is invalid!");
            return result;
        }
        std::string tail = fileName.substr(fileName.length() - FIX_MP4.length(), FIX_MP4.length());
        if (tail != FIX_MP4) {
            MEDIA_LOGE("AddCustomizedToneCheck: video type, but file format is not mp4!");
            return result;
        }
    }
    return "";
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<ToneAttrs> &toneAttrs,
    ParamsForAddCustomizedTone &paramsForAddCustomizedTone)
{
    MEDIA_LOGI("AddCustomizedToneByFdAndOffset: Start.");
    MediaTrace::TraceBegin("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
    off_t fileSize = 0;
    std::string checkResult = AddCustomizedToneCheck(toneAttrs, paramsForAddCustomizedTone.length);
    if (!checkResult.empty()) {
        SendCustomizedToneEvent(true, toneAttrs, fileSize, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        return checkResult;
    }
    std::lock_guard<std::mutex> lock(uriMutex_);
    int32_t srcFd = paramsForAddCustomizedTone.srcFd;
    off_t lseekResult = lseek(srcFd, paramsForAddCustomizedTone.offset, SEEK_SET);
    if (srcFd < 0 || lseekResult == -1) {
        MEDIA_LOGE("AddCustomizedToneByFdAndOffset: fd is error");
        SendCustomizedToneEvent(true, toneAttrs, paramsForAddCustomizedTone.length, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        return "";
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        MEDIA_LOGE("AddCustomizedToneByFdAndOffset: Create dataShare failed, datashare or ringtone library error.");
        SendCustomizedToneEvent(true, toneAttrs, paramsForAddCustomizedTone.length, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        return "";
    }
    int32_t sert = AddCustomizedTone(dataShareHelper, toneAttrs, paramsForAddCustomizedTone.length);
    if (sert < 0) {
        SendCustomizedToneEvent(true, toneAttrs, paramsForAddCustomizedTone.length, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        std::string result = DealAddCustomizedToneError(sert, paramsForAddCustomizedTone, toneAttrs, dataShareHelper);
        dataShareHelper->Release();
        return result;
    }
    std::string dstPath = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(sert);
    paramsForAddCustomizedTone = { dstPath, srcFd, paramsForAddCustomizedTone.length };
    return CustomizedToneWriteFile(dataShareHelper, toneAttrs, paramsForAddCustomizedTone);
}

std::string SystemSoundManagerImpl::DealAddCustomizedToneError(int32_t &sert,
    ParamsForAddCustomizedTone &paramsForAddCustomizedTone, const std::shared_ptr<ToneAttrs> &toneAttrs,
    std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    if (sert == VIDEOS_NUM_EXCEEDS_SPECIFICATION) {
        return FILE_COUNT_EXCEEDS_LIMIT;
    } else if (sert == NOT_ENOUGH_ROM) {
        return ROM_IS_INSUFFICIENT;
    } else if (sert == FILE_EXIST && toneAttrs->GetMediaType() == ToneMediaType::MEDIA_TYPE_VID) {
        DataShare::DatashareBusinessError businessError;
        DataShare::DataSharePredicates queryPredicates;
        queryPredicates.EqualTo(RINGTONE_COLUMN_DISPLAY_NAME, toneAttrs->GetFileName());
        queryPredicates.EqualTo(RINGTONE_COLUMN_TITLE, toneAttrs->GetTitle());
        queryPredicates.EqualTo(RINGTONE_COLUMN_SIZE, paramsForAddCustomizedTone.length);
        if (toneAttrs->GetCategory() == TONE_CATEGORY_RINGTONE) {
            queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, TONE_TYPE_RINGTONE);
        } else if (toneAttrs->GetCategory() == TONE_CATEGORY_CONTACTS) {
            queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, TONE_TYPE_CONTACTS);
        }
        auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
        auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
        CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query failed, ringtone library error.");
        unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
        if (results != nullptr) results->Close();
        if (ringtoneAsset == nullptr) {
            MEDIA_LOGE("DealAddCustomizedToneError: duplicate file name!");
            paramsForAddCustomizedTone.duplicateFile = true;
            return toneAttrs->GetUri();
        } else {
            return ringtoneAsset->GetPath();
        }
    }
    return "";
}

std::string SystemSoundManagerImpl::CustomizedToneWriteFile(
    std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper, const std::shared_ptr<ToneAttrs> &toneAttrs,
    ParamsForAddCustomizedTone &paramsForAddCustomizedTone)
{
    MEDIA_LOGI("CustomizedToneWriteFile: Start.");
    Uri ofUri(paramsForAddCustomizedTone.dstPath);
    int32_t dstFd = dataShareHelper->OpenFile(ofUri, "rw");
    if (dstFd < 0) {
        MEDIA_LOGE("CustomizedToneWriteFile: Open error is %{public}s", strerror(errno));
        DeleteCustomizedTone(dataShareHelper, toneAttrs, paramsForAddCustomizedTone.length);
        dataShareHelper->Release();
        SendCustomizedToneEvent(true, toneAttrs, paramsForAddCustomizedTone.length, mimeType_, ERROR);
        MediaTrace::TraceEnd("SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset", FAKE_POINTER(this));
        return "";
    }
    MEDIA_LOGI("CustomizedToneWriteFile: OpenFile success, begin write file.");
    char buffer[4096];
    int32_t len = paramsForAddCustomizedTone.length;
    memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    int32_t bytesRead = 0;
    while ((bytesRead = read(paramsForAddCustomizedTone.srcFd, buffer, sizeof(buffer))) > 0 && len > 0) {
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
    SendCustomizedToneEvent(true, toneAttrs, paramsForAddCustomizedTone.length, mimeType_, SUCCESS);
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
        if (results != nullptr) results->Close();
        dataShareHelper->Release();
        SendCustomizedToneEvent(false, toneAttrs, fileSize, mimeType, ERROR);
        return ERROR;
    }
    while ((ringtoneAsset != nullptr) &&
        (SOURCE_TYPE_CUSTOMISED != ringtoneAsset->GetSourceType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        SetToneAttrs(toneAttrs, ringtoneAsset);
        mimeType = ringtoneAsset->GetMimeType();
        DataShare::DataSharePredicates deletePredicates;
        deletePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
        deletePredicates.SetWhereArgs({to_string(ringtoneAsset->GetId())});
        changedRows = dataShareHelper->Delete(RINGTONEURI, deletePredicates);
    } else {
        MEDIA_LOGE("DoRemove: the ringtone is not customized!");
    }
    if (results != nullptr) results->Close();
    dataShareHelper->Release();
    SendCustomizedToneEvent(false, toneAttrs, fileSize, mimeType, SUCCESS);
    return changedRows;
}

void SystemSoundManagerImpl::SetToneAttrs(std::shared_ptr<ToneAttrs> &toneAttrs,
    const unique_ptr<RingtoneAsset> &ringtoneAsset)
{
    int32_t toneType = ringtoneAsset->GetToneType();
    if (toneType == TONE_TYPE_RINGTONE) {
        toneAttrs->SetCategory(TONE_CATEGORY_RINGTONE);
    } else if (toneType == TONE_TYPE_NOTIFICATION) {
        toneAttrs->SetCategory(TONE_CATEGORY_NOTIFICATION);
    } else if (toneType == TONE_TYPE_ALARM) {
        toneAttrs->SetCategory(TONE_CATEGORY_ALARM);
    } else if (toneType == TONE_TYPE_CONTACTS) {
        toneAttrs->SetCategory(TONE_CATEGORY_CONTACTS);
    } else if (toneType == TONE_TYPE_APP_NOTIFICATION) {
        toneAttrs->SetCategory(TONE_CATEGORY_NOTIFICATION_APP);
    }
    if (ringtoneAsset->GetMediaType() == RINGTONE_MEDIA_TYPE_VIDEO) {
        toneAttrs->SetMediaType(ToneMediaType::MEDIA_TYPE_VID);
    } else {
        toneAttrs->SetMediaType(ToneMediaType::MEDIA_TYPE_AUD);
    }
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
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
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
        currentToneUri = GetSystemToneAttrs(databaseTool, systemToneType).GetUri();
    } else {
        MEDIA_LOGE("Invalid tone haptics type");
    }
    return currentToneUri;
}

int32_t SystemSoundManagerImpl::UpdateToneHapticsSettings(const DatabaseTool &databaseTool,
    const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
    MEDIA_LOGI("UpdateToneHapticsSettings: toneUri[%{public}s], mode[%{public}d], hapticsUri[%{public}s]",
        toneUri.c_str(), settings.mode, settings.hapticsUri.c_str());
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_MODE, hapticsTypeWhereArgsMap_[toneHapticsType].first);
    queryPredicates.And();
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE, hapticsTypeWhereArgsMap_[toneHapticsType].second);

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_TONE_FILE, toneUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_FILE, settings.hapticsUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_RING_MODE, to_string(hapticsModeMap_[settings.mode]));
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_MODE, to_string(VIBRATE_TYPE_STANDARD));

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_SIMCARD_SETTING +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = SIMCARD_SETTING_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    int32_t result = databaseTool.dataShareHelper->Update(queryUri, queryPredicates, valuesBucket);
    if (result > 0) {
        return SUCCESS;
    } else {
        MEDIA_LOGE("UpdateToneHapticsSettings: update haptics settings fail");
    }
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_MODE, to_string(hapticsTypeWhereArgsMap_[toneHapticsType].first));
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE,
        to_string(hapticsTypeWhereArgsMap_[toneHapticsType].second));
    result = databaseTool.dataShareHelper->Insert(queryUri, valuesBucket);
    if (result <= 0) {
        MEDIA_LOGE("UpdateToneHapticsSettings: insert haptics settings fail");
    }
    return result > 0 ? SUCCESS : IO_ERROR;
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
    auto results = make_unique<RingtoneFetchResult<SimcardSettingAsset>>(move(resultSet));
    unique_ptr<SimcardSettingAsset> simcardSettingAsset = results->GetFirstObject();
    return simcardSettingAsset;
}

std::string SystemSoundManagerImpl::GetToneSyncedHapticsUri(
    const DatabaseTool &databaseTool, const std::string &toneUri)
{
    std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
    int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, databaseTool, toneHapticsAttrs);
    if (result == SUCCESS && toneHapticsAttrs) {
        return toneHapticsAttrs->GetUri();
    }
    return "";
}

std::string SystemSoundManagerImpl::GetDefaultNonSyncedHapticsUri(
    const DatabaseTool &databaseTool, ToneHapticsType toneHapticsType)
{
    MEDIA_LOGD("GetDefaultNonSyncedHapticsUri: toneHapticsType %{public}d", toneHapticsType);
    auto toneHapticsItem = defaultToneHapticsUriMap_.find(toneHapticsType);
    if (toneHapticsItem == defaultToneHapticsUriMap_.end()) {
        MEDIA_LOGE("GetDefaultNonSyncedHapticsUri: get type %{public}d defaultTone haptics fail", toneHapticsType);
        return "";
    }

    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("Create dataShare failed, datashare or ringtone library error");
        return "";
    }

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME, toneHapticsItem->second);
    queryPredicatesByUri.And();
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, VIBRATE_TYPE_STANDARD);

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = VIBRATE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSetByUri = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
        &businessError);
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
    const DatabaseTool &databaseTool, const std::string &currentToneUri,
    ToneHapticsType toneHapticsType, ToneHapticsSettings &settings)
{
    settings.hapticsUri = GetToneSyncedHapticsUri(databaseTool, currentToneUri);
    if (!settings.hapticsUri.empty()) {
        settings.mode = ToneHapticsMode::SYNC;
        return SUCCESS;
    }
    settings.hapticsUri = GetDefaultNonSyncedHapticsUri(databaseTool, toneHapticsType);
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

    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};

    string currentToneUri = GetCurrentToneUri(databaseTool, toneHapticsType);

    int32_t result = GetToneHapticsSettings(databaseTool, currentToneUri, toneHapticsType, settings);
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
    if (simcardSettingAsset == nullptr || simcardSettingAsset->GetToneFile().empty()) {
        result = GetDefaultToneHapticsSettings(databaseTool, toneUri, toneHapticsType, settings);
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
        result = GetDefaultToneHapticsSettings(databaseTool, toneUri, toneHapticsType, settings);
    }
    if (result == SUCCESS) {
        MEDIA_LOGI("GetDefaultToneHapticsSettings: get defaultTone haptics settings success");
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

    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    string currentToneUri = GetCurrentToneUri(context, toneHapticsType);

    int32_t res = SetToneHapticsSettings(databaseTool, currentToneUri, toneHapticsType, settings);
    dataShareHelper->Release();
    return res;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::SetToneHapticsSettings(const DatabaseTool &databaseTool,
    const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    std::lock_guard<std::mutex> lock(toneHapticsMutex_);
    MEDIA_LOGI("SetToneHapticsSettings: toneUri %{public}s type %{public}d hapticsUri %{public}s mode %{public}d",
        toneUri.c_str(), toneHapticsType, settings.hapticsUri.c_str(), settings.mode);
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr ||
        toneUri.empty() || !IsToneHapticsTypeValid(toneHapticsType)) {
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

        std::string ringtoneLibraryUri = "";
        if (databaseTool.isProxy) {
            ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
                "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
        } else {
            ringtoneLibraryUri = VIBRATE_PATH_URI;
        }
        Uri queryUri(ringtoneLibraryUri);
        auto resultSetByUri = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByUri,
            VIBRATE_TABLE_COLUMNS, &businessError);
        auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
        unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
        CHECK_AND_RETURN_RET_LOG(vibrateAssetByUri != nullptr, OPERATION_ERROR,
            "SetToneHapticsSettings: vibration of uri is not in the ringtone library!");
    } else if (settings.mode == ToneHapticsMode::SYNC) {
        std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
        int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, databaseTool, toneHapticsAttrs);
        if (result != SUCCESS) {
            return result;
        }
        updateSettings.hapticsUri = toneHapticsAttrs->GetUri();
    }

    int32_t res = UpdateToneHapticsSettings(databaseTool, toneUri, toneHapticsType, updateSettings);
    if (res != SUCCESS) {
        MEDIA_LOGE("SetToneHapticsSettings: set tone haptics settings fail!");
    }
    return res;
#endif
    return UNSUPPORTED_ERROR;
}

DataShare::DataSharePredicates SystemSoundManagerImpl::CreateVibrationListQueryPredicates(bool isSynced)
{
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
    return queryPredicates;
}

int32_t SystemSoundManagerImpl::GetToneHapticsList(const std::shared_ptr<AbilityRuntime::Context> &context,
    bool isSynced, std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray)
{
#ifdef SUPPORT_VIBRATOR
    MEDIA_LOGI("GetToneHapticsList: get vibration list, type : %{public}s.", isSynced ? "sync" : "non sync");
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates = CreateVibrationListQueryPredicates(isSynced);
    std::string queryUri = isProxy ? RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES + "&user=" +
        std::to_string(SystemSoundManagerUtils::GetCurrentUserId()) : VIBRATE_PATH_URI;
    Uri QUERYURI(queryUri);
    auto resultSet = dataShareHelper->Query(QUERYURI, queryPredicates, VIBRATE_TABLE_COLUMNS, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, QUERY_FAILED, "query failed.");
    auto results = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSet));
    toneHapticsAttrsArray.clear();
    unique_ptr<VibrateAsset> vibrateAsset = results->GetFirstObject();
    std::string gentleTitle;
    std::string gentleName;
    std::string gentleUri;
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    if (vibrateAsset == nullptr) {
        MEDIA_LOGE("GetToneHapticsList: get %{public}s vibration list fail!", isSynced ? "sync" : "non sync");
    } else {
        while (vibrateAsset != nullptr) {
            int32_t result = GetGentleHapticsAttr(databaseTool,
                vibrateAsset->GetPath(), gentleTitle, gentleName, gentleUri);
            if (result != 0) {
                MEDIA_LOGW("GetHapticsAttrsSyncedWithTone: get gentle haptics attrs fail");
            }
            auto toneHapticsAttrs = std::make_shared<ToneHapticsAttrs>(vibrateAsset->GetTitle(),
                vibrateAsset->GetDisplayName(), vibrateAsset->GetPath(), gentleTitle, gentleName, gentleUri);
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
    const DatabaseTool &databaseTool, const std::string &toneUri)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr || toneUri.empty()) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: param fail");
        return nullptr;
    }
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, toneUri);

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] inexistence in the ringtone library!", toneUri.c_str());
        return nullptr;
    }
    if (ringtoneAsset->GetSourceType() != SOURCE_TYPE_PRESET) {
        MEDIA_LOGE("IsPresetRingtone: toneUri[%{public}s] is not system prefabrication!", toneUri.c_str());
        return nullptr;
    }
    if (results != nullptr) results->Close();
    return ringtoneAsset;
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
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    int32_t result = GetHapticsAttrsSyncedWithTone(toneUri, databaseTool, toneHapticsAttrs);
    dataShareHelper->Release();
    return result;
#endif
    return UNSUPPORTED_ERROR;
}

DataShare::DataSharePredicates SystemSoundManagerImpl::CreateVibrateQueryPredicates(
    const std::string &displayName, int32_t vibrateType)
{
    DataShare::DataSharePredicates vibrateQueryPredicates;
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME, ConvertToHapticsFileName(displayName));
    vibrateQueryPredicates.And();
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, vibrateType);
    vibrateQueryPredicates.And();
    vibrateQueryPredicates.EqualTo(VIBRATE_COLUMN_PLAY_MODE, VIBRATE_PLAYMODE_SYNC);
    return vibrateQueryPredicates;
}
    
int32_t SystemSoundManagerImpl::GetHapticsAttrsSyncedWithTone(const std::string &toneUri,
    const DatabaseTool &databaseTool, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs)
{
#ifdef SUPPORT_VIBRATOR
    MEDIA_LOGI("GetHapticsAttrsSyncedWithTone: get %{public}s sync vibration.", toneUri.c_str());
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr || toneUri.empty()) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: param fail");
        return IO_ERROR;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = IsPresetRingtone(databaseTool, toneUri);
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not presetRingtone!", toneUri.c_str());
        return OPERATION_ERROR;
    }
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates vibrateQueryPredicates = CreateVibrateQueryPredicates(
        ringtoneAsset->GetDisplayName(), GetStandardVibrateType(ringtoneAsset->GetToneType()));
    
    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = VIBRATE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto vibrateResultSet = databaseTool.dataShareHelper->Query(queryUri, vibrateQueryPredicates,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto vibrateResults = make_unique<RingtoneFetchResult<VibrateAsset>>(move(vibrateResultSet));

    unique_ptr<VibrateAsset> vibrateAsset = vibrateResults->GetFirstObject();
    if (vibrateAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not sync vibration!", toneUri.c_str());
        return IO_ERROR;
    }
    std::string gentleTitle;
    std::string gentleName;
    std::string gentleUri;
    int32_t result = GetGentleHapticsAttr(databaseTool, vibrateAsset->GetPath(), gentleTitle, gentleName, gentleUri);
    if (result != 0) {
        MEDIA_LOGW("GetHapticsAttrsSyncedWithTone: get gentle haptics attrs fail");
    }
    toneHapticsAttrs = std::make_shared<ToneHapticsAttrs>(vibrateAsset->GetTitle(), vibrateAsset->GetDisplayName(),
        vibrateAsset->GetPath(), gentleTitle, gentleName, gentleUri);
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
    MEDIA_LOGI("GetHapticsUriByStyle: getHapticsUriByStyle is proxy = %{public}d, the vibrateFilesUri is %{public}s",
        databaseTool.isProxy, vibrateFilesUri.c_str());
    std::string hapticsUri = GetHapticsUriByStyle(databaseTool, standardHapticsUri, hapticsStyle, vibrateFilesUri);
    return hapticsUri;
}

std::string SystemSoundManagerImpl::GetHapticsUriByStyle(const DatabaseTool &databaseTool,
    const std::string &standardHapticsUri, HapticsStyle hapticsStyle, const std::string &vibrateFilesUri)
{
    Uri queryUri(vibrateFilesUri);
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, standardHapticsUri);
    auto resultSetByUri = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByUri,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, "", "query failed, ringtone library error.");
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByUri != nullptr, "", "vibrateAssetByUri is nullptr.");
    int vibrateType = 0;
    bool getResult = GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(), hapticsStyle, vibrateType);
    if (resultsByUri != nullptr) resultsByUri->Close();
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
    CHECK_AND_RETURN_RET_LOG(resultsByDisplayName != nullptr, "", "query failed, ringtone library error.");
    unique_ptr<VibrateAsset> vibrateAssetByDisplayName = resultsByDisplayName->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByDisplayName != nullptr, "", "vibrateAssetByDisplayName is nullptr.");

    std::string hapticsUri = vibrateAssetByDisplayName->GetPath();
    if (resultsByDisplayName != nullptr) resultsByDisplayName->Close();
    MEDIA_LOGI("get style vibration %{public}s!", hapticsUri.c_str());
    return hapticsUri;
}

int32_t SystemSoundManagerImpl::GetGentleHapticsAttr(const DatabaseTool &databaseTool,
    const std::string &standardHapticsUri, std::string &hapticsTitle,
    std::string &hapticsFileName, std::string &hapticsUri)
{
#ifdef SUPPORT_VIBRATOR
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        MEDIA_LOGE("The database tool is not ready!");
        return IO_ERROR;
    }
    CHECK_AND_RETURN_RET_LOG(!standardHapticsUri.empty(), IO_ERROR, "The standardHapticsUri is empty!");
    std::string vibrateFilesUri = databaseTool.isProxy ? (RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES +
        "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId())) : VIBRATE_PATH_URI;
    Uri queryUri(vibrateFilesUri);
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, standardHapticsUri);
    auto resultSetByUri = databaseTool.dataShareHelper->Query(queryUri, queryPredicatesByUri,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    CHECK_AND_RETURN_RET_LOG(resultsByUri != nullptr, IO_ERROR, "query failed, ringtone library error.");
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByUri != nullptr, OPERATION_ERROR, "vibrateAssetByUri is nullptr.");
    int vibrateType = 0;
    bool getResult = GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(),
    HapticsStyle::HAPTICS_STYLE_GENTLE, vibrateType);
    if (resultsByUri != nullptr) resultsByUri->Close();
    if (!getResult) {
        if (resultsByUri != nullptr) resultsByUri->Close();
        return IO_ERROR;
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
    CHECK_AND_RETURN_RET_LOG(resultsByDisplayName != nullptr, IO_ERROR, "query failed, ringtone library error.");
    unique_ptr<VibrateAsset> vibrateAssetByDisplayName = resultsByDisplayName->GetFirstObject();
    CHECK_AND_RETURN_RET_LOG(vibrateAssetByDisplayName != nullptr, OPERATION_ERROR, "vibrateAssetByDisplayName null.");
    hapticsTitle = vibrateAssetByDisplayName->GetTitle();
    hapticsFileName = vibrateAssetByDisplayName->GetDisplayName();
    hapticsUri = vibrateAssetByDisplayName->GetPath();
    if (resultsByDisplayName != nullptr) resultsByDisplayName->Close();
    MEDIA_LOGI("GetGentleHapticsAttr: title=%{public}s, name=%{public}s, uri=%{public}s",
        hapticsTitle.c_str(), hapticsFileName.c_str(), hapticsUri.c_str());
#endif
    return SUCCESS;
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
        SendPlaybackFailedEvent(INVALID_DATASHARE);
        return "";
    }
    std::string uri = RingtoneCheckUtils::GetCustomRingtoneCurrentPath(audioUri);
    if (SystemSoundManagerUtils::VerifyCustomPath(uri)) {
        MEDIA_LOGI("The audio uri is custom path.");
        return OpenCustomAudioUri(uri);
    }
    std::string newAudioUri = uri;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    vector<string> columns = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, uri);

    std::string ringtoneLibraryUri = "";
    if (databaseTool.isProxy) {
        ringtoneLibraryUri = RINGTONE_LIBRARY_PROXY_DATA_URI_TONE_FILES +
            "&user=" + std::to_string(SystemSoundManagerUtils::GetCurrentUserId());
    } else {
        ringtoneLibraryUri = RINGTONE_PATH_URI;
    }
    Uri queryUri(ringtoneLibraryUri);
    auto resultSet = databaseTool.dataShareHelper->Query(queryUri, queryPredicates, columns, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        SendPlaybackFailedEvent(QUERY_FAILED);
        MEDIA_LOGE("query failed, ringtone library error.");
        return newAudioUri;
    }
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("The ringtoneAsset is nullptr! audioUri : %{public}s, uri : %{public}s, isProxy : %{public}d",
            audioUri.c_str(), uri.c_str(), databaseTool.isProxy);
        return newAudioUri;
    }
    int32_t audioId = ringtoneAsset->GetId();
    newAudioUri = OpenAudioFile(databaseTool, uri, audioId);
    if (results != nullptr) {
        results->Close();
    }
    return newAudioUri;
}

std::string SystemSoundManagerImpl::OpenAudioFile(const DatabaseTool &databaseTool,
    const std::string &uri, int32_t audioId)
{
    std::string newAudioUri = uri;
    int32_t fd  = 0;
    if (databaseTool.isProxy) {
        std::string absFilePath;
        PathToRealPath(uri, absFilePath);
        fd = open(absFilePath.c_str(), O_RDONLY);
    } else {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(audioId);
        Uri ofUri(uriStr);
        fd = databaseTool.dataShareHelper->OpenFile(ofUri, "r");
    }

    if (fd > 0) {
        newAudioUri = FDHEAD + to_string(fd);
    } else {
        SendPlaybackFailedEvent(OPEN_FAILED);
        MEDIA_LOGE("The audioUri open failed!");
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
    if (dataShareHelper == nullptr) {
        SendPlaybackFailedEvent(INVALID_DATASHARE);
        MEDIA_LOGE("Invalid dataShare.");
        return newAudioUri;
    }
    auto resultSet = dataShareHelper->Query(ringtonePathUri, queryPredicates, columns, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    if (results == nullptr) {
        SendPlaybackFailedEvent(QUERY_FAILED);
        MEDIA_LOGE("query failed, ringtone library error.");
        return newAudioUri;
    }
    CHECK_AND_RETURN_RET_LOG(results != nullptr, newAudioUri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    int32_t fd = 0;
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        MEDIA_LOGD("OpenCustomAudioUri: uri is %{public}s", uriStr.c_str());
        Uri ofUri(uriStr);
        fd = dataShareHelper->OpenFile(ofUri, "r");
        if (results != nullptr) results->Close();
    }
    if (fd > 0) {
        newAudioUri = FDHEAD + to_string(fd);
    } else {
        SendPlaybackFailedEvent(OPEN_FAILED);
    }
    MEDIA_LOGI("OpenCustomAudioUri: newAudioUri is %{public}s", newAudioUri.c_str());
    if (results != nullptr) {
        results->Close();
    }
    dataShareHelper->Release();
    return newAudioUri;
}

std::string SystemSoundManagerImpl::OpenHapticsUri(const DatabaseTool &databaseTool, const std::string &hapticsUri)
{
    if (!databaseTool.isInitialized || databaseTool.dataShareHelper == nullptr) {
        SendPlaybackFailedEvent(INVALID_DATASHARE);
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
    auto results = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSet));
    if (results == nullptr) {
        MEDIA_LOGE("query failed, ringtone library error.");
        SendPlaybackFailedEvent(QUERY_FAILED);
        return newHapticsUri;
    }
    unique_ptr<VibrateAsset> vibrateAssetByUri = results->GetFirstObject();
    if (vibrateAssetByUri == nullptr) {
        MEDIA_LOGE("The vibrateAssetByUri is nullptr!");
        SendPlaybackFailedEvent(QUERY_FAILED);
        return newHapticsUri;
    }
    int32_t hapticsId = vibrateAssetByUri->GetId();
    newHapticsUri = OpenHapticsFile(databaseTool, hapticsUri, hapticsId);
    if (results != nullptr) {
        results->Close();
    }
    return newHapticsUri;
}

std::string SystemSoundManagerImpl::OpenHapticsFile(
    const DatabaseTool &databaseTool, const std::string &hapticsUri, int32_t hapticsId)
{
    std::string newHapticsUri = hapticsUri;
    int32_t fd = 0;
    if (databaseTool.isProxy) {
        std::string absFilePath;
        PathToRealPath(hapticsUri, absFilePath);
        fd = open(absFilePath.c_str(), O_RDONLY);
    } else {
        string uriStr = VIBRATE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(hapticsId);
        MEDIA_LOGD("OpenHapticsUri: uri is %{public}s", uriStr.c_str());
        Uri ofUri(uriStr);
        fd = databaseTool.dataShareHelper->OpenFile(ofUri, "r");
    }

    if (fd > 0) {
        newHapticsUri = FDHEAD + to_string(fd);
    } else {
        SendPlaybackFailedEvent(OPEN_FAILED);
    }
    MEDIA_LOGI("OpenHapticsUri result: newHapticsUri is %{public}s", newHapticsUri.c_str());
    return newHapticsUri;
}

void SystemSoundManagerImpl::SendCustomizedToneEvent(bool flag, const std::shared_ptr<ToneAttrs> &toneAttrs,
    off_t fileSize, std::string mimeType, int result)
{
    auto now = std::chrono::system_clock::now();
    time_t rawtime = std::chrono::system_clock::to_time_t(now);
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::ModuleId::AUDIO, Media::MediaMonitor::EventId::ADD_REMOVE_CUSTOMIZED_TONE,
        Media::MediaMonitor::EventType::DURATION_AGGREGATION_EVENT);
    bean->Add("ADD_REMOVE_OPERATION", static_cast<int32_t>(flag));
    MEDIA_LOGI("SendCustomizedToneEvent: operation is %{public}d(0 delete; 1 add).", flag);
    bean->Add("APP_NAME", GetBundleName());
    MEDIA_LOGI("SendCustomizedToneEvent: app name is %{public}s", GetBundleName().c_str());
    bean->Add("FILE_SIZE", static_cast<uint64_t>(fileSize));
    MEDIA_LOGI("SendCustomizedToneEvent: fileSize is %{public}ld byte, max is 200M(209715200 byte)",
        static_cast<long>(fileSize));
    bean->Add("RINGTONE_CATEGORY", toneAttrs->GetCategory());
    MEDIA_LOGI("SendCustomizedToneEvent: category is %{public}d"
        "(1 ringtone; 4 message or notification; 8 alarm; 16 contact).", toneAttrs->GetCategory());
    bean->Add("MEDIA_TYPE", static_cast<int32_t>(toneAttrs->GetMediaType()));
    MEDIA_LOGI("SendCustomizedToneEvent: mediaType is %{public}d(0 audio; 1 video).",
        static_cast<int32_t>(toneAttrs->GetMediaType()));
    bean->Add("MIME_TYPE", mimeType);
    MEDIA_LOGI("SendCustomizedToneEvent: mimeType is %{public}s", mimeType.c_str());
    bean->Add("TIMESTAMP", static_cast<uint64_t>(rawtime));
    bean->Add("RESULT", static_cast<int32_t>(result));
    MEDIA_LOGI("SendCustomizedToneEvent: result is %{public}d(0 success; -1 error).", result);
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

std::vector<ToneInfo> SystemSoundManagerImpl::GetCurrentToneInfos()
{
    std::vector<ToneInfo> toneInfos = {};
    ToneAttrs toneAttrs = { "", "", "", CUSTOMISED, TONE_CATEGORY_INVALID };
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, isProxy, dataShareHelper);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, toneInfos,
        "Failed to CreateDataShareHelper! datashare or ringtone library error.");
    DatabaseTool databaseTool = {true, isProxy, dataShareHelper};
    toneAttrs = GetRingtoneAttrs(databaseTool, RINGTONE_TYPE_SIM_CARD_0);
    toneInfos.push_back({EXT_TYPE_RINGTONE_ONE, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    toneAttrs = GetRingtoneAttrs(databaseTool, RINGTONE_TYPE_SIM_CARD_1);
    toneInfos.push_back({EXT_TYPE_RINGTONE_TWO, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    toneAttrs = GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_SIM_CARD_0);
    toneInfos.push_back({EXT_TYPE_MESSAGETONE_ONE, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    toneAttrs = GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_SIM_CARD_1);
    toneInfos.push_back({EXT_TYPE_MESSAGETONE_TWO, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    toneAttrs = GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_NOTIFICATION);
    toneInfos.push_back({EXT_TYPE_NOTIFICATION, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    toneAttrs = GetAlarmToneAttrs(databaseTool);
    toneInfos.push_back({EXT_TYPE_ALARMTONE, toneAttrs.GetUri(), toneAttrs.GetTitle()});

    dataShareHelper->Release();
    MEDIA_LOGI("Finish to get tone infos!");
    return toneInfos;
}

void SystemSoundManagerImpl::SendPlaybackFailedEvent(const int32_t &errorCode)
{
    MEDIA_LOGI("Send playback failed event.");
    std::shared_ptr<Media::MediaMonitor::EventBean> bean = std::make_shared<Media::MediaMonitor::EventBean>(
        Media::MediaMonitor::ModuleId::AUDIO, Media::MediaMonitor::EventId::TONE_PLAYBACK_FAILED,
        Media::MediaMonitor::EventType::FAULT_EVENT);
    bean->Add("ERROR_CODE", errorCode);
    bean->Add("ERROR_REASON", SystemSoundManagerUtils::GetTonePlaybackErrorReason(errorCode));
    Media::MediaMonitor::MediaMonitorManager::GetInstance().WriteLogMsg(bean);
}
} // namesapce Media
} // namespace OHOS
