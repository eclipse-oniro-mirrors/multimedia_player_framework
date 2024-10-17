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

#include "config_policy_utils.h"
#include "file_ex.h"
#include "nlohmann/json.hpp"

#include "media_log.h"
#include "media_errors.h"
#include "ringtone_player_impl.h"
#include "vibrate_type.h"
#include "system_tone_player_impl.h"

using namespace std;
using namespace nlohmann;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::DataShare;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundManagerImpl"};
}

namespace OHOS {
namespace Media {
const std::string RING_TONE = "ring_tone";
const std::string SYSTEM_TONE = "system_tone";
const std::string DEFAULT_SYSTEM_SOUND_PATH = "resource/media/audio/";
const std::string DEFAULT_RINGTONE_URI_JSON = "ringtone_incall.json";
const std::string DEFAULT_RINGTONE_PATH = "ringtones/";
const std::string DEFAULT_SYSTEM_TONE_URI_JSON = "ringtone_sms-notification.json";
const std::string DEFAULT_SYSTEM_TONE_PATH = "notifications/";
const int STORAGE_MANAGER_MANAGER_ID = 5003;
const int UNSUPPORTED_ERROR = -5;
#ifdef SUPPORT_VIBRATOR
const int OPERATION_ERROR = -4;
#endif
const int IO_ERROR = -3;
const int TYPEERROR = -2;
const int ERROR = -1;
const int SUCCESS = 0;

std::shared_ptr<SystemSoundManager> SystemSoundManagerFactory::systemSoundManager_ = nullptr;
std::mutex SystemSoundManagerFactory::systemSoundManagerMutex_;
std::unordered_map<RingtoneType, RingToneType> ringtoneTypeMap_;
std::unordered_map<int32_t, ToneCustomizedType> sourceTypeMap_;
std::unordered_map<SystemToneType, int32_t> systemTypeMap_;
std::unordered_map<SystemToneType, ShotToneType> shotToneTypeMap_;
std::unordered_map<ToneHapticsMode, VibratePlayMode> hapticsModeMap_;
std::unordered_map<ToneHapticsType, std::pair<int32_t, int32_t>> hapticsTypeWhereArgsMap_;
std::unordered_map<int32_t, std::unordered_map<HapticsStyle, int32_t>> hapticsStyleMap_;
Uri RINGTONEURI(RINGTONE_PATH_URI);
Uri VIBRATEURI(VIBRATE_PATH_URI);
Uri SIMCARDSETTINGURI(SIMCARD_SETTING_PATH_URI);
vector<string> COLUMNS = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}, {RINGTONE_COLUMN_DISPLAY_NAME},
    {RINGTONE_COLUMN_TITLE}, {RINGTONE_COLUMN_TONE_TYPE}, {RINGTONE_COLUMN_SOURCE_TYPE},
    {RINGTONE_COLUMN_SHOT_TONE_TYPE}, {RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE},
    {RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE}, {RINGTONE_COLUMN_RING_TONE_TYPE},
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
    {RINGTONE_CONTAINER_TYPE_WAV}};

std::shared_ptr<SystemSoundManager> SystemSoundManagerFactory::CreateSystemSoundManager()
{
    std::lock_guard<std::mutex> lock(systemSoundManagerMutex_);
    if (systemSoundManager_ == nullptr) {
        systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    }
    CHECK_AND_RETURN_RET_LOG(systemSoundManager_ != nullptr, nullptr, "Failed to create sound manager object");
    return systemSoundManager_;
}

static shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_LOGE("Get system ability manager failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_LOGE("Get system ability:[%{public}d] failed.", systemAbilityId);
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, RINGTONE_URI);
}

SystemSoundManagerImpl::SystemSoundManagerImpl()
{
    InitDefaultUriMap();
    InitRingerMode();
    InitMap();
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
    hapticsModeMap_[NONE] = VIBRATE_PLAYMODE_NONE;
    hapticsModeMap_[SYNC] = VIBRATE_PLAYMODE_SYNC;
    hapticsModeMap_[NON_SYNC] = VIBRATE_PLAYMODE_CLASSIC;
    hapticsTypeWhereArgsMap_ = {
        {HAPTICS_RINGTONE_TYPE_SIM_CARD_0, {RING_TONE_TYPE_SIM_CARD_1, TONE_SETTING_TYPE_RINGTONE}},
        {HAPTICS_RINGTONE_TYPE_SIM_CARD_1, {RING_TONE_TYPE_SIM_CARD_2, TONE_SETTING_TYPE_RINGTONE}},
        {HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_0, {RING_TONE_TYPE_SIM_CARD_1, TONE_SETTING_TYPE_SHOT}},
        {HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_1, {RING_TONE_TYPE_SIM_CARD_2, TONE_SETTING_TYPE_SHOT}},
        {HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, {RING_TONE_TYPE_SIM_CARD_BOTH, TONE_SETTING_TYPE_NOTIFICATION}},
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
        case HAPTICS_RINGTONE_TYPE_SIM_CARD_0 :
        case HAPTICS_RINGTONE_TYPE_SIM_CARD_1 :
        case HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_0 :
        case HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_1 :
        case HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION :
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

int32_t SystemSoundManagerImpl::SetRingtoneUri(const shared_ptr<Context> &context, const string &uri,
    RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType), MSERR_INVALID_VAL, "Invalid ringtone type");

    MEDIA_LOGI("SetRingtoneUri: ringtoneType %{public}d, uri %{public}s", ringtoneType, uri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
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
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetRingtoneUriByType(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const std::string &type)
{
    std::string uri = "";
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, uri,
        "Invalid dataShare, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_RING_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_CUSTOMISED)});
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetRingtoneUri(const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType), "", "Invalid ringtone type");
    std::string ringtoneUri = "";
    MEDIA_LOGI("GetRingtoneUri: ringtoneType %{public}d", ringtoneType);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
        "Create dataShare failed, datashare or ringtone library error.");
    ringtoneUri = GetRingtoneUriByType(dataShareHelper, to_string(ringtoneTypeMap_[ringtoneType]));
    if (ringtoneUri.empty()) {
        ringtoneUri = GetRingtoneUriByType(dataShareHelper, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
    }
    if (ringtoneUri.empty()) {
        std::shared_ptr<ToneAttrs> ringtoneAttrs = GetDefaultRingtoneAttrs(context, ringtoneType);
        if (ringtoneAttrs != nullptr) {
            ringtoneUri = ringtoneAttrs ->GetUri();
        } else {
            MEDIA_LOGE("GetRingtoneUri: no ringtone in the ringtone library!");
        }
    }
    dataShareHelper->Release();
    if (!ringtoneUri.empty()) {
        MEDIA_LOGI("GetRingtoneUri: ringtoneUri %{public}s", ringtoneUri.c_str());
    }
    return ringtoneUri;
}

std::string SystemSoundManagerImpl::GetRingtoneTitle(const std::string &ringtoneUri)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::string ringtoneTitle = "";
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
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

int32_t SystemSoundManagerImpl::SetSystemToneUri(const shared_ptr<Context> &context, const string &uri,
    SystemToneType systemToneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType), MSERR_INVALID_VAL, "Invalid system tone type");

    MEDIA_LOGI("SetSystemToneUri: systemToneType %{public}d, uri %{public}s", systemToneType, uri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
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
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetShotToneUriByType(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const std::string &type)
{
    std::string uri = "";
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, uri,
        "Invalid dataShare, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_SHOT_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({type, to_string(SOURCE_TYPE_CUSTOMISED)});
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, uri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        uri = ringtoneAsset->GetPath();
    }
    resultSet == nullptr ? : resultSet->Close();
    return uri;
}

std::string SystemSoundManagerImpl::GetNotificationToneUriByType(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper)
{
    std::string uri = "";
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, uri,
        "Invalid dataShare, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.SetWhereClause(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE + " = ? AND " +
        RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE + " = ? ");
    queryPredicates.SetWhereArgs({to_string(NOTIFICATION_TONE_TYPE), to_string(SOURCE_TYPE_CUSTOMISED)});
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
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
    MEDIA_LOGI("GetSystemToneUri: systemToneType %{public}d", systemToneType);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, "",
        "Create dataShare failed, datashare or ringtone library error.");
    switch (systemToneType) {
        case SYSTEM_TONE_TYPE_SIM_CARD_0:
        case SYSTEM_TONE_TYPE_SIM_CARD_1:
            systemToneUri = GetShotToneUriByType(dataShareHelper, to_string(systemTypeMap_[systemToneType]));
            if (systemToneUri.empty()) {
                systemToneUri = GetShotToneUriByType(dataShareHelper, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
            }
            break;
        case SYSTEM_TONE_TYPE_NOTIFICATION:
            systemToneUri = GetNotificationToneUriByType(dataShareHelper);
            break;
        default:
            break;
    }
    if (systemToneUri.empty()) {
        std::shared_ptr<ToneAttrs> systemToneAttrs = GetDefaultSystemToneAttrs(context, systemToneType);
        if (systemToneAttrs != nullptr) {
            systemToneUri = systemToneAttrs ->GetUri();
        } else {
            MEDIA_LOGE("GetSystemToneUri: no systemtone in the ringtone library!");
        }
    }
    dataShareHelper->Release();
    if (!systemToneUri.empty()) {
        MEDIA_LOGI("GetSystemToneUri: systemToneUri %{public}s", systemToneUri.c_str());
    }
    return systemToneUri;
}

std::shared_ptr<ToneAttrs> SystemSoundManagerImpl::GetDefaultRingtoneAttrs(
    const shared_ptr<Context> &context, RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRingtoneTypeValid(ringtoneType),  nullptr, "Invalid ringtone type");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    ringtoneAttrs_ = nullptr;
    queryPredicates.EqualTo(RINGTONE_COLUMN_RING_TONE_TYPE, to_string(ringtoneTypeMap_[ringtoneType]));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "single sim card failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (TONE_TYPE_RINGTONE != ringtoneAsset->GetToneType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        ringtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_RINGTONE);
    } else {
        MEDIA_LOGE("GetDefaultRingtoneAttrs: no single card default ringtone in the ringtone library!");
    }
    DataShare::DataSharePredicates queryPredicatesBothCard;
    queryPredicatesBothCard.EqualTo(RINGTONE_COLUMN_RING_TONE_TYPE, to_string(RING_TONE_TYPE_SIM_CARD_BOTH));
    resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicatesBothCard, COLUMNS, &businessError);
    results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query both sim card failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetBothCard = results->GetFirstObject();
    while ((ringtoneAssetBothCard != nullptr) &&
        (TONE_TYPE_RINGTONE != ringtoneAssetBothCard->GetToneType())) {
        ringtoneAssetBothCard = results->GetNextObject();
    }
    if (ringtoneAssetBothCard != nullptr) {
        ringtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAssetBothCard->GetTitle(),
            ringtoneAssetBothCard->GetDisplayName(), ringtoneAssetBothCard->GetPath(),
            sourceTypeMap_[ringtoneAssetBothCard->GetSourceType()], TONE_CATEGORY_RINGTONE);
    } else {
        MEDIA_LOGE("GetDefaultRingtoneAttrs: no both card default ringtone in the ringtone library!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return ringtoneAttrs_;
}

std::vector<std::shared_ptr<ToneAttrs>> SystemSoundManagerImpl::GetRingtoneAttrList(
    const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    ringtoneAttrsArray_.clear();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ringtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_RINGTONE));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
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
    std::lock_guard<std::mutex> lock(uriMutex_);
    CHECK_AND_RETURN_RET_LOG(IsSystemToneTypeValid(systemToneType),  nullptr, "Invalid systemtone type");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr,
        "Create dataShare failed, datashare or ringtone library error.");
    std::string ringToneType = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE : RINGTONE_COLUMN_SHOT_TONE_TYPE;
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    int32_t valueOfRingToneType = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        NOTIFICATION_TONE_TYPE : SHOT_TONE_TYPE_SIM_CARD_BOTH;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    systemtoneAttrs_ = nullptr;
    queryPredicates.EqualTo(ringToneType, to_string(systemTypeMap_[systemToneType]));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query single systemtone failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && IsSystemToneType(ringtoneAsset, systemToneType)) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        systemtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], category);
    } else {
        MEDIA_LOGE("GetDefaultSystemToneAttrs: no single default systemtone in the ringtone library!");
    }
    DataShare::DataSharePredicates queryPredicatesBothCard;
    queryPredicatesBothCard.EqualTo(ringToneType, to_string(valueOfRingToneType));
    resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicatesBothCard, COLUMNS, &businessError);
    results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query both systemtone failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAssetBothCard = results->GetFirstObject();
    while ((ringtoneAssetBothCard != nullptr) && IsSystemToneType(ringtoneAssetBothCard, systemToneType)) {
        ringtoneAssetBothCard = results->GetNextObject();
    }
    if (ringtoneAssetBothCard != nullptr) {
        systemtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAssetBothCard->GetTitle(),
            ringtoneAssetBothCard->GetDisplayName(), ringtoneAssetBothCard->GetPath(),
            sourceTypeMap_[ringtoneAssetBothCard->GetSourceType()], category);
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
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, systemtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    int32_t category = systemToneType == SYSTEM_TONE_TYPE_NOTIFICATION ?
        TONE_CATEGORY_NOTIFICATION : TONE_CATEGORY_TEXT_MESSAGE;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_NOTIFICATION));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
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
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
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
        updatePredicates.SetWhereArgs({to_string(ringtoneAsset->GetId())});
        updateValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_TYPE, ALARM_TONE_TYPE);
        updateValuesBucket.Put(RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE, SOURCE_TYPE_CUSTOMISED);
        int32_t changedRows = dataShareHelper->Update(RINGTONEURI, updatePredicates, updateValuesBucket);
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        return changedRows > 0 ? SUCCESS : ERROR;
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
}

std::string SystemSoundManagerImpl::GetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context)
{
    int32_t count = 2;
    std::string alarmToneUri = "";
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmToneUri,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_ALARM_TONE_TYPE, to_string(ALARM_TONE_TYPE));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, alarmToneUri, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (SOURCE_TYPE_CUSTOMISED !=
        ringtoneAsset->GetAlarmtoneSourceType()) && (results->GetCount() == count)) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        alarmToneUri = ringtoneAsset->GetPath();
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
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    alarmtoneAttrs_ = nullptr;
    queryPredicates.EqualTo(RINGTONE_COLUMN_ALARM_TONE_TYPE, to_string(ALARM_TONE_TYPE));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, nullptr, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    while ((ringtoneAsset != nullptr) && (TONE_TYPE_ALARM != ringtoneAsset->GetToneType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        alarmtoneAttrs_ = std::make_shared<ToneAttrs>(ringtoneAsset->GetTitle(),
            ringtoneAsset->GetDisplayName(), ringtoneAsset->GetPath(),
            sourceTypeMap_[ringtoneAsset->GetSourceType()], TONE_CATEGORY_ALARM);
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
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, alarmtoneAttrsArray_,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_TONE_TYPE, to_string(TONE_TYPE_ALARM));
    queryPredicates.GreaterThan(RINGTONE_COLUMN_MEDIA_TYPE, to_string(RINGTONE_MEDIA_TYPE_INVALID));
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
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
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSetByUri = dataShareHelper->Query(RINGTONEURI, queryPredicatesByUri, COLUMNS, &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSetByUri));
    unique_ptr<RingtoneAsset> ringtoneAssetByUri = resultsByUri->GetFirstObject();
    if (ringtoneAssetByUri == nullptr) {
        MEDIA_LOGE("OpenAlarmTone: tone of uri is not in the ringtone library!");
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
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        Uri ofUri(uriStr);
        int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        return fd > 0 ? fd : ERROR;
    }
    MEDIA_LOGE("OpenAlarmTone: tone of uri is not alarm!");
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return TYPEERROR;
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
    std::string fdHead = "fd://";
    std::string srcPath = externalUri;
    int32_t srcFd;
    if (srcPath.find(fdHead) != std::string::npos) {
        StrToInt(srcPath.substr(fdHead.size()), srcFd);
    } else {
        srcFd = open(srcPath.c_str(), O_RDONLY);
    }
    if (srcFd < 0) {
        MEDIA_LOGE("AddCustomizedTone: fd open error is %{public}s", strerror(errno));
        fdHead.clear();
        return fdHead;
    }
    return AddCustomizedToneByFd(context, toneAttrs, srcFd);
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFd(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd)
{
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
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR, "Invalid dataShareHelper.");
    int32_t category = -1;
    category = toneAttrs->GetCategory();
    GetCustomizedTone(toneAttrs);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(RINGTONE_COLUMN_DISPLAY_NAME, static_cast<string>(displayName_));
    valuesBucket.Put(RINGTONE_COLUMN_TITLE, static_cast<string>(toneAttrs->GetTitle()));
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
        default:
            break;
    }
    valuesBucket.Put(RINGTONE_COLUMN_DATA, static_cast<string>(toneAttrs->GetUri()));
    return dataShareHelper->Insert(RINGTONEURI, valuesBucket);
}

std::string SystemSoundManagerImpl::AddCustomizedToneByFdAndOffset(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<ToneAttrs> &toneAttrs,
    const int32_t &fd, const int32_t &offset, const int32_t &length)
{
    std::string result = "TYPEERROR";
    if (toneAttrs->GetCustomizedType() != CUSTOMISED) {
        MEDIA_LOGE("AddCustomizedTone: the ringtone is not customized!");
        return result;
    }
    std::lock_guard<std::mutex> lock(uriMutex_);
    int32_t srcFd = fd;
    off_t lseekResult = lseek(srcFd, offset, SEEK_SET);
    if (srcFd < 0 || lseekResult == -1) {
        MEDIA_LOGE("fd is error");
        result.clear();
        return result;
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (dataShareHelper == nullptr) {
        MEDIA_LOGE("Create dataShare failed, datashare or ringtone library error.");
        result.clear();
        return result;
    }
    int32_t sert = AddCustomizedTone(dataShareHelper, toneAttrs);
    std::string dstPath = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(sert);
    Uri ofUri(dstPath);
    int32_t dstFd = dataShareHelper->OpenFile(ofUri, "rw");
    if (dstFd < 0) {
        MEDIA_LOGE("AddCustomizedTone: open error is %{public}s", strerror(errno));
        result.clear();
        dataShareHelper->Release();
        return result;
    }
    char buffer[4096];
    int32_t len = length;
    memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    int32_t bytesRead = 0;
    while ((bytesRead = read(srcFd, buffer, sizeof(buffer))) > 0 && len > 0) {
        int32_t bytesWritten = write(dstFd, buffer, (bytesRead < len) ? bytesRead : len);
        memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
        len -= bytesWritten;
        if (bytesWritten == -1) {
            break;
        }
    }
    close(srcFd);
    close(dstFd);
    dataShareHelper->Release();
    return toneAttrs->GetUri();
}

int32_t SystemSoundManagerImpl::RemoveCustomizedTone(
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri)
{
    std::lock_guard<std::mutex> lock(uriMutex_);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, ERROR,
        "Create dataShare failed, datashare or ringtone library error.");
    int32_t changedRows = TYPEERROR;
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, uri);
    auto resultSet = dataShareHelper->Query(RINGTONEURI, queryPredicates, COLUMNS, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    CHECK_AND_RETURN_RET_LOG(results != nullptr, ERROR, "query failed, ringtone library error.");
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("RemoveCustomizedTone: tone of uri is not in the ringtone library!");
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
        return ERROR;
    }
    while ((ringtoneAsset != nullptr) &&
        (SOURCE_TYPE_CUSTOMISED != ringtoneAsset->GetSourceType())) {
        ringtoneAsset = results->GetNextObject();
    }
    if (ringtoneAsset != nullptr) {
        DataShare::DataSharePredicates deletePredicates;
        deletePredicates.SetWhereClause(RINGTONE_COLUMN_TONE_ID + " = ? ");
        deletePredicates.SetWhereArgs({to_string(ringtoneAsset->GetId())});
        changedRows = dataShareHelper->Delete(RINGTONEURI, deletePredicates);
    } else {
        MEDIA_LOGE("RemoveCustomizedTone: the ringtone is not customized!");
    }
    resultSet == nullptr ? : resultSet->Close();
    dataShareHelper->Release();
    return changedRows;
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
        case HAPTICS_RINGTONE_TYPE_SIM_CARD_0:
            ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
            return true;
        case HAPTICS_RINGTONE_TYPE_SIM_CARD_1:
            ringtoneType = RINGTONE_TYPE_SIM_CARD_1;
            return true;
        default:
            return false;
    }
}

bool SystemSoundManagerImpl::ConvertToSystemToneType(ToneHapticsType toneHapticsType, SystemToneType &systemToneType)
{
    switch (toneHapticsType) {
        case HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_0:
            systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
            return true;
        case HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_1:
            systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_1;
            return true;
        case HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION:
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
    string currentToneUri = "";
    RingtoneType ringtoneType;
    SystemToneType systemToneType;
    if (ConvertToRingtoneType(toneHapticsType, ringtoneType)) {
        currentToneUri = GetRingtoneUri(context, ringtoneType);
    } else if (ConvertToSystemToneType(toneHapticsType, systemToneType)) {
        currentToneUri = GetSystemToneUri(context, systemToneType);
    } else {
        MEDIA_LOGE("Invalid tone haptics type");
    }
    return currentToneUri;
}


int32_t SystemSoundManagerImpl::UpdateToneHapticsSettings(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
    MEDIA_LOGI("UpdateToneHapticsSettings: update haptics settings, toneUri[%{public}s] type[%{public}d],"
        "mode[%{public}d] hapticsUri[%{public}s]", toneUri.c_str(), toneHapticsType, settings.mode,
        settings.hapticsUri.c_str());
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_MODE, hapticsTypeWhereArgsMap_[toneHapticsType].first);
    queryPredicates.And();
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE, hapticsTypeWhereArgsMap_[toneHapticsType].second);

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_TONE_FILE, toneUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_FILE, settings.hapticsUri);
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_RING_MODE, to_string(hapticsModeMap_[settings.mode]));
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_VIBRATE_MODE, to_string(VIBRATE_TYPE_STANDARD));

    int32_t result = dataShareHelper->Update(SIMCARDSETTINGURI, queryPredicates, valuesBucket);
    if (result > 0) {
        return SUCCESS;
    } else {
        MEDIA_LOGE("UpdateToneHapticsSettings: update haptics settings fail");
    }

    valuesBucket.Put(SIMCARD_SETTING_COLUMN_MODE, to_string(hapticsTypeWhereArgsMap_[toneHapticsType].first));
    valuesBucket.Put(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE,
        to_string(hapticsTypeWhereArgsMap_[toneHapticsType].second));
    result = dataShareHelper->Insert(SIMCARDSETTINGURI, valuesBucket);
    if (result <= 0) {
        MEDIA_LOGE("UpdateToneHapticsSettings: insert haptics settings fail");
    }
    return result > 0 ? SUCCESS : IO_ERROR;
}

std::unique_ptr<SimcardSettingAsset> SystemSoundManagerImpl::GetSimcardSettingAssetByToneHapticsType(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, ToneHapticsType toneHapticsType)
{
    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_MODE, hapticsTypeWhereArgsMap_[toneHapticsType].first);
    queryPredicates.And();
    queryPredicates.EqualTo(SIMCARD_SETTING_COLUMN_RINGTONE_TYPE, hapticsTypeWhereArgsMap_[toneHapticsType].second);
    auto resultSet = dataShareHelper->Query(SIMCARDSETTINGURI, queryPredicates, SETTING_TABLE_COLUMNS,
        &businessError);
    auto results = make_unique<RingtoneFetchResult<SimcardSettingAsset>>(move(resultSet));
    unique_ptr<SimcardSettingAsset> simcardSettingAsset = results->GetFirstObject();
    return simcardSettingAsset;
}

std::string SystemSoundManagerImpl::GetToneSyncedHapticsUri(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &toneUri)
{
    std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
    int32_t result = GetHapticsAttrsSyncedWithTone(context, toneUri, toneHapticsAttrs);
    if (result == SUCCESS && toneHapticsAttrs) {
        return toneHapticsAttrs->GetUri();
    }
    return "";
}

std::string SystemSoundManagerImpl::GetFirstNonSyncedHapticsUri(
    const std::shared_ptr<AbilityRuntime::Context> &context)
{
    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = GetToneHapticsList(context, false, toneHapticsAttrsArray);
    if (result == SUCCESS && !toneHapticsAttrsArray.empty()) {
        return toneHapticsAttrsArray[0]->GetUri();
    }
    return "";
}

int32_t SystemSoundManagerImpl::GetDefaultToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
    const std::string &currentToneUri, ToneHapticsType toneHapticsType, ToneHapticsSettings &settings)
{
    settings.hapticsUri = GetToneSyncedHapticsUri(context, currentToneUri);
    if (!settings.hapticsUri.empty()) {
        settings.mode = ToneHapticsMode::SYNC;
        return SUCCESS;
    }
    settings.hapticsUri = GetFirstNonSyncedHapticsUri(context);
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
    MEDIA_LOGI("GetToneHapticsSettings: toneHapticsType %{public}d", toneHapticsType);
    string currentToneUri = GetCurrentToneUri(context, toneHapticsType);
    CHECK_AND_RETURN_RET_LOG(!currentToneUri.empty(), IO_ERROR, "GetToneHapticsSettings: get current tone fail!");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    int32_t result = SUCCESS;
    auto simcardSettingAsset = GetSimcardSettingAssetByToneHapticsType(dataShareHelper, toneHapticsType);
    if (simcardSettingAsset == nullptr || simcardSettingAsset->GetToneFile().empty()) {
        result = GetDefaultToneHapticsSettings(context, currentToneUri, toneHapticsType, settings);
        if (result != SUCCESS) {
            MEDIA_LOGE("GetToneHapticsSettings: get defaultTone haptics settings fail");
        }
        dataShareHelper->Release();
        return result;
    }

    if (currentToneUri == simcardSettingAsset->GetToneFile()) {
        settings.hapticsUri = simcardSettingAsset->GetVibrateFile();
        settings.mode = IntToToneHapticsMode(simcardSettingAsset->GetRingMode());
        dataShareHelper->Release();
        return SUCCESS;
    }

    if (simcardSettingAsset->GetRingMode() != VIBRATE_PLAYMODE_SYNC) {
        settings.hapticsUri = simcardSettingAsset->GetVibrateFile();
        settings.mode = IntToToneHapticsMode(simcardSettingAsset->GetRingMode());
    } else {
        result = GetDefaultToneHapticsSettings(context, currentToneUri, toneHapticsType, settings);
    }
    if (result == SUCCESS) {
        result = UpdateToneHapticsSettings(dataShareHelper, currentToneUri, toneHapticsType, settings);
    } else {
        MEDIA_LOGE("GetToneHapticsSettings: get defaultTone haptics settings fail");
    }

    dataShareHelper->Release();
    return result;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::SetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
    ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings)
{
#ifdef SUPPORT_VIBRATOR
    CHECK_AND_RETURN_RET_LOG(IsToneHapticsTypeValid(toneHapticsType), OPERATION_ERROR, "Invalid tone haptics type");
    MEDIA_LOGI("SetToneHapticsSettings: toneHapticsType %{public}d, hapticsUri %{public}s toneHapticsMode %{public}d",
        toneHapticsType, settings.hapticsUri.c_str(), settings.mode);
    string currentToneUri = GetCurrentToneUri(context, toneHapticsType);
    CHECK_AND_RETURN_RET_LOG(!currentToneUri.empty(), IO_ERROR, "SetToneHapticsSettings: get current tone fail!");
    string toneTitle = GetRingtoneTitle(currentToneUri);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    ToneHapticsSettings updateSettings = settings;
    if (updateSettings.mode == ToneHapticsMode::NON_SYNC) {
        DataShare::DatashareBusinessError businessError;
        DataShare::DataSharePredicates queryPredicatesByUri;
        queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, updateSettings.hapticsUri);
        queryPredicatesByUri.And();
        queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_PLAY_MODE, hapticsModeMap_[updateSettings.mode]);
        auto resultSetByUri = dataShareHelper->Query(VIBRATEURI, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
            &businessError);
        auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
        unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
        if (vibrateAssetByUri == nullptr) {
            MEDIA_LOGE("SetToneHapticsSettings: vibration of uri is not in the ringtone library!");
            dataShareHelper->Release();
            return OPERATION_ERROR;
        }
    } else if (settings.mode == ToneHapticsMode::SYNC) {
        std::shared_ptr<ToneHapticsAttrs> toneHapticsAttrs;
        int32_t result = GetHapticsAttrsSyncedWithTone(context, currentToneUri, toneHapticsAttrs);
        if (result != SUCCESS) {
            MEDIA_LOGE("SetToneHapticsSettings: current tone does not support sync vibration!");
            dataShareHelper->Release();
            return result;
        }
        updateSettings.hapticsUri = toneHapticsAttrs->GetUri();
    }

    int32_t res = UpdateToneHapticsSettings(dataShareHelper, currentToneUri, toneHapticsType, updateSettings);
    if (res != SUCCESS) {
        MEDIA_LOGE("SetToneHapticsSettings: set tone haptics settings fail!");
    }
    dataShareHelper->Release();
    return res;
#endif
    return UNSUPPORTED_ERROR;
}

int32_t SystemSoundManagerImpl::GetToneHapticsList(const std::shared_ptr<AbilityRuntime::Context> &context,
    bool isSynced, std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray)
{
#ifdef SUPPORT_VIBRATOR
    MEDIA_LOGI("GetToneHapticsList: get vibration list, type : %{public}s.", isSynced ? "sync" : "non sync");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
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
    auto resultSet = dataShareHelper->Query(VIBRATEURI, queryPredicates, VIBRATE_TABLE_COLUMNS, &businessError);
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
    MEDIA_LOGI("GetHapticsAttrsSyncedWithTone: get %{public}s sync vibration.", toneUri.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, IO_ERROR,
        "Create dataShare failed, datashare or ringtone library error.");

    unique_ptr<RingtoneAsset> ringtoneAsset = IsPresetRingtone(dataShareHelper, toneUri);
    if (ringtoneAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not presetRingtone!", toneUri.c_str());
        dataShareHelper->Release();
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
    auto vibrateResultSet = dataShareHelper->Query(VIBRATEURI, vibrateQueryPredicates, VIBRATE_TABLE_COLUMNS,
        &businessError);
    auto vibrateResults = make_unique<RingtoneFetchResult<VibrateAsset>>(move(vibrateResultSet));

    unique_ptr<VibrateAsset> vibrateAsset = vibrateResults->GetFirstObject();
    if (vibrateAsset == nullptr) {
        MEDIA_LOGE("GetHapticsAttrsSyncedWithTone: toneUri[%{public}s] is not sync vibration!", toneUri.c_str());
        dataShareHelper->Release();
        return IO_ERROR;
    }

    toneHapticsAttrs = std::make_shared<ToneHapticsAttrs>(vibrateAsset->GetTitle(), vibrateAsset->GetDisplayName(),
        vibrateAsset->GetPath());
    dataShareHelper->Release();
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
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
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
        hapticsStyle, hapticsStyle, vibrateType);
    return true;
}

std::string SystemSoundManagerImpl::GetHapticsUriByStyle(const std::string &standardHapticsUri,
    HapticsStyle hapticsStyle)
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, {},
        "Create dataShare failed, datashare or ringtone library error.");
    MEDIA_LOGI("GetHapticsUriByStyle: standardHapticsUri %{public}s, style %{public}d", standardHapticsUri.c_str(),
        hapticsStyle);

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicatesByUri;
    queryPredicatesByUri.EqualTo(VIBRATE_COLUMN_DATA, standardHapticsUri);
    auto resultSetByUri = dataShareHelper->Query(VIBRATEURI, queryPredicatesByUri, VIBRATE_TABLE_COLUMNS,
        &businessError);
    auto resultsByUri = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByUri));
    unique_ptr<VibrateAsset> vibrateAssetByUri = resultsByUri->GetFirstObject();
    if (vibrateAssetByUri == nullptr) {
        MEDIA_LOGE("GetHapticsUriByStyle: vibration of uri is not in the ringtone library!");
        return "";
    }
    int vibrateType = 0;
    if (!GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(), hapticsStyle, vibrateType)) {
        MEDIA_LOGE("GetHapticsUriByStyle: vibration of uri is not standard vibrate!");
        return "";
    }

    DataShare::DataSharePredicates queryPredicatesByDisplayName;
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_DISPLAY_NAME, vibrateAssetByUri->GetDisplayName());
    queryPredicatesByDisplayName.And();
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_PLAY_MODE, vibrateAssetByUri->GetPlayMode());
    queryPredicatesByDisplayName.And();
    queryPredicatesByDisplayName.EqualTo(VIBRATE_COLUMN_VIBRATE_TYPE, vibrateType);
    auto resultSetByDisplayName = dataShareHelper->Query(VIBRATEURI, queryPredicatesByDisplayName,
        VIBRATE_TABLE_COLUMNS, &businessError);
    auto resultsByDisplayName = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSetByDisplayName));
    unique_ptr<VibrateAsset> vibrateAssetByDisplayName = resultsByDisplayName->GetFirstObject();
    if (vibrateAssetByDisplayName == nullptr) {
        MEDIA_LOGE("GetHapticsUriByStyle: style %{public}d vibration is not in the ringtone library!", hapticsStyle);
        return "";
    }
    MEDIA_LOGI("GetHapticsUriByStyle: get style %{public}d vibration %{public}s!", hapticsStyle,
        vibrateAssetByDisplayName->GetPath().c_str());
    return vibrateAssetByDisplayName->GetPath();
}

// Ringer mode callback class symbols
RingerModeCallbackImpl::RingerModeCallbackImpl(SystemSoundManagerImpl &systemSoundManagerImpl)
    : sysSoundMgr_(systemSoundManagerImpl) {}

void RingerModeCallbackImpl::OnRingerModeUpdated(const AudioStandard::AudioRingerMode &ringerMode)
{
    ringerMode_ = ringerMode;
    int32_t result = sysSoundMgr_.SetRingerMode(ringerMode_);
    if (result == MSERR_OK && ringerMode_ == AudioStandard::AudioRingerMode::RINGER_MODE_SILENT) {
        SystemSoundVibrator::StopVibrator();
    }
}
} // namesapce AudioStandard
} // namespace OHOS
