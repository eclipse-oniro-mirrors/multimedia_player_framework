/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "os_account_manager.h"
#include "system_tone_player_impl.h"
#include "parameter.h"
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
const std::string RING_TONE = "ring_tone";
const std::string SYSTEM_TONE = "system_tone";
const std::string DEFAULT_SYSTEM_SOUND_PATH = "resource/media/audio/";
const std::string DEFAULT_RINGTONE_URI_JSON = "ringtone_incall.json";
const std::string DEFAULT_RINGTONE_PATH = "ringtones/";
const std::string DEFAULT_SYSTEM_TONE_URI_JSON = "ringtone_sms-notification.json";
const std::string DEFAULT_SYSTEM_TONE_PATH = "notifications/";
const int STORAGE_MANAGER_MANAGER_ID = 5003;
 
const int SUCCESS = 0;
 
constexpr int32_t MIN_USER_ACCOUNT = 100;
const std::string SETTING_COLUMN_KEYWORD = "KEYWORD";
const std::string SETTING_COLUMN_VALUE = "VALUE";
const std::string SETTING_URI_PROXY = "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string SETTING_USER_URI_PROXY = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string SETTING_USER_SECURE_URI_PROXY =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
 
int32_t SystemSoundManagerImpl::GetStringValue(const std::string &key,
    std::string &value, std::string tableType)
{
    auto helper = CreateDataShareHelperProxy(tableType);
    if (helper == nullptr) {
        MEDIA_LOGE("helper return nullptr");
        return MSERR_INVALID_VAL;
    }
    std::vector<std::string> columns = {SETTING_COLUMN_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(AssembleUri(key, tableType));
    auto resultSet = helper->Query(uri, predicates, columns);
    helper->Release();
    if (resultSet == nullptr) {
        MEDIA_LOGE("helper->Query return nullptr");
        return MSERR_INVALID_OPERATION;
    }
    int32_t count;
    resultSet->GetRowCount(count);
    if (count == 0) {
        MEDIA_LOGW("not found value, key=%{public}s, count=%{public}d", key.c_str(), count);
        resultSet->Close();
        return MSERR_INVALID_OPERATION;
    }
    int32_t index = 0;
    resultSet->GoToRow(index);
    int32_t ret = resultSet->GetString(index, value);
    if (ret != SUCCESS) {
        MEDIA_LOGW("resultSet->GetString return not ok, ret=%{public}d", ret);
        resultSet->Close();
        return MSERR_INVALID_VAL;
    }
    resultSet->Close();
    return MSERR_OK;
}

int32_t SystemSoundManagerImpl::UpdateStringValue(const std::string &key,
    std::string &value, std::string tableType)
{
    auto helper = CreateDataShareHelperProxy(tableType);
    if (helper == nullptr) {
        MEDIA_LOGE("helper return nullptr");
        return MSERR_INVALID_VAL;
    }
    DataShare::DataShareValueObject valueObj(value);
    DataShare::DataShareValuesBucket valueBucket;
    valueBucket.Put(SETTINGS_COLUMN_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_COLUMN_KEYWORD, key);
    int32_t ret = helper->Update(uri, predicates, valueBucket);
    if (ret <= 0) {
        TELEPHONY_LOGE("DataShareHelper update failed, retCode:%{public}d", ret);
        helper->Release();
        return TELEPHONY_ERROR;
    }
    helper->NotifyChange(uri);
    resultSet->Close();
    return MSERR_OK;
}
 
bool SystemSoundManagerImpl::CheckVibrateSwitchStatus()
{
    std::string key = "hw_vibrate_when_ringing";
    std::string valueStr;
    std::string tableType = "system";
    int32_t ret = GetStringValue(key, valueStr, tableType);
    if (ret != MSERR_OK) {
        return true; // default status is open
    }
    MEDIA_LOGI("vibrare switch value %{public}s", valueStr.c_str());
    return valueStr == "1"; // 1 for open, 0 for close
}
 
Uri SystemSoundManagerImpl::AssembleUri(const std::string &key, std::string tableType)
{
    int32_t currentuserId = SystemSoundManagerUtils::GetCurrentUserId();
    if (currentuserId < MIN_USER_ACCOUNT) {
        currentuserId = MIN_USER_ACCOUNT;
    }
    std::string settingSystemUrlProxy = "";
 
    // deal with multi useraccount table
    if (currentuserId > 0 && tableType == "system") {
        settingSystemUrlProxy = SETTING_USER_URI_PROXY + std::to_string(currentuserId) + "?Proxy=true";
        Uri uri(settingSystemUrlProxy + "&key=" + key);
        return uri;
    } else if (currentuserId > 0 && tableType == "secure") {
        settingSystemUrlProxy = SETTING_USER_SECURE_URI_PROXY + std::to_string(currentuserId) + "?Proxy=true";
        Uri uri(settingSystemUrlProxy + "&key=" + key);
        return uri;
    }
    Uri uri(SETTING_URI_PROXY + "&key=" + key);
    return uri;
}

std::shared_ptr<DataShare::DataShareHelper> SystemSoundManagerImpl::CreateDataShareHelperProxy(std::string
    tableType)
{
    int32_t currentuserId = SystemSoundManagerUtils::GetCurrentUserId();
    if (currentuserId < MIN_USER_ACCOUNT) {
        currentuserId = MIN_USER_ACCOUNT;
    }
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_LOGE("saManager return nullptr");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObj == nullptr) {
        MEDIA_LOGE("saManager->GetSystemAbility return nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareHelper> helper = nullptr;
    std::string SettingSystemUrlProxy = "";
    
    // deal with multi useraccount table
    if (currentuserId > 0 && tableType == "system") {
        SettingSystemUrlProxy =
            SETTING_USER_URI_PROXY + std::to_string(currentuserId) + "?Proxy=true";
        helper = DataShare::DataShareHelper::Creator(remoteObj, SettingSystemUrlProxy, SETTINGS_DATA_EXT_URI);
    } else if (currentuserId > 0 && tableType == "secure") {
        SettingSystemUrlProxy =
            SETTING_USER_SECURE_URI_PROXY + std::to_string(currentuserId) + "?Proxy=true";
        helper = DataShare::DataShareHelper::Creator(remoteObj, SettingSystemUrlProxy, SETTINGS_DATA_EXT_URI);
    } else {
        helper = DataShare::DataShareHelper::Creator(remoteObj, SETTING_URI_PROXY, SETTINGS_DATA_EXT_URI);
    }
    if (helper == nullptr) {
        MEDIA_LOGW("helper is nullptr, uri=%{public}s", SettingSystemUrlProxy.c_str());
        return nullptr;
    }
    return helper;
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