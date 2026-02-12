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

#ifndef SYSTEM_SOUND_MANAGER_IMPL_H
#define SYSTEM_SOUND_MANAGER_IMPL_H

#include <array>

#include "datashare_helper.h"
#include "data_ability_helper.h"
#include "ability_runtime/context/context.h"
#include "uri.h"
#include "want.h"
#include "audio_utils.h"
#include "access_token.h"
#include <iostream>
#include "system_ability_definition.h"
#include "ringtone_db_const.h"
#include "ringtone_type.h"
#include "ringtone_asset.h"
#include "simcard_setting_asset.h"
#include "vibrate_asset.h"
#include "ringtone_fetch_result.h"
#include "iservice_registry.h"
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#include "audio_system_manager.h"

#include "system_sound_manager.h"

namespace OHOS {
namespace Media {
class RingerModeCallbackImpl;

enum HapticsStyle {
    HAPTICS_STYLE_STANDARD = 1,
    HAPTICS_STYLE_GENTLE,
};

struct DatabaseTool {
    bool isInitialized = false;
    bool isProxy = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
};

class SystemSoundManagerImpl : public SystemSoundManager {
public:
    SystemSoundManagerImpl();
    ~SystemSoundManagerImpl();

    int32_t SetRingerMode(const AudioStandard::AudioRingerMode &ringerMode);
    AudioStandard::AudioRingerMode GetRingerMode() const;
    std::string GetDefaultRingtoneUri(RingtoneType ringtoneType);
    std::string GetDefaultSystemToneUri(SystemToneType systemToneType);

    // SystemSoundManager override
    int32_t SetRingtoneUri(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri,
        RingtoneType ringtoneType) override;
    std::string GetRingtoneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) override;
    ToneAttrs GetCurrentRingtoneAttribute(RingtoneType ringtoneType) override;
    std::shared_ptr<RingtonePlayer> GetRingtonePlayer(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) override;
    std::shared_ptr<RingtonePlayer> GetSpecificRingTonePlayer(const std::shared_ptr<AbilityRuntime::Context> &context,
        const RingtoneType ringtoneType, std::string &ringtoneUri) override;

    int32_t SetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri,
        SystemToneType systemToneType) override;
    std::string GetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemToneType systemToneType) override;
    std::shared_ptr<SystemTonePlayer> GetSystemTonePlayer(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemToneType systemToneType) override;

    std::shared_ptr<ToneAttrs> GetDefaultRingtoneAttrs(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) override;
    std::vector<std::shared_ptr<ToneAttrs>> GetRingtoneAttrList(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) override;
    std::shared_ptr<ToneAttrs> GetDefaultSystemToneAttrs(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemToneType systemToneType) override;
    std::vector<std::shared_ptr<ToneAttrs>> GetSystemToneAttrList(
        const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType) override;
    std::shared_ptr<ToneAttrs> GetDefaultAlarmToneAttrs(
        const std::shared_ptr<AbilityRuntime::Context> &context) override;
    std::vector<std::shared_ptr<ToneAttrs>> GetAlarmToneAttrList(
        const std::shared_ptr<AbilityRuntime::Context> &context) override;
    std::string GetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context) override;
    int32_t SetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri) override;
    int32_t OpenAlarmTone(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri) override;
    int32_t Close(const int32_t &fd) override;
    std::string AddCustomizedToneByExternalUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const std::string &externalUri) override;
    std::string AddCustomizedToneByFd(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd) override;
    std::string AddCustomizedToneByFdAndOffset(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, ParamsForAddCustomizedTone &paramsForAddCustomizedTone) override;
    int32_t RemoveCustomizedTone(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri) override;
    std::vector<std::pair<std::string, SystemSoundError>> RemoveCustomizedToneList(
        const std::vector<std::string> &uriList, SystemSoundError &errCode) override;
    int32_t GetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, ToneHapticsSettings &settings) override;
    int32_t SetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings) override;
    int32_t GetToneHapticsList(const std::shared_ptr<AbilityRuntime::Context> &context,
        bool isSynced, std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray) override;
    int32_t GetHapticsAttrsSyncedWithTone(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &toneUri, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs) override;
    int32_t OpenToneHaptics(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &hapticsUri) override;

    // other public functions
    std::string GetRingtoneTitle(const std::string &ringtoneUri);
    std::string GetRingtoneUri(const DatabaseTool &databaseTool, RingtoneType ringtoneType);
    ToneAttrs GetRingtoneAttrs(const DatabaseTool &databaseTool, RingtoneType ringtoneType);
    ToneAttrs GetSystemToneAttrs(SystemToneType systemToneType);
    ToneAttrs GetSystemToneAttrs(const DatabaseTool &databaseTool, SystemToneType systemToneType);
    ToneAttrs GetAlarmToneAttrs(const std::shared_ptr<AbilityRuntime::Context> &context);
    std::string OpenAudioUri(const DatabaseTool &databaseTool, const std::string &audioUri);
    std::string OpenHapticsUri(const DatabaseTool &databaseTool, const std::string &hapticsUri);
    std::string GetHapticsUriByStyle(const DatabaseTool &databaseTool,
        const std::string &standardHapticsUri, HapticsStyle hapticsStyle);
    int32_t GetGentleHapticsAttr(const DatabaseTool &databaseTool,
            const std::string &standardHapticsUri, std::string &hapticsTitle,
            std::string &hapticsFileName, std::string &hapticsUri);
    int32_t GetToneHapticsSettings(const DatabaseTool &databaseTool, const std::string &toneUri,
        ToneHapticsType toneHapticsType, ToneHapticsSettings &settings);
    int32_t GetHapticsAttrsSyncedWithTone(const std::string &toneUri, const DatabaseTool &databaseTool,
        std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs);
    int32_t SetToneHapticsSettings(const DatabaseTool &databaseTool,
        const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings);
    bool CheckVibrateSwitchStatus();
    int32_t OpenToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri, int32_t toneType) override;
    std::vector<std::tuple<std::string, int64_t, SystemSoundError>> OpenToneList(
        const std::vector<std::string> &uriList, SystemSoundError &errCode) override;
    std::vector<ToneInfo> GetCurrentToneInfos() override;

private:
    void InitDefaultUriMap();
    void InitDefaultRingtoneUriMap(const std::string &ringtoneJsonPath);
    void InitDefaultSystemToneUriMap(const std::string &systemToneJsonPath);
    void InitDefaultToneHapticsMap();
    void ReadDefaultToneHaptics(const char *paramName, ToneHapticsType toneHapticsType);
    std::string GetFullPath(const std::string &originalUri);
    std::string GetJsonValue(const std::string &jsonPath);
    std::string OpenCustomAudioUri(const std::string &customAudioUri);

    int32_t AddCustomizedTone(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const std::shared_ptr<ToneAttrs> &toneAttrs, int32_t &length);
    std::string DealAddCustomizedToneError(int32_t &sert,
        ParamsForAddCustomizedTone &paramsForAddCustomizedTone, const std::shared_ptr<ToneAttrs> &toneAttrs,
        std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper);
    bool DeleteCustomizedTone(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const std::shared_ptr<ToneAttrs> &toneAttrs, int32_t &length);
    int32_t WriteUriToDatabase(const std::string &key, const std::string &uri);
    std::string GetUriFromDatabase(const std::string &key);
    std::string GetKeyForDatabase(const std::string &systemSoundType, int32_t type);
    void InitRingerMode(void);
    void GetCustomizedTone(const std::shared_ptr<ToneAttrs> &toneAttrs);
    void InitMap();
    std::string GetRingtoneUriByType(const DatabaseTool &databaseTool, const std::string &type);
    ToneAttrs GetRingtoneAttrsByType(const DatabaseTool &databaseTool, const std::string &type);
    std::string GetPresetRingToneUriByType(const DatabaseTool &databaseTool, const std::string &type);
    ToneAttrs GetPresetRingToneAttrByType(const DatabaseTool &databaseTool, const std::string &type);
    int32_t SetNoRingToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        RingtoneType ringtoneType);
    int32_t RemoveSourceTypeForRingTone(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        RingtoneType ringtoneType, SourceType sourceType);
    int32_t UpdateRingtoneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const int32_t &toneId,
        RingtoneType ringtoneType, const int32_t &num);
    std::string GetShotToneUriByType(const DatabaseTool &databaseTool, const std::string &type);
    ToneAttrs GetShotToneAttrsByType(const DatabaseTool &databaseTool, const std::string &type);
    std::string GetNotificationToneUriByType(const DatabaseTool &databaseTool);
    ToneAttrs GetNotificationToneAttrsByType(const DatabaseTool &databaseTool);
    std::string GetPresetShotToneUriByType(const DatabaseTool &databaseTool, const std::string &type);
    ToneAttrs GetPresetShotToneAttrsByType(const DatabaseTool &databaseTool, const std::string &type);
    std::string GetPresetNotificationToneUri(const DatabaseTool &databaseTool);
    ToneAttrs GetPresetNotificationToneAttrs(const DatabaseTool &databaseTool);
    ToneAttrs GetAlarmToneAttrs(const DatabaseTool &databaseTool);
    int32_t UpdateShotToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const int32_t &toneId,
        SystemToneType systemToneType, const int32_t &num);
    int32_t OpenToneUri(const DatabaseTool &databaseTool, const std::string &uri, int32_t toneType);
    int32_t OpenToneFile(const DatabaseTool &databaseTool,
        const std::string &uri, int32_t toneType, int32_t toneId);
    std::string OpenAudioFile(const DatabaseTool &databaseTool, const std::string &uri, int32_t audioId);
    std::string OpenHapticsFile(const DatabaseTool &databaseTool, const std::string &hapticsUri, int32_t hapticsId);
    int32_t OpenCustomToneUri(const std::string &customAudioUri, int32_t toneType);
    int32_t SetSystemToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const std::string &uri, SystemToneType systemToneType);
    int32_t UpdateNotificatioToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const int32_t &toneId);
    int32_t UpdataeAlarmToneUri(const std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const int32_t ringtoneAssetId);
    int32_t SetNoSystemToneUri(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        SystemToneType systemToneType);
    int32_t RemoveSourceTypeForSystemTone(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        SystemToneType systemToneType, SourceType sourceType);
    int32_t UpdateAlarmTone(const std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const std::string &uri, const int32_t &toneId);
    bool ConvertToRingtoneType(ToneHapticsType toneHapticsType, RingtoneType &ringtoneType);
    bool ConvertToSystemToneType(ToneHapticsType toneHapticsType, SystemToneType &systemToneType);
    std::string ConvertToHapticsFileName(const std::string &fileName);
    ToneHapticsMode IntToToneHapticsMode(int32_t value);
    std::string GetCurrentToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType);
    std::string GetCurrentToneUri(const DatabaseTool &databaseTool, ToneHapticsType toneHapticsType);
    std::unique_ptr<SimcardSettingAsset> GetSimcardSettingAssetByToneHapticsType(const DatabaseTool &databaseTool,
        ToneHapticsType toneHapticsType);

    std::string GetToneSyncedHapticsUri(const DatabaseTool &databaseTool,
        const std::string &toneUri);
    std::string GetDefaultNonSyncedHapticsUri(const DatabaseTool &databaseTool,
        ToneHapticsType toneHapticsType);
    std::string GetFirstNonSyncedHapticsUri();
    int32_t GetDefaultToneHapticsSettings(const DatabaseTool &databaseTool,
        const std::string &currentToneUri, ToneHapticsType toneHapticsType, ToneHapticsSettings &settings);

    int32_t UpdateToneHapticsSettings(const DatabaseTool &databaseTool,
        const std::string &toneUri, ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings);
    bool GetVibrateTypeByStyle(int standardVibrateType, HapticsStyle hapticsStyle, int &vibrateType);
    std::unique_ptr<RingtoneAsset> IsPresetRingtone(const DatabaseTool &databaseTool, const std::string &toneUri);
    int GetStandardVibrateType(int toneType);
    std::string GetHapticsUriByStyle(const DatabaseTool &databaseTool,
        const std::string &standardHapticsUri, HapticsStyle hapticsStyle, const std::string &vibrateFilesUri);

    bool IsRingtoneTypeValid(RingtoneType ringtongType);
    bool IsSystemToneTypeValid(SystemToneType systemToneType);
    bool IsSystemToneType(const std::unique_ptr<RingtoneAsset> &ringtoneAsset,
        const SystemToneType &systemToneType);
    bool IsToneHapticsTypeValid(ToneHapticsType toneHapticsType);

    static Uri AssembleUri(const std::string &key, std::string tableType = "");
    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelperProxy(std::string tableType = "");
    int32_t GetStringValue(const std::string &key, std::string &value, std::string tableType = "");
    void SetExtRingtoneUri(const std::string &uri, const std::string &title,
        int32_t ringType, int32_t toneType, int32_t changedRows);
    int32_t SetExtRingToneUri(const std::string &uri, const std::string &title, int32_t toneType);
    void SendCustomizedToneEvent(bool flag, const std::shared_ptr<ToneAttrs> &toneAttrs, off_t fileSize,
        std::string mimeType, int result);
    void SendPlaybackFailedEvent(const int32_t &errorCode);
    std::string CustomizedToneWriteFile(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const std::shared_ptr<ToneAttrs> &toneAttrs, ParamsForAddCustomizedTone &paramsForAddCustomizedTone);
    void OpenOneFile(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const std::string &uri, std::tuple<std::string, int64_t, SystemSoundError> &resultOfOpen);
    int32_t DoRemove(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper, const std::string &uri,
        off_t fileSize);
    std::string GetBundleName();
    std::string AddCustomizedToneCheck(const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &length);
    void SetToneAttrs(std::shared_ptr<ToneAttrs> &toneAttrs, const std::unique_ptr<RingtoneAsset> &ringtoneAsset);
    DataShare::DataSharePredicates CreateVibrationListQueryPredicates(bool isSynced);
    DataShare::DataSharePredicates CreateVibrateQueryPredicates(const std::string &displayName, int32_t vibrateType);
    
    std::string systemSoundPath_ = "";
    std::mutex uriMutex_;
    std::mutex playerMutex_;
#ifdef SUPPORT_VIBRATOR
    std::mutex toneHapticsMutex_;
#endif
    std::string mimeType_ = "";
    std::string displayName_ = "";
    std::unordered_map<RingtoneType, std::string> defaultRingtoneUriMap_;
    std::unordered_map<SystemToneType, std::string> defaultSystemToneUriMap_;
    std::unordered_map<ToneHapticsType, std::string> defaultToneHapticsUriMap_;
    std::shared_ptr<ToneAttrs> ringtoneAttrs_;
    std::shared_ptr<ToneAttrs> systemtoneAttrs_;
    std::shared_ptr<ToneAttrs> alarmtoneAttrs_;

    std::atomic<AudioStandard::AudioRingerMode> ringerMode_ = AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL;
    std::shared_ptr<AudioStandard::AudioGroupManager> audioGroupManager_ = nullptr;
    std::shared_ptr<AudioStandard::AudioRingerModeCallback> ringerModeCallback_ = nullptr;
    std::vector<std::shared_ptr<ToneAttrs>> ringtoneAttrsArray_;
    std::vector<std::shared_ptr<ToneAttrs>> systemtoneAttrsArray_;
    std::vector<std::shared_ptr<ToneAttrs>> alarmtoneAttrsArray_;
};

class RingerModeCallbackImpl : public AudioStandard::AudioRingerModeCallback {
public:
    explicit RingerModeCallbackImpl(SystemSoundManagerImpl &systemSoundManagerImpl);
    virtual ~RingerModeCallbackImpl() = default;
    void OnRingerModeUpdated(const AudioStandard::AudioRingerMode &ringerMode) override;

private:
    SystemSoundManagerImpl &sysSoundMgr_;
    AudioStandard::AudioRingerMode ringerMode_ { AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL };
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_SOUND_MANAGER_IMPL_H
