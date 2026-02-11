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

#ifndef SYSTEM_SOUND_MANAGER_H
#define SYSTEM_SOUND_MANAGER_H

#include <string>

#include "ability_runtime/context/context.h"

#include "ringtone_player.h"
#include "system_tone_player.h"
#include "tone_attrs.h"
#include "tone_haptics_attrs.h"

namespace OHOS {
namespace Media {
inline const std::string NO_SYSTEM_SOUND = "no_system_sound";
inline const std::string NO_RING_SOUND = "no_ring_sound";
inline const std::string FILE_SIZE_EXCEEDS_LIMIT = "20700004";
inline const std::string FILE_COUNT_EXCEEDS_LIMIT = "20700005";
inline const std::string ROM_IS_INSUFFICIENT = "20700006";

enum RingtoneType {
    RINGTONE_TYPE_SIM_CARD_0 = 0,
    RINGTONE_TYPE_SIM_CARD_1 = 1,
};

enum SystemToneType {
    SYSTEM_TONE_TYPE_SIM_CARD_0 = 0,
    SYSTEM_TONE_TYPE_SIM_CARD_1 = 1,
    SYSTEM_TONE_TYPE_NOTIFICATION = 32,
};

enum ToneHapticsType {
    CALL_SIM_CARD_0 = 0,
    CALL_SIM_CARD_1 = 1,
    TEXT_MESSAGE_SIM_CARD_0 = 20,
    TEXT_MESSAGE_SIM_CARD_1 = 21,
    NOTIFICATION = 40,
};

enum SystemToneUriType {
    UNKNOW_RINGTONES = -1,
    NO_RINGTONES = 0,
    PRESET_RINGTONES = 1,
    CUSTOM_RINGTONES = 2,
};

enum SystemSoundError {
    ERROR_IO = 5400103,
    ERROR_OK = 20700000,
    ERROR_TYPE_MISMATCH = 20700001,
    ERROR_UNSUPPORTED_OPERATION = 20700003,
    ERROR_DATA_TOO_LARGE = 20700004,
    ERROR_TOO_MANY_FILES = 20700005,
    ERROR_INSUFFICIENT_ROM = 20700006,
    ERROR_INVALID_PARAM = 20700007,
};

enum SystemSoundType {
    PHOTO_SHUTTER = 0,
    VIDEO_RECORDING_BEGIN = 1,
    VIDEO_RECORDING_END = 2,
};

struct ParamsForAddCustomizedTone {
    std::string dstPath;
    int32_t srcFd;
    int32_t length;
    int32_t offset;
    bool duplicateFile;
};

struct ToneInfo {
    int32_t type;
    std::string uri;
    std::string title;
};

class SystemSoundManager {
public:
    virtual ~SystemSoundManager() = default;

    /**
     * @brief Returns the ringtone player instance.
     *
     * @param context Indicates the Context object on OHOS.
     * @param ringtoneType Indicates the ringtone type for which player instance has to be returned.
     * @return Returns RingtonePlayer.
     * @since 10
     */
    virtual std::shared_ptr<RingtonePlayer> GetRingtonePlayer(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) = 0;

    /**
     * @brief Return to the dedicated contact ringtone player instance.
     *
     * @param context Indicates the Context object on OHOS.
     * @param ringtoneType Indicates the ringtone type for which player instance has to be returned.
     * @param ringtoneUri Indicates the ringtone URI for a specific contact.
     * @return Returns SpecificRingTonePlayer.
     */
    virtual std::shared_ptr<RingtonePlayer> GetSpecificRingTonePlayer(const std::shared_ptr<AbilityRuntime::Context>
        &context, const RingtoneType ringtoneType, std::string &ringtoneUri) = 0;

    /**
     * @brief API used for setting the ringtone uri.
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri Indicates which uri to be set for the tone type.
     * @param ringtoneType Indicates the ringtone type.
     * @return Returns {@link MSERR_OK} if set the ringtone uri successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 10
     */
    virtual int32_t SetRingtoneUri(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri,
        RingtoneType ringtoneType) = 0;

    /**
     * @brief Returns the current ringtone uri.
     *
     * @param context Indicates the Context object on OHOS.
     * @param ringtoneType Indicates the ringtone type.
     * @return Returns the current ringtone uri.
     * @since 10
     */
    virtual std::string GetRingtoneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) = 0;

    /**
     * @brief Returns the current ringtone attrs.
     *
     * @param ringtoneType Indicates the ringtone type.
     * @return Returns the current ringtone attrs.
     * @since 12
     */
    virtual ToneAttrs GetCurrentRingtoneAttribute(RingtoneType ringtoneType) = 0;

    /**
     * @brief Returns the system tone player instance
     *
     * @param context Indicates the Context object on OHOS.
     * @param systemToneType Indicates the system tone type for which player instance has to be returned.
     * @return Returns SystemTonePlayer.
     * @since 11
     */
    virtual std::shared_ptr<SystemTonePlayer> GetSystemTonePlayer(
        const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType) = 0;

    /**
     * @brief API used for setting the system tone uri
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri indicates which uri to be set for system tone.
     * @param systemToneType Indicates the system tone type.
     * @return Returns {@link MSERR_OK} if set the system tone uri successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 11
     */
    virtual int32_t SetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri,
        SystemToneType systemToneType) = 0;

    /**
     * @brief Returns the current system tone uri
     *
     * @param context Indicates the Context object on OHOS.
     * @return Returns the system tone uri
     * @since 11
     */
    virtual std::string GetSystemToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemToneType systemToneType)= 0;

    /**
     * @brief Returns the default ringtone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @param ringtoneType Indicates the ringtone type.
     * @return Returns the default ringtone attrs.
     * @since 12
     */
    virtual std::shared_ptr<ToneAttrs> GetDefaultRingtoneAttrs(const std::shared_ptr<AbilityRuntime::Context> &context,
        RingtoneType ringtoneType) = 0;

    /**
     * @brief Returns the list of ringtone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @param ringtoneType Indicates the ringtone type.
     * @return Returns the list of ringtone attrs.
     * @since 12
     */
    virtual std::vector<std::shared_ptr<ToneAttrs>> GetRingtoneAttrList(
        const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType) = 0;

    /**
     * @brief Returns the default systemtone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @param systemToneType Indicates the systemtone type.
     * @return Returns the default systemtone attrs.
     * @since 12
     */
    virtual std::shared_ptr<ToneAttrs>  GetDefaultSystemToneAttrs(
        const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemtoneType) = 0;

    /**
     * @brief Returns the list of systemtone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @param systemToneType Indicates the systemtone type.
     * @return Returns the list of systemtone attrs.
     * @since 12
     */
    virtual std::vector<std::shared_ptr<ToneAttrs>> GetSystemToneAttrList(
        const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType) = 0;

    /**
     * @brief  Sets uri of the current alarm tone.
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri indicates which uri to be set for system tone.
     * @return Returns {@link MSERR_OK} if set the system tone uri successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t SetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri) = 0;

    /**
     * @brief Gets uri of the current alarm tone.
     *
     * @param context Indicates the Context object on OHOS.
     * @return Returns the alarm tone uri
     * @since 12
     */
    virtual std::string GetAlarmToneUri(const std::shared_ptr<AbilityRuntime::Context> &context) = 0;

    /**
     * @brief Returns the default alarmTone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @return Returns the default alarmTone attrs.
     * @since 12
     */
    virtual std::shared_ptr<ToneAttrs> GetDefaultAlarmToneAttrs(
        const std::shared_ptr<AbilityRuntime::Context> &context) = 0;

    /**
     * @brief Returns the list of alarmTone attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @return Returns the list of alarmTone attrs.
     * @since 12
     */
    virtual std::vector<std::shared_ptr<ToneAttrs>> GetAlarmToneAttrList(
        const std::shared_ptr<AbilityRuntime::Context> &context) = 0;

    /**
     * @brief Open the alarm tone file.
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri Uri of alarm tone to open.
     * @return Returns the fd of tone.
     * @since 12
     */
    virtual int32_t OpenAlarmTone(const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri) = 0;

    /**
     * @brief Close the tone file.
     *
     * @param fd File descriptor.
     * @return Returns {@link MSERR_OK} if close the fd successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t Close(const int32_t &fd) = 0;

    /**
     * @brief Add customized tone into ringtone library.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneAttrs Tone attributes.
     * @param externalUri Tone uri in external storage.
     * @return Returns the tone uri after adding into ringtone library.
     * @since 12
     */
    virtual std::string AddCustomizedToneByExternalUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const std::string &externalUri) = 0;

    /**
     * @brief Add customized tone into ringtone library.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneAttrs Tone attributes.
     * @param fd File descriptor.
     * @return Returns the tone uri after adding into ringtone library.
     * @since 12
     */
    virtual std::string AddCustomizedToneByFd(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd) = 0;

    /**
     * @brief Add customized tone into ringtone library.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneAttrs Tone attributes.
     * @param fd File descriptor.
     * @param offset The offset in the file where the data to be read, in bytes.
     * @param length The length in bytes of the data to be read.
     * @return Returns the tone uri after adding into ringtone library.
     * @since 12
     */
    virtual std::string AddCustomizedToneByFdAndOffset(
        const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<ToneAttrs> &toneAttrs,
            ParamsForAddCustomizedTone &paramsForAddCustomizedTone) = 0;

    /**
     * @brief Remove customized tone in ringtone library.
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri tone uri
     * @return Returns {@link MSERR_OK} if remove the customized tone successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t RemoveCustomizedTone(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri) = 0;

    /**
     * @brief Remove customized tones in ringtone library.
     *
     * @param uriList tone uris
     * @return Returns {@link MSERR_OK} if remove the customized tone successfully;
     * returns error codes defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual std::vector<std::pair<std::string, SystemSoundError>> RemoveCustomizedToneList(
        const std::vector<std::string> &uriList, SystemSoundError &errCode) = 0;

    /**
     * @brief Returns the tone haptics settings.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneHapticsType Indicates the tone type.
     * @param settings tone haptics settings.
     * @return Returns {@link MSERR_OK} if get the tone haptics settings successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t GetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, ToneHapticsSettings &settings) = 0;

     /**
     * @brief  Sets tone haptics of the current tone.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneHapticsType Indicates which haptics to be set for tone.
     * @param settings Indicates the haptics settings.
     * @return Returns {@link MSERR_OK} if set the tone haptics successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t SetToneHapticsSettings(const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings) = 0;

    /**
     * @brief Returns the list of tone haptics attributes.
     *
     * @param context Indicates the Context object on OHOS.
     * @param isSynced Indicates the haptics is synced.
     * @param toneHapticsAttrsArray the list of tone haptics attrs.
     * @return Returns {@link MSERR_OK} if set the tone haptics successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t GetToneHapticsList(const std::shared_ptr<AbilityRuntime::Context> &context,
        bool isSynced, std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray) = 0;

    /**
     * @brief Returns the haptics attributes synced with tone.
     *
     * @param context Indicates the Context object on OHOS.
     * @param toneUri Get the ringtone uri of the sync haptics.
     * @param toneHapticsAttrsthe haptics attrs synced with tone.
     * @return Returns {@link MSERR_OK} if set the tone haptics successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 12
     */
    virtual int32_t GetHapticsAttrsSyncedWithTone(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &toneUri, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs) = 0;

    /**
     * @brief Open the tone haptics file.
     *
     * @param context Indicates the Context object on OHOS.
     * @param hapticsUri Uri of haptics to open.
     * @return Returns the fd of haptics.
     * @since 12
     */
    virtual int32_t OpenToneHaptics(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &hapticsUri) = 0;

    /**
     * @brief Open the tone file.
     *
     * @param context Indicates the Context object on OHOS.
     * @param uri Uri of tone to open.
     * @return Returns the fd of tone.
     * @since 12
     */
    virtual int32_t OpenToneUri(const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri, int32_t toneType) = 0;

    /**
     * @brief Returns fds of the uris in uriList.
     *
     * @param uriList Indicates the uris to open.
     * @return Returns fds of the uris in uriList.
     * @since 12
     */
    virtual std::vector<std::tuple<std::string, int64_t, SystemSoundError>> OpenToneList(
        const std::vector<std::string> &uriList, SystemSoundError &errCode) = 0;

    /**
     * @brief Get the tone infos.
     *
     * @return Returns ToneInfo vector.
     */
    virtual std::vector<ToneInfo> GetCurrentToneInfos() = 0;
};

class __attribute__((visibility("default"))) SystemSoundManagerFactory {
public:
    static std::shared_ptr<SystemSoundManager> CreateSystemSoundManager();

private:
    static std::shared_ptr<SystemSoundManager> systemSoundManager_;
    static std::mutex systemSoundManagerMutex_;
    SystemSoundManagerFactory() = default;
    ~SystemSoundManagerFactory() = default;
};
} // Media
} // OHOS
#endif // SYSTEM_SOUND_MANAGER_H
