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

#ifndef SYSTEM_TONE_PLAYER_IMPL_H
#define SYSTEM_TONE_PLAYER_IMPL_H

#include "audio_haptic_manager.h"
#include "system_sound_manager_impl.h"

namespace OHOS {
namespace Media {
class SystemTonePlayerCallback;

class SystemTonePlayerImpl : public SystemTonePlayer, public std::enable_shared_from_this<SystemTonePlayerImpl> {
public:
    SystemTonePlayerImpl(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemSoundManagerImpl &systemSoundMgr, SystemToneType systemToneType);
    ~SystemTonePlayerImpl();

    // SystemTonePlayer override
    std::string GetTitle() const override;
    int32_t Prepare() override;
    int32_t Start() override;
    int32_t Start(const SystemToneOptions &systemToneOptions) override;
    int32_t Stop(const int32_t &streamID) override;
    int32_t Release() override;
    int32_t SetAudioVolume(float volume) override;
    int32_t GetAudioVolume(float &recvValue) override;
    int32_t GetSupportHapticsFeatures(std::vector<ToneHapticsFeature> &recvFeatures) override;
    int32_t SetHapticsFeature(ToneHapticsFeature feature) override;
    int32_t GetHapticsFeature(ToneHapticsFeature &feature) override;
    bool IsStreamIdExist(int32_t streamId) override;
    int32_t SetSystemTonePlayerFinishedAndErrorCallback(
        const std::shared_ptr<SystemTonePlayerFinishedAndErrorCallback> &finishedAndErrorCallback) override;

    void NotifyEndofStreamEvent(const int32_t &streamId);
    void NotifyInterruptEvent(const int32_t &streamId, const AudioStandard::InterruptEvent &interruptEvent);
    void NotifyErrorEvent(int32_t errCode);

private:
    int32_t InitPlayer(const std::string &audioUri);
    int32_t CreatePlayerWithOptions(const AudioHapticPlayerOptions &options);
    void DeletePlayer(const int32_t &streamId);
    void DeleteAllPlayer();
    std::string GetNewHapticUriForAudioUri(const std::string &audioUri, const std::string &ringtonePath,
        const std::string& hapticsPath);
    void GetNewHapticUriForAudioUri(const std::string &audioUri,
        std::map<ToneHapticsFeature, std::string> &hapticsUriMap);
    void GetHapticUriForAudioUri(const std::string &audioUri, std::map<ToneHapticsFeature, std::string> &hapticsUris);
    std::string GetDefaultNonSyncHapticsPath();
    SystemToneOptions GetOptionsFromRingerMode();
    void InitHapticsSourceIds();
    void ReleaseHapticsSourceIds();
    ToneHapticsType ConvertToToneHapticsType(SystemToneType type);
    HapticsMode ConvertToHapticsMode(ToneHapticsMode toneHapticsMode);
    void GetNewHapticSettings(const std::string &audioUri, std::map<ToneHapticsFeature, std::string> &hapticsUris);
    void GetCurrentHapticSettings(const std::string &audioUri, std::map<ToneHapticsFeature, std::string> &hapticUriMap);
    bool IsSameHapticMaps(const std::map<ToneHapticsFeature, std::string> &hapticUriMap);
    void UpdateStreamId();
    bool InitDatabaseTool();
    void ReleaseDatabaseTool();
    int32_t RegisterSource(const std::string &audioUri, const std::string &hapticUri);
    void CreateCallbackThread(int32_t delayTime);
    void DeleteCallbackThreadId(int32_t streamId);
    void DeleteAllCallbackThreadId();
    bool IsExitCallbackThreadId(int32_t streamId);
    void SendMessageZoneEvent(const int32_t &errorCode, bool muteAudio, bool muteHaptics);
    bool VerifyPath(const std::string& systemtoneUri);

    std::shared_ptr<AudioHapticManager> audioHapticManager_ = nullptr;
    std::unordered_map<int32_t, std::shared_ptr<AudioHapticPlayer>> playerMap_;
    std::unordered_map<int32_t, std::shared_ptr<SystemTonePlayerCallback>> callbackMap_;
    int32_t streamId_ = 0;
    std::string configuredUri_ = "";
    std::string defaultNonSyncHapticUri_ = "";
    std::shared_ptr<AbilityRuntime::Context> context_;
    SystemSoundManagerImpl &systemSoundMgr_;
    SystemToneType systemToneType_;
    SystemToneState systemToneState_ = SystemToneState::STATE_INVALID;
    float volume_ = SYS_TONE_PLAYER_MAX_VOLUME;
    ToneHapticsFeature hapticsFeature_ = ToneHapticsFeature::STANDARD;
    std::map<ToneHapticsFeature, int32_t> sourceIds_;
    std::vector<ToneHapticsFeature> supportedHapticsFeatures_;
    HapticsMode hapticsMode_ = HapticsMode::HAPTICS_MODE_INVALID;
    std::map<ToneHapticsFeature, std::string> hapticUriMap_;
    bool isHapticUriEmpty_ = false;
    bool isNoneHaptics_ = false;
    DatabaseTool databaseTool_ = {false, false, nullptr};
    std::shared_ptr<SystemTonePlayerFinishedAndErrorCallback> finishedAndErrorCallback_ = nullptr;
    std::unordered_map<int32_t, std::thread::id> callbackThreadIdMap_;

    std::mutex systemTonePlayerMutex_;
};

class SystemTonePlayerCallback : public AudioHapticPlayerCallback {
public:
    explicit SystemTonePlayerCallback(int32_t streamId, std::shared_ptr<SystemTonePlayerImpl> systemTonePlayerImpl);
    virtual ~SystemTonePlayerCallback() = default;

    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnEndOfStream(void) override;
    void OnError(int32_t errorCode) override;

private:
    std::weak_ptr<SystemTonePlayerImpl> systemTonePlayerImpl_;
    int32_t streamId_;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_TONE_PLAYER_IMPL_H
