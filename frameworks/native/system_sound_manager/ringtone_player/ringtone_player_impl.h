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

#ifndef RINGTONE_PLAYER_IMPL_H
#define RINGTONE_PLAYER_IMPL_H
#include "audio_stream_info.h"
#include "audio_info.h"
#include "audio_renderer.h"

#include "audio_haptic_manager.h"
#include "player.h"
#include "system_sound_manager_impl.h"
#include "system_sound_vibrator.h"


namespace OHOS {
namespace Media {
class RingtonePlayerCallback;

class RingtonePlayerInterruptCallback;

class RingtonePlayerImpl : public RingtonePlayer {
public:
    RingtonePlayerImpl(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemSoundManagerImpl &sysSoundMgr, RingtoneType type);
    RingtonePlayerImpl(const std::shared_ptr<AbilityRuntime::Context> &context,
        SystemSoundManagerImpl &sysSoundMgr, const RingtoneType type, std::string &ringtoneUri);
    ~RingtonePlayerImpl();
    void NotifyEndofStreamEvent();
    void NotifyInterruptEvent(const AudioStandard::InterruptEvent &interruptEvent);

    // RingtonePlayer override
    RingtoneState GetRingtoneState() override;
    int32_t Configure(const float &volume, const bool &loop) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t GetAudioRendererInfo(AudioStandard::AudioRendererInfo &rendererInfo) const override;
    std::string GetTitle() override;
    int32_t SetRingtonePlayerInterruptCallback(
        const std::shared_ptr<RingtonePlayerInterruptCallback> &interruptCallback) override;

private:
    void InitPlayer(std::string &audioUri, ToneHapticsSettings &settings, AudioHapticPlayerOptions options);
    std::string GetNewHapticUriForAudioUri(const std::string &audioUri, const std::string &ringtonePath,
        const std::string& hapticsPath);
    std::string GetNewHapticUriForAudioUri(const std::string &audioUri);
    std::string GetHapticUriForAudioUri(const std::string &audioUri);
    bool IsFileExisting(const std::string &fileUri);
    std::string ChangeUri(const std::string &audioUri);
    ToneHapticsType ConvertToToneHapticsType(RingtoneType type);
    HapticsMode ConvertToHapticsMode(ToneHapticsMode toneHapticsMode);
    ToneHapticsSettings GetHapticSettings(std::string &audioUri, bool &muteHaptics);
    std::string ChangeHapticsUri(const std::string &hapticsUri);
    bool InitDataShareHelper();
    void ReleaseDataShareHelper();
    int32_t RegisterSource(const std::string &audioUri, const std::string &hapticUri);
    bool VerifyPath(const std::string& audio);

    float volume_ = 1.0f;
    bool loop_ = false;
    std::string configuredUri_ = "";
    ToneHapticsSettings configuredHaptcisSettings_;
    std::shared_ptr<AudioHapticManager> audioHapticManager_ = nullptr;
    int32_t sourceId_ = -1;
    std::shared_ptr<AudioHapticPlayer> player_ = nullptr;
    std::shared_ptr<AbilityRuntime::Context> context_;
    std::shared_ptr<AudioHapticPlayerCallback> callback_ = nullptr;
    std::shared_ptr<RingtonePlayerInterruptCallback> interruptCallback_ = nullptr;
    SystemSoundManagerImpl &systemSoundMgr_;
    RingtoneType type_ = RINGTONE_TYPE_SIM_CARD_0;
    RingtoneState ringtoneState_ = STATE_NEW;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_ = nullptr;
    std::string specifyRingtoneUri_ = "";
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer_ {nullptr};
    AudioStandard::AudioRendererParams rendererParams_ {};

    std::mutex playerMutex_;
};

class RingtonePlayerCallback : public AudioHapticPlayerCallback {
public:
    explicit RingtonePlayerCallback(RingtonePlayerImpl &ringtonePlayerImpl);
    virtual ~RingtonePlayerCallback() = default;

    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnEndOfStream(void) override;
    void OnError(int32_t errorCode) override;

private:
    RingtonePlayerImpl &ringtonePlayerImpl_;
};
} // namespace Media
} // namespace OHOS
#endif // RINGTONE_PLAYER_IMPL_H
