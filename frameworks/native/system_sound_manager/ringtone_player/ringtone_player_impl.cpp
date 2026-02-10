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

#include "ringtone_player_impl.h"

#include <sys/stat.h>
#include "directory_ex.h"
#include "ringtone_proxy_uri.h"
#include "config_policy_utils.h"

#include "parameter.h"
#include "system_sound_log.h"
#include "system_sound_vibrator.h"
#include "media_errors.h"
#include "system_sound_manager_utils.h"

using namespace std;
using namespace OHOS::AbilityRuntime;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "RingtonePlayer"};
}

namespace OHOS {
namespace Media {
const int32_t ERRCODE_IOERROR = 5400103;
const float HIGH_VOL = 1.0f;
const float LOW_VOL = 0.0f;
const std::string AUDIO_FORMAT_STR = ".ogg";
const std::string HAPTIC_FORMAT_STR = ".json";
const std::string RINGTONE_PATH = "/media/audio/";
const std::string STANDARD_HAPTICS_PATH = "/media/haptics/standard/synchronized/";
const std::string NON_SYNC_HAPTICS_PATH = "resource/media/haptics/standard/non-synchronized/";
const std::string FDHEAD = "fd://";

RingtonePlayerImpl::RingtonePlayerImpl(const shared_ptr<Context> &context,
    SystemSoundManagerImpl &sysSoundMgr, RingtoneType type)
    : volume_(HIGH_VOL),
      loop_(false),
      context_(context),
      systemSoundMgr_(sysSoundMgr),
      type_(type)
{
    if (!InitDatabaseTool()) {
        MEDIA_LOGE("Failed to init DatabaseTool!");
        return;
    }

    audioHapticManager_ = AudioHapticManagerFactory::CreateAudioHapticManager();
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to get audio haptic manager");

    std::string ringtoneUri = systemSoundMgr_.GetRingtoneUri(databaseTool_, type_);
    AudioHapticPlayerOptions options = {false, false};
    ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
    InitPlayer(ringtoneUri, settings, options);
    ReleaseDatabaseTool();
}

RingtonePlayerImpl::RingtonePlayerImpl(const shared_ptr<Context> &context,
    SystemSoundManagerImpl &sysSoundMgr, const RingtoneType type, string &ringtoneUri)
    : volume_(HIGH_VOL),
      loop_(false),
      context_(context),
      systemSoundMgr_(sysSoundMgr),
      type_(type),
      specifyRingtoneUri_(ringtoneUri)
{
    if (!InitDatabaseTool()) {
        MEDIA_LOGE("Failed to init DatabaseTool!");
        return;
    }

    audioHapticManager_ = AudioHapticManagerFactory::CreateAudioHapticManager();
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to get audio haptic manager");

    AudioHapticPlayerOptions options = {false, false};
    ToneHapticsSettings settings = GetHapticSettings(specifyRingtoneUri_, options.muteHaptics);
    InitPlayer(specifyRingtoneUri_, settings, options);
    ReleaseDatabaseTool();
}

RingtonePlayerImpl::~RingtonePlayerImpl()
{
    if (player_ != nullptr) {
        player_->Release();
        (void)SystemSoundVibrator::StopVibrator();
        player_ = nullptr;
        callback_ = nullptr;
    }
    if (audioHapticManager_ != nullptr) {
        (void)audioHapticManager_->UnregisterSource(sourceId_);
        audioHapticManager_ = nullptr;
    }
    if (audioRenderer_ != nullptr) {
        (void)audioRenderer_->Release();
        audioRenderer_ = nullptr;
    }
    ReleaseDatabaseTool();
}

bool RingtonePlayerImpl::IsFileExisting(const std::string &fileUri)
{
    struct stat buffer;
    return (stat(fileUri.c_str(), &buffer) == 0);
}

std::string RingtonePlayerImpl::GetNewHapticUriForAudioUri(const std::string &audioUri,
    const std::string &ringtonePath, const std::string& hapticsPath)
{
    string hapticUri = audioUri;
    size_t pos = hapticUri.find(ringtonePath);
    if (pos == string::npos) {
        return "";
    }
    hapticUri.replace(pos, ringtonePath.size(), hapticsPath);
    if (hapticUri.length() > AUDIO_FORMAT_STR.length() &&
        hapticUri.rfind(AUDIO_FORMAT_STR) == hapticUri.length() - AUDIO_FORMAT_STR.length()) {
        hapticUri.replace(hapticUri.rfind(AUDIO_FORMAT_STR), AUDIO_FORMAT_STR.length(), HAPTIC_FORMAT_STR);
        if (IsFileExisting(hapticUri)) {
            return hapticUri;
        }
    }
    return "";
}

std::string RingtonePlayerImpl::GetNewHapticUriForAudioUri(const std::string &audioUri)
{
    std::string hapticUri = GetNewHapticUriForAudioUri(audioUri, RINGTONE_PATH, STANDARD_HAPTICS_PATH);
    if (hapticUri.empty()) {
        MEDIA_LOGW("Failed to find the vibration json file for audioUri.");
    }
    return hapticUri;
}

std::string RingtonePlayerImpl::GetHapticUriForAudioUri(const std::string &audioUri)
{
    std::string hapticUri = "";
    if (audioUri.length() > AUDIO_FORMAT_STR.length() &&
        audioUri.rfind(AUDIO_FORMAT_STR) == audioUri.length() - AUDIO_FORMAT_STR.length()) {
        // the end of audio uri is ".ogg"
        hapticUri = audioUri;
        hapticUri.replace(hapticUri.rfind(AUDIO_FORMAT_STR), AUDIO_FORMAT_STR.length(), HAPTIC_FORMAT_STR);
    }

    if (hapticUri == "" || !IsFileExisting(hapticUri)) {
        MEDIA_LOGW("Failed to find the vibration json file for audioUri.");
    }

    return hapticUri;
}

bool RingtonePlayerImpl::InitDatabaseTool()
{
    if (databaseTool_.isInitialized) {
        MEDIA_LOGI("The database tool has been initialized. No need to reload.");
        return true;
    }
    SystemSoundManagerUtils::CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID,
        databaseTool_.isProxy, databaseTool_.dataShareHelper);
    if (databaseTool_.dataShareHelper == nullptr) {
        MEDIA_LOGE("Failed to create dataShareHelper!");
        databaseTool_.isInitialized = false;
        return false;
    }
    databaseTool_.isInitialized = true;
    MEDIA_LOGI("Finish to InitDatabaseTool(): isProxy %{public}d", databaseTool_.isProxy);
    return true;
}

void RingtonePlayerImpl::ReleaseDatabaseTool()
{
    if (!databaseTool_.isInitialized) {
        MEDIA_LOGI("The database tool has been released!");
        return;
    }
    if (databaseTool_.dataShareHelper != nullptr) {
        MEDIA_LOGD("Enter ReleaseDataShareHelperUri()");
        databaseTool_.dataShareHelper->Release();
        databaseTool_.dataShareHelper = nullptr;
    }
    databaseTool_.isProxy = false;
    databaseTool_.isInitialized = false;
}

ToneHapticsType RingtonePlayerImpl::ConvertToToneHapticsType(RingtoneType type)
{
    switch (type) {
        case RingtoneType::RINGTONE_TYPE_SIM_CARD_0:
            return ToneHapticsType::CALL_SIM_CARD_0;
        case RingtoneType::RINGTONE_TYPE_SIM_CARD_1:
            return ToneHapticsType::CALL_SIM_CARD_1;
        default:
            return ToneHapticsType::CALL_SIM_CARD_0;
    }
}

HapticsMode RingtonePlayerImpl::ConvertToHapticsMode(ToneHapticsMode toneHapticsMode)
{
    switch (toneHapticsMode) {
        case ToneHapticsMode::NONE:
            return HapticsMode::HAPTICS_MODE_NONE;
        case ToneHapticsMode::SYNC:
            return HapticsMode::HAPTICS_MODE_SYNC;
        case ToneHapticsMode::NON_SYNC:
            return HapticsMode::HAPTICS_MODE_NON_SYNC;
        default:
            return HapticsMode::HAPTICS_MODE_INVALID;
    }
}

ToneHapticsSettings RingtonePlayerImpl::GetHapticSettings(std::string &audioUri, bool &muteHaptics)
{
    ToneHapticsSettings settings;
    int32_t result = systemSoundMgr_.GetToneHapticsSettings(databaseTool_, audioUri,
        ConvertToToneHapticsType(type_), settings);
    if (result == 0) {
        MEDIA_LOGI("GetHapticSettings: hapticsUri:%{public}s, mode:%{public}d.",
            settings.hapticsUri.c_str(), settings.mode);
        return settings;
    }
    settings.mode = ToneHapticsMode::SYNC;
    settings.hapticsUri = GetNewHapticUriForAudioUri(audioUri);
    if (settings.hapticsUri.empty()) {
        settings.hapticsUri = GetHapticUriForAudioUri(audioUri);
        if (settings.hapticsUri.empty()) {
            MEDIA_LOGW("haptic uri is empty. Play ringtone without vibration");
            muteHaptics = true;
            settings.mode = ToneHapticsMode::NONE;
        }
    }
    MEDIA_LOGI("GetHapticSettings: hapticsUri:%{public}s, mode:%{public}d.",
        settings.hapticsUri.c_str(), settings.mode);
    return settings;
}

int32_t RingtonePlayerImpl::RegisterSource(const std::string &audioUri, const std::string &hapticUri)
{
    string newAudioUri = systemSoundMgr_.OpenAudioUri(databaseTool_, audioUri);
    string newHapticUri = systemSoundMgr_.OpenHapticsUri(databaseTool_, hapticUri);

    if (newAudioUri.find(FDHEAD) == std::string::npos && newAudioUri != NO_RING_SOUND) {
        MEDIA_LOGI("Failed to open ringtone file, select to open default ringtone and play.");
        std::string uri = "";
        std::shared_ptr<ToneAttrs> ringtoneAttrs = systemSoundMgr_.GetDefaultRingtoneAttrs(context_, type_);
        if (ringtoneAttrs != nullptr) {
            uri = ringtoneAttrs->GetUri();
        }
        newAudioUri = systemSoundMgr_.OpenAudioUri(databaseTool_, uri);
    }

    int32_t sourceId = audioHapticManager_->RegisterSource(newAudioUri, newHapticUri);

    if (newAudioUri.find(FDHEAD) != std::string::npos) {
        int32_t fd = atoi(newAudioUri.substr(FDHEAD.size()).c_str());
        if (fd > 0) {
            close(fd);
        }
    }
    if (newHapticUri.find(FDHEAD) != std::string::npos) {
        int32_t fd = atoi(newHapticUri.substr(FDHEAD.size()).c_str());
        if (fd > 0) {
            close(fd);
        }
    }

    return sourceId;
}

void RingtonePlayerImpl::InitPlayer(std::string &audioUri, ToneHapticsSettings &settings,
    AudioHapticPlayerOptions options)
{
    MEDIA_LOGI("InitPlayer: ToneUri:%{public}s, hapticsUri:%{public}s, mode:%{public}d.",
        audioUri.c_str(), settings.hapticsUri.c_str(), settings.mode);
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to create audio haptic manager.");
    if (sourceId_ != -1) {
        (void)audioHapticManager_->UnregisterSource(sourceId_);
        sourceId_ = -1;
    }

    sourceId_ = RegisterSource(audioUri, settings.hapticsUri);
    CHECK_AND_RETURN_LOG(sourceId_ != -1, "Failed to register source for audio haptic manager");
    (void)audioHapticManager_->SetAudioLatencyMode(sourceId_, AUDIO_LATENCY_MODE_NORMAL);
    (void)audioHapticManager_->SetStreamUsage(sourceId_, AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE);

    bool hapticsSwitchStatus = systemSoundMgr_.CheckVibrateSwitchStatus();
    AudioStandard::AudioRingerMode ringerMode = systemSoundMgr_.GetRingerMode();
    if (ringerMode == AudioStandard::AudioRingerMode::RINGER_MODE_SILENT ||
        (ringerMode == AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL && !hapticsSwitchStatus)) {
        options.muteHaptics = true;
    }
    player_ = audioHapticManager_->CreatePlayer(sourceId_, options);
    CHECK_AND_RETURN_LOG(player_ != nullptr, "Failed to create ringtone player instance");
    player_->SetHapticsMode(ConvertToHapticsMode(settings.mode));
    int32_t result = player_->Prepare();
    if (audioUri == NO_RING_SOUND) {
        MEDIA_LOGI("The incoming audioUri is no_ring_sound.");
        configuredUri_ = NO_RING_SOUND;
        ringtoneState_ = RingtoneState::STATE_NEW;
        result = MSERR_OK;
    }
    CHECK_AND_RETURN_LOG(result == MSERR_OK, "Failed to load source for audio haptic manager");
    configuredUri_ = audioUri;
    configuredHaptcisSettings_ = settings;

    if (callback_ == nullptr) {
        callback_ = std::make_shared<RingtonePlayerCallback>(*this);
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "Failed to create callback object");
    (void)player_->SetAudioHapticPlayerCallback(callback_);
    (void)player_->SetVolume(volume_);
    (void)player_->SetLoop(loop_);

    ringtoneState_ = STATE_NEW;
}

int32_t RingtonePlayerImpl::Configure(const float &volume, const bool &loop)
{
    MEDIA_LOGI("RingtonePlayerImpl::Configure with volume %{public}f, loop %{public}d", volume, loop);
    CHECK_AND_RETURN_RET_LOG(volume >= LOW_VOL && volume <= HIGH_VOL,
        MSERR_INVALID_VAL, "Volume level invalid");

    std::lock_guard<std::mutex> lock(playerMutex_);

    if (configuredUri_ == NO_RING_SOUND && ringtoneState_ == STATE_RUNNING &&
        std::abs(volume - 0.0f) <= std::numeric_limits<float>::epsilon()) {
        MEDIA_LOGI("Set volume to 0.0 for NO_RING_SOUND. Stop vibrator!");
        SystemSoundVibrator::StopVibrator();
        return MSERR_OK;
    }

    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");
    volume_ = volume;
    loop_ = loop;
    (void)player_->SetVolume(volume_);
    (void)player_->SetLoop(loop_);

    return MSERR_OK;
}

int32_t RingtonePlayerImpl::Start(const HapticStartupMode startupMode)
{
    MEDIA_LOGI("RingtonePlayerImpl::Start with startupMode %{public}d", static_cast<int32_t>(startupMode));
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_RUNNING, MSERR_INVALID_OPERATION, "ringtone player is running");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    if (!databaseTool_.isInitialized && !InitDatabaseTool()) {
        MEDIA_LOGE("The database tool is not ready!");
        return ERRCODE_IOERROR;
    }

    MEDIA_LOGI("RingtonePlayerImpl::specifyRingtoneUri_ %{public}s", specifyRingtoneUri_.c_str());
    std::string ringtoneUri = "";
    if (specifyRingtoneUri_ == "") {
        ringtoneUri = systemSoundMgr_.GetRingtoneUri(databaseTool_, type_);
        MEDIA_LOGI("RingtonePlayerImpl::ringtoneUri: %{public}s", ringtoneUri.c_str());
    } else if (specifyRingtoneUri_ == "-1") {
        // The current ringtone is no ringtone.
        ringtoneUri = NO_RING_SOUND;
        MEDIA_LOGI("RingtonePlayerImpl::ringtoneUri: %{public}s", ringtoneUri.c_str());
    } else {
        ringtoneUri = specifyRingtoneUri_;
    }
    if (ringtoneUri == NO_RING_SOUND) {
        MEDIA_LOGI("The ringtoneUri is no_ring_sound.");
        return StartForNoRing(startupMode);
    }
    AudioHapticPlayerOptions options = {false, false};
    ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
    if (startupMode == HapticStartupMode::FAST && NeedToVibrate(settings)) {
        (void)SystemSoundVibrator::StartVibratorForFastMode();
    }
    if (ringtoneUri != configuredUri_ || settings.hapticsUri != configuredHaptcisSettings_.hapticsUri ||
        settings.mode != configuredHaptcisSettings_.mode) {
        MEDIA_LOGI("Ringtone uri changed. Reload player");
        InitPlayer(ringtoneUri, settings, options);
    }
    ReleaseDatabaseTool();
    int32_t ret = player_->Start();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_START_FAILED, "Start failed %{public}d", ret);
    ringtoneState_ = STATE_RUNNING;

    return MSERR_OK;
}

int32_t RingtonePlayerImpl::StartForNoRing(const HapticStartupMode startupMode)
{
    AudioHapticPlayerOptions options = {true, true};
    std::string ringtoneUri = NO_RING_SOUND;
    ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
    if (startupMode == HapticStartupMode::FAST && NeedToVibrate(settings)) {
        (void)SystemSoundVibrator::StartVibratorForFastMode();
    }

    if (ringtoneUri != configuredUri_ || settings.hapticsUri != configuredHaptcisSettings_.hapticsUri ||
        settings.mode != configuredHaptcisSettings_.mode) {
        MEDIA_LOGI("Ringtone uri changed. Reload player");
        InitPlayer(ringtoneUri, settings, options);
    }
    // Start an empty audio stream for NoRing.
    rendererParams_.sampleFormat = AudioStandard::SAMPLE_S24LE;
    rendererParams_.channelCount = AudioStandard::STEREO;
    if (audioRenderer_ == nullptr) {
        audioRenderer_ = AudioStandard::AudioRenderer::Create(AudioStandard::AudioStreamType::STREAM_VOICE_RING);
    }
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "no audioRenderer");
    int32_t audioRet = audioRenderer_->SetParams(rendererParams_);
    bool isStarted = audioRenderer_->Start();
    MEDIA_LOGI("isStarted : %{public}d, audioRet: %{public}d, ", isStarted, audioRet);

    int32_t result = MSERR_OK; // if no need to start vibrator, return MSERR_OK.
    if (NeedToVibrate(settings)) {
        std::string hapticUri = systemSoundMgr_.OpenHapticsUri(databaseTool_, settings.hapticsUri);
        MEDIA_LOGI("need to start vibrator and get the hapticUri as :%{public}s. ", hapticUri.c_str());
        result = SystemSoundVibrator::StartVibratorForRingtone(hapticUri);
    }
    ringtoneState_ = STATE_RUNNING;
    ReleaseDatabaseTool();
    return result;
}

bool RingtonePlayerImpl::NeedToVibrate(const ToneHapticsSettings &settings)
{
    if (settings.mode == NONE || settings.hapticsUri.empty()) {
        MEDIA_LOGI("settings.mode is NONE or hapticsUri is empty!");
        return false;
    }

    AudioStandard::AudioRingerMode ringerMode = systemSoundMgr_.GetRingerMode();
    if (ringerMode == AudioStandard::AudioRingerMode::RINGER_MODE_SILENT) {
        MEDIA_LOGI("The ringer mode is silent!");
        return false;
    }
    if (ringerMode == AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL) {
        bool hapticsSwitchStatus = systemSoundMgr_.CheckVibrateSwitchStatus();
        if (!hapticsSwitchStatus) {
            MEDIA_LOGI("The hapticsSwitchStatus is false!");
            return false;
        }
        return true;
    }

    return true;
}

int32_t RingtonePlayerImpl::Stop()
{
    MEDIA_LOGI("RingtonePlayerImpl::Stop");
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_STOPPED, MSERR_INVALID_OPERATION,
        "ringtone player has been stopped");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    (void)player_->Stop();
    if (configuredUri_ == NO_RING_SOUND && ringtoneState_ == STATE_RUNNING) {
        MEDIA_LOGI("The configuredUri is no_ring_sound and state is running. Stop vibrator!");
        SystemSoundVibrator::StopVibrator();
    }
    if (audioRenderer_ != nullptr) {
        bool isStopped = audioRenderer_->Stop();
        if (!isStopped) {
            MEDIA_LOGE("Failed to stop audioRenderer_ for NO_RING_SOUND");
        }
    }
    ringtoneState_ = STATE_STOPPED;

    return MSERR_OK;
}

int32_t RingtonePlayerImpl::Release()
{
    MEDIA_LOGI("RingtonePlayerImpl::Release");
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_RELEASED, MSERR_INVALID_OPERATION,
        "ringtone player has been released");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    (void)player_->Release();
    if (configuredUri_ == NO_RING_SOUND && ringtoneState_ == STATE_RUNNING) {
        MEDIA_LOGI("The configuredUri is no_ring_sound and state is running. Stop vibrator!");
        SystemSoundVibrator::StopVibrator();
    }
    if (audioRenderer_ != nullptr) {
        bool isReleased = audioRenderer_->Release();
        if (!isReleased) {
            MEDIA_LOGE("Failed to release audioRenderer_ for NO_RING_SOUND");
        }
        audioRenderer_ = nullptr;
    }
    player_ = nullptr;
    callback_ = nullptr;

    if (audioHapticManager_ != nullptr) {
        (void)audioHapticManager_->UnregisterSource(sourceId_);
        audioHapticManager_ = nullptr;
    }
    configuredUri_ = "";

    ringtoneState_ = STATE_RELEASED;
    return MSERR_OK;
}

RingtoneState RingtonePlayerImpl::GetRingtoneState()
{
    MEDIA_LOGI("RingtonePlayerImpl::GetRingtoneState");
    std::lock_guard<std::mutex> lock(playerMutex_);
    return ringtoneState_;
}

int32_t RingtonePlayerImpl::GetAudioRendererInfo(AudioStandard::AudioRendererInfo &rendererInfo) const
{
    MEDIA_LOGI("RingtonePlayerImpl::GetAudioRendererInfo");
    rendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    rendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE;
    rendererInfo.rendererFlags = 0;
    return MSERR_OK;
}

std::string RingtonePlayerImpl::GetTitle()
{
    MEDIA_LOGI("RingtonePlayerImpl::GetTitle");
    CHECK_AND_RETURN_RET_LOG(configuredUri_ != "", "", "Configured uri is null");
    return systemSoundMgr_.GetRingtoneTitle(configuredUri_);
}

int32_t RingtonePlayerImpl::SetRingtonePlayerInterruptCallback(
    const std::shared_ptr<RingtonePlayerInterruptCallback> &interruptCallback)
{
    MEDIA_LOGI("RingtonePlayerImpl::SetRingtonePlayerInterruptCallback");
    std::lock_guard<std::mutex> lock(playerMutex_);
    interruptCallback_ = interruptCallback;
    return MSERR_OK;
}

void RingtonePlayerImpl::NotifyEndofStreamEvent()
{
    std::lock_guard<std::mutex> lock(playerMutex_);
    if (!loop_) {
        ringtoneState_ = RingtoneState::STATE_STOPPED;
    }
}

void RingtonePlayerImpl::NotifyInterruptEvent(const AudioStandard::InterruptEvent &interruptEvent)
{
    if (interruptCallback_ != nullptr) {
        interruptCallback_->OnInterrupt(interruptEvent);
        MEDIA_LOGI("RingtonePlayerImpl::NotifyInterruptEvent");
    } else {
        MEDIA_LOGE("RingtonePlayerImpl::interruptCallback_ is nullptr");
    }
}

int32_t RingtonePlayerImpl::SetRingtoneHapticsFeature(const RingtoneHapticsFeature &feature)
{
    MEDIA_LOGI("RingtonePlayerImpl::SetRingtoneHapticsFeature");
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_RELEASED, MSERR_INVALID_OPERATION,
        "ringtone player has been released");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    HapticsFeature hapticsFeature = static_cast<HapticsFeature>(static_cast<int>(feature));
    int32_t ret = player_->SetHapticsFeature(hapticsFeature);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetRingtoneHapticsFeature error");
    
    return ret;
}

int32_t RingtonePlayerImpl::SetRingtoneHapticsRamp(int32_t duration, float startIntensity, float endIntensity)
{
    MEDIA_LOGI("RingtonePlayerImpl::SetRingtoneHapticsRamp %{public}d, %{public}f, %{public}f",
        duration, startIntensity, endIntensity);

    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_RELEASED, MSERR_INVALID_OPERATION,
        "ringtone player has been released.");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    // duration not less than 100ms
    if (duration < 100) {
        MEDIA_LOGE("RingtonePlayerImpl::SetRingtoneHapticsRamp: the duration value is invalid.");
        return MSERR_INVALID_VAL;
    }

    if (startIntensity < 1.0f || startIntensity > 100.0f) {
        MEDIA_LOGE("RingtonePlayerImpl::SetRingtoneHapticsRamp: the startIntensity value is invalid.");
        return MSERR_INVALID_VAL;
    }

    if (endIntensity < 1.0f || endIntensity > 100.0f) {
        MEDIA_LOGE("RingtonePlayerImpl::SetRingtoneHapticsRamp: the endIntensity value is invalid.");
        return MSERR_INVALID_VAL;
    }

    int32_t result = player_->SetHapticsRamp(duration, startIntensity, endIntensity);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result, "RingtonePlayerImpl::SetRingtoneHapticsRamp error");

    return result;
}

// Callback class symbols
RingtonePlayerCallback::RingtonePlayerCallback(RingtonePlayerImpl &ringtonePlayerImpl)
    : ringtonePlayerImpl_(ringtonePlayerImpl) {}

void RingtonePlayerCallback::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("RingtonePlayerCallback::OnInterrupt: hintTye %{public}d", interruptEvent.hintType);
    ringtonePlayerImpl_.NotifyInterruptEvent(interruptEvent);
}

void RingtonePlayerCallback::OnEndOfStream(void)
{
    MEDIA_LOGI("RingtonePlayerCallback::OnEndOfStream");
    ringtonePlayerImpl_.NotifyEndofStreamEvent();
}

void RingtonePlayerCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError from audio haptic player. errorCode %{public}d", errorCode);
}
} // namesapce Media
} // namespace OHOS
