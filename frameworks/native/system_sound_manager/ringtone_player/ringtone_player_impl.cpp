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
#include "config_policy_utils.h"

#include "ringtone_proxy_uri.h"
#include "directory_ex.h"
#include "system_sound_log.h"
#include "system_sound_vibrator.h"
#include "media_errors.h"

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

RingtonePlayerImpl::RingtonePlayerImpl(const shared_ptr<Context> &context,
    SystemSoundManagerImpl &sysSoundMgr, RingtoneType type)
    : volume_(HIGH_VOL),
      loop_(false),
      context_(context),
      systemSoundMgr_(sysSoundMgr),
      type_(type)
{
    audioHapticManager_ = AudioHapticManagerFactory::CreateAudioHapticManager();
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to get audio haptic manager");

    if (InitDataShareHelper()) {
        std::string ringtoneUri = systemSoundMgr_.GetRingtoneUri(context_, type_);
        AudioHapticPlayerOptions options = {false, false};
        ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
        InitPlayer(ringtoneUri, settings, options);
        ReleaseDataShareHelper();
    }
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
    audioHapticManager_ = AudioHapticManagerFactory::CreateAudioHapticManager();
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to get audio haptic manager");

    if (InitDataShareHelper()) {
        AudioHapticPlayerOptions options = {false, false};
        ToneHapticsSettings settings = GetHapticSettings(specifyRingtoneUri_, options.muteHaptics);
        InitPlayer(specifyRingtoneUri_, settings, options);
        ReleaseDataShareHelper();
    }
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
    ReleaseDataShareHelper();
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
        MEDIA_LOGW("Failed to find the vibration json file for audioUri. Use the default json file.");
        std::string currAudioUri = systemSoundMgr_.GetDefaultRingtoneUri(RINGTONE_TYPE_SIM_CARD_0);
        return GetNewHapticUriForAudioUri(currAudioUri, RINGTONE_PATH, STANDARD_HAPTICS_PATH);
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
        MEDIA_LOGW("Failed to find the vibration json file for audioUri. Use the default json file.");
        std::string defaultRingtoneUri = systemSoundMgr_.GetDefaultRingtoneUri(RINGTONE_TYPE_SIM_CARD_0);
        if (defaultRingtoneUri.length() > AUDIO_FORMAT_STR.length() &&
            defaultRingtoneUri.rfind(AUDIO_FORMAT_STR) == defaultRingtoneUri.length() - AUDIO_FORMAT_STR.length()) {
            // the end of default ringtone uri is ".ogg"
            hapticUri = defaultRingtoneUri;
            hapticUri.replace(hapticUri.rfind(AUDIO_FORMAT_STR), AUDIO_FORMAT_STR.length(), HAPTIC_FORMAT_STR);
        } else {
            MEDIA_LOGW("The default ringtone uri is invalid!");
        }
    }

    return hapticUri;
}

static shared_ptr<DataShare::DataShareHelper> CreateDataShareHelperUri(int32_t systemAbilityId)
{
    MEDIA_LOGI("CreateDataShareHelperUri : Enter the CreateDataShareHelperUri interface");
    DataShare::CreateOptions options;
    options.enabled_ = true;
    return DataShare::DataShareHelper::Creator(RINGTONE_LIBRARY_PROXY_URI, options);
}

bool RingtonePlayerImpl::InitDataShareHelper()
{
    MEDIA_LOGD("Enter InitDataShareHelper()");
    ReleaseDataShareHelper();
    dataShareHelper_ = CreateDataShareHelperUri(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, false, "Failed to create dataShareHelper.");
    return true;
}

void RingtonePlayerImpl::ReleaseDataShareHelper()
{
    if (dataShareHelper_ != nullptr) {
        MEDIA_LOGD("Enter ReleaseDataShareHelper()");
        dataShareHelper_->Release();
        dataShareHelper_ = nullptr;
    }
}

std::string RingtonePlayerImpl::ChangeUri(const std::string &audioUri)
{
    const std::string FDHEAD = "fd://";
    std::string ringtoneUri = audioUri;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, ringtoneUri, "Failed to init dataShareHelper_.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    Uri ringtonePathUri(RINGTONE_PATH_URI);
    vector<string> columns = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, audioUri);
    auto resultSet = dataShareHelper_->Query(ringtonePathUri, queryPredicates, columns, &businessError);
    auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
    unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
    if (ringtoneAsset != nullptr) {
        string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
        MEDIA_LOGD("ChangeUri::Open ringtoneUri is %{public}s", uriStr.c_str());
        Uri ofUri(uriStr);
        int32_t fd = dataShareHelper_->OpenFile(ofUri, "r");
        if (fd > 0) {
            ringtoneUri = FDHEAD + to_string(fd);
        }
    }

    resultSet == nullptr ? : resultSet->Close();
    MEDIA_LOGI("RingtonePlayerImpl::ChangeUri ringtoneUri is %{public}s", ringtoneUri.c_str());
    return ringtoneUri;
}

std::string RingtonePlayerImpl::ChangeHapticsUri(const std::string &hapticsUri)
{
    const std::string FDHEAD = "fd://";
    std::string newHapticsUri = hapticsUri;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, newHapticsUri, "Failed to create dataShareHelper.");

    DataShare::DatashareBusinessError businessError;
    DataShare::DataSharePredicates queryPredicates;
    Uri hapticsPathUri(RINGTONE_LIBRARY_PROXY_DATA_URI_VIBATE_FILES);
    vector<string> columns = {{VIBRATE_COLUMN_VIBRATE_ID}, {VIBRATE_COLUMN_DATA}};
    queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, hapticsUri);
    auto resultSet = dataShareHelper_->Query(hapticsPathUri, queryPredicates, columns, &businessError);
    auto results = make_unique<RingtoneFetchResult<VibrateAsset>>(move(resultSet));

    unique_ptr<VibrateAsset> vibrateAssetByUri = results->GetFirstObject();
    if (vibrateAssetByUri != nullptr) {
        string absFilePath;
        PathToRealPath(hapticsUri, absFilePath);
        int32_t fd = open(absFilePath.c_str(), O_RDONLY);
        if (fd > 0) {
            newHapticsUri = FDHEAD + to_string(fd);
        }
    }

    resultSet == nullptr ? : resultSet->Close();
    MEDIA_LOGI("RingtonePlayerImpl::ChangeHapticsUri newHapticsUri is %{public}s", newHapticsUri.c_str());
    return newHapticsUri;
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
    int32_t result = systemSoundMgr_.GetToneHapticsSettings(dataShareHelper_, audioUri,
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
    string newAudioUri = ChangeUri(audioUri);
    string newHapticUri = ChangeHapticsUri(hapticUri);

    int32_t sourceId = audioHapticManager_->RegisterSource(newAudioUri, newHapticUri);

    const std::string fdHead = "fd://";
    if (newAudioUri.find(fdHead) != std::string::npos) {
        int32_t fd = atoi(newAudioUri.substr(fdHead.size()).c_str());
        if (fd > 0) {
            close(fd);
        }
    }
    if (newHapticUri.find(fdHead) != std::string::npos) {
        int32_t fd = atoi(newHapticUri.substr(fdHead.size()).c_str());
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
        if (!configuredUri_.empty() && configuredUri_ == audioUri) {
            MEDIA_LOGI("The right ring tone uri has been registered. Return directly.");
            ringtoneState_ = RingtoneState::STATE_PREPARED;
        }
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

    if (configuredUri_ == NO_RING_SOUND && ringtoneState_ == STATE_RUNNING) {
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

int32_t RingtonePlayerImpl::Start()
{
    MEDIA_LOGI("RingtonePlayerImpl::Start");
    std::lock_guard<std::mutex> lock(playerMutex_);
    CHECK_AND_RETURN_RET_LOG(ringtoneState_ != STATE_RUNNING, MSERR_INVALID_OPERATION, "ringtone player is running");
    CHECK_AND_RETURN_RET_LOG(player_ != nullptr && ringtoneState_ != STATE_INVALID, MSERR_INVALID_VAL, "no player_");

    if (!InitDataShareHelper()) {
        return ERRCODE_IOERROR;
    }

    MEDIA_LOGI("RingtonePlayerImpl::specifyRingtoneUri_  %{public}s", specifyRingtoneUri_.c_str());
    std::string ringtoneUri = "";
    if (specifyRingtoneUri_ == "") {
        ringtoneUri = systemSoundMgr_.GetRingtoneUri(context_, type_);
        MEDIA_LOGI("RingtonePlayerImpl::ringtoneUri: %{public}s", ringtoneUri.c_str());
    //The current ringtone is no ringtone
    } else if (specifyRingtoneUri_ == "-1") {
        ringtoneUri = NO_RING_SOUND;
        MEDIA_LOGI("RingtonePlayerImpl::ringtoneUri: %{public}s", ringtoneUri.c_str());
    } else {
        ringtoneUri = specifyRingtoneUri_;
    }
    if (ringtoneUri == NO_RING_SOUND) {
        AudioHapticPlayerOptions options = {true, true};
        ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
        InitPlayer(ringtoneUri, settings, options);
        std::string hapticUri = ChangeHapticsUri(settings.hapticsUri);
        rendererParams_.sampleFormat = AudioStandard::SAMPLE_S24LE;
        rendererParams_.channelCount = AudioStandard::STEREO;
        audioRenderer_ = AudioStandard::AudioRenderer::Create(AudioStandard::AudioStreamType::STREAM_VOICE_RING);
        CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "no audioRenderer");
        int32_t ret = audioRenderer_->SetParams(rendererParams_);
        bool isStarted = audioRenderer_->Start();
        ringtoneState_ = isStarted ? STATE_RUNNING : ringtoneState_;
        MEDIA_LOGI("isStarted : %{public}d, ret: %{public}d, ", isStarted, ret);
        return SystemSoundVibrator::StartVibratorForRingtone(hapticUri);
    }
    AudioHapticPlayerOptions options = {false, false};
    ToneHapticsSettings settings = GetHapticSettings(ringtoneUri, options.muteHaptics);
    if (ringtoneUri != configuredUri_ || settings.hapticsUri != configuredHaptcisSettings_.hapticsUri ||
        settings.mode != configuredHaptcisSettings_.mode) {
        MEDIA_LOGI("Ringtone uri changed. Reload player");
        InitPlayer(ringtoneUri, settings, options);
    }
    ReleaseDataShareHelper();
    int32_t ret = player_->Start();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_START_FAILED, "Start failed %{public}d", ret);
    ringtoneState_ = STATE_RUNNING;

    return MSERR_OK;
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
    ringtoneState_ = RingtoneState::STATE_STOPPED;
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
} // namesapce AudioStandard
} // namespace OHOS
