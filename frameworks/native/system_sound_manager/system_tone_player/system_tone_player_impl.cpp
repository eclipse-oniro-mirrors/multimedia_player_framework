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

#include "system_tone_player_impl.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <thread>

#include "audio_info.h"

#include "system_sound_log.h"
#include "media_errors.h"

using namespace std;
using namespace OHOS::AbilityRuntime;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemTonePlayer"};
}

namespace OHOS {
namespace Media {
const std::string FDHEAD = "fd://";
const std::string AUDIO_FORMAT_STR = ".ogg";
const std::string HAPTIC_FORMAT_STR = ".json";
const int32_t MAX_STREAM_ID = 128;
const int32_t ERRCODE_OPERATION_NOT_ALLOWED = 5400102;
const int32_t ERRCODE_INVALID_PARAMS = 20700002;
const int32_t ERRCODE_UNSUPPORTED_OPERATION = 20700003;
const std::string GENTLE_HAPTIC_PATH = "/sys_prod/resource/media/haptics/gentle/synchronized/notifications";
const std::string RINGTONE_PATH = "/media/audio/";
const std::string STANDARD_HAPTICS_PATH = "/media/haptics/standard/synchronized/";
const std::string GENTLE_HAPTICS_PATH = "/media/haptics/gentle/synchronized/";

static std::string FormateHapticUri(const std::string &audioUri, ToneHapticsFeature feature)
{
    std::string hapticUri = audioUri;
    if (feature == ToneHapticsFeature::GENTLE) {
        hapticUri.replace(0, hapticUri.rfind("/"), GENTLE_HAPTIC_PATH);
    }
    hapticUri.replace(hapticUri.rfind(AUDIO_FORMAT_STR), AUDIO_FORMAT_STR.length(), HAPTIC_FORMAT_STR);
    return hapticUri;
}


static bool IsFileExisting(const std::string &fileUri)
{
    struct stat buffer;
    return (stat(fileUri.c_str(), &buffer) == 0);
}

static std::string FindHapticUriByAudioUri(const std::string &audioUri, ToneHapticsFeature feature,
    bool &isSupported)
{
    std::string hapticUri = "";
    if (audioUri.length() <= AUDIO_FORMAT_STR.length() ||
        audioUri.rfind(AUDIO_FORMAT_STR) != audioUri.length() - AUDIO_FORMAT_STR.length()) {
        MEDIA_LOGW("invalid audio uri: %{public}s", audioUri.c_str());
        isSupported = false;
        return hapticUri;
    }
    // the end of default system tone uri is ".ogg"
    hapticUri = FormateHapticUri(audioUri, feature);
    isSupported = !hapticUri.empty() && IsFileExisting(hapticUri);
    return hapticUri;
}

SystemTonePlayerImpl::SystemTonePlayerImpl(const shared_ptr<Context> &context,
    SystemSoundManagerImpl &systemSoundMgr, SystemToneType systemToneType)
    : context_(context),
      systemSoundMgr_(systemSoundMgr),
      systemToneType_(systemToneType)
{
    audioHapticManager_ = AudioHapticManagerFactory::CreateAudioHapticManager();
    CHECK_AND_RETURN_LOG(audioHapticManager_ != nullptr, "Failed to get audio haptic manager");

    std::string systemToneUri = systemSoundMgr_.GetSystemToneUri(context_, systemToneType_);
    InitPlayer(systemToneUri);
}

SystemTonePlayerImpl::~SystemTonePlayerImpl()
{
    DeleteAllPlayer();
    if (audioHapticManager_ != nullptr) {
        ReleaseHapticsSourceIds();
        audioHapticManager_ = nullptr;
    }
}

int32_t SystemTonePlayerImpl::InitPlayer(const std::string &audioUri)
{
    MEDIA_LOGI("Enter InitPlayer() with audio uri %{public}s", audioUri.c_str());

    ReleaseHapticsSourceIds();
    // Determine whether vibration is needed
    muteHaptics_ = GetMuteHapticsValue();
    // Get the haptic file uri according to the audio file uri.
    InitHapticsSourceIds(audioUri);

    configuredUri_ = audioUri;
    systemToneState_ = SystemToneState::STATE_NEW;
    return MSERR_OK;
}

int32_t SystemTonePlayerImpl::CreatePlayerWithOptions(const AudioHapticPlayerOptions &options)
{
    streamId_++;
    if (streamId_ > MAX_STREAM_ID) {
        streamId_ = 1;
        DeletePlayer(streamId_);
    }

    CHECK_AND_RETURN_RET_LOG(sourceIds_.find(hapticsFeature_) != sourceIds_.end(), MSERR_OPEN_FILE_FAILED,
        "Failed to find suorce id");
    playerMap_[streamId_] = audioHapticManager_->CreatePlayer(sourceIds_[hapticsFeature_], options);
    CHECK_AND_RETURN_RET_LOG(playerMap_[streamId_] != nullptr, MSERR_OPEN_FILE_FAILED,
        "Failed to create system tone player instance");

    callbackMap_[streamId_] = std::make_shared<SystemTonePlayerCallback>(streamId_, shared_from_this());
    CHECK_AND_RETURN_RET_LOG(callbackMap_[streamId_] != nullptr, MSERR_OPEN_FILE_FAILED,
        "Failed to create system tone player callback object");
    (void)playerMap_[streamId_]->SetAudioHapticPlayerCallback(callbackMap_[streamId_]);

    int32_t result = playerMap_[streamId_]->Prepare();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result,
        "Failed to prepare for system tone player: %{public}d", result);
    return MSERR_OK;
}

bool SystemTonePlayerImpl::GetMuteHapticsValue()
{
    bool muteHaptics = false;
    if (systemSoundMgr_.GetRingerMode() == AudioStandard::AudioRingerMode::RINGER_MODE_SILENT) {
        muteHaptics = true;
    }
    return muteHaptics;
}

std::string SystemTonePlayerImpl::GetNewHapticUriForAudioUri(const std::string &audioUri,
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

void SystemTonePlayerImpl::GetNewHapticUriForAudioUri(const std::string &audioUri,
    std::map<ToneHapticsFeature, std::string> &hapticsUriMap)
{
    supportedHapticsFeatures_.clear();
    std::string currAudioUri = audioUri;
    std::string hapticUri = GetNewHapticUriForAudioUri(audioUri, RINGTONE_PATH, STANDARD_HAPTICS_PATH);
    if (hapticUri.empty()) {
        currAudioUri = systemSoundMgr_.GetDefaultSystemToneUri(SYSTEM_TONE_TYPE_NOTIFICATION);
        hapticUri = GetNewHapticUriForAudioUri(currAudioUri, RINGTONE_PATH, STANDARD_HAPTICS_PATH);
        if (hapticUri.empty()) {
            MEDIA_LOGW("Failed to find the default json file.");
            return;
        }
        muteHaptics_ = true;
        MEDIA_LOGW("haptic uri is empty. Play system tone without vibration");
    }
    supportedHapticsFeatures_.push_back(ToneHapticsFeature::STANDARD);
    hapticsUriMap[ToneHapticsFeature::STANDARD] = hapticUri;
    MEDIA_LOGI("GetNewHapticUriForAudioUri: STANDARD hapticUri %{public}s ", hapticUri.c_str());
    hapticUri = GetNewHapticUriForAudioUri(currAudioUri, RINGTONE_PATH, GENTLE_HAPTICS_PATH);
    if (!hapticUri.empty()) {
        supportedHapticsFeatures_.push_back(ToneHapticsFeature::GENTLE);
        hapticsUriMap[ToneHapticsFeature::GENTLE] = hapticUri;
        MEDIA_LOGI("GetNewHapticUriForAudioUri: GENTLE hapticUri %{public}s ", hapticUri.c_str());
    }
}

void SystemTonePlayerImpl::GetHapticUriForAudioUri(const std::string &audioUri,
    std::map<ToneHapticsFeature, std::string> &hapticsUriMap)
{
    supportedHapticsFeatures_.clear();
    bool isSupported = false;
    std::string currAudioUri = audioUri;
    std::string hapticUri = FindHapticUriByAudioUri(currAudioUri, ToneHapticsFeature::STANDARD, isSupported);
    if (!isSupported) {
        MEDIA_LOGW("Failed to find the vibration json file for audioUri. Use the default json file.");
        currAudioUri = systemSoundMgr_.GetDefaultSystemToneUri(SYSTEM_TONE_TYPE_NOTIFICATION);
        hapticUri = FindHapticUriByAudioUri(currAudioUri, ToneHapticsFeature::STANDARD, isSupported);
        if (!isSupported) {
            MEDIA_LOGW("Failed to find the default json file.");
            return;
        }
        muteHaptics_ = true;
        MEDIA_LOGW("haptic uri is empty. Play system tone without vibration");
    }
    supportedHapticsFeatures_.push_back(ToneHapticsFeature::STANDARD);
    hapticsUriMap[ToneHapticsFeature::STANDARD] = hapticUri;
    MEDIA_LOGI("GetHapticUriForAudioUri: STANDARD hapticUri %{public}s ", hapticUri.c_str());
    hapticUri = FindHapticUriByAudioUri(currAudioUri, ToneHapticsFeature::GENTLE, isSupported);
    if (isSupported) {
        supportedHapticsFeatures_.push_back(ToneHapticsFeature::GENTLE);
        hapticsUriMap[ToneHapticsFeature::GENTLE] = hapticUri;
        MEDIA_LOGI("GetHapticUriForAudioUri: GENTLE hapticUri %{public}s ", hapticUri.c_str());
    }
}

static shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, RINGTONE_URI);
}

std::string SystemTonePlayerImpl::ChangeUri(const std::string &uri)
{
    std::string systemtoneUri = uri;
    size_t found = uri.find(RINGTONE_CUSTOMIZED_BASE_PATH);
    if (found != std::string::npos) {
        std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
            CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
        CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, uri, "Failed to create dataShareHelper.");
        DataShare::DatashareBusinessError businessError;
        DataShare::DataSharePredicates queryPredicates;
        Uri ringtonePathUri(RINGTONE_PATH_URI);
        vector<string> columns = {{RINGTONE_COLUMN_TONE_ID}, {RINGTONE_COLUMN_DATA}};
        queryPredicates.EqualTo(RINGTONE_COLUMN_DATA, uri);
        auto resultSet = dataShareHelper->Query(ringtonePathUri, queryPredicates, columns, &businessError);
        auto results = make_unique<RingtoneFetchResult<RingtoneAsset>>(move(resultSet));
        unique_ptr<RingtoneAsset> ringtoneAsset = results->GetFirstObject();
        if (ringtoneAsset != nullptr) {
            string uriStr = RINGTONE_PATH_URI + RINGTONE_SLASH_CHAR + to_string(ringtoneAsset->GetId());
            Uri ofUri(uriStr);
            int32_t fd = dataShareHelper->OpenFile(ofUri, "r");
            if (fd > 0) {
                systemtoneUri = FDHEAD + to_string(fd);
            }
        }
        resultSet == nullptr ? : resultSet->Close();
        dataShareHelper->Release();
    }
    MEDIA_LOGI("SystemTonePlayerImpl::ChangeUri systemtoneUri is %{public}s", systemtoneUri.c_str());
    return systemtoneUri;
}

int32_t SystemTonePlayerImpl::Prepare()
{
    MEDIA_LOGI("Enter Prepare()");
    std::lock_guard<std::mutex> lock(systemTonePlayerMutex_);
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, MSERR_INVALID_STATE,
        "System tone player has been released!");

    std::string systemToneUri = systemSoundMgr_.GetSystemToneUri(context_, systemToneType_);
    if (!configuredUri_.empty() && configuredUri_ == systemToneUri) {
        MEDIA_LOGI("The right system tone uri has been registered. Return directly.");
        systemToneState_ = SystemToneState::STATE_PREPARED;
        return MSERR_OK;
    }

    // reload audio haptic player for system tone.
    int32_t result = InitPlayer(systemToneUri);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, result,
        "Failed to init player for system tone player: %{public}d", result);
    systemToneState_ = SystemToneState::STATE_PREPARED;
    return result;
}

int32_t SystemTonePlayerImpl::Start()
{
    MEDIA_LOGI("Enter Start()");
    SystemToneOptions systemToneOptions = {false, false};
    return Start(systemToneOptions);
}

int32_t SystemTonePlayerImpl::Start(const SystemToneOptions &systemToneOptions)
{
    MEDIA_LOGI("Enter Start() with systemToneOptions: muteAudio %{public}d, muteHaptics %{public}d",
        systemToneOptions.muteAudio, systemToneOptions.muteHaptics);
    std::lock_guard<std::mutex> lock(systemTonePlayerMutex_);
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, MSERR_INVALID_STATE,
        "System tone player has been released!");

    int32_t result = MSERR_OK;
    bool actualMuteHaptics = systemToneOptions.muteHaptics || muteHaptics_;
    AudioHapticPlayerOptions actualOptions = {systemToneOptions.muteAudio, actualMuteHaptics};
    result = CreatePlayerWithOptions(actualOptions);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, -1,
        "Failed to create audio haptic player: %{public}d", result);

    result = playerMap_[streamId_]->SetVolume(volume_);
    result = playerMap_[streamId_]->Start();
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, -1,
        "Failed to start audio haptic player: %{public}d", result);
    return streamId_;
}

int32_t SystemTonePlayerImpl::Stop(const int32_t &streamId)
{
    MEDIA_LOGI("Enter Stop() with streamId %{public}d", streamId);
    std::lock_guard<std::mutex> lock(systemTonePlayerMutex_);
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, MSERR_INVALID_STATE,
        "System tone player has been released!");

    if (playerMap_.count(streamId) == 0) {
        MEDIA_LOGW("The stream has been stopped or the id %{public}d is invalid.", streamId);
        return MSERR_OK;
    }

    int32_t result = playerMap_[streamId]->Stop();
    DeletePlayer(streamId);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, MSERR_INVALID_OPERATION,
        "Failed to stop audio haptic player: %{public}d", result);
    return result;
}

int32_t SystemTonePlayerImpl::Release()
{
    MEDIA_LOGI("Enter Release()");
    std::lock_guard<std::mutex> lock(systemTonePlayerMutex_);
    if (systemToneState_ == SystemToneState::STATE_RELEASED) {
        MEDIA_LOGW("System tone player has been released!");
        return MSERR_OK;
    }
    DeleteAllPlayer();
    streamId_ = 0;
    configuredUri_ = "";

    if (audioHapticManager_ != nullptr) {
        ReleaseHapticsSourceIds();
        audioHapticManager_ = nullptr;
    }
    hapticsFeature_ = ToneHapticsFeature::STANDARD;
    volume_ = SYS_TONE_PLAYER_MAX_VOLUME;
    systemToneState_ = SystemToneState::STATE_RELEASED;
    return MSERR_OK;
}

std::string SystemTonePlayerImpl::GetTitle() const
{
    MEDIA_LOGI("Enter GetTitle()");
    std::string uri = systemSoundMgr_.GetSystemToneUri(context_, systemToneType_);
    return uri.substr(uri.find_last_of("/") + 1);
}

void SystemTonePlayerImpl::DeletePlayer(const int32_t &streamId)
{
    MEDIA_LOGI("DeletePlayer for streamId %{public}d", streamId);
    if (playerMap_.count(streamId) > 0) {
        playerMap_[streamId]->Release();
        playerMap_.erase(streamId);
    }
    if (callbackMap_.count(streamId) > 0) {
        callbackMap_.erase(streamId);
    }
    MEDIA_LOGI("DeletePlayer. playerMap_.size() %{public}zu  callbackMap_.size() %{public}zu ",
        playerMap_.size(), callbackMap_.size());
}

void SystemTonePlayerImpl::DeleteAllPlayer()
{
    MEDIA_LOGI("Delete all audio haptic player!");
    for (auto iter = playerMap_.begin(); iter != playerMap_.end(); iter++) {
        iter->second->Release();
    }
    playerMap_.clear();
    callbackMap_.clear();
}

void SystemTonePlayerImpl::NotifyEndofStreamEvent(const int32_t &streamId)
{
    std::lock_guard<std::mutex> lock(systemTonePlayerMutex_);
    // onPlayFinished for a stream.
    DeletePlayer(streamId);
}

void SystemTonePlayerImpl::NotifyInterruptEvent(const int32_t &streamId,
    const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGW("Interrupt event is not supported for system tone player!");
}

// Callback class symbols
SystemTonePlayerCallback::SystemTonePlayerCallback(int32_t streamId,
    std::shared_ptr<SystemTonePlayerImpl> systemTonePlayerImpl)
{
    streamId_ = streamId;
    systemTonePlayerImpl_ = systemTonePlayerImpl;
}

void SystemTonePlayerCallback::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("OnInterrupt from audio haptic player: hintTye %{public}d", interruptEvent.hintType);
    std::shared_ptr<SystemTonePlayerImpl> player = systemTonePlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyInterruptEvent(streamId_, interruptEvent);
}

void SystemTonePlayerCallback::OnEndOfStream(void)
{
    MEDIA_LOGI("OnEndOfStream from audio haptic player. StreamId %{public}d", streamId_);
    std::shared_ptr<SystemTonePlayerImpl> player = systemTonePlayerImpl_.lock();
    if (player == nullptr) {
        MEDIA_LOGE("The audio haptic player has been released.");
        return;
    }
    player->NotifyEndofStreamEvent(streamId_);
}

void SystemTonePlayerCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError from audio haptic player. errorCode %{public}d", errorCode);
}

static bool IsValidVolume(float &scale)
{
    static float eps = 1e-5;
    static float maxVal = 1;
    static float minVal = 0;
    if (scale >= minVal || scale <= maxVal) {
        return true;
    }
    if (scale > maxVal && abs(scale - maxVal) < eps) {
        scale = maxVal;
        return true;
    }
    if (scale < minVal && abs(scale - minVal) < eps) {
        scale = minVal;
        return true;
    }
    return false;
}

int32_t SystemTonePlayerImpl::SetAudioVolume(float volume)
{
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, ERRCODE_OPERATION_NOT_ALLOWED,
        "System tone player has been released!");
    CHECK_AND_RETURN_RET_LOG(IsValidVolume(volume), ERRCODE_INVALID_PARAMS,
        "Invliad volume, the volume must be in the [0, 1] range");
    volume_ = volume;
    return MSERR_OK;
}

int32_t SystemTonePlayerImpl::GetAudioVolume(float &recvValue)
{
    recvValue = volume_;
    return MSERR_OK;
}

int32_t SystemTonePlayerImpl::GetSupportHapticsFeatures(std::vector<ToneHapticsFeature> &recvFeatures)
{
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, ERRCODE_UNSUPPORTED_OPERATION,
        "System tone player has been released!");
    recvFeatures = supportedHapticsFeatures_;
    return MSERR_OK;
}

int32_t SystemTonePlayerImpl::SetHapticsFeature(ToneHapticsFeature feature)
{
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, ERRCODE_OPERATION_NOT_ALLOWED,
        "System tone player has been released!");
    CHECK_AND_RETURN_RET_LOG((feature == ToneHapticsFeature::STANDARD || feature == ToneHapticsFeature::GENTLE) &&
        std::find(supportedHapticsFeatures_.begin(),
        supportedHapticsFeatures_.end(), feature) != supportedHapticsFeatures_.end(),
        ERRCODE_UNSUPPORTED_OPERATION, "Unsupport haptics features %{public}d", feature);
    hapticsFeature_ = feature;
    return MSERR_OK;
}

int32_t SystemTonePlayerImpl::GetHapticsFeature(ToneHapticsFeature &feature)
{
    CHECK_AND_RETURN_RET_LOG(systemToneState_ != SystemToneState::STATE_RELEASED, ERRCODE_UNSUPPORTED_OPERATION,
        "System tone player has been released!");
    feature = hapticsFeature_;
    return MSERR_OK;
}

void SystemTonePlayerImpl::InitHapticsSourceIds(const std::string &audioUri)
{
    if (audioHapticManager_ == nullptr) {
        return;
    }
    std::map<ToneHapticsFeature, std::string> uriMap;
    GetNewHapticUriForAudioUri(audioUri, uriMap);
    if (uriMap.empty()) {
        GetHapticUriForAudioUri(audioUri, uriMap);
    }
    int32_t sourceId;
    for (auto it = uriMap.begin(); it != uriMap.end(); ++it) {
        sourceId = audioHapticManager_->RegisterSource(ChangeUri(audioUri), it->second);
        CHECK_AND_CONTINUE_LOG(sourceId != -1, "Failed to register source for audio haptic manager");
        (void)audioHapticManager_->SetAudioLatencyMode(sourceId, AUDIO_LATENCY_MODE_NORMAL);
        (void)audioHapticManager_->SetStreamUsage(sourceId, AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION);
        sourceIds_[it->first] = sourceId;
    }
}

void SystemTonePlayerImpl::ReleaseHapticsSourceIds()
{
    for (auto it = sourceIds_.begin(); it != sourceIds_.end(); ++it) {
        if (it->second != -1) {
            audioHapticManager_->UnregisterSource(it->second);
            it->second = -1;
        }
    }
}
} // namesapce AudioStandard
} // namespace OHOS
