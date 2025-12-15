/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "system_sound_player_impl.h"

#include <fcntl.h>

#include "audio_system_manager.h"
#include "directory_ex.h"
#include "system_sound_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundPlayer"};
}

namespace OHOS {
namespace Media {
constexpr int32_t MAX_SOUND_POOL_STREAMS = 1;
constexpr int32_t LOAD_WAIT_SECONDS = 2;
const std::string FDHEAD = "fd://";

SystemSoundPlayerImpl::SystemSoundPlayerImpl()
{
    MEDIA_LOGI("Construtor");
}

SystemSoundPlayerImpl::~SystemSoundPlayerImpl()
{
    MEDIA_LOGI("Destructor");
    if (!isReleased_) {
        (void)ReleaseInternal();
    }
}

bool SystemSoundPlayerImpl::IsSystemSoundTypeValid(SystemSoundType systemSoundType)
{
    bool result = false;
    switch (systemSoundType) {
        case PHOTO_SHUTTER:
        case VIDEO_RECORDING_BEGIN:
        case VIDEO_RECORDING_END:
            result = true;
            break;
        default:
            MEDIA_LOGW("The systemSoundType %{public}d is invalid!", systemSoundType);
            break;
    }
    return result;
}

bool SystemSoundPlayerImpl::InitSoundPoolPlayer()
{
    if (soundPool_ != nullptr) {
        MEDIA_LOGW("The sound pool player has been initialized!");
        return true;
    }

    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRenderInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = AudioStandard::AUDIO_FLAG_NORMAL;
    soundPool_ = SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRenderInfo);
    if (soundPool_ == nullptr) {
        MEDIA_LOGE("Failed to create sound pool!");
        return false;
    }

    soundPoolCallback_ = std::make_shared<PlayerSoundPoolCallback>(shared_from_this());
    if (soundPoolCallback_ == nullptr) {
        MEDIA_LOGE("Failed to create PlayerSoundPoolCallback!");
        soundPool_ = nullptr;
        return false;
    }
    soundPool_->SetSoundPoolCallback(soundPoolCallback_);
    return true;
}

int32_t SystemSoundPlayerImpl::Load(SystemSoundType systemSoundType)
{
    if (!IsSystemSoundTypeValid(systemSoundType)) {
        MEDIA_LOGE("The systemSoundType %{public}d is invalid!", systemSoundType);
        return ERRCODE_INVALID_PARAM;
    }

    MEDIA_LOGI("Load the systemSoundType: %{public}d", systemSoundType);
    std::lock_guard<std::mutex> lock(systemSoundPlayerMutex_);
    CHECK_AND_RETURN_RET_LOG(!isReleased_, ERRCODE_SYSTEM_ERROR, "The SystemSoundPlayer has been released!");

    if (soundIds_.count(systemSoundType) > 0 && soundIds_[systemSoundType] >= 0) {
        MEDIA_LOGI("The systemSoundType: %{public}d has been loaded.", systemSoundType);
        return SSP_SUCCESS;
    }
    // Get the system sound path
    std::string filePath = AudioStandard::AudioSystemManager::GetInstance()->
        GetSystemSoundPath(static_cast<int32_t>(systemSoundType));
    CHECK_AND_RETURN_RET_LOG(filePath != "", ERRCODE_IO_ERROR, "Failed to get system sound path!");

    // Load file with sound pool
    if (soundPool_ == nullptr && !InitSoundPoolPlayer()) {
        MEDIA_LOGE("Failed to init sound pool player!");
        return ERRCODE_SYSTEM_ERROR;
    }

    int32_t fileFd = OpenSystemSoundFile(filePath);
    CHECK_AND_RETURN_RET_LOG(fileFd >= 0, ERRCODE_IO_ERROR, "Failed to OpenSystemSoundFile!");

    int32_t soundId = soundPool_->Load(FDHEAD + std::to_string(fileFd));
    if (soundId < 0) {
        MEDIA_LOGE("Load: Failed to load soundPool uri.");
        close(fileFd);
        return ERRCODE_IO_ERROR;
    }
    std::unique_lock<std::mutex> loadLock(loadMutex_);
    isLoadCompleted_ = false; // The flag needs to be reset because the Load function can be called repeatedly.
    loadCond_.wait_for(loadLock, std::chrono::seconds(LOAD_WAIT_SECONDS),
        [this]() { return isLoadCompleted_ || isReleased_; });
    if (isReleased_) {
        MEDIA_LOGE("The sound pool is released when it is preparing.");
        close(fileFd);
        return ERRCODE_SYSTEM_ERROR;
    }
    if (!isLoadCompleted_) {
        MEDIA_LOGE("Failed to load audio uri: time out.");
        close(fileFd);
        return ERRCODE_IO_ERROR;
    }

    MEDIA_LOGI("Load the systemSoundType: %{public}d successfully. soundId: %{public}d", systemSoundType, soundId);
    soundIds_[systemSoundType] = soundId;
    soundFds_[systemSoundType] = fileFd;
    return SSP_SUCCESS;
}

int32_t SystemSoundPlayerImpl::OpenSystemSoundFile(const std::string &filePath)
{
    std::string absFilePath = "";
    CHECK_AND_RETURN_RET_LOG(PathToRealPath(filePath, absFilePath), -1,
        "file is not real path, file path: %{private}s", filePath.c_str());
    CHECK_AND_RETURN_RET_LOG(!absFilePath.empty(), -1,
        "Failed to obtain the canonical path for source path %{public}d %{private}s",
        errno, filePath.c_str());

    int32_t fd = open(absFilePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        MEDIA_LOGE("Failed to OpenSystemSoundFile!");
        return -1;
    }
    return fd;
}

int32_t SystemSoundPlayerImpl::Play(SystemSoundType systemSoundType)
{
    if (!IsSystemSoundTypeValid(systemSoundType)) {
        MEDIA_LOGE("The systemSoundType %{public}d is invalid!", systemSoundType);
        return ERRCODE_INVALID_PARAM;
    }

    MEDIA_LOGI("Play the systemSoundType: %{public}d", systemSoundType);
    std::lock_guard<std::mutex> lock(systemSoundPlayerMutex_);
    if (isReleased_) {
        MEDIA_LOGE("The SystemSoundPlayer has been released!");
        return ERRCODE_SYSTEM_ERROR;
    }
    if (soundIds_.count(systemSoundType) == 0 || soundIds_[systemSoundType] < 0) {
        MEDIA_LOGE("The systemSoundType: %{public}d is not loaded!", systemSoundType);
        return ERRCODE_IO_ERROR;
    }
    PlayParams playParams {
        .loop = 0,
        .rate = 0, // default AudioRendererRate::RENDER_RATE_NORMAL
        .leftVolume = 1.0,
        .rightVolume = 1.0,
        .priority = 0,
        .parallelPlayFlag = true, // mix with others
    };
    int32_t streamId = soundPool_->Play(soundIds_[systemSoundType], playParams);
    if (streamId == 0) {
        MEDIA_LOGE("Failed to play the systemSoundType: %{public}d", systemSoundType);
        return ERRCODE_SYSTEM_ERROR;
    }
    return SSP_SUCCESS;
}

int32_t SystemSoundPlayerImpl::Unload(SystemSoundType systemSoundType)
{
    if (!IsSystemSoundTypeValid(systemSoundType)) {
        MEDIA_LOGE("The systemSoundType %{public}d is invalid!", systemSoundType);
        return ERRCODE_INVALID_PARAM;
    }

    MEDIA_LOGI("Unload the systemSoundType: %{public}d", systemSoundType);
    std::lock_guard<std::mutex> lock(systemSoundPlayerMutex_);
    if (isReleased_) {
        MEDIA_LOGE("The SystemSoundPlayer has been released!");
        return ERRCODE_SYSTEM_ERROR;
    }
    if (soundIds_.count(systemSoundType) == 0) {
        MEDIA_LOGW("The systemSoundType: %{public}d has been unloaded!", systemSoundType);
        return SSP_SUCCESS;
    }

    int32_t result = soundPool_->Unload(soundIds_[systemSoundType]);
    if (result != SSP_SUCCESS) {
        MEDIA_LOGE("Failed to unload the systemSoundType: %{public}d", systemSoundType);
        return ERRCODE_SYSTEM_ERROR;
    }
    soundIds_.erase(systemSoundType);
    if (soundFds_.count(systemSoundType) != 0) {
        if (soundFds_[systemSoundType] >= 0) {
            close(soundFds_[systemSoundType]);
        }
        soundFds_.erase(systemSoundType);
    }
    return SSP_SUCCESS;
}

int32_t SystemSoundPlayerImpl::Release()
{
    MEDIA_LOGI("Release in");
    std::lock_guard<std::mutex> lock(systemSoundPlayerMutex_);
    if (isReleased_) {
        MEDIA_LOGW("The SystemSoundPlayer has been released!");
        return SSP_SUCCESS;
    }
    return ReleaseInternal();
}

int32_t SystemSoundPlayerImpl::ReleaseInternal()
{
    MEDIA_LOGI("ReleaseInternal in");
    {
        std::lock_guard<std::mutex> loadLock(loadMutex_);
        isReleased_ = true;
        loadCond_.notify_all();
    }
    if (soundPool_ != nullptr) {
        (void)soundPool_->Release();
        soundPool_ = nullptr;
    }
    soundPoolCallback_ = nullptr;

    soundIds_.clear();
    for (auto &[systemSoundType, fd] : soundFds_) {
        if (fd >= 0) {
            close(fd);
        }
    }
    return SSP_SUCCESS;
}

void SystemSoundPlayerImpl::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("soundId: %{public}d", soundId);
    std::lock_guard<std::mutex> loadLock(loadMutex_);
    isLoadCompleted_ = true;
    loadCond_.notify_all();
}

void SystemSoundPlayerImpl::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("streamID: %{public}d", streamID);
}

void SystemSoundPlayerImpl::OnError(int32_t errorCode)
{
    MEDIA_LOGI("errorCode: %{public}d", errorCode);
}

// PlayerSoundPoolCallback class symbols
PlayerSoundPoolCallback::PlayerSoundPoolCallback(std::shared_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl)
    : systemSoundPlayerImpl_(systemSoundPlayerImpl) {}

void PlayerSoundPoolCallback::OnLoadCompleted(int32_t soundId)
{
    MEDIA_LOGI("OnLoadCompleted reported from sound pool. soundId: %{public}d", soundId);
    std::shared_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl = systemSoundPlayerImpl_.lock();
    if (systemSoundPlayerImpl == nullptr) {
        MEDIA_LOGE("The systemSoundPlayerImpl has been released.");
        return;
    }
    systemSoundPlayerImpl->OnLoadCompleted(soundId);
}

void PlayerSoundPoolCallback::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("OnPlayFinished reported from sound pool. streamID: %{public}d", streamID);
    std::shared_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl = systemSoundPlayerImpl_.lock();
    if (systemSoundPlayerImpl == nullptr) {
        MEDIA_LOGE("The systemSoundPlayerImpl has been released.");
        return;
    }
    systemSoundPlayerImpl->OnPlayFinished(streamID);
}

void PlayerSoundPoolCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGE("OnError reported from sound pool. errorCode: %{public}d", errorCode);
    std::shared_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl = systemSoundPlayerImpl_.lock();
    if (systemSoundPlayerImpl == nullptr) {
        MEDIA_LOGE("The systemSoundPlayerImpl has been released.");
        return;
    }
    systemSoundPlayerImpl->OnError(errorCode);
}

// class SystemSoundPlayerFactory.
std::mutex SystemSoundPlayerFactory::g_systemSoundPlayerMutex;

std::shared_ptr<SystemSoundPlayer> SystemSoundPlayerFactory::CreateSystemSoundPlayer()
{
    MEDIA_LOGI("CreateSystemSoundPlayer in.");
    std::lock_guard<std::mutex> lock(g_systemSoundPlayerMutex);
    std::shared_ptr<SystemSoundPlayer> result = std::make_shared<SystemSoundPlayerImpl>();
    if (result == nullptr) {
        MEDIA_LOGE("Failed to CreateSystemSoundPlayer!");
    }
    return result;
}
} // namesapce Media
} // namespace OHOS
