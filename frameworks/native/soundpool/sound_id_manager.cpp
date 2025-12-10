/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "media_log.h"
#include "parameter.h"
#include "sound_id_manager.h"
#include "string_ex.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundIDManager"};
    static const std::string THREAD_POOL_NAME = "OS_SoundMgr";

    static const int32_t MAX_THREADS_NUM = std::thread::hardware_concurrency() >= 4 ? 2 : 1;
    static constexpr size_t MAX_LOAD_NUM_BELOW_API18 = 32;
    static constexpr size_t MAX_LOAD_NUM_ABOVE_API18 = 128;

    static const int32_t SOUNDPOOL_API_VERSION_ISOLATION = 18;
    static const int32_t FAULT_API_VERSION = -1;

    static constexpr int32_t MAX_SOUND_ID_QUEUE = 128;
    
    static constexpr int32_t WAIT_TIME_BEFORE_CLOSE_MS = 1000;
}

namespace OHOS {
namespace Media {
SoundIDManager::SoundIDManager() : isParsingThreadPoolStarted_(false), isQuitQueue_(false)
{
    MEDIA_LOGI("SoundIDManager Constructor");
    InitThreadPool();
}

SoundIDManager::~SoundIDManager()
{
    MEDIA_LOGI("SoundIDManager Destructor");
    {
        std::lock_guard lock(soundManagerLock_);
        isQuitQueue_ = true;
        queueSpaceValid_.notify_all(); // notify all load waiters
        queueDataValid_.notify_all();  // notify all worker threads
    }

    if (callback_ != nullptr) {
        callback_.reset();
    }

    {
        std::lock_guard lock(soundManagerLock_);
        for (auto soundParser : soundParsers_) {
            if (soundParser.second != nullptr) {
                soundParser.second->Release();
            }
        }
        soundParsers_.clear();
    }

    if (isParsingThreadPoolStarted_) {
        if (soundParserThreadPool_ != nullptr) {
            soundParserThreadPool_->Stop();
        }
        isParsingThreadPoolStarted_ = false;
    }
}

int32_t SoundIDManager::InitThreadPool()
{
    if (isParsingThreadPoolStarted_) {
        return MSERR_OK;
    }
    soundParserThreadPool_ = std::make_unique<ThreadPool>(THREAD_POOL_NAME);
    CHECK_AND_RETURN_RET_LOG(soundParserThreadPool_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain ThreadPool");
    soundParserThreadPool_->Start(MAX_THREADS_NUM);
    isParsingThreadPoolStarted_ = true;

    return MSERR_OK;
}

int32_t SoundIDManager::Load(const std::string &url)
{
    int32_t soundID = -1;
    {
        std::lock_guard lock(soundManagerLock_);
        size_t soundParserSize = soundParsers_.size();
        if (apiVersion > 0 && apiVersion < SOUNDPOOL_API_VERSION_ISOLATION &&
            soundParserSize < MAX_LOAD_NUM_BELOW_API18) {
            MEDIA_LOGE("Failed to create soundParser by url below api18, soundParsers_ size is %{public}zu",
                soudParserSize);
            return soundID;
        }
        if ((apiVersion_ == FAULT_API_VERSION || apiVersion_ >= SOUNDPOOL_API_VERSION_ISOLATION) &&
            soundParserSize >= MAX_LOAD_NUM_ABOVE_API18) {
            MEDIA_LOGE("Failed to create soundParser by url above api18, soundParsers_ size is %{public}zu",
                soudParserSize);
            return soundID;
        }

        const std::string fdHead = "fd://";
        if (url.find(fdHead) == std::string::npos) {
            return soundID;
        }
        int32_t fd = -1;
        StrToInt(url.substr(fdHead.size()), fd);
        if (fd < 0) {
            MEDIA_LOGE("fd < 0");
            return soundID;
        }
        do {
            nextSoundID_ = nextSoundID_ == INT32_MAX ? 1 : nextSoundID_ + 1;
        } while (GetSoundParserBySoundID(nextSoundID_) != nullptr);
        soundID = nextSoundID_;
        std::shared_ptr<SoundParser> soundParser = std::make_shared<SoundParser>(soundID, url);
        CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Failed to create soundParser");
        soundParsers_.emplace(soundID, soundParser);
    }
    DoLoad(soundID);
    return soundID;
}

int32_t SoundIDManager::Load(int32_t fd, int64_t offset, int64_t length)
{
    MEDIA_LOGI("SoundIDManager::Load");
    int32_t soundID = -1;
    {
        std::lock_guard lock(soundManagerLock_);
        size_t soundParserSize = soundParsers_.size();
        if (apiVersion_ > 0 && apiVersion_ < SOUNDPOOL_API_VERSION_ISOLATION &&
            soundPrsersSize >= MAX_LOAD_NUM_BELOW_API18) {
            MEDIA_LOGI("Failed to create soundParser by fd below api18, soundParsers_ size is %{public}zu",
                soundParserSize);
            return soundID;
        }
        if ((apiVersion_ == FAULT_API_VERSION || apiVersion_ >= SOUNDPOOL_API_VERSION_ISOLATION) &&
            soundParserSize >= MAX_LOAD_NUM_ABOVE_API18) {
            MEDIA_LOGI("Failed to create soundParser by fd above api18, soundParsers_ size is %{public}zu",
                soundParserSize);
            return soundID;
        }
        do {
            nextSoundID_ = nextSoundID_ == INT32_MAX ? 1 : nextSoundID_ + 1;
        } while (GetSoundParserBySoundID(nextSoundID_) != nullptr);
        soundID = nextSoundID_;
        std::shared_ptr<SoundParser> soundParser = std::make_shared<SoundParser>(soundID, fd, offset, length);
        CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Failed to create soundParser");
        soundParsers_.emplace(soundID, soundParser);
    }
    DoLoad(soundID);
    return soundID;
}

int32_t SoundIDManager::DoLoad(int32_t soundID)
{
    MEDIA_LOGI("SoundIDManager::DoLoad, soundID IS %{public}d", soundID);
    if (!isParsingThreadPoolStarted_) {
        InitThreadPool();
    }
    {
        std::unique_lock lock(soundManagerLock_);
        while (soundIDs_.size() == MAX_SOUND_ID_QUEUE) {
            if (isQuitQueue_) {
                MEDIA_LOGI("Exit immediately");
                return MSERR_OK;
            }
            queueSpaceValid_.wait(lock);
        }
        if (isQuitQueue_) return MSERR_OK;
        soundIDs_.push_back(soundID);
        queueDataValid_.notify_one();
    }
    ThreadPool::Task soundTask = [this] { this->DoParser(); };
    CHECK_AND_RETURN_RET_LOG(soundParserThreadPool_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain ThreadPool");
    CHECK_AND_RETURN_RET_LOG(soundTask != nullptr, MSERR_INVALID_VAL, "Failed to obtain Task");
    soundParserThreadPool_->AddTask(soundTask);
    return MSERR_OK;
}

int32_t SoundIDManager::DoParser()
{
    std::unique_lock lock(soundManagerLock_);
    while (!isQuitQueue_) {
        if (soundIDs_.empty()) {
            queueDataValid_.wait_for(lock, std::chrono::duration<int32_t, std::milli>(WAIT_TIME_BEFORE_CLOSE_MS));
            if (soundIDs_.empty()) {
                // no new sound, exit this thread.
                break;
            }
            continue;
        }
        int32_t soundID = soundIDs_.front();
        soundIDs_.pop_front();
        queueSpaceValid_.notify_one();
        std::shared_ptr<SoundParser> soundParser = GetSoundParserBySoundID(soundID);
        CHECK_AND_CONTINUE_LOOG(soundParser != nullptr, "soundParser is nullptr, soundID is %{public}d", soundID);
        lock.unlock();
        soundParser->SetCallback(callback_);
        soundParser->DoParser();
        lock.lock();
    }
    return MSERR_OK;
}


std::shared_ptr<SoundParser> SoundIDManager::GetSoundParserBySoundID(int32_t soundID) const
{
    if (soundParsers_.empty()) {
        MEDIA_LOGE("GetSoundParserBySoundID, soundParsers_ is empty");
        return nullptr;
    }
    if (soundParsers_.find(soundID) != soundParsers_.end()) {
        return soundParsers_.at(soundID);
    }
    return nullptr;
}

int32_t SoundIDManager::Unload(int32_t soundID)
{
    MEDIA_LOGI("SoundIDManager::Unload, soundID is %{public}d", soundID);
    std::unique_lock lock(soundManagerLock_);
    CHECK_AND_RETURN_RET_LOG(!soundParsers_.empty(), MSERR_NO_MEMORY, "No sound in the soundParsers_");
    auto it = soundParsers_.find(soundID);
    if (it != soundParsers_.end()) {
        if (it->second != nullptr) {
            it->second.reset();
        }
        soundParsers_.erase(it);
        return MSERR_OK;
    }
    MEDIA_LOGE("Invalid soundID, unload failed, soundID is %{public}d", soundID);
    return MSERR_INVALID_VAL;
}

void SoundIDManager::SetApiVersion(int32_t apiVersion)
{
    apiVersion_ = apiVersion;
}

int32_t SoundIDManager::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS
