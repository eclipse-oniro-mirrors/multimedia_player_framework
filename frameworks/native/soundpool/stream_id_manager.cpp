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

#include <algorithm>
#include "parameter.h"
#include "soundpool.h"
#include "media_log.h"
#include "media_errors.h"
#include "stream_id_manager.h"

namespace {
    // audiorender max concurrency.
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "StreamIDManager"};
    static const std::string THREAD_POOL_NAME = "OS_StreamMgr";
    static const int32_t MAX_THREADS_NUM = std::thread::hardware_concurrency() >= 4 ? 2 : 1;
}

namespace OHOS {
namespace Media {
StreamIDManager::StreamIDManager(int32_t maxStreams,
    AudioStandard::AudioRendererInfo audioRenderInfo) : audioRendererInfo_(audioRenderInfo), maxStreams_(maxStreams)
{
    MEDIA_LOGI("Construction StreamIDManager.");
    InitThreadPool();
}

StreamIDManager::~StreamIDManager()
{
    MEDIA_LOGI("Destruction StreamIDManager");
    if (callback_ != nullptr) {
        callback_.reset();
    }
    if (frameWriteCallback_ != nullptr) {
        frameWriteCallback_.reset();
    }
    for (auto cacheBuffer : cacheBuffers_) {
        if (cacheBuffer.second != nullptr) {
            cacheBuffer.second->Release();
        }
    }
    cacheBuffers_.clear();
    if (isStreamPlayingThreadPoolStarted_.load()) {
        if (streamPlayingThreadPool_ != nullptr) {
            streamPlayingThreadPool_->Stop();
        }
        isStreamPlayingThreadPoolStarted_.store(false);
    }
}

int32_t StreamIDManager::InitThreadPool()
{
    if (isStreamPlayingThreadPoolStarted_.load()) {
        return MSERR_OK;
    }
    streamPlayingThreadPool_ = std::make_unique<ThreadPool>(THREAD_POOL_NAME);
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain playing ThreadPool");
    if (maxStreams_ > MAX_PLAY_STREAMS_NUMBER) {
        maxStreams_ = MAX_PLAY_STREAMS_NUMBER;
        MEDIA_LOGI("more than max play stream number, align to max play strem number.");
    }
    if (maxStreams_ < MIN_PLAY_STREAMS_NUMBER) {
        maxStreams_ = MIN_PLAY_STREAMS_NUMBER;
        MEDIA_LOGI("less than min play stream number, align to min play strem number.");
    }
    MEDIA_LOGI("stream playing thread pool maxStreams_:%{public}d", maxStreams_);
    // For stream priority logic, thread num need align to task num.
    streamPlayingThreadPool_->Start(maxStreams_);
    streamPlayingThreadPool_->SetMaxTaskNum(maxStreams_);
    isStreamPlayingThreadPoolStarted_.store(true);

    return MSERR_OK;
}

int32_t StreamIDManager::Play(std::shared_ptr<SoundParser> soundParser, PlayParams playParameters)
{
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Invalid soundParser.");
    int32_t soundID = soundParser->GetSoundID();
    int32_t streamID = GetFreshStreamID(soundID, playParameters);
    {
        std::lock_guard lock(streamIDManagerLock_);
        if (streamID <= 0) {
            do {
                nextStreamID_ = nextStreamID_ == INT32_MAX ? 1 : nextStreamID_ + 1;
            } while (FindCacheBuffer(nextStreamID_) != nullptr);
            streamID = nextStreamID_;
            std::deque<std::shared_ptr<AudioBufferEntry>> cacheData;
            soundParser->GetSoundData(cacheData);
            size_t cacheDataTotalSize = soundParser->GetSoundDataTotalSize();
            MEDIA_LOGI("cacheData size:%{public}zu , cacheDataTotalSize:%{public}zu",
                cacheData.size(), cacheDataTotalSize);
            auto cacheBuffer =
                std::make_shared<CacheBuffer>(soundParser->GetSoundTrackFormat(), cacheData, cacheDataTotalSize,
                     soundID, streamID);
            CHECK_AND_RETURN_RET_LOG(cacheBuffer != nullptr, -1, "failed to create cache buffer");
            CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "Invalid callback.");
            cacheBuffer->SetCallback(callback_);
            cacheBufferCallback_ = std::make_shared<CacheBufferCallBack>(weak_from_this());
            CHECK_AND_RETURN_RET_LOG(cacheBufferCallback_ != nullptr, MSERR_INVALID_VAL,
                "Invalid cachebuffer callback");
            cacheBuffer->SetCacheBufferCallback(cacheBufferCallback_);
            if (frameWriteCallback_ != nullptr) {
                cacheBuffer->SetFrameWriteCallback(frameWriteCallback_);
            }
            cacheBuffers_.emplace(streamID, cacheBuffer);
        }
    }
    SetPlay(soundID, streamID, playParameters);
    return streamID;
}

int32_t StreamIDManager::SetPlay(const int32_t soundID, const int32_t streamID, const PlayParams playParameters)
{
    if (!isStreamPlayingThreadPoolStarted_.load()) {
        InitThreadPool();
    }

    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stream play threadpool.");
    MEDIA_LOGI("StreamIDManager cur task num:%{public}zu, maxStreams_:%{public}d",
        currentTaskNum_, maxStreams_);
    // CacheBuffer must prepare before play.
    std::shared_ptr<CacheBuffer> freshCacheBuffer = FindCacheBuffer(streamID);
    CHECK_AND_RETURN_RET_LOG(freshCacheBuffer != nullptr, -1, "Invalid fresh cache buffer");
    freshCacheBuffer->PreparePlay(streamID, audioRendererInfo_, playParameters);
    int32_t tempMaxStream = maxStreams_;
    if (currentTaskNum_ < static_cast<size_t>(tempMaxStream)) {
        AddPlayTask(streamID, playParameters);
    } else {
        int32_t playingStreamID = playingStreamIDs_.back();
        std::shared_ptr<CacheBuffer> playingCacheBuffer = FindCacheBuffer(playingStreamID);
        CHECK_AND_RETURN_RET_LOG(freshCacheBuffer != nullptr, -1, "Invalid fresh cache buffer");
        CHECK_AND_RETURN_RET_LOG(playingCacheBuffer != nullptr, -1, "Invalid playingCacheBuffer");
        MEDIA_LOGI("StreamIDManager fresh sound priority:%{public}d, playing stream priority:%{public}d",
            freshCacheBuffer->GetPriority(), playingCacheBuffer->GetPriority());
        if (freshCacheBuffer->GetPriority() >= playingCacheBuffer->GetPriority()) {
            MEDIA_LOGI("StreamIDManager stop playing low priority sound:%{public}d", playingStreamID);
            playingCacheBuffer->Stop(playingStreamID);
            MEDIA_LOGI("StreamIDManager to playing fresh sound:%{public}d.", streamID);
            AddPlayTask(streamID, playParameters);
        } else {
            std::lock_guard lock(streamIDManagerLock_);
            MEDIA_LOGI("StreamIDManager queue will play streams, streamID:%{public}d.", streamID);
            StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo;
            freshStreamIDAndPlayParamsInfo.streamID = streamID;
            freshStreamIDAndPlayParamsInfo.playParameters = playParameters;
            QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo);
        }
    }
    for (size_t i = 0; i < playingStreamIDs_.size(); i++) {
        int32_t playingStreamID = playingStreamIDs_[i];
        MEDIA_LOGD("StreamIDManager::SetPlay  playingStreamID:%{public}d", playingStreamID);
    }
    for (size_t i = 0; i < willPlayStreamInfos_.size(); i++) {
        StreamIDAndPlayParamsInfo willPlayInfo = willPlayStreamInfos_[i];
        MEDIA_LOGD("StreamIDManager::SetPlay  willPlayStreamID:%{public}d", willPlayInfo.streamID);
    }
    return MSERR_OK;
}

// Sort in descending order
// 0 has the lowest priority, and the higher the value, the higher the priority
// The queue head has the highest value and priority
void StreamIDManager::QueueAndSortPlayingStreamID(int32_t streamID)
{
    if (playingStreamIDs_.empty()) {
        playingStreamIDs_.emplace_back(streamID);
    } else {
        bool shouldReCombinePlayingQueue = false;
        for (size_t i = 0; i < playingStreamIDs_.size(); i++) {
            int32_t playingStreamID = playingStreamIDs_[i];
            std::shared_ptr<CacheBuffer> freshCacheBuffer = FindCacheBuffer(streamID);
            std::shared_ptr<CacheBuffer> playingCacheBuffer = FindCacheBuffer(playingStreamID);
            if (playingCacheBuffer == nullptr) {
                playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
                shouldReCombinePlayingQueue = true;
                break;
            }
            if (freshCacheBuffer == nullptr) {
                break;
            }
            if (freshCacheBuffer->GetPriority() >= playingCacheBuffer->GetPriority()) {
                playingStreamIDs_.insert(playingStreamIDs_.begin() + i, streamID);
                break;
            }
            if (i == playingStreamIDs_.size() - 1 &&
                freshCacheBuffer->GetPriority() < playingCacheBuffer->GetPriority()) {
                playingStreamIDs_.push_back(streamID);
                break;
            }
        }
        if (shouldReCombinePlayingQueue) {
            QueueAndSortPlayingStreamID(streamID);
        }
    }
}

// Sort in descending order.
// 0 has the lowest priority, and the higher the value, the higher the priority
// The queue head has the highest value and priority
void StreamIDManager::QueueAndSortWillPlayStreamID(StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo)
{
    if (willPlayStreamInfos_.empty()) {
        willPlayStreamInfos_.emplace_back(freshStreamIDAndPlayParamsInfo);
    } else {
        bool shouldReCombineWillPlayQueue = false;
        for (size_t i = 0; i < willPlayStreamInfos_.size(); i++) {
            std::shared_ptr<CacheBuffer> freshCacheBuffer = FindCacheBuffer(freshStreamIDAndPlayParamsInfo.streamID);
            std::shared_ptr<CacheBuffer> willPlayCacheBuffer = FindCacheBuffer(willPlayStreamInfos_[i].streamID);
            if (willPlayCacheBuffer == nullptr) {
                willPlayStreamInfos_.erase(willPlayStreamInfos_.begin() + i);
                shouldReCombineWillPlayQueue = true;
                break;
            }
            if (freshCacheBuffer == nullptr) {
                break;
            }
            if (freshCacheBuffer->GetPriority() >= willPlayCacheBuffer->GetPriority()) {
                willPlayStreamInfos_.insert(willPlayStreamInfos_.begin() + i, freshStreamIDAndPlayParamsInfo);
                break;
            }
            if (i == willPlayStreamInfos_.size() - 1 &&
                freshCacheBuffer->GetPriority() < willPlayCacheBuffer->GetPriority()) {
                willPlayStreamInfos_.push_back(freshStreamIDAndPlayParamsInfo);
                break;
            }
        }
        if (shouldReCombineWillPlayQueue) {
            QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo);
        }
    }
}

int32_t StreamIDManager::AddPlayTask(const int32_t streamID, const PlayParams playParameters)
{
    ThreadPool::Task streamPlayTask = [this, streamID] { this->DoPlay(streamID); };
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain playing ThreadPool");
    CHECK_AND_RETURN_RET_LOG(streamPlayTask != nullptr, MSERR_INVALID_VAL, "Failed to obtain stream play Task");
    streamPlayingThreadPool_->AddTask(streamPlayTask);
    std::lock_guard lock(streamIDManagerLock_);
    currentTaskNum_++;
    QueueAndSortPlayingStreamID(streamID);
    return MSERR_OK;
}

int32_t StreamIDManager::DoPlay(const int32_t streamID)
{
    MEDIA_LOGI("StreamIDManager::DoPlay start streamID:%{public}d", streamID);
    std::shared_ptr<CacheBuffer> cacheBuffer = FindCacheBuffer(streamID);
    CHECK_AND_RETURN_RET_LOG(cacheBuffer.get() != nullptr, MSERR_INVALID_VAL, "cachebuffer invalid.");
    if (cacheBuffer->DoPlay(streamID) == MSERR_OK) {
        MEDIA_LOGI("StreamIDManager::DoPlay success streamID:%{public}d", streamID);
        return MSERR_OK;
    }
    MEDIA_LOGI("StreamIDManager::DoPlay failed streamID:%{public}d", streamID);
    {
        std::lock_guard lock(streamIDManagerLock_);
        currentTaskNum_--;
        for (int32_t i = 0; i < static_cast<int32_t>(playingStreamIDs_.size()); i++) {
            int32_t playingStreamID = playingStreamIDs_[i];
            std::shared_ptr<CacheBuffer> playingCacheBuffer = FindCacheBuffer(playingStreamID);
            if (playingCacheBuffer != nullptr && !playingCacheBuffer->IsRunning()) {
                MEDIA_LOGI("StreamIDManager::DoPlay fail erase playingStreamID:%{public}d", playingStreamID);
                playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
                i--;
            }
        }
    }
    return MSERR_INVALID_VAL;
}

std::shared_ptr<CacheBuffer> StreamIDManager::FindCacheBuffer(const int32_t streamID)
{
    if (cacheBuffers_.empty()) {
        MEDIA_LOGI("StreamIDManager cacheBuffers_ empty");
        return nullptr;
    }
    if (cacheBuffers_.find(streamID) != cacheBuffers_.end()) {
        return cacheBuffers_.at(streamID);
    }
    return nullptr;
}

int32_t StreamIDManager::GetStreamIDBySoundID(const int32_t soundID)
{
    PlayParams playParameters;
    return GetFreshStreamID(soundID, playParameters);
}

int32_t StreamIDManager::ReorderStream(int32_t streamID, int32_t priority)
{
    std::lock_guard lock(streamIDManagerLock_);
    int32_t playingSize = static_cast<int32_t>(playingStreamIDs_.size());
    for (int32_t i = 0; i < playingSize - 1; ++i) {
        for (int32_t j = 0; j < playingSize - 1 - i; ++j) {
            std::shared_ptr<CacheBuffer> left = FindCacheBuffer(playingStreamIDs_[j]);
            std::shared_ptr<CacheBuffer> right = FindCacheBuffer(playingStreamIDs_[j + 1]);
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                int32_t streamIdTemp = playingStreamIDs_[j];
                playingStreamIDs_[j] = playingStreamIDs_[j + 1];
                playingStreamIDs_[j + 1] = streamIdTemp;
            }
        }
    }
    for (size_t i = 0; i < playingStreamIDs_.size(); i++) {
        int32_t playingStreamID = playingStreamIDs_[i];
        MEDIA_LOGD("StreamIDManager::ReorderStream  playingStreamID:%{public}d", playingStreamID);
    }
    
    int32_t willPlaySize = static_cast<int32_t>(willPlayStreamInfos_.size());
    for (int32_t i = 0; i < willPlaySize - 1; ++i) {
        for (int32_t j = 0; j < willPlaySize - 1 - i; ++j) {
            std::shared_ptr<CacheBuffer> left = FindCacheBuffer(willPlayStreamInfos_[j].streamID);
            std::shared_ptr<CacheBuffer> right = FindCacheBuffer(willPlayStreamInfos_[j + 1].streamID);
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                StreamIDAndPlayParamsInfo willPlayInfoTemp = willPlayStreamInfos_[j];
                willPlayStreamInfos_[j] = willPlayStreamInfos_[j + 1];
                willPlayStreamInfos_[j + 1] = willPlayInfoTemp;
            }
        }
    }
    for (size_t i = 0; i < willPlayStreamInfos_.size(); i++) {
        StreamIDAndPlayParamsInfo willPlayInfo = willPlayStreamInfos_[i];
        MEDIA_LOGD("StreamIDManager::ReorderStream  willPlayStreamID:%{public}d", willPlayInfo.streamID);
    }
    return MSERR_OK;
}

int32_t StreamIDManager::GetFreshStreamID(const int32_t soundID, PlayParams playParameters)
{
    int32_t streamID = 0;
    if (cacheBuffers_.empty()) {
        MEDIA_LOGI("StreamIDManager cacheBuffers_ empty");
        return streamID;
    }
    for (auto cacheBuffer : cacheBuffers_) {
        if (cacheBuffer.second == nullptr) {
            MEDIA_LOGE("Invalid cacheBuffer, soundID:%{public}d", soundID);
            continue;
        }
        if (soundID == cacheBuffer.second->GetSoundID()) {
            streamID = cacheBuffer.second->GetStreamID();
            MEDIA_LOGI("Have cache soundID:%{public}d, streamID:%{public}d", soundID, streamID);
            break;
        }
    }
    return streamID;
}

void StreamIDManager::OnPlayFinished()
{
    {
        std::lock_guard lock(streamIDManagerLock_);
        currentTaskNum_--;
        for (int32_t i = 0; i < static_cast<int32_t>(playingStreamIDs_.size()); i++) {
            int32_t playingStreamID = playingStreamIDs_[i];
            std::shared_ptr<CacheBuffer> playingCacheBuffer = FindCacheBuffer(playingStreamID);
            if (playingCacheBuffer != nullptr && !playingCacheBuffer->IsRunning()) {
                MEDIA_LOGI("StreamIDManager::OnPlayFinished erase playingStreamID:%{public}d", playingStreamID);
                playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
                i--;
            }
        }
    }
    if (!willPlayStreamInfos_.empty()) {
        MEDIA_LOGI("StreamIDManager OnPlayFinished will play streams non empty, get the front.");
        StreamIDAndPlayParamsInfo willPlayStreamInfo =  willPlayStreamInfos_.front();
        AddPlayTask(willPlayStreamInfo.streamID, willPlayStreamInfo.playParameters);
        std::lock_guard lock(streamIDManagerLock_);
        willPlayStreamInfos_.pop_front();
    }
}

int32_t StreamIDManager::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t StreamIDManager::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS
