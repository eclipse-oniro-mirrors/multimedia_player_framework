/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "parallel_stream_manager.h"
#include "audio_renderer_manager.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "ParallelStreamManager"};
    static const std::string THREAD_POOL_NAME = "OS_PalStream";
    static const std::string THREAD_POOL_NAME_STREAM = "OS_Stream";
    static const int32_t MAX_PLAY_STREAMS_NUMBER = 32;
    static const int32_t MIN_PLAY_STREAMS_NUMBER = 1;
    static const int32_t STREAM_THREAD_NUMBER = 1;
    static const int32_t ERROE_STREAM_ID = -1;
    static const int32_t ERROE_GLOBAL_ID = -1;
}

namespace OHOS {
namespace Media {
ParallelStreamManager::ParallelStreamManager(int32_t maxStreams,
    AudioStandard::AudioRendererInfo audioRenderInfo) : audioRendererInfo_(audioRenderInfo), maxStreams_(maxStreams)
{
    MEDIA_LOGI("Construction ParallelStreamManager");
}

ParallelStreamManager::~ParallelStreamManager()
{
    parallelStreamManagerLock_.lock();
    MEDIA_LOGI("ParallelStreamManager::~ParallelStreamManager start");
    if (callback_ != nullptr) {
        callback_.reset();
    }
    if (frameWriteCallback_ != nullptr) {
        frameWriteCallback_.reset();
    }

    waitingStream_.clear();
    std::vector<std::shared_ptr<Stream>> vector;
    for (auto it = playingStream_.begin(); it != playingStream_.end();) {
        vector.push_back(it->second);
        it = playingStream_.erase(it);
    }
    parallelStreamManagerLock_.unlock();
    for (auto& item : vector) {
        item->Stop();
    }
    vector.clear();
    if (streamPlayThreadPool_ != nullptr) {
        streamPlayThreadPool_->Stop();
    }
    if (streamStopThreadPool_ != nullptr) {
        streamStopThreadPool_->Stop();
    }
    MEDIA_LOGI("ParallelStreamManager::~ParallelStreamManager end");
}

int32_t ParallelStreamManager::InitThreadPool()
{
    if (maxStreams_ > MAX_PLAY_STREAMS_NUMBER) {
        maxStreams_ = MAX_PLAY_STREAMS_NUMBER;
        MEDIA_LOGI("more than max play stream number, align to max play strem number.");
    }
    if (maxStreams_ < MIN_PLAY_STREAMS_NUMBER) {
        maxStreams_ = MIN_PLAY_STREAMS_NUMBER;
        MEDIA_LOGI("less than min play stream number, align to min play strem number.");
    }
    MEDIA_LOGI("stream playing thread pool maxStreams_:%{public}d", maxStreams_);
    streamPlayThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
    CHECK_AND_RETURN_RET_LOG(streamPlayThreadPool_ != nullptr, MSERR_INVALID_VAL, "Parallel playThreadPool fail");
    streamPlayThreadPool_->Start(maxStreams_);

    streamStopThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_STREAM);
    CHECK_AND_RETURN_RET_LOG(streamStopThreadPool_ != nullptr, MSERR_INVALID_VAL, "Parallel stopThreadPool fail");
    streamStopThreadPool_->Start(STREAM_THREAD_NUMBER);

    AudioRendererManager::GetInstance().SetParallelManager(weak_from_this());
    return MSERR_OK;
}

int32_t ParallelStreamManager::GetGlobalId(int32_t soundId)
{
    std::lock_guard lock(globalIdMutex_);
    for (auto it = globalIdVector_.begin(); it !=  globalIdVector_.end();) {
        if (it->first == soundId) {
            return it->second;
        } else {
            ++it;
        }
    }
    return ERROE_GLOBAL_ID;
}

void ParallelStreamManager::DelGlobalId(int32_t globalId)
{
    std::lock_guard lock(globalIdMutex_);
    for (auto it = globalIdVector_.begin(); it !=  globalIdVector_.end();) {
        if (it->second == globalId) {
            globalIdVector_.erase(it);
            break;
        } else {
            ++it;
        }
    }
}

void ParallelStreamManager::SetGlobalId(int32_t soundId, int32_t globalId)
{
    std::lock_guard lock(globalIdMutex_);
    globalIdVector_.push_back(std::make_pair(soundId, globalId));
}

void ParallelStreamManager::DelSoundId(int32_t soundId)
{
    std::lock_guard lock(globalIdMutex_);
    for (auto it = globalIdVector_.begin(); it !=  globalIdVector_.end();) {
        if (it->first == soundId) {
            OHOS::Media::AudioRendererManager::GetInstance().DelAudioRenderer(it->second);
            it = globalIdVector_.erase(it);
        } else {
            ++it;
        }
    }
}

int32_t ParallelStreamManager::Play(std::shared_ptr<SoundParser> soundParser, const PlayParams &playParameters)
{
    MediaTrace trace("ParallelStreamManager::Play");
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Invalid soundParser.");
    int32_t streamId;
    std::shared_ptr<Stream> stream;
    int32_t soundId = soundParser->GetSoundID();
    {
        std::lock_guard lock(parallelStreamManagerLock_);
        do {
            nextStreamId_ = nextStreamId_ == INT32_MAX ? 1 : nextStreamId_ + 1;
        } while (FindStream(nextStreamId_) != nullptr);
        streamId = nextStreamId_;
    }
    std::shared_ptr<AudioBufferEntry> cacheData;
    soundParser->GetSoundData(cacheData);
    size_t cacheDataTotalSize = soundParser->GetSoundDataTotalSize();
    MEDIA_LOGI("ParallelStreamManager::Play cacheDataTotalSize:%{public}zu", cacheDataTotalSize);
    stream = std::make_shared<Stream>(soundParser->GetSoundTrackFormat(), soundId, streamId, streamStopThreadPool_);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "failed to create stream");
    stream->SetSoundData(cacheData, cacheDataTotalSize);
    stream->SetPlayParamAndRendererInfo(playParameters, audioRendererInfo_);
    stream->SetManager(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "Invalid callback");
    stream->SetCallback(callback_);
    std::shared_ptr<ISoundPoolCallback> streamCallback_ = std::make_shared<StreamCallBack>(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(streamCallback_ != nullptr, MSERR_INVALID_VAL, "error stream callback");
    stream->SetStreamCallback(streamCallback_);
    if (frameWriteCallback_ != nullptr) {
        stream->SetFrameWriteCallback(frameWriteCallback_);
    }

    int32_t ret = PreparePlay(stream, false);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ERROE_STREAM_ID, "ParallelStreamManager PreparePlay fail");
    return streamId;
}

int32_t ParallelStreamManager::PreparePlay(std::shared_ptr<Stream> stream, bool waitQueueFlag)
{
    MediaTrace trace("ParallelStreamManager::PreparePlay");
    std::shared_ptr<Stream> lastPlay;
    bool lastPlayStopFlag = false;
    {
        std::lock_guard lock(parallelStreamManagerLock_);
        CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "PreparePlay invaid stream");
        if (waitQueueFlag) {
            stream = waitingStream_.front().second;
            MEDIA_LOGI("PreparePlay start from waitqueue streamID:%{public}d", stream->GetStreamID());
        }
        int32_t streamId = stream->GetStreamID();
        MEDIA_LOGI("ParallelStreamManager playingDeque size:%{public}d, maxStreams_:%{public}d",
            static_cast<int32_t>(playingStream_.size()), maxStreams_);
        if (playingStream_.size() < static_cast<size_t>(maxStreams_)) {
            DealQueueAndAddTask(streamId, stream, waitQueueFlag);
        } else {
            lastPlay = playingStream_.back().second;
            if (stream->GetPriority() >= lastPlay->GetPriority()) {
                MEDIA_LOGI("stop streamId:%{public}d, play streamId:%{public}d", lastPlay->GetStreamID(), streamId);
                lastPlayStopFlag = true;
                playingStream_.pop_back();
                DealQueueAndAddTask(streamId, stream, waitQueueFlag);
            } else {
                MEDIA_LOGI("ParallelStreamManager to add waitingStream_");
                if (!waitQueueFlag) {
                    AddToWaitingDeque(streamId, stream);
                }
            }
        }
    }
    if (lastPlayStopFlag && lastPlay != nullptr) {
        ThreadPool::Task streamStopTask = [weakThis = std::weak_ptr<Stream>(lastPlay)] {
            if (auto thisPtr = weakThis.lock()) {
                thisPtr->Stop();
            } else {
                MEDIA_LOGI("PreparePlay Stream object has been destroyed, skipping Stop");
            }
        };
        streamStopThreadPool_->AddTask(streamStopTask);
    }
    return MSERR_OK;
}

void ParallelStreamManager::DealQueueAndAddTask(int32_t streamId, std::shared_ptr<Stream> stream, bool waitQueueFlag)
{
    AddToPlayingDeque(streamId, stream);
    if (waitQueueFlag) {
        RemoveFromWaitingDeque(streamId);
    }
    ThreadPool::Task streamPlayTask = [this, streamId] { this->DoPlay(streamId); };
    streamPlayThreadPool_->AddTask(streamPlayTask);
}

void ParallelStreamManager::RemoveFromWaitingDeque(int32_t streamId)
{
    for (auto it = waitingStream_.begin(); it != waitingStream_.end();) {
        if (it->first == streamId) {
            it = waitingStream_.erase(it);
            break;
        } else {
            ++it;
        }
    }
}

void ParallelStreamManager::AddToPlayingDeque(int32_t streamID, std::shared_ptr<Stream> stream)
{
    if (playingStream_.empty()) {
        playingStream_.push_front(std::make_pair(streamID, stream));
    } else {
        for (size_t i = 0; i < playingStream_.size(); i++) {
            std::shared_ptr<Stream> playingStream = playingStream_[i].second;
            if (stream->GetPriority() >= playingStream->GetPriority()) {
                playingStream_.insert(playingStream_.begin() + i, std::make_pair(streamID, stream));
                break;
            }
            if (playingStream_.size() >= 1 && i == playingStream_.size() - 1 &&
                stream->GetPriority() < playingStream->GetPriority()) {
                playingStream_.push_back(std::make_pair(streamID, stream));
                break;
            }
        }
    }
}

void ParallelStreamManager::AddToWaitingDeque(int32_t streamID, std::shared_ptr<Stream> stream)
{
    if (waitingStream_.empty()) {
        waitingStream_.push_front(std::make_pair(streamID, stream));
    } else {
        for (size_t i = 0; i < waitingStream_.size(); i++) {
            std::shared_ptr<Stream> waitingStream = waitingStream_[i].second;
            if (stream->GetPriority() >= waitingStream->GetPriority()) {
                waitingStream_.insert(waitingStream_.begin() + i, std::make_pair(streamID, stream));
                break;
            }
            if (waitingStream_.size() >= 1 && i == waitingStream_.size() - 1 &&
                stream->GetPriority() < waitingStream->GetPriority()) {
                waitingStream_.push_back(std::make_pair(streamID, stream));
                break;
            }
        }
    }
}

int32_t ParallelStreamManager::DoPlay(int32_t streamID)
{
    MediaTrace trace("ParallelStreamManager::DoPlay");
    std::shared_ptr<Stream> stream;
    {
        std::lock_guard lock(parallelStreamManagerLock_);
        MEDIA_LOGI("ParallelStreamManager::DoPlay start streamID:%{public}d", streamID);
        stream = FindStream(streamID);
        CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "doplay stream invalid.");
    }

    if (stream->DoPlay() == MSERR_OK) {
        MEDIA_LOGI("ParallelStreamManager::DoPlay success streamID:%{public}d", streamID);
        return MSERR_OK;
    }
    
    MEDIA_LOGE("ParallelStreamManager::DoPlay failed streamID:%{public}d", streamID);
    {
        std::lock_guard lock(parallelStreamManagerLock_);
        for (auto it = playingStream_.begin(); it != playingStream_.end();) {
            if (it->first == streamID) {
                it = playingStream_.erase(it);
                break;
            } else {
                ++it;
            }
        }
    }
    return MSERR_INVALID_VAL;
}

std::shared_ptr<Stream> ParallelStreamManager::FindStream(const int32_t streamId)
{
    CHECK_AND_RETURN_RET_LOG(streamId >= 0, nullptr, "streamId invalid.");
    for (auto it = playingStream_.begin(); it != playingStream_.end();) {
        if (it->first == streamId) {
            return it->second;
        } else {
            ++it;
        }
    }
    for (auto it = waitingStream_.begin(); it != waitingStream_.end();) {
        if (it->first == streamId) {
            return it->second;
        } else {
            ++it;
        }
    }
    return nullptr;
}

std::shared_ptr<Stream> ParallelStreamManager::FindStreamLock(const int32_t streamId)
{
    std::lock_guard lock(parallelStreamManagerLock_);
    return FindStream(streamId);
}

int32_t ParallelStreamManager::UnloadStream(int32_t soundId)
{
    MediaTrace trace("ParallelStreamManager::UnloadStream");
    parallelStreamManagerLock_.lock();
    for (auto it = waitingStream_.begin(); it != waitingStream_.end();) {
        if (it->second->GetSoundID() == soundId) {
            it = waitingStream_.erase(it);
        } else {
            ++it;
        }
    }
    std::vector<std::shared_ptr<Stream>> vector;
    for (auto it = playingStream_.begin(); it != playingStream_.end();) {
        if (it->second->GetSoundID() == soundId) {
            vector.push_back(it->second);
            it = playingStream_.erase(it);
        } else {
            ++it;
        }
    }
    parallelStreamManagerLock_.unlock();
    for (auto& item : vector) {
        item->Stop();
    }
    DelSoundId(soundId);
    return MSERR_OK;
}

void ParallelStreamManager::ReorderStream()
{
    std::lock_guard lock(parallelStreamManagerLock_);
    int32_t playingSize = static_cast<int32_t>(playingStream_.size());
    for (int32_t i = 0; i < playingSize - 1; ++i) {
        for (int32_t j = 0; j < playingSize - 1 - i; ++j) {
            std::shared_ptr<Stream> left = playingStream_[j].second;
            std::shared_ptr<Stream> right = playingStream_[j + 1].second;
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                auto streamTemp = playingStream_[j];
                playingStream_[j] = playingStream_[j + 1];
                playingStream_[j + 1] = streamTemp;
            }
        }
    }
    
    int32_t willPlaySize = static_cast<int32_t>(waitingStream_.size());
    for (int32_t i = 0; i < willPlaySize - 1; ++i) {
        for (int32_t j = 0; j < willPlaySize - 1 - i; ++j) {
            std::shared_ptr<Stream> left = waitingStream_[j].second;
            std::shared_ptr<Stream> right = waitingStream_[j + 1].second;
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                auto willPlayTemp = waitingStream_[j];
                waitingStream_[j] = waitingStream_[j + 1];
                waitingStream_[j + 1] = willPlayTemp;
            }
        }
    }
}

void ParallelStreamManager::OnPlayFinished(int32_t streamID)
{
    MediaTrace trace("ParallelStreamManager::OnPlayFinished");
    std::lock_guard lock(parallelStreamManagerLock_);
    MEDIA_LOGI("ParallelStreamManager::OnPlayFinished streamID:%{public}d", streamID);
    for (auto it = playingStream_.begin(); it != playingStream_.end();) {
        if (it->first == streamID) {
            it = playingStream_.erase(it);
            break;
        } else {
            ++it;
        }
    }
    if (waitingStream_.size() > 0) {
        MEDIA_LOGI("ParallelStreamManager::OnPlayFinished waitingStream_");
        bool playFlag = true;
        std::shared_ptr<Stream> waitFront = waitingStream_.front().second;
        ThreadPool::Task streamPlayTask = [this, waitFront, playFlag] {
            this->PreparePlay(waitFront, playFlag);
        };
        streamPlayThreadPool_->AddTask(streamPlayTask);
    }
}

int32_t ParallelStreamManager::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t ParallelStreamManager::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}

void ParallelStreamManager::StreamCallBack::OnLoadCompleted(int32_t soundId)
{
    (void)soundId;
}

void ParallelStreamManager::StreamCallBack::OnPlayFinished(int32_t streamId)
{
    if (std::shared_ptr<ParallelStreamManager> ptr = parallelStreamManagerInner_.lock()) {
        ptr->OnPlayFinished(streamId);
    }
}

void ParallelStreamManager::StreamCallBack::OnError(int32_t errorCode)
{
    (void)errorCode;
}

} // namespace Media
} // namespace OHOS
