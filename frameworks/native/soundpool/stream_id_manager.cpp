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

#include "audio_renderer_manager.h"
#include "media_errors.h"
#include "media_log.h"
#include "parameter.h"
#include "soundpool.h"
#include "stream_id_manager.h"

namespace {
    // audiorender max concurrency.
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "StreamIDManager"};
    static const std::string THREAD_POOL_NAME = "OS_StreamMgr";
    static const std::string THREAD_POOL_NAME_CACHE_BUFFER = "OS_CacheBuf";
    static const int32_t MAX_THREADS_NUM = 3;
    static const int32_t ERROE_GLOBAL_ID = -1;
    static const size_t MAX_NUMBER_OF_PARALLEL_PLAYING = 5;
    static const int32_t MAX_NUMBER_OF_HELD_STREAMS = 5;
}

namespace OHOS {
namespace Media {
StreamIDManager::StreamIDManager(int32_t maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo,
    InterruptMode interruptMode) : audioRendererInfo_(audioRenderInfo), maxStreams_(maxStreams)
{
    MEDIA_LOGI("StreamIDManager Constructor");
    audioRendererInfo_.playerType = AudioStandard::PlayerType::PLAYER_TYPE_SOUND_POOL;
    currentStreamsNum_.store(0);
}

StreamIDManager::~StreamIDManager()
{
    MEDIA_LOGI("StreamIDManager Destructor");
    if (callback_ != nullptr) {
        callback_.reset();
    }
    if (frameWriteCallback_ != nullptr) {
        frameWriteCallback_.reset();
    }
    for (auto stream : soundID2Stream_) {
        if (stream.second != nullptr) {
            stream.second->Stop();
            stream.second->Release();
        }
    }
    soundID2Stream_.clear();

    for (auto &mem : soundID2MultiStreams_) {
        for (std::shared_ptr<AudioStream> stream : mem.second) {
            if (stream != nullptr) {
                stream->Stop();
                stream->Release();
            }
        }
    }
    soundID2MultiStreams_.clear();

    if (isStreamPlayingThreadPoolStarted_.load()) {
        if (streamPlayingThreadPool_ != nullptr) {
            streamPlayingThreadPool_->Stop();
        }
        isStreamPlayingThreadPoolStarted_.store(false);
    }
    if (isStreamStopThreadPoolStarted_.load()) {
        if (streamStopThreadPool_ != nullptr) {
            streamStopThreadPool_->Stop();
        }
        isStreamStopThreadPoolStarted_.store(false);
    }
    currentStreamsNum_.store(0);
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
    streamPlayingThreadPool_->Start(MAX_THREADS_NUM);
    streamPlayingThreadPool_->SetMaxTaskNum(MAX_THREADS_NUM);
    isStreamPlayingThreadPoolStarted_.store(true);

    streamStopThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_CACHE_BUFFER);
    CHECK_AND_RETURN_RET_LOG(streamStopThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stop ThreadPool");
    streamStopThreadPool_->Start(MAX_THREADS_NUM);
    streamStopThreadPool_->SetMaxTaskNum(MAX_THREADS_NUM);
    isStreamStopThreadPoolStarted_.store(true);

    OHOS::Media::AudioRendererManager::GetInstance().SetStreamIDManager(weak_from_this());
    return MSERR_OK;
}

int32_t StreamIDManager::PlayWithSameSoundInterrupt(const std::shared_ptr<SoundParser> &soundParser,
    const PlayParams &playParameters)
{
    MediaTrace trace("StreamIDManager::PlayWithSameSoundInterrupt");
    std::lock_guard lock(streamIDManagerLock_);
    MEDIA_LOGI("PlayWithSameSoundInterrupt, before remove")
    PrintPlayingStreams();
    PrintSoundID2Stream();
    RemoveInvalidStreamsInInterruptMode();
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "PlayWithSameSoundInterrupt, soundParser is nullptr");
    int32_t soundID = soundParser->GetSoundID();
    int32_t streamID = GetAvailableStreamIDBySoundID(soundID);
    if (streamID == 0) {
        CHECK_AND_RETURN_RET_LOG(MSERR_OK == CreateAudioStream(soundID, streamID, soundParser), -1,
            "Init stream failed");
    }
    MEDIA_LOGI("PlayWithSameSoundInterrupt, get stream successfully, soundID is %{public}d, streamID is %{public}d",
        soundID, streamID);
    int32_t result = SetPlayWithSameSoundInterrupt(soundID, streamID, playParameters);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, errorStreamId, "Invalid SetPlayWithSameSoundIntetrrupt");
    return streamID;
}

int32_t StreamIDManager::SetPlayWithSameSoundInterrupt(int32_t soundID, int32_t streamID,
    const PlayParams &playParameters)
{
    MEDIA_LOGI("SetPlayWithSameSoundInterrupt start");
    MediaTrace trace("StreamIDManager::SetPlayWithSameSoundInterrupt");
    if (!isStreamPlayingThreadPoolStarted_.load()) {
        InitThreadPool();
    }
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stream play threadpool");
    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "SetPlayWithSameSoundInterrupt, "
        "stream(%{public}d) is nullptr", streamID);
    stream->SetPriorityWithoutLock(playParameters.priority);
    stream->ConfigurePlayParametersWithoutLock(audioRendererInfo_, playParameters);

    if (playingStreamIDs_.size() < MAX_NUMBER_OF_PARALLEL_PLAYING) {
        MEDIA_LOGI("SetPlayWithSameSoundInterrupt, playingStreamIDs_.size is %{public}zu < 5",
            playingStreamIDs_.size());
        AddPlayTask(streamID);
        return MSERR_OK;
    }

    MEDIA_LOGI("size of playingStreamIDs_ is %{public}zu", playingStreamIDs_.size());
    int32_t lastStreamID = playingStreamIDs_.back();
    std::shared_ptr<AudioStream> lastStream = GetStreamByStreamID(lastStreamID);
    if (lastStream == nullptr) {
        MEDIA_LOGI("SetPlayWithNoInterrupt, lastStream is nullptr");
        playingStreamIDs_.pop_back();
        return MSERR_INVALID_VAL;
    }

    if (stream->GetPriority() >= lastStream->GetPriority()) {
        MEDIA_LOGI("SetPlayWithSameSoundInterrupt, last streamID is %{public}d, priority is %{public}d, "
            "state is %{public}d, current streamID is %{public}d, priority is %{public}d, state is %{public}d",
            lastStream->GetStreamID(), lastStream->GetPriority(), lastStream->GetStreamState(), stream->GetStreamID(),
            stream->GetPriority(), stream->GetStreamState());
        playingStreamIDs_.pop_back();
        AddStopTask(lastStream);
        AddPlayTask(streamID);
        return MSERR_OK;
    }
    
    MEDIA_LOGI("Stream(%{public}d) will be queued for playing", streamID);
    StreamIDAndPlayParamsInfo streamIDAndPlayParamsInfo;
    streamIDAndPlayParamsInfo.streamID = streamID;
    streamIDAndPlayParamsInfo.playParameters = playParameters;
    QueueAndSortWillPlayStreamID(streamIDAndPlayParamsInfo);
    return MSERR_OK;
}

int32_t StreamIDManager::PlayWithNoInterrupt(const std::shared_ptr<SoundParser> &soundParser,
    const PlayParams &playParameters)
{
    MediaTrace trace("StreamIDManager::PlayWithNoInterrupt");
    std::lock_guard lock(streamIDManagerLock_);
    MEDIA_LOGI("PlayWithNoInterrupt, before remove")
    PrintPlayingStreams();
    PrintSoundID2MultiStreams();
    RemoveInvalidStreamsInNoInterruptMode();
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "PlayWithNoInterrupt, soundParser is nullptr");
    int32_t soundID = soundParser->GetSoundID();
    int32_t streamID = GetAvailableStreamIDBySoundID(soundID);
    if (streamID == 0) {
        CHECK_AND_RETURN_RET_LOG(MSERR_OK == CreateAudioStream(soundID, streamID, soundParser), -1,
            "Init stream failed");
    }
    MEDIA_LOGI("PlayWithNoInterrupt, get stream successfully, soundID is %{public}d, streamID is %{public}d",
        soundID, streamID);
    int32_t result = SetPlayWithNoInterrupt(soundID, streamID, playParameters);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, errorStreamId, "Invalid PlayWithNoInterrupt");
    return streamID;
}

int32_t StreamIDManager::SetPlayWithNoInterrupt(int32_t soundID, int32_t streamID, const PlayParams &playParameters)
{
    MEDIA_LOGI("SetPlayWithNoInterrupt start");
    MediaTrace trace("StreamIDManager::SetPlayWithNoInterrupt");
    if (!isStreamPlayingThreadPoolStarted_.load()) {
        InitThreadPool();
    }
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stream play threadpool");
    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "SetPlayWithNoInterrupt, "
        "stream(%{public}d) is nullptr", streamID);
    stream->SetPriority(playParameters.priority);
    stream->ConfigurePlayParameters(audioRendererInfo_, playParameters);

    if (playingStreamIDs_.size() < MAX_NUMBER_OF_PARALLEL_PLAYING) {
        MEDIA_LOGI("SetPlayWithNoInterrupt, playingStreamIDs_.size is %{public}zu < 5", playingStreamIDs_size());
        AddPlayTask(streamID);
        return MSERR_OK;
    }

    MEDIA_LOGI("size of playingStreamIDs_ is %{public}zu", playingStreamIDs_.size());
    int32_t lastStreamID = playingStreamIDs_.back();
    std::shared_ptr<AudioStream> lastStream = GetStreamByStreamID(lastStreamID);
    if (lastStream == nullptr) {
        MEDIA_LOGI("SetPlayWithNoInterrupt, lastStream is nullptr");
        playingStreamIDs_.pop_back();
        return MSERR_INVALID_VAL;
    }

    if (stream->GetPriority() >= lastStream->GetPriority()) {
        MEDIA_LOGI("SetPlayWithNoInterrupt, last streamID is %{public}d, priority is %{public}d, "
            "state is %{public}d, current streamID is %{public}d, priority is %{public}d, state is %{public}d",
            lastStream->GetStreamID(), lastStream->GetPriority(), lastStream->GetStreamState(), stream->GetStreamID(),
            stream->GetPriority(), stream->GetStreamState());
        playingStreamIDs_.pop_back();
        AddStopTask(lastStream);
        AddPlayTask(streamID);
        MEDIA_LOGI("SetPlayWithNoInterrupt end");
        return MSERR_OK;
    }
    
    MEDIA_LOGI("stream(%{public}d) will not be played", streamID);
    if (stream->GetStreamState() == StreamState::PREPARED) {
        stream->SetStreamState(StreamState::STOPPED);
    }
    return MSERR_INVALID_VAL;
}

// Sort in descending order
// 0 has the lowest priority, and the higher the value, the higher the priority
// The queue head has the highest value and priority
void StreamIDManager::QueueAndSortPlayingStreamID(int32_t freshStreamID)
{
    MEDIA_LOGI("StreamIDManager::QueueAndSortPlayingStreamID start");
    if (playingStreamIDs_.empty()) {
        playingStreamIDs_.emplace_back(freshStreamID);
        return;
    }

    bool shouldReCombinePlayingQueue = false;
    for (size_t i = 0; i < playingStreamIDs_.size(); i++) {
        int32_t playingStreamID = playingStreamIDs_[i];
        std::shared_ptr<AudioStream> freshStream = GetStreamByStreamID(freshStreamID);
        std::shared_ptr<AudioStream> playingStream = GetStreamByStreamID(playingStreamID);
        if (playingStream == nullptr) {
            playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
            shouldReCombinePlayingQueue = true;
            break;
        }
        if (freshStream == nullptr) {
            break;
        }
        if (freshStream->GetPriority() >= playingStream->GetPriority()) {
            playingStreamIDs_.insert(playingStreamIDs_.begin() + i, freshStreamID);
            break;
        }
        if (playingStreamIDs_.size() >= 1 && i == playingStreamIDs_.size() - 1 &&
            freshStream->GetPriority() < playingStream->GetPriority()) {
            playingStreamIDs_.push_back(freshStreamID);
            break;
        }
    }
    if (shouldReCombinePlayingQueue) {
        QueueAndSortPlayingStreamID(freshStreamID);
    }
}

// Sort in descending order.
// 0 has the lowest priority, and the higher the value, the higher the priority
// The queue head has the highest value and priority
void StreamIDManager::QueueAndSortWillPlayStreamID(const StreamIDAndPlayParamsInfo &streamIDAndPlayParamsInfo)
{
    if (willPlayStreamInfos_.empty()) {
        willPlayStreamInfos_.emplace_back(streamIDAndPlayParamsInfo);
        return;
    }

    bool shouldReCombineWillPlayQueue = false;
    for (size_t i = 0; i < willPlayStreamInfos_.size(); i++) {
        std::shared_ptr<AudioStream> freshCacheBuffer = GetStreamByStreamID(streamIDAndPlayParamsInfo.streamID);
        std::shared_ptr<AudioStream> willPlayCacheBuffer = GetStreamByStreamID(willPlayStreamInfos_[i].streamID);
        if (willPlayCacheBuffer == nullptr) {
            willPlayStreamInfos_.erase(willPlayStreamInfos_.begin() + i);
            shouldReCombineWillPlayQueue = true;
            break;
        }
        if (freshCacheBuffer == nullptr) {
            break;
        }
        if (freshCacheBuffer->GetPriority() >= willPlayCacheBuffer->GetPriority()) {
            willPlayStreamInfos_.insert(willPlayStreamInfos_.begin() + i, streamIDAndPlayParamsInfo);
            break;
        }
        if (willPlayStreamInfos_.size() >= 1 && i == willPlayStreamInfos_.size() - 1 &&
            freshCacheBuffer->GetPriority() < willPlayCacheBuffer->GetPriority()) {
            willPlayStreamInfos_.push_back(streamIDAndPlayParamsInfo);
            break;
        }
    }
    if (shouldReCombineWillPlayQueue) {
        QueueAndSortWillPlayStreamID(streamIDAndPlayParamsInfo);
    }
}

int32_t StreamIDManager::AddPlayTask(int32_t streamID)
{
    MEDIA_LOGI("AddPlayTask, streamID is %{public}d", streamID);
    ThreadPool::Task streamPlayTask = [this, streamID] { this->DoPlay(streamID); };
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain streamPlayingThreadPool_");
    CHECK_AND_RETURN_RET_LOG(streamPlayTask != nullptr, MSERR_INVALID_VAL,
        "AddPlayTask, streamPlayingThreadPool_ is nullptr");
    QueueAndSortPlayingStreamID(streamID);
    streamPlayingThreadPool_->AddTask(streamPlayTask);
    MEDIA_LOGI("AddPlayTask end, streamID is %{public}d", streamID);
    return MSERR_OK;
}

int32_t StreamIDManager::AddStopTask(const std::shared_ptr<AudioStream> &stream)
{
    MEDIA_LOGI("AddStopTask, streamID is %{public}d", streamID);
    ThreadPool::Task streamStopTask = [stream] { stream->Stop(); };
    CHECK_AND_RETURN_RET_LOG(streamStopThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain streamStopThreadPool_");
    CHECK_AND_RETURN_RET_LOG(streamStopTask != nullptr, MSERR_INVALID_VAL,
        "AddStopTask, streamPlayingThreadPool_ is nullptr");
    streamStopThreadPool_->AddTask(streamStopTask);
    MEDIA_LOGI("AddStopTask end, streamID is %{public}d", streamID);
    return MSERR_OK;
}

int32_t StreamIDManager::DoPlay(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManager::DoPlay start streamID is %{public}d", streamID);
    std::shared_ptr<AudioStream> stream = GetStreamByStreamIDWithLock(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "StreamIDManager::DoPlay, stream is nullptr");
    if (stream->DoPlay() == MSERR_OK) {
        MEDIA_LOGI("StreamIDManager::DoPlay successfully, streamID is %{public}d", streamID);
        return MSERR_OK;
    }

    {
        std::lock_guard lock(streamIDManagerLock_);
        MEDIA_LOGI("StreamIDManager::DoPlay failed, streamID is %{public}d", streamID);
        for (int32_t i = 0; i < static_cast<int32_t>(playingStreamIDs_.size()); i++) {
            if (streamID == playingStreamIDs_[i]) {
                std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
                CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL,
                    "StreamIDManager::DoPlay, stream is nullptr");
                playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
                stream->SetStreamState(StreamState::RELEASED);
                return MSERR_INVALID_VAL;
            }
        }
        return MSERR_INVALID_VAL;
    }
}

std::shared_ptr<AudioStream> StreamIDManager::GetStreamByStreamID(int32_t streamID)
{
    CHECK_AND_RETURN_RET_LOG(streamID >= 0, nullptr, "GetStreamByStreamID, streamID is invalid.");
    std::shared_ptr<AudioStream> stream = nullptr;
    if (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT) {
        for (auto mem : soundID2Stream_) {
            CHECK_AND_CONTINUE_LOG(mem.second != nullptr, "stream corresponding to soundID(%{public}d) is nullptr",
                mem.first);
            if (streamID == mem.second->GetStreamID()) {
                stream = mem.second;
                return stream;
            }
        }
        MEDIA_LOGE("SAME_SOUND_INTERRUPT, No corresponding stream(%{public}d) found", streamID);
        return stream;
    }
    for (auto mem : soundID2MultiStreams_) {
        const std::list<std::shared_ptr<AudioStream>> &streams = mem.second;
        for (auto stream : streams) {
            if (stream != nullptr && streamID == stream->GetStreamID()) {
                return stream;
            }
        }
    }
    MEDIA_LOGE("NO_INTERRUPT, No corresponding stream(%{public}d) found", streamID);
    return stream;
}

void StreamIDManager::RemoveInvalidStreamsInInterruptMode()
{
    MEDIA_LOGI("SAME_SOUND_INTERRUPT");
    for (auto it = soundID2Stream_.begin(); it != soundID2Stream_.end();) {
        if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
            return;
        }
        if (it->second != nullptr && StreamState::RELEASED == it->second->GetStreamState()) {
            it->second->Release();
            it = soundID2Stream_.erase(it);
            currentStreamsNum_--;
            continue;
        }
        it++;
    }
    for (auto it = soundID2Stream_.begin(); it != soundID2Stream_.end();) {
        if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
            return;
        }
        if (it->second != nullptr && StreamState::STOPPED == it->second->GetStreamState()) {
            it->second->Release();
            it = soundID2Stream_.erase(it);
            currentStreamsNum_--;
            continue;
        }
        it++;
    }
    for (auto it = soundID2Stream_.begin(); it != soundID2Stream_.end();) {
        if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
            return;
        }
        if (it->second != nullptr && StreamState::PREPARED == it->second->GetStreamState()) {
            it->second->Release();
            it = soundID2Stream_.erase(it);
            currentStreamsNum_--;
            continue;
        }
        it++;
    }
    return;
}

void StreamIDManager::RemoveInvalidStreamsInNoInterruptMode()
{
    MEDIA_LOGI("NO_INTERRUPT");
    for (auto &mem : soundID2MultiStreams_) {
        if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
            return;
        }
        std::list<std::shared_ptr<AudioStream>> &streams = mem.second;
        for (auto it = streams.begin(); it != streams.end();) {
            if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
                return;
            }
            if ((*it) != nullptr && StreamState::RELEASED == (*it)->GetStreamState()) {
                MEDIA_LOGE("RemoveInvalidStreamsInNoInterruptMode, NO_INTERRUPT, streamID is %{public}d",
                    (*it)->GetStreamID());
                (*it)->Release();
                it = streams.erase(it);
                currentStreamsNum_--;
                continue;
            }
            it++;
        }
    }
    
    for (auto &mem : soundID2MultiStreams_) {
        if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
            return;
        }
        std::list<std::shared_ptr<AudioStream>> &streams = mem.second;
        for (auto it = streams.begin(); it != streams.end();) {
            if (currentStreamsNum_.load() <= MAX_NUMBER_OF_HELD_STREAMS) {
                return;
            }
            if ((*it) != nullptr && StreamState::STOPPED == (*it)->GetStreamState()) {
                MEDIA_LOGE("RemoveInvalidStreamsInNoInterruptMode, NO_INTERRUPT, streamID is %{public}d",
                    (*it)->GetStreamID());
                (*it)->Release();
                it = streams.erase(it);
                currentStreamsNum_--;
                continue;
            }
            it++;
        }
    }
}

std::shared_ptr<AudioStream> StreamIDManager::GetStreamByStreamIDWithLock(int32_t streamID)
{
    std::lock_guard lock(streamIDManagerLock_);
    return GetStreamByStreamID(streamID);
}

int32_t StreamIDManager::ReorderStream(int32_t streamID, int32_t priority)
{
    std::lock_guard lock(streamIDManagerLock_);
    int32_t playingSize = static_cast<int32_t>(playingStreamIDs_.size());
    for (int32_t i = 0; i < playingSize - 1; ++i) {
        for (int32_t j = 0; j < playingSize - 1 - i; ++j) {
            std::shared_ptr<AudioStream> left = GetStreamByStreamID(playingStreamIDs_[j]);
            std::shared_ptr<AudioStream> right = GetStreamByStreamID(playingStreamIDs_[j + 1]);
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                int32_t tmpStreamId = playingStreamIDs_[j];
                playingStreamIDs_[j] = playingStreamIDs_[j + 1];
                playingStreamIDs_[j + 1] = tmpStreamId;
            }
        }
    }
    for (size_t i = 0; i < playingStreamIDs_.size(); i++) {
        int32_t playingStreamID = playingStreamIDs_[i];
        MEDIA_LOGD("ReorderStream,  playingStreamID is %{public}d", playingStreamID);
    }
    
    int32_t willPlaySize = static_cast<int32_t>(willPlayStreamInfos_.size());
    for (int32_t i = 0; i < willPlaySize - 1; ++i) {
        for (int32_t j = 0; j < willPlaySize - 1 - i; ++j) {
            std::shared_ptr<AudioStream> left = GetStreamByStreamID(willPlayStreamInfos_[j].streamID);
            std::shared_ptr<AudioStream> right = GetStreamByStreamID(willPlayStreamInfos_[j + 1].streamID);
            if (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) {
                StreamIDAndPlayParamsInfo willPlayInfoTemp = willPlayStreamInfos_[j];
                willPlayStreamInfos_[j] = willPlayStreamInfos_[j + 1];
                willPlayStreamInfos_[j + 1] = willPlayInfoTemp;
            }
        }
    }
    for (size_t i = 0; i < willPlayStreamInfos_.size(); i++) {
        StreamIDAndPlayParamsInfo willPlayInfo = willPlayStreamInfos_[i];
        MEDIA_LOGD("ReorderStream, willPlayStreamID is %{public}d", willPlayInfo.streamID);
    }
    return MSERR_OK;
}

int32_t StreamIDManager::ClearStreamIDInDeque(int32_t soundID, int32_t streamID)
{
    std::lock_guard lock(streamIDManagerLock_);
    for (auto it = playingStreamIDs_.begin(); it != playingStreamIDs_.end();) {
        if (*it == streamID) {
            MEDIA_LOGI("ClearStreamIDInDeque, PlayingDel streamID is %{public}d", streamID);
            it = playingStreamIDs_.erase(it);
            continue;
        }
        ++it;
    }

    for (auto it = willPlayStreamInfos_.begin(); it != willPlayStreamInfos_.end();) {
        if (it->streamID == streamID) {
            MEDIA_LOGI("StreamIDManager::ClearStreamIDInDeque willPlayDel streamID:%{public}d", streamID);
            it = willPlayStreamInfos_.erase(it);
            continue;
        }
        ++it;
    }

    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "ClearStreamIDInDeque, stream is nullptr");
    stream->Release();
    stream->SetStreamState(StreamState::RELEASED);
    if (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT) {
        RemoveStreamByStreamIDInNoInterruptMode(soundID);
        return MSERR_OK;
    }
    if (interruptMode_ == InterruptMode::NO_INTERRUPT) {
        RemoveStreamByStreamIDInInterruptMode(soundID, streamID);
        return MSERR_OK;
    }

    return MSERR_OK;
}

int32_t StreamIDManager::GetStreamIDBySoundID(int32_t soundID)
{
    CHECK_AND_RETURN_RET_LOG(!soundID2Stream_.empty(), 0, "GetStreamIDBySoundID, soundID2Stream_ is empty");
    CHECK_AND_RETURN_RET_LOG(soundID2Stream_.find(soundID) != soundID2Stream_.end(), 0,
        "GetStreamIDBySoundID, soundID2Stream_[%{public}d] is nullptr", soundID);
    CHECK_AND_RETURN_RET_LOG(soundID2Stream_[soundID] != nullptr, 0,
        "GetStreamIDBySoundID, soundID2Stream_[%{public}d] is nullptr", soundID);
    int32_t streamID = soundID2Stream_[soundID]->GetStreamID();
    return streamID;
}

int32_t StreamIDManager::GetStreamIDBySoundIDWithLock(int32_t soundID)
{
    std::lock_guard lock(streamIDManagerLock_);
    return GetStreamIDBySoundID(soundID);
}

void StreamIDManager::RemoveStreamByStreamIDInInterruptMode(int32_t soundID, int32_t streamID)
{
    CHECK_AND_RETURN_LOG(soundID2MultiStreams_.find(soundID) != soundID2MultiStreams_.end(),
        "soundID(%{public}d) not exist in soundID2MultiStreams_", soundID);
    std::list<std::shared_ptr<AudioStream>> &streams = soundID2MultiStreams_[soundID];
    for (auto it = streams.begin(); it != streams.end(); it++) {
        if ((*it) != nullptr && (*it)->GetStreamID() == streamID) {
            streams.erase(it);
            currentStreamsNum_--;
            return;
        }
    }
}

void StreamIDManager::RemoveStreamByStreamIDInNoInterruptMode(int32_t soundID)
{
    CHECK_AND_RETURN_LOG(soundID2Stream_.find(soundID) != soundID2Stream_.end(),
        "soundID(%{public}d) not exist in soundID2Stream_", soundID);
    soundID2Stream_.erase(soundID);
    currentStreamsNum_--;
    return;
}

int32_t StreamIDManager::GetAvailableStreamIDBySoundID(int32_t soundID)
{
    if (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT) {
        CHECK_AND_RETURN_RET_LOG(soundID2Stream_.find(soundID) != soundID2Stream_.end(), 0,
            "soundID not exist in soundID2Stream_");
        const std::shared_ptr<AudioStream> &stream = soundID2Stream_[soundID];
        CHECK_AND_RETURN_RET_LOG(stream != nullptr, 0, "GetAvailableStreamIDBySoundID, stream is nullptr");
        if (stream->GetStreamState() == StreamState::STOPPED) {
            stream->SetStreamState(StreamState::PREPARED);
            return stream->GetStreamID();
        }
        MEDIA_LOGI("GetAvailableStreamIDBySoundID, before StopSameSoundWithoutLock");
        if (stream->GetStreamState() == StreamState::PLAYING) {
            stream->StopSameSoundWithoutLock();
            stream->SetStreamState(StreamState::PREPARED);
            return stream->GetStreamID();
        }
        return 0;
    }

    CHECK_AND_RETURN_RET_LOG(soundID2MultiStreams_.find(soundID) != soundID2MultiStreams_.end(), 0,
        "soundID not exist in soundID2MultiStreams_");
    const std::list<std::shared_ptr<AudioStream>> &streams = soundID2MultiStreams_[soundID];
    for (const std::shared_ptr<AudioStream> &stream : streams) {
        CHECK_AND_RETURN_RET_LOG(stream != nullptr, 0, "GetAvailableStreamIDBySoundID, stream is nullptr");
        if (stream->GetStreamState() == StreamState::STOPPED) {
            stream->SetStreamState(StreamState::PREPARED);
            return stream->GetStreamID();
        }
    }
    return 0;
}

int32_t StreamIDManager::CreateAudioStream(int32_t soundID, int32_t &streamID,
    const std::shared_ptr<SoundParser> &soundParser)
{
    do {
        nextStreamID_ = nextStreamID_ == INT32_MAX ? 1 : nextStreamID_ + 1;
    } while (GetStreamByStreamID(nextStreamID_) != nullptr);
    streamID = nextStreamID_;

    std::shared_ptr<AudioBufferEntry> pcmBuffer = nullptr;
    soundParser->GetSoundData(pcmBuffer);
    size_t pcmBufferSize = soundParser->GetSoundDataTotalSize();

    std::shared_ptr<AudioStream> stream = std::make_shared<AudioStream>(soundParser->GetSoundTrackFormat(), soundID,
        streamID, streamStopThreadPool_);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "failed to create stream");
    stream->SetPcmBuffer(pcmBuffer, pcmBufferSize);
    stream->SetManager(weak_from_this());

    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    stream->SetCallback(callback_);
    audioStreamCallback_ = std::make_shared<AudioStreamCallBack>(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(audioStreamCallback_ != nullptr, MSERR_INVALID_VAL,
        "audioStreamCallback_ is nullptr");
    stream->SetStreamCallback(audioStreamCallback_);
    if (frameWriteCallback_ != nullptr) {
        stream->SetFrameWriteCallback(frameWriteCallback_);
    }
    std::chrono::microseconds duration(soundParser->GetSourceDuration());
    int64_t durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    stream->SetSourceDuration(durationMs);
    MEDIA_LOGI("InitStream, push {%{public}d, %{public}d}", soundID, streamID);
    if (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT) {
        soundID2Stream_[soundID] = stream;
        currentStreamsNum_++;
        return MSERR_OK;
    }
    soundID2MultiStreams_[soundID].push_back(stream);
    currentStreamsNum_++;
    return MSERR_OK;
}

void StreamIDManager::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManager::OnPlayFinished start");
    std::lock_guard lock(streamIDManagerLock_);
    auto it = std::find(playingStreamIDs_.begin(), playingStreamIDs_.end(), streamID);
    if (it != playingStreamIDs_.end()) {
        playingStreamIDs_.erase(it);
    }
    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    if (stream->GetStreamState() == StreamState::PLAYING) {
        stream->SetStreamState(StreamState::STOPPED);
    }
    MEDIA_LOGI("StreamIDManager::OnPlayFinished end, streamID is %{public}d", streamID);
    if (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT && !willPlayStreamInfos_.empty()) {
        MEDIA_LOGI("StreamIDManager OnPlayFinished will play streams non empty, get the front.");
        StreamIDAndPlayParamsInfo willPlayStreamInfo = willPlayStreamInfos_.front();
        AddPlayTask(willPlayStreamInfo.streamID);
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

void StreamIDManager::AudioStreamCallBack::OnLoadCompleted(int32_t soundID)
{
    (void)soundID;
}

void StreamIDManager::AudioStreamCallBack::OnPlayFinished(int32_t streamID)
{
    (void)streamID;
    if (std::shared_ptr<StreamIDManager> ptr = streamIDManagerInner_.lock()) {
        ptr->OnPlayFinished(streamID);
    }
}

void StreamIDManager::AudioStreamCallBack::OnError(int32_t errorCode)
{
    (void)errorCode;
}

void StreamIDManager::PrintSoundID2Stream()
{
    for (const auto &mem : soundID2Stream_) {
        CHECK_AND_CONTINUE_LOG(mem.second != nullptr, "soundID is %{public}d, stream is nullptr", mem.first);
        MEDIA_LOGI("PrintSoundID2Stream, soundID is %{public}d, streamID is %{public}d, state is %{public}d",
            mem.first, mem.second->GetStreamID(), mem.second->GetStreamState());
    }
}

void StreamIDManager::PrintSoundID2MultiStreams()
{
    for (const auto &mem : soundID2MultiStreams_) {
        for (const auto &stream : mem.second) {
            CHECK_AND_CONTINUE_LOG(stream != nullptr, "soundID is %{public}d, stream is nullptr", mem.first);
            MEDIA_LOGI("PrintSoundID2MultiStreams, soundID is %{public}d, streamID is %{public}d, state is %{public}d",
                mem.first, stream->GetStreamID(), stream->GetStreamState());
        }
    }
}

void StreamIDManager::PrintPlayingStreams()
{
    for (const auto &mem : playingStreamIDs_) {
        MEDIA_LOGI("PrintPlayingStreams, streamID is %{public}d", mem);
    }
}
} // namespace Media
} // namespace OHOS
