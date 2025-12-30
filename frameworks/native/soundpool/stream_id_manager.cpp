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
    static const int32_t MAX_START_THREADS_NUM = 5;
    static const int32_t MAX_STOPPED_THREADS_NUM = 5;
    static const int32_t ERROE_GLOBAL_ID = -1;
    static const size_t MAX_NUMBER_OF_PLAYING = 32;
    static const int32_t MAX_NUMBER_OF_HELD_STREAMS = 5;
}

namespace OHOS {
namespace Media {
IStreamIDManager::IStreamIDManager(int32_t maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo)
    : audioRendererInfo_(audioRenderInfo), maxStreams_(maxStreams)
{
    audioRendererInfo_.playerType = AudioStandard::PlayerType::PLAYER_TYPE_SOUND_POOL;
    currentStreamsNum_.store(0);
}

IStreamIDManager::~IStreamIDManager()
{
    MEDIA_LOGI("IStreamIDManager Destructor");
    if (callback_ != nullptr) {
        callback_.reset();
    }
    if (frameWriteCallback_ != nullptr) {
        frameWriteCallback_.reset();
    }

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

int32_t IStreamIDManager::InitThreadPool()
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
    streamPlayingThreadPool_->Start(MAX_START_THREADS_NUM);
    streamPlayingThreadPool_->SetMaxTaskNum(maxStreams_);
    isStreamPlayingThreadPoolStarted_.store(true);

    streamStopThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_CACHE_BUFFER);
    CHECK_AND_RETURN_RET_LOG(streamStopThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stop ThreadPool");
    streamStopThreadPool_->Start(MAX_STOPPED_THREADS_NUM);
    streamStopThreadPool_->SetMaxTaskNum(maxStreams_);
    isStreamStopThreadPoolStarted_.store(true);

    return MSERR_OK;
}

std::vector<int32_t> IStreamIDManager::GetStreamIDBySoundIDWithLock(int32_t soundID)
{
    std::lock_guard lock(streamIDManagerLock_);
    return GetStreamIDBySoundID(soundID);
}

std::shared_ptr<AudioStream> IStreamIDManager::GetStreamByStreamIDWithLock(int32_t streamID)
{
    std::lock_guard lock(streamIDManagerLock_);
    return GetStreamByStreamID(streamID);
}

int32_t IStreamIDManager::ReorderStream(int32_t streamID, int32_t priority)
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

int32_t IStreamIDManager::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t IStreamIDManager::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}

int32_t IStreamIDManager::Play(const std::shared_ptr<SoundParser> &soundParser, const PlayParams &playParameters)
{
    MediaTrace trace("IStreamIDManager::Play");
    std::lock_guard lock(streamIDManagerLock_);
    MEDIA_LOGI("Play, before remove");
    PrintPlayingStreams();
    PrintSoundID2Stream();
    RemoveInvalidStreams();
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Play, soundParser is nullptr");
    int32_t soundID = soundParser->GetSoundID();
    int32_t streamID = GetAvailableStreamIDBySoundID(soundID);
    if (streamID == 0) {
        CHECK_AND_RETURN_RET_LOG(MSERR_OK == CreateAudioStream(soundID, streamID, soundParser), -1,
            "Init stream failed");
    }
    MEDIA_LOGI("Play, get stream successfully, soundID is %{public}d, streamID is %{public}d", soundID, streamID);
    int32_t result = SetPlay(soundID, streamID, playParameters);
    CHECK_AND_RETURN_RET_LOG(result == MSERR_OK, errorStreamId, "Invalid SetPlay");
    return streamID;
}

std::shared_ptr<AudioStream> IStreamIDManager::InnerProcessOfCreateAudioStream(int32_t soundID, int32_t &streamID,
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
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, nullptr, "failed to create stream");
    CHECK_AND_RETURN_RET_LOG(stream->SetPcmSharedMemory(soundParser->GetAudioSharedMemory(), pcmBufferSize), nullptr,
        "SetPcmSharedMemory failed");

    if (frameWriteCallback_ != nullptr) {
        stream->SetFrameWriteCallback(frameWriteCallback_);
    }
    std::chrono::microseconds duration(soundParser->GetSourceDuration());
    int64_t durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    stream->SetSourceDuration(durationMs);
    return stream;
}

void IStreamIDManager::PrintPlayingStreams()
{
    for (const auto &mem : playingStreamIDs_) {
        MEDIA_LOGI("PrintPlayingStreams, streamID is %{public}d", mem);
    }
}

bool IStreamIDManager::InnerProcessOfOnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("InnerProcessOfOnPlayFinished start");
    auto it = std::find(playingStreamIDs_.begin(), playingStreamIDs_.end(), streamID);
    if (it != playingStreamIDs_.end()) {
        playingStreamIDs_.erase(it);
    }
    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, false, "OnPlayFinished, stream is nullptr");
    if (stream->GetStreamState() == StreamState::PLAYING) {
        stream->SetStreamState(StreamState::STOPPED);
    }
    MEDIA_LOGI("InnerProcessOfOnPlayFinished end, streamID is %{public}d", streamID);
    return true;
}

int32_t IStreamIDManager::AddPlayTask(int32_t streamID)
{
    MEDIA_LOGI("AddPlayTask, streamID is %{public}d", streamID);
    ThreadPool::Task streamPlayTask = [this, streamID] { this->DoPlay(streamID); };
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain streamPlayingThreadPool_");
    CHECK_AND_RETURN_RET_LOG(streamPlayTask != nullptr, MSERR_INVALID_VAL,
        "AddPlayTask, streamPlayTask is nullptr");
    QueueAndSortPlayingStreamID(streamID);

    streamPlayingThreadPool_->AddTask(streamPlayTask);
    MEDIA_LOGI("AddPlayTask end, streamID is %{public}d", streamID);
    return MSERR_OK;
}

int32_t IStreamIDManager::AddStopTask(const std::shared_ptr<AudioStream> &stream)
{
    MEDIA_LOGI("AddStopTask, streamID is %{public}d", stream->GetStreamID());
    ThreadPool::Task streamStopTask = [stream] { stream->Stop(); };
    CHECK_AND_RETURN_RET_LOG(streamStopThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain streamStopThreadPool_");
    CHECK_AND_RETURN_RET_LOG(streamStopTask != nullptr, MSERR_INVALID_VAL,
        "AddStopTask, streamStopTask is nullptr");
    streamStopThreadPool_->AddTask(streamStopTask);
    MEDIA_LOGI("AddStopTask end, streamID is %{public}d", stream->GetStreamID());
    return MSERR_OK;
}

// Sort in descending order
// 0 has the lowest priority, and the higher the value, the higher the priority
// The queue head has the highest value and priority
void IStreamIDManager::QueueAndSortPlayingStreamID(int32_t freshStreamID)
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
void IStreamIDManager::QueueAndSortWillPlayStreamID(const StreamIDAndPlayParamsInfo &streamIDAndPlayParamsInfo)
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

void IStreamIDManager::PostProcessingOfStreamDoPlayFailed(int32_t streamID)
{
    MEDIA_LOGI("PostProcessingOfStreamDoPlayFailed, streamID is %{public}d", streamID);
    for (int32_t i = 0; i < static_cast<int32_t>(playingStreamIDs_.size()); i++) {
        if (streamID == playingStreamIDs_[i]) {
            std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
            CHECK_AND_RETURN_LOG(stream != nullptr, "PostProcessingOfStreamDoPlayFailed, stream is nullptr");
            playingStreamIDs_.erase(playingStreamIDs_.begin() + i);
            stream->SetStreamState(StreamState::RELEASED);
            return;
        }
    }
    return;
}

void IStreamIDManager::AudioStreamCallBack::OnLoadCompleted(int32_t soundID)
{
    (void)soundID;
}

void IStreamIDManager::AudioStreamCallBack::OnPlayFinished(int32_t streamID)
{
    (void)streamID;
    if (std::shared_ptr<IStreamIDManager> ptr = streamIDManagerInner_.lock()) {
        ptr->OnPlayFinished(streamID);
    }
}

void IStreamIDManager::AudioStreamCallBack::OnError(int32_t errorCode)
{
    (void)errorCode;
}

StreamIDManagerWithSameSoundInterrupt::StreamIDManagerWithSameSoundInterrupt(int32_t maxStreams,
    const AudioStandard::AudioRendererInfo &audioRenderInfo) : IStreamIDManager(maxStreams, audioRenderInfo)
{
    MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt Constructor");
}

StreamIDManagerWithSameSoundInterrupt::~StreamIDManagerWithSameSoundInterrupt()
{
    MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt Destructor");
    for (auto stream : soundID2Stream_) {
        if (stream.second != nullptr) {
            stream.second->Stop();
            stream.second->Release();
        }
    }
    soundID2Stream_.clear();
}

int32_t StreamIDManagerWithSameSoundInterrupt::GetAvailableStreamIDBySoundID(int32_t soundID)
{
    CHECK_AND_RETURN_RET_LOG(soundID2Stream_.find(soundID) != soundID2Stream_.end(), 0,
        "soundID not exist in soundID2Stream_");
    const std::shared_ptr<AudioStream> &stream = soundID2Stream_[soundID];
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, 0, "GetAvailableStreamIDBySoundID, stream is nullptr");
    if (stream->GetStreamState() != StreamState::RELEASED) {
        return stream->GetStreamID();
    }
    return 0;
}

void StreamIDManagerWithSameSoundInterrupt::RemoveInvalidStreams()
{
    MEDIA_LOGI("SAME_SOUND_INTERRUPT");
    static std::vector<StreamState> statesToCheck = {
        StreamState::RELEASED, StreamState::STOPPED, StreamState::PREPARED
    };
    for (const StreamState &state : statesToCheck) {
        for (auto it = soundID2Stream_.begin(); it != soundID2Stream_.end();) {
            CHECK_AND_RETURN(currentStreamsNum_.load() > MAX_NUMBER_OF_HELD_STREAMS);
            if (it->second != nullptr && state == it->second->GetStreamState()) {
                it->second->Release();
                it = soundID2Stream_.erase(it);
                currentStreamsNum_--;
                continue;
            }
            it++;
        }
    }
}

void StreamIDManagerWithSameSoundInterrupt::RemoveStreamBySoundIDAndStreamID(int32_t soundID, int32_t streamID)
{
    auto it = soundID2Stream_.find(soundID);
    CHECK_AND_RETURN_LOG(it != soundID2Stream_.end(), "soundID(%{public}d) not exist in soundID2Stream_", soundID);
    if ((*it).second->GetStreamID() != streamID) {
        MEDIA_LOGE("RemoveStreamBySoundIDAndStreamID, soundID(%{public}d) does not correspond to streamID(%{public}d)",
            soundID, streamID);
        return;
    }
    soundID2Stream_.erase(soundID);
    currentStreamsNum_--;
    return;
}

int32_t StreamIDManagerWithSameSoundInterrupt::ClearStreamIDInDeque(int32_t soundID, int32_t streamID)
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
    RemoveStreamBySoundIDAndStreamID(soundID, streamID);
    return MSERR_OK;
}

void StreamIDManagerWithSameSoundInterrupt::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt::OnPlayFinished start");
    std::lock_guard lock(streamIDManagerLock_);
    CHECK_AND_RETURN(InnerProcessOfOnPlayFinished(streamID));
    if (!willPlayStreamInfos_.empty()) {
        MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt OnPlayFinished will play streams non empty, get the front.");
        StreamIDAndPlayParamsInfo willPlayStreamInfo = willPlayStreamInfos_.front();
        AddPlayTask(willPlayStreamInfo.streamID);
        willPlayStreamInfos_.pop_front();
    }
}

int32_t StreamIDManagerWithSameSoundInterrupt::CreateAudioStream(int32_t soundID, int32_t &streamID,
    const std::shared_ptr<SoundParser> &soundParser)
{
    std::shared_ptr<AudioStream> stream = InnerProcessOfCreateAudioStream(soundID, streamID, soundParser);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "failed to create stream");
    stream->SetManager(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    stream->SetCallback(callback_);
    audioStreamCallback_ = std::make_shared<AudioStreamCallBack>(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(audioStreamCallback_ != nullptr, MSERR_INVALID_VAL, "audioStreamCallback_ is nullptr");
    stream->SetStreamCallback(audioStreamCallback_);
    MEDIA_LOGI("InitStream, push {%{public}d, %{public}d}", soundID, streamID);
    soundID2Stream_[soundID] = stream;
    currentStreamsNum_++;
    return MSERR_OK;
}

void StreamIDManagerWithSameSoundInterrupt::PrintSoundID2Stream()
{
    for (const auto &mem : soundID2Stream_) {
        CHECK_AND_CONTINUE_LOG(mem.second != nullptr, "soundID is %{public}d, stream is nullptr", mem.first);
        MEDIA_LOGI("PrintSoundID2Stream, soundID is %{public}d, streamID is %{public}d, state is %{public}d",
            mem.first, mem.second->GetStreamID(), mem.second->GetStreamState());
    }
}

int32_t StreamIDManagerWithSameSoundInterrupt::SetPlay(int32_t soundID, int32_t streamID,
    const PlayParams &playParameters)
{
    MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt::SetPlay start");
    MediaTrace trace("StreamIDManagerWithSameSoundInterrupt::SetPlay");
    if (!isStreamPlayingThreadPoolStarted_.load()) {
        InitThreadPool();
    }
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stream play threadpool");
    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "SetPlay, stream(%{public}d) is nullptr", streamID);
    stream->SetPriorityWithoutLock(playParameters.priority);
    stream->ConfigurePlayParametersWithoutLock(audioRendererInfo_, playParameters);

    if (playingStreamIDs_.size() < static_cast<size_t>(maxStreams_)) {
        MEDIA_LOGI("SetPlay, playingStreamIDs_.size is %{public}zu < %{public}d",
            playingStreamIDs_.size(), maxStreams_);
        AddPlayTask(streamID);
        return MSERR_OK;
    }

    MEDIA_LOGI("size of playingStreamIDs_ is %{public}zu", playingStreamIDs_.size());
    int32_t lastStreamID = playingStreamIDs_.back();
    std::shared_ptr<AudioStream> lastStream = GetStreamByStreamID(lastStreamID);
    if (lastStream == nullptr) {
        MEDIA_LOGI("SetPlay, lastStream is nullptr");
        playingStreamIDs_.pop_back();
        return MSERR_INVALID_VAL;
    }

    if (stream->GetPriority() >= lastStream->GetPriority()) {
        MEDIA_LOGI("SetPlay, last streamID is %{public}d, priority is %{public}d, state is %{public}d, "
            "current streamID is %{public}d, priority is %{public}d, state is %{public}d",
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

int32_t StreamIDManagerWithSameSoundInterrupt::DoPlay(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt::DoPlay start streamID is %{public}d", streamID);
    std::shared_ptr<AudioStream> stream = GetStreamByStreamIDWithLock(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL,
        "StreamIDManagerWithSameSoundInterrupt::DoPlay, stream is nullptr");
    if (stream->DoPlayWithSameSoundInterrupt() == MSERR_OK) {
        MEDIA_LOGI("StreamIDManagerWithSameSoundInterrupt::DoPlay successfully, streamID is %{public}d", streamID);
        return MSERR_OK;
    }

    {
        std::lock_guard lock(streamIDManagerLock_);
        PostProcessingOfStreamDoPlayFailed(streamID);
        return MSERR_INVALID_VAL;
    }
}

std::vector<int32_t> StreamIDManagerWithSameSoundInterrupt::GetStreamIDBySoundID(int32_t soundID)
{
    std::vector<int32_t> ret;
    CHECK_AND_RETURN_RET_LOG(!soundID2Stream_.empty(), ret, "GetStreamIDBySoundID, soundID2Stream_ is empty");
    CHECK_AND_RETURN_RET_LOG(soundID2Stream_.find(soundID) != soundID2Stream_.end(), ret,
        "GetStreamIDBySoundID, soundID(%{public}d) not exists in soundID2Stream_", soundID);
    CHECK_AND_RETURN_RET_LOG(soundID2Stream_[soundID] != nullptr, ret,
        "GetStreamIDBySoundID, soundID2Stream_[%{public}d] is nullptr", soundID);
    int32_t streamID = soundID2Stream_[soundID]->GetStreamID();
    return { streamID };
}

std::shared_ptr<AudioStream> StreamIDManagerWithSameSoundInterrupt::GetStreamByStreamID(int32_t streamID)
{
    CHECK_AND_RETURN_RET_LOG(streamID >= 0, nullptr, "streamID is invalid.");
    std::shared_ptr<AudioStream> stream = nullptr;
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

StreamIDManagerWithNoInterrupt::StreamIDManagerWithNoInterrupt(int32_t maxStreams,
    const AudioStandard::AudioRendererInfo &audioRenderInfo) : IStreamIDManager(maxStreams, audioRenderInfo)
{
    MEDIA_LOGI("StreamIDManagerWithNoInterrupt Constructor");
    maxNumOfParallelPlaying_ = static_cast<size_t>(maxStreams_) < maxNumOfParallelPlaying_ ?
        static_cast<size_t>(maxStreams_) : maxNumOfParallelPlaying_;
}

StreamIDManagerWithNoInterrupt::~StreamIDManagerWithNoInterrupt()
{
    MEDIA_LOGI("StreamIDManagerWithNoInterrupt Destructor");
    for (auto &mem : soundID2MultiStreams_) {
        for (std::shared_ptr<AudioStream> stream : mem.second) {
            if (stream != nullptr) {
                stream->Stop();
                stream->Release();
            }
        }
    }
    soundID2MultiStreams_.clear();
}

int32_t StreamIDManagerWithNoInterrupt::GetAvailableStreamIDBySoundID(int32_t soundID)
{
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

void StreamIDManagerWithNoInterrupt::RemoveInvalidStreams()
{
    MEDIA_LOGI("NO_INTERRUPT");
    static std::vector<StreamState> statesToCheck = {
        StreamState::RELEASED, StreamState::STOPPED
    };
    for (const StreamState &state : statesToCheck) {
        if (InnerProcessOfRemoveInvalidStreams(state)) {
            return;
        }
    }
}

bool StreamIDManagerWithNoInterrupt::InnerProcessOfRemoveInvalidStreams(const StreamState &state)
{
    for (auto &mem : soundID2MultiStreams_) {
        CHECK_AND_RETURN_RET(currentStreamsNum_.load() > MAX_NUMBER_OF_HELD_STREAMS, true);
        std::list<std::shared_ptr<AudioStream>> &streams = mem.second;
        for (auto it = streams.begin(); it != streams.end();) {
            CHECK_AND_RETURN_RET(currentStreamsNum_.load() > MAX_NUMBER_OF_HELD_STREAMS, true);
            if ((*it) != nullptr && state == (*it)->GetStreamState()) {
                MEDIA_LOGE("InnerProcessOfRemoveInvalidStreams, NO_INTERRUPT, streamID is %{public}d",
                    (*it)->GetStreamID());
                (*it)->Release();
                it = streams.erase(it);
                currentStreamsNum_--;
                continue;
            }
            it++;
        }
    }
    return false;
}

void StreamIDManagerWithNoInterrupt::RemoveStreamBySoundIDAndStreamID(int32_t soundID, int32_t streamID)
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

int32_t StreamIDManagerWithNoInterrupt::ClearStreamIDInDeque(int32_t soundID, int32_t streamID)
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

    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "ClearStreamIDInDeque, stream is nullptr");
    stream->Release();
    stream->SetStreamState(StreamState::RELEASED);
    RemoveStreamBySoundIDAndStreamID(soundID, streamID);
    return MSERR_OK;
}

void StreamIDManagerWithNoInterrupt::OnPlayFinished(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManagerWithNoInterrupt::OnPlayFinished start");
    std::lock_guard lock(streamIDManagerLock_);
    InnerProcessOfOnPlayFinished(streamID);
}

int32_t StreamIDManagerWithNoInterrupt::CreateAudioStream(int32_t soundID, int32_t &streamID,
    const std::shared_ptr<SoundParser> &soundParser)
{
    std::shared_ptr<AudioStream> stream = InnerProcessOfCreateAudioStream(soundID, streamID, soundParser);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "failed to create stream");
    stream->SetManager(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    stream->SetCallback(callback_);
    audioStreamCallback_ = std::make_shared<AudioStreamCallBack>(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(audioStreamCallback_ != nullptr, MSERR_INVALID_VAL, "audioStreamCallback_ is nullptr");
    stream->SetStreamCallback(audioStreamCallback_);
    MEDIA_LOGI("InitStream, push {%{public}d, %{public}d}", soundID, streamID);
    soundID2MultiStreams_[soundID].push_back(stream);
    currentStreamsNum_++;
    return MSERR_OK;
}

void StreamIDManagerWithNoInterrupt::PrintSoundID2Stream()
{
    for (const auto &mem : soundID2MultiStreams_) {
        for (const auto &stream : mem.second) {
            CHECK_AND_CONTINUE_LOG(stream != nullptr, "soundID is %{public}d, stream is nullptr", mem.first);
            MEDIA_LOGI("PrintSoundID2Stream, soundID is %{public}d, streamID is %{public}d, state is %{public}d",
                mem.first, stream->GetStreamID(), stream->GetStreamState());
        }
    }
}

int32_t StreamIDManagerWithNoInterrupt::SetPlay(int32_t soundID, int32_t streamID,
    const PlayParams &playParameters)
{
    MEDIA_LOGI("StreamIDManagerWithNoInterrupt::SetPlay start");
    MediaTrace trace("StreamIDManagerWithNoInterrupt::SetPlay");
    if (!isStreamPlayingThreadPoolStarted_.load()) {
        InitThreadPool();
    }
    CHECK_AND_RETURN_RET_LOG(streamPlayingThreadPool_ != nullptr, MSERR_INVALID_VAL,
        "Failed to obtain stream play threadpool");

    std::shared_ptr<AudioStream> stream = GetStreamByStreamID(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL, "SetPlay, stream(%{public}d) is nullptr", streamID);
    stream->SetPriority(playParameters.priority);
    stream->ConfigurePlayParameters(audioRendererInfo_, playParameters);
    if (playingStreamIDs_.size() < maxNumOfParallelPlaying_) {
        MEDIA_LOGI("SetPlay, playingStreamIDs_.size is %{public}zu < 5", playingStreamIDs_.size());
        AddPlayTask(streamID);
        return MSERR_OK;
    }

    MEDIA_LOGI("size of playingStreamIDs_ is %{public}zu", playingStreamIDs_.size());
    int32_t lastStreamID = playingStreamIDs_.back();
    std::shared_ptr<AudioStream> lastStream = GetStreamByStreamID(lastStreamID);
    if (lastStream == nullptr) {
        MEDIA_LOGI("SetPlay, lastStream is nullptr");
        playingStreamIDs_.pop_back();
        return MSERR_INVALID_VAL;
    }

    if (stream->GetPriority() >= lastStream->GetPriority()) {
        MEDIA_LOGI("SetPlay, last streamID is %{public}d, priority is %{public}d, state is %{public}d, "
            "current streamID is %{public}d, priority is %{public}d, state is %{public}d",
            lastStream->GetStreamID(), lastStream->GetPriority(), lastStream->GetStreamState(), stream->GetStreamID(),
            stream->GetPriority(), stream->GetStreamState());
        playingStreamIDs_.pop_back();
        AddStopTask(lastStream);
        AddPlayTask(streamID);
        MEDIA_LOGI("SetPlay end");
        return MSERR_OK;
    }
    
    MEDIA_LOGI("stream(%{public}d) will not be played", streamID);
    if (stream->GetStreamState() == StreamState::PREPARED) {
        stream->SetStreamState(StreamState::STOPPED);
    }
    return MSERR_INVALID_VAL;
}

int32_t StreamIDManagerWithNoInterrupt::DoPlay(int32_t streamID)
{
    MEDIA_LOGI("StreamIDManagerWithNoInterrupt::DoPlay start, streamID is %{public}d", streamID);
    std::shared_ptr<AudioStream> stream = GetStreamByStreamIDWithLock(streamID);
    CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL,
        "StreamIDManagerWithNoInterrupt::DoPlay, stream is nullptr");
    if (stream->DoPlayWithNoInterrupt() == MSERR_OK) {
        MEDIA_LOGI("StreamIDManagerWithNoInterrupt::DoPlayWithNoInterrupt successfully, streamID is %{public}d",
            streamID);
        return MSERR_OK;
    }

    {
        std::lock_guard lock(streamIDManagerLock_);
        PostProcessingOfStreamDoPlayFailed(streamID);
        return MSERR_INVALID_VAL;
    }
}

std::vector<int32_t> StreamIDManagerWithNoInterrupt::GetStreamIDBySoundID(int32_t soundID)
{
    std::vector<int32_t> ret;
    CHECK_AND_RETURN_RET_LOG(!soundID2MultiStreams_.empty(), ret,
        "GetStreamIDBySoundID, soundID2MultiStreams_ is empty");
    CHECK_AND_RETURN_RET_LOG(soundID2MultiStreams_.find(soundID) != soundID2MultiStreams_.end(), ret,
        "GetStreamIDBySoundID, soundID(%{public}d) not exists in soundID2MultiStreams_", soundID);
    CHECK_AND_RETURN_RET_LOG(!soundID2MultiStreams_[soundID].empty(), ret,
        "GetStreamIDBySoundID, soundID2MultiStreams_[%{public}d] is empty", soundID);
    std::list<std::shared_ptr<AudioStream>> audioStreams = soundID2MultiStreams_[soundID];
    for (const std::shared_ptr<AudioStream> &stream : audioStreams) {
        CHECK_AND_CONTINUE(stream != nullptr);
        ret.push_back(stream->GetStreamID());
    }
    return ret;
}

std::shared_ptr<AudioStream> StreamIDManagerWithNoInterrupt::GetStreamByStreamID(int32_t streamID)
{
    CHECK_AND_RETURN_RET_LOG(streamID >= 0, nullptr, "GetStreamByStreamID, streamID is invalid.");
    std::shared_ptr<AudioStream> stream = nullptr;
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
} // namespace Media
} // namespace OHOS
