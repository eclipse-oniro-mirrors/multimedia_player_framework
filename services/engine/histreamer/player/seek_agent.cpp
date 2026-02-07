/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#define HST_LOG_TAG "SeekAgent"

#include "seek_agent.h"
#include "common/log.h"
#include "meta/media_types.h"
#include "meta/meta.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "SeekAgent" };
}

namespace OHOS {
namespace Media {

AudioBufferFilledListener::AudioBufferFilledListener(std::shared_ptr<SeekAgent> seekAgent,
    sptr<AVBufferQueueProducer> producer, int32_t trackId)
    : seekAgent_(seekAgent), producer_(producer), trackId_(trackId)
{
    MEDIA_LOG_I("AudioBufferFilledListener ctor called.");
}

void AudioBufferFilledListener::OnBufferFilled(std::shared_ptr<AVBuffer>& buffer)
{
    if (auto agent = seekAgent_.lock()) {
        agent->OnAudioBufferFilled(buffer, producer_, trackId_);
    } else {
        MEDIA_LOG_E("Invalid agent instance.");
    }
}

VideoBufferFilledListener::VideoBufferFilledListener(std::shared_ptr<SeekAgent> seekAgent,
    sptr<AVBufferQueueProducer> producer, int32_t trackId)
    : seekAgent_(seekAgent), producer_(producer), trackId_(trackId)
{
    MEDIA_LOG_I("VideoBufferFilledListener ctor called.");
}

void VideoBufferFilledListener::OnBufferFilled(std::shared_ptr<AVBuffer>& buffer)
{
    if (auto agent = seekAgent_.lock()) {
        agent->OnVideoBufferFilled(buffer, producer_, trackId_);
    } else {
        MEDIA_LOG_E("Invalid agent instance.");
    }
}

SeekAgent::SeekAgent(std::shared_ptr<Pipeline::DemuxerFilter> demuxer, int64_t startPts)
    : demuxer_(demuxer), isAudioTargetArrived_(true), isVideoTargetArrived_(true),
    seekTargetPts_(-1), mediaStartPts_(startPts), isSeeking_(false)
{
    MEDIA_LOG_I("SeekAgent ctor called.");
}

SeekAgent::~SeekAgent()
{
    MEDIA_LOG_I("~SeekAgent dtor called.");
}

Status SeekAgent::Seek(int64_t seekPos, bool &timeout, const std::shared_ptr<Pipeline::EventReceiver>& receiver)
{
    MEDIA_LOG_I("Seek start, seekPos: %{public}" PRId64, seekPos);
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, Status::ERROR_INVALID_PARAMETER, "Invalid demuxer filter instance.");
    seekTargetPts_ = seekPos * MS_TO_US + mediaStartPts_;
    int64_t realSeekTime = seekPos;
    auto st = demuxer_->SeekTo(seekPos, Plugins::SeekMode::SEEK_CLOSEST_INNER, realSeekTime);
    FALSE_RETURN_V_MSG_E(st == Status::OK, Status::ERROR_INVALID_OPERATION, "Seekto error.");
 
    isSeeking_ = true;
    st = SetBufferFilledListener();
    FALSE_RETURN_V_MSG_E(st == Status::OK, Status::ERROR_INVALID_OPERATION, "SetBufferFilledListener failed.");

    demuxer_->SetIsNotPrepareBeforeStart(true);
    MEDIA_LOG_I("demuxer_ realSeekTime: %{public}" PRId64 "ns", realSeekTime);
    demuxer_->PrepareBeforeStart();
    bool isClosetSeekDone = true;
    {
        AutoLock lock(targetArrivedLock_);
        receiver->OnEvent({"seek_agent", EventType::EVENT_NOTIFY_SEEK_CLOSEST, false});
        demuxer_->ResumeForSeek();
        MEDIA_LOG_I("ResumeForSeek end");
        isClosetSeekDone = targetArrivedCond_.WaitFor(lock, WAIT_MAX_MS, [this] {
            return (isAudioTargetArrived_ && (isVideoTargetArrived_ || demuxer_->IsVideoMuted())) || isInterruptNeeded_;
        });
        receiver->OnEvent({"seek_agent", EventType::EVENT_NOTIFY_SEEK_CLOSEST, true});
        MEDIA_LOG_I("Wait end");
    }
    MEDIA_LOG_I("PauseForSeek start");
    demuxer_->PauseForSeek();
    st = RemoveBufferFilledListener();
    // interrupt with error
    if (isInterruptNeeded_) {
        return Status::ERROR_INVALID_OPERATION;
    }
    if (!isClosetSeekDone) {
        MEDIA_LOG_I("closet seek time out");
        timeout = true;
        demuxer_->Flush();
        auto st = demuxer_->SeekTo(seekPos, Plugins::SeekMode::SEEK_CLOSEST_INNER, realSeekTime);
        FALSE_RETURN_V_MSG_E(st == Status::OK, Status::ERROR_INVALID_OPERATION, "Seekto error.");
    }
    return st;
}

Status SeekAgent::GetAllTrackInfo(std::vector<int32_t> &videoTrackIds, std::vector<int32_t> &audioTrackIds)
{
    auto trackInfo = demuxer_->GetStreamMetaInfo();
    int32_t trackInfoSize = static_cast<int32_t>(trackInfo.size());
    for (int32_t index = 0; index < trackInfoSize; index++) {
        auto trackMeta = trackInfo[index];
        std::string mimeType;
        if (trackMeta->Get<Tag::MIME_TYPE>(mimeType) && mimeType.find("video") == 0) {
            MEDIA_LOG_I("Find video trackId: " PUBLIC_LOG_U32 ", mimeType: " PUBLIC_LOG_S, index, mimeType.c_str());
            videoTrackIds.push_back(index);
            continue;
        }
        if (trackMeta->Get<Tag::MIME_TYPE>(mimeType) && mimeType.find("audio") == 0) {
            MEDIA_LOG_I("Find audio trackId: " PUBLIC_LOG_U32 ", mimeType: " PUBLIC_LOG_S, index, mimeType.c_str());
            audioTrackIds.push_back(index);
        }
    }
    return Status::OK;
}

bool SeekAgent::GetAudioTrackId(int32_t &audioTrackId)
{
    FALSE_RETURN_V_MSG_E(!producerMap_.empty(), false, "producerMap is empty.");
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, false, "Invalid demuxer filter instance.");
    auto trackInfo = demuxer_->GetStreamMetaInfo();
    FALSE_RETURN_V_MSG_E(!trackInfo.empty(), false, "track info is empty.");
    int32_t trackInfoSize = static_cast<int32_t>(trackInfo.size());
    for (int32_t index = 0; index < trackInfoSize; index++) {
        auto trackMeta = trackInfo[index];
        std::string mimeType;
        if (!trackMeta->Get<Tag::MIME_TYPE>(mimeType) || mimeType.find("audio") != 0) {
            continue;
        }
        if (producerMap_.find(index) != producerMap_.end() && producerMap_[index] != nullptr) {
            audioTrackId = index;
            return true;
        }
    }
    return false;
}

Status SeekAgent::SetBufferFilledListener()
{
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, Status::ERROR_INVALID_PARAMETER, "Invalid demuxer filter instance.");
    producerMap_ = demuxer_->GetBufferQueueProducerMap();
    FALSE_RETURN_V_MSG_E(!producerMap_.empty(), Status::ERROR_INVALID_PARAMETER, "producerMap is empty.");

    std::vector<int32_t> videoTrackIds;
    std::vector<int32_t> audioTrackIds;
    GetAllTrackInfo(videoTrackIds, audioTrackIds);

    auto it = producerMap_.begin();
    while (it != producerMap_.end()) {
        if (it->second == nullptr) {
            it++;
            continue;
        }
        if (std::find(audioTrackIds.begin(), audioTrackIds.end(), it->first) != audioTrackIds.end()) {
            sptr<IBrokerListener> audioListener
                = new AudioBufferFilledListener(shared_from_this(), it->second, it->first);
            {
                AutoLock lock(targetArrivedLock_);
                isAudioTargetArrived_ = false;
            }
            MEDIA_LOG_I("Add Listener audio id : %{public}d", it->first);
            it->second->SetBufferFilledListener(audioListener);
            listenerMap_.insert({it->first, audioListener});
            it++;
            continue;
        }
        if (std::find(videoTrackIds.begin(), videoTrackIds.end(), it->first) != videoTrackIds.end()) {
            sptr<IBrokerListener> videoListener
                = new VideoBufferFilledListener(shared_from_this(), it->second, it->first);
            {
                AutoLock lock(targetArrivedLock_);
                isVideoTargetArrived_ = false;
            }
            MEDIA_LOG_I("Add Listener video id : %{public}d", it->first);
            it->second->SetBufferFilledListener(videoListener);
            listenerMap_.insert({it->first, videoListener});
        }
        it++;
    }
    return Status::OK;
}

Status SeekAgent::RemoveBufferFilledListener()
{
    auto it = listenerMap_.begin();
    while (it != listenerMap_.end()) {
        auto iterator = producerMap_.find(it->first);
        if (iterator == producerMap_.end()) {
            it++;
            continue;
        }
        auto producer = iterator->second;
        if (producer == nullptr) {
            it++;
            continue;
        }
        if (it->second == nullptr) {
            it++;
            continue;
        }
        producer->RemoveBufferFilledListener(it->second);
        it++;
    }
    return Status::OK;
}

Status SeekAgent::OnAudioBufferFilled(std::shared_ptr<AVBuffer>& buffer,
    sptr<AVBufferQueueProducer> producer, int32_t trackId)
{
    MEDIA_LOG_D("OnAudioBufferFilled, pts: %{public}" PRId64, buffer->pts_);
    if (buffer->pts_ >= seekTargetPts_ || (buffer->flag_ & static_cast<uint32_t>(AVBufferFlag::EOS))) {
        {
            AutoLock lock(targetArrivedLock_);
            isAudioTargetArrived_ = true;
        }
        MEDIA_LOG_I("audio arrive target pts = %{public}" PRId64, buffer->pts_);
        FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, Status::ERROR_NULL_POINTER, "demuxer_ is nullptr.");
        demuxer_->PauseTaskByTrackId(trackId);
        targetArrivedCond_.NotifyAll();

        producer->ReturnBuffer(buffer, false);
        return Status::OK;
    }
    MEDIA_LOG_D("OnAudioBufferFilled, ReturnBuffer");
    producer->ReturnBuffer(buffer, false);
    return Status::OK;
}

Status SeekAgent::OnVideoBufferFilled(std::shared_ptr<AVBuffer>& buffer,
    sptr<AVBufferQueueProducer> producer, int32_t trackId)
{
    MEDIA_LOG_I("OnVideoBufferFilled, pts: %{public}" PRId64, buffer->pts_);
    if (buffer->pts_ >= seekTargetPts_ || (buffer->flag_ & static_cast<uint32_t>(AVBufferFlag::EOS))) {
        {
            AutoLock lock(targetArrivedLock_);
            isVideoTargetArrived_ = true;
        }
        MEDIA_LOG_I("video arrive target");
        FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, Status::ERROR_NULL_POINTER, "demuxer_ is nullptr.");
        demuxer_->PauseTaskByTrackId(trackId);
        targetArrivedCond_.NotifyAll();
        producer->ReturnBuffer(buffer, true);
        return Status::OK;
    }
    bool canDrop = false;
    buffer->meta_->GetData(Media::Tag::VIDEO_BUFFER_CAN_DROP, canDrop);
    MEDIA_LOG_D("ReturnBuffer, pts: %{public}" PRId64 ", isPushBuffer: %{public}i", buffer->pts_, !canDrop);
    producer->ReturnBuffer(buffer, !canDrop);
    return Status::OK;
}

Status SeekAgent::AlignAudioPosition(int64_t audioPosition)
{
    MEDIA_LOG_I("AlignAudioPosition, audioPosition: %{public}" PRId64, audioPosition);
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr, Status::OK, "Invalid demuxer filter instance.");
    producerMap_ = demuxer_->GetBufferQueueProducerMap();
    FALSE_RETURN_V_MSG_E(!producerMap_.empty(), Status::OK, "producerMap is empty.");
    int32_t audioTrackId = 0;
    FALSE_RETURN_V_MSG_E(GetAudioTrackId(audioTrackId), Status::OK, "audioTrackIds is empty.");
    seekTargetPts_ = audioPosition * MS_TO_US;
    sptr<IBrokerListener> audioListener
        = new AudioBufferFilledListener(shared_from_this(), producerMap_[audioTrackId], audioTrackId);
    {
        AutoLock lock(targetArrivedLock_);
        isAudioTargetArrived_ = false;
    }
    producerMap_[audioTrackId]->SetBufferFilledListener(audioListener);
    listenerMap_.insert({audioTrackId, audioListener});
    {
        AutoLock lock(targetArrivedLock_);
        demuxer_->ResumeAudioAlign();
        targetArrivedCond_.WaitFor(lock, WAIT_MAX_MS, [this] {return isAudioTargetArrived_;});
        MEDIA_LOG_I("Wait end");
    }
    MEDIA_LOG_I("PauseForSeek start");
    auto ret = demuxer_->PauseAudioAlign();
    RemoveBufferFilledListener();
    return ret;
}

void SeekAgent::OnInterrupted(bool isInterruptNeeded)
{
    MEDIA_LOG_D("SeekAgent onInterrupted %{public}d", isInterruptNeeded);
    isInterruptNeeded_ = isInterruptNeeded;
    targetArrivedCond_.NotifyAll();
}
}  // namespace Media
}  // namespace OHOS
