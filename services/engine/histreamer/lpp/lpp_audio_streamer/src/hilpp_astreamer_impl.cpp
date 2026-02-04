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
#include "hilpp_astreamer_impl.h"
#include "common/log.h"
#include "media_errors.h"
#include "param_wrapper.h"
#include "osal/task/pipeline_threadpool.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "HiLppAStreamer"};
}

namespace OHOS {
namespace Media {

class LppAudioEventReceiver : public EventReceiver {
public:
    explicit LppAudioEventReceiver(std::weak_ptr<HiLppAudioStreamerImpl> audioStreamer, std::string streamerId)
    {
        MEDIA_LOG_I("LppAudioEventReceiver ctor called.");
        audioStreamer_ = audioStreamer;
        task_ = std::make_unique<Task>("AudioEventReceiver", streamerId, TaskType::GLOBAL, TaskPriority::HIGH, false);
    }

    void OnEvent(const Event &event) override
    {
        MEDIA_LOG_D("AudioEventReceiver OnEvent.");
        FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
        task_->SubmitJobOnce([this, event] {
            auto audioStreamer = audioStreamer_.lock();
            FALSE_RETURN_MSG(audioStreamer != nullptr, "audioStreamer is nullptr");
            audioStreamer->OnEvent(event);
        });
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("PlayerEventReceiver NotifyRelease.");
    }

private:
    std::weak_ptr<HiLppAudioStreamerImpl> audioStreamer_;
    std::unique_ptr<Task> task_;
};

HiLppAudioStreamerImpl::HiLppAudioStreamerImpl()
{
    std::string isLpp;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_audio_lpp", isLpp, "false");
    isLpp_ = ret == 0 ? isLpp == "true" : false;
    MEDIA_LOG_I("HiLppAudioStreamerImpl enabled: " PUBLIC_LOG_D32, isLpp_);
    streamerId_ = std::string("LppA_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
    MEDIA_LOG_I("HiLppAudioStreamerImpl " PUBLIC_LOG_S " construct.", streamerId_.c_str());
}

HiLppAudioStreamerImpl::~HiLppAudioStreamerImpl()
{
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    lppEngineManager.RemoveLppAudioInstance(streamerId_);
    Stop();
    FALSE_RETURN_MSG(aRender_ != nullptr, "audio renderer Start nullptr");
    aRender_->Deinit();
    MEDIA_LOG_I("HiLppAudioStreamerImpl Instances destroy.");
    PipeLineThreadPool::GetInstance().DestroyThread(streamerId_);
}

int32_t HiLppAudioStreamerImpl::Init(const std::string &mime)
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Init");
    callbackLooper_ = std::make_shared<LppAudioCallbackLooper>(streamerId_);
    dataMgr_ = std::make_shared<LppAudioDataManager>(streamerId_);
    adec_ = std::make_shared<LppAudioDecoderAdapter>(streamerId_);
    auto ret = adec_->Init(mime);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "Init failed");
    aRender_ = std::make_shared<LppAudioRenderAdapter>(streamerId_);
    return MSERR_OK;
}

std::string HiLppAudioStreamerImpl::GetStreamerId()
{
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    lppEngineManager.AddLppAudioInstance(streamerId_, shared_from_this());
    return streamerId_;
}

int32_t HiLppAudioStreamerImpl::SetLppVideoStreamerId(std::string videoStreamerId)
{
    videoStreamerId_ = videoStreamerId;
    MEDIA_LOG_I("HiLppAudioStreamerImpl::videoStreamerId %{public}s", videoStreamerId.c_str());
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    videoStreamerEngine_ = lppEngineManager.GetLppVideoInstance(videoStreamerId);
    FALSE_RETURN_V_MSG(videoStreamerEngine_ != nullptr, MSERR_NO_MEMORY, "videoStreamerEngine_ nullptr");
    syncMgr_ = videoStreamerEngine_->GetLppSyncManager();
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr, MSERR_NO_MEMORY, "syncMgr_ nullptr");
    auto ret = syncMgr_->SetAudioIsLpp(isLpp_);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "SetAudioIsLpp failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::SetObs(const std::weak_ptr<ILppAudioStreamerEngineObs> &obs)
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::SetObs");
    FALSE_RETURN_V_MSG(callbackLooper_ != nullptr, MSERR_INVALID_OPERATION, "callbackLooper_ nullptr");
    callbackLooper_->StartWithLppAudioStreamerEngineObs(obs);
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Configure(const Format &param)
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::SetParameter");
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    auto ret = adec_->Configure(param);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "Configure failed");
    ret = aRender_->SetParameter(param);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ SetParameter failed");
    ret = aRender_->Init();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Init failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::Prepare()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Prepare");
    eventReceiver_ = std::make_shared<LppAudioEventReceiver>(weak_from_this(), streamerId_);
    FALSE_RETURN_V_MSG(eventReceiver_ != nullptr, MSERR_NO_MEMORY, "callbackLooper_ is nullptr");
    FALSE_RETURN_V_MSG(videoStreamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "videoStreamerEngine_ is nullptr");
    callbackLooper_->SetEngine(weak_from_this());
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    aRender_->SetEventReceiver(eventReceiver_);
    adec_->SetEventReceiver(eventReceiver_);
    dataMgr_->SetEventReceiver(eventReceiver_);
    auto ret = aRender_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Prepare failed");
    ret = adec_->SetOutputBufferQueue(aRender_->GetBufferQueueProducer());
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ SetOutputBufferQueue failed");
    ret = adec_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Prepare failed");
    sptr<Media::AVBufferQueueProducer> producer = adec_->GetInputBufferQueue();
    FALSE_RETURN_V_MSG(producer != nullptr, MSERR_NO_MEMORY, "producer is nullptr");
    ret = dataMgr_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Prepare failed");
    ret = dataMgr_->SetDecoderInputProducer(producer);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ SetDecoderInputProducer failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::Start()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Start");
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        isPaused_ = false;
    }
    auto ret = aRender_->Start();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Start failed");
    ret = adec_->Start();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Start failed");
    ret = dataMgr_->Start();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Start failed");
    FALSE_RETURN_V_MSG(callbackLooper_ != nullptr, MSERR_INVALID_OPERATION, "callbackLooper_ is nullptr");
    callbackLooper_->StartPositionUpdate();
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Pause()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Pause");
    FALSE_RETURN_V_MSG(callbackLooper_ != nullptr, MSERR_INVALID_OPERATION, "callbackLooper_ is nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        FALSE_RETURN_V_MSG(!isPaused_, MSERR_OK, "HiLppAudioStreamerImpl is EOS");
        isPaused_ = true;
    }
    callbackLooper_->StopPositionUpdate();
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    auto ret = dataMgr_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Pause failed");
    ret = adec_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Pause failed");
    ret = aRender_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Pause failed");
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Resume()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Resume");
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr && callbackLooper_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        isPaused_ = false;
    }
    callbackLooper_->StartPositionUpdate();
    auto ret = aRender_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Resume failed");
    ret = adec_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Resume failed");
    ret = dataMgr_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Resume failed");
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Flush()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Flush");
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    auto ret = aRender_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Flush failed");
    ret = adec_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Flush failed");
    ret = dataMgr_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Flush failed");
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Stop()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Stop");
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    lppEngineManager.RemoveLppAudioInstance(streamerId_);
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr && callbackLooper_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    callbackLooper_->StopPositionUpdate();
    auto ret = aRender_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Stop failed");
    ret = adec_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Stop failed");
    ret = dataMgr_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Stop failed");
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::Reset()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::Reset");
    FALSE_RETURN_V_MSG(aRender_ != nullptr, MSERR_INVALID_OPERATION, "aRender_ nullptr");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr, MSERR_INVALID_OPERATION, "dataMgr_ nullptr");
    auto ret = aRender_->Reset();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Reset failed");
    dataMgr_->Reset();
    return MSERR_OK;
}
int32_t HiLppAudioStreamerImpl::SetVolume(const float volume)
{
    MEDIA_LOG_D("HiLppAudioStreamerImpl::SetVolume" PUBLIC_LOG_F, volume);
    FALSE_RETURN_V_MSG(aRender_ != nullptr, MSERR_INVALID_OPERATION, "aRender_ nullptr");
    auto ret = aRender_->SetVolume(volume);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ SetVolume failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::SetLoudnessGain(const float loudnessGain)
{
    MEDIA_LOG_D("SetLoudnessGain " PUBLIC_LOG_F, loudnessGain);
    FALSE_RETURN_V_MSG(aRender_ != nullptr, MSERR_INVALID_OPERATION, "aRender_ nullptr");
    auto ret = aRender_->SetLoudnessGain(loudnessGain);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ SetLoudnessGain failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::SetPlaybackSpeed(const float playbackSpeed)
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::SetPlaybackSpeed" PUBLIC_LOG_F, playbackSpeed);
    FALSE_RETURN_V_MSG(aRender_ != nullptr, MSERR_INVALID_OPERATION, "aRender_ nullptr");
    auto ret = aRender_->SetSpeed(playbackSpeed);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ SetPlaybackSpeed failed");
    return MSERR_OK;
}

int32_t HiLppAudioStreamerImpl::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr, MSERR_INVALID_OPERATION, "dataMgr_ nullptr");
    FALSE_RETURN_V_MSG(framePacket != nullptr, MSERR_INVALID_VAL, "framePacket nullptr");
    auto ret = dataMgr_->ProcessNewData(framePacket);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ ProcessNewData failed");
    return MSERR_OK;
}

void HiLppAudioStreamerImpl::OnEvent(const Event &event)
{
    MEDIA_LOG_D("OnEvent entered, event type is: %{public}d", event.type);
    switch (event.type) {
        case EventType::EVENT_DATA_NEEDED : {
            HandleDataNeededEvent(event);
            break;
        }
        case EventType::EVENT_ANCHOR_UPDATE: {
            HandleAnchorUpdateEvent(event);
            break;
        }
        case EventType::EVENT_COMPLETE: {
            HandleCompleteEvent(event);
            break;
        }
        case EventType::EVENT_AUDIO_DEVICE_CHANGE: {
            HandleDeviceChangeEvent(event);
            break;
        }
        case EventType::EVENT_AUDIO_INTERRUPT: {
            HandleInterruptEvent(event);
            break;
        }
        case EventType::EVENT_ERROR : {
            HandleErrorEvent(event);
            break;
        }
        default:
            break;
    }
}

void HiLppAudioStreamerImpl::HandleDataNeededEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    callbackLooper_->OnDataNeeded(AnyCast<int32_t>(event.param));
}

void HiLppAudioStreamerImpl::HandleAnchorUpdateEvent(const Event &event)
{
    auto [anchorPts, anchorClk] = AnyCast<std::pair<int64_t, int64_t>>(event.param);
    FALSE_RETURN_MSG(anchorPts >= 0 && anchorClk >= 0, "invalid anchor info");
    MEDIA_LOG_I("HandleAnchorUpdateEvent anchorPts=" PUBLIC_LOG_D64 " anchorClk=" PUBLIC_LOG_D64, anchorPts, anchorClk);
    FALSE_RETURN_MSG(syncMgr_ != nullptr, "syncMgr_ nullptr");
    auto ret = syncMgr_->UpdateTimeAnchor(anchorPts, anchorClk);
    FALSE_RETURN_MSG(ret == MSERR_OK, "syncMgr_ UpdateTimeAnchor failed");
    return;
}

void HiLppAudioStreamerImpl::HandleCompleteEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    (void)event;
    FALSE_RETURN_MSG(EosPause() == MSERR_OK, "EosPause failed");
    callbackLooper_->OnEos();
}

void HiLppAudioStreamerImpl::HandleInterruptEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    std::pair<int64_t, int64_t> interruptInfo = AnyCast<std::pair<int64_t, int64_t>>(event.param);
    callbackLooper_->OnInterrupted(interruptInfo.first, interruptInfo.second);
}

void HiLppAudioStreamerImpl::HandleDeviceChangeEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    int64_t reason = AnyCast<int64_t>(event.param);
    callbackLooper_->OnDeviceChanged(reason);
}

int32_t HiLppAudioStreamerImpl::GetCurrentPosition(int64_t &currentPosition)
{
    FALSE_RETURN_V_MSG(aRender_ != nullptr, MSERR_INVALID_OPERATION, "aRender_ nullptr");
    return aRender_->GetCurrentPosition(currentPosition);
}


int32_t HiLppAudioStreamerImpl::EosPause()
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::EosPause");
    FALSE_RETURN_V_MSG(callbackLooper_ != nullptr, MSERR_INVALID_OPERATION, "callbackLooper_ is nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        FALSE_RETURN_V_MSG(!isPaused_, MSERR_OK, "HiLppAudioStreamerImpl is paused when eos, return OK");
        isPaused_ = true;
    }
    callbackLooper_->StopPositionUpdate();
    FALSE_RETURN_V_MSG(aRender_ != nullptr && adec_ != nullptr && dataMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    auto ret = dataMgr_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Pause failed");
    ret = adec_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "adec_ Pause failed");
    ret = aRender_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "aRender_ Pause failed");
    return MSERR_OK;
}

void HiLppAudioStreamerImpl::HandleErrorEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    std::pair<MediaServiceErrCode, std::string> errorPair =
        AnyCast<std::pair<MediaServiceErrCode, std::string>>(event.param);
    MEDIA_LOG_I("HiLppAudioStreamer errorcode: %{public}d, errorMsg: %{public}s",
        static_cast<int32_t>(errorPair.first), errorPair.second.c_str());
    callbackLooper_->OnError(errorPair.first, errorPair.second);
}
}  // namespace Media
}  // namespace OHOS