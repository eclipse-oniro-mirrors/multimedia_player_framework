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
#include "hilpp_vstreamer_impl.h"
#include "lpp_sync_manager.h"
#include "common/log.h"
#include "media_errors.h"
#include "avcodec_video_decoder.h"
#include "param_wrapper.h"
#include "osal/task/pipeline_threadpool.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "HiLppVStreamer"};
static constexpr int32_t SURFACE_CONSUME_WAIT_MS = 200;
}

namespace OHOS {
namespace Media {

class LppVideoEventReceiver : public Pipeline::EventReceiver {
public:
    explicit LppVideoEventReceiver(std::weak_ptr<HiLppVideoStreamerImpl> videoStreamer, std::string streamerId)
    {
        MEDIA_LOG_I("LppVideoEventReceiver ctor called.");
        videoStreamer_ = videoStreamer;
        task_ = std::make_unique<Task>("VideoEventReceiver", streamerId, TaskType::GLOBAL, TaskPriority::HIGH, false);
    }

    void OnEvent(const Event &event) override
    {
        MEDIA_LOG_D("VideoEventReceiver OnEvent.");
        FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
        task_->SubmitJobOnce([this, event] {
            auto videoStreamer = videoStreamer_.lock();
            FALSE_RETURN_MSG(videoStreamer != nullptr, "videoStreamer is nullptr");
            videoStreamer->OnEvent(event);
        });
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("PlayerEventReceiver NotifyRelease.");
    }
private:
    std::weak_ptr<HiLppVideoStreamerImpl> videoStreamer_;
    std::unique_ptr<Task> task_;
};

HiLppVideoStreamerImpl::HiLppVideoStreamerImpl()
{
    std::string isLpp;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_video_lpp", isLpp, "true");
    isLpp_ = ret == 0 ? isLpp == "true" : false;
    MEDIA_LOG_I("HiLppVideoStreamerImpl enabled: " PUBLIC_LOG_D32, isLpp_);
    streamerId_ = std::string("LppV_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
    MEDIA_LOG_I("HiLppVideoStreamerImpl initialized.");
}

HiLppVideoStreamerImpl::~HiLppVideoStreamerImpl()
{
    Stop();
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    lppEngineManager.RemoveLppVideoInstance(streamerId_);
    FALSE_RETURN_MSG(vdec_ != nullptr, "vdec_ nullptr");
    vdec_->Release();
    MEDIA_LOG_I("HiLppVideoStreamerImpl Instances destroy.");
    PipeLineThreadPool::GetInstance().DestroyThread(streamerId_);
}

int32_t HiLppVideoStreamerImpl::Init(const std::string &mime)
{
    callbackLooper_ = std::make_shared<LppVideoCallbackLooper>(streamerId_);
    // init vdec first for lpp enable
    vdec_ = std::make_shared<LppVideoDecoderAdapter>(streamerId_, isLpp_);
    bool switchToCommon = false;
    auto ret = vdec_->Init(mime, switchToCommon);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ init failed");
    FALSE_LOG_MSG_W(!switchToCommon, "switch isLpp_ to false");
    isLpp_ = isLpp_ ? !switchToCommon : isLpp_;
    dataMgr_ = std::make_shared<LppVideoDataManager>(streamerId_, isLpp_);
    syncMgr_ = std::make_shared<LppSyncManager>(streamerId_, isLpp_);
    ret = syncMgr_->Init();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Init failed");
    vdec_->SetSyncManager(syncMgr_);
    return MSERR_OK;
}

std::string HiLppVideoStreamerImpl::GetStreamerId()
{
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    lppEngineManager.AddLppVideoInstance(streamerId_, shared_from_this());
    return streamerId_;
}

int32_t HiLppVideoStreamerImpl::SetLppAudioStreamerId(std::string audioStreamerId)
{
    audioStreamerId_ = audioStreamerId;
    MEDIA_LOG_I("HiLppVideoStreamerImpl::SetLppAudioStreamerId %{public}s", audioStreamerId.c_str());
    auto &lppEngineManager = ILppEngineManager::GetInstance();
    audioStreamerEngine_ = lppEngineManager.GetLppAudioInstance(audioStreamerId);
    auto audioStreamerEngine = audioStreamerEngine_.lock();
    FALSE_RETURN_V_MSG(audioStreamerEngine != nullptr, MSERR_INVALID_VAL, "audioStreamerEngine nullptr");
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::SetObs(const std::weak_ptr<ILppVideoStreamerEngineObs> &obs)
{
    MEDIA_LOG_I("HiLppAudioStreamerImpl::SetObs");
    FALSE_RETURN_V_MSG(callbackLooper_ != nullptr, MSERR_INVALID_OPERATION, "callbackLooper_ nullptr");
    callbackLooper_->StartWithLppVideoStreamerEngineObs(obs);
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::SetParameter(const Format &param)
{
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    auto ret = vdec_->SetParameter(param);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ SetParameter Failed!");
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::GetLatestPts(int64_t &pts)
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::GetLatestPts");
    if (!isLpp_) {
        FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
        pts = vdec_->GetLastCommonPts();
        return MSERR_OK;
    }
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr, MSERR_INVALID_OPERATION, "syncMgr_ nullptr");
    return syncMgr_->GetLatestPts(pts);
}

int32_t HiLppVideoStreamerImpl::Configure(const Format &param)
{
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    auto ret = vdec_->Configure(param);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Configure Failed!");
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::SetVideoSurface(sptr<Surface> surface)
{
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr, MSERR_INVALID_OPERATION, "object is nullptr");
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    FALSE_RETURN_V_MSG(surface != nullptr, MSERR_INVALID_VAL, "surface nullptr");
    int32_t ret = MSERR_OK;
    bool isSwitchSurface = surface_ != nullptr;
    if (isSwitchSurface && isLpp_) {
        surface_->SetLppShareFd(shareBufferFd_, false);
    }
    if (isLpp_) {
        MEDIA_LOG_I("surface->GetUniqueId() " PUBLIC_LOG_U64 " success", surface->GetUniqueId());
        ret = syncMgr_->SetTunnelId(surface->GetUniqueId());
        FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ SetTunnelId Failed!");
    }
    if (isSwitchSurface && isLpp_) {
        surface->SetSurfaceSourceType(OH_SURFACE_SOURCE_LOWPOWERVIDEO);
        ret = syncMgr_->GetShareBuffer(shareBufferFd_);
        FALSE_RETURN_V_MSG(ret == MSERR_OK, MSERR_UNKNOWN, "syncMgr_ GetShareBuffer failed");
        surface->SetLppShareFd(shareBufferFd_, true);
    }
    surface_ = surface;
    ret = vdec_->SetVideoSurface(surface);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ SetTunnelId Failed!");
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::Prepare()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Prepare");
    eventReceiver_ = std::make_shared<LppVideoEventReceiver>(weak_from_this(), streamerId_);
    FALSE_RETURN_V_MSG(eventReceiver_ != nullptr, MSERR_NO_MEMORY, "callbackLooper_ is nullptr");
    auto audioStreamerEngine = audioStreamerEngine_.lock();
    FALSE_RETURN_V_MSG(audioStreamerEngine != nullptr, MSERR_INVALID_OPERATION, "audioStreamerEngine_ is nullptr");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr,
        MSERR_INVALID_OPERATION, "object is nullptr");
    dataMgr_->SetEventReceiver(eventReceiver_);
    vdec_->SetEventReceiver(eventReceiver_);
    syncMgr_->SetEventReceiver(eventReceiver_);
    auto ret = vdec_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Prepare failed");
    sptr<Media::AVBufferQueueProducer> producer = vdec_->GetInputBufferQueue();
    FALSE_RETURN_V_MSG(producer != nullptr, MSERR_NO_MEMORY, "producer is nullptr");
    ret = dataMgr_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Prepare failed");
    ret = dataMgr_->SetDecoderInputProducer(producer);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ SetDecoderInputProducer failed");
    ret = syncMgr_->Prepare();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Prepare failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::StartDecode()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::StartDecode");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        isPaused_ = false;
    }
    int32_t ret = vdec_->StartDecode();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ StartDecode failed");
    ret = dataMgr_->StartDecode();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ StartDecode failed");
    if (!isLpp_) {
        vdec_->SetChannelIdDone();
        return ret;
    }
    FALSE_RETURN_V_NOLOG(!isChannelSetDone_, ret);
    ret = vdec_->GetChannelId(channelId_);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ GetChannelId failed");
    ret = syncMgr_->SetVideoChannelId(channelId_);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ SetVideoChannelId failed");
    vdec_->SetChannelIdDone();
    isChannelSetDone_ = true;
    return ret;
}

int32_t HiLppVideoStreamerImpl::RenderFirstFrame()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::RenderFirstFrame");
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    auto ret = vdec_->RenderFirstFrame();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec RenderFirstFrame failed");
    return MSERR_OK;
}

int32_t HiLppVideoStreamerImpl::StartRender()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::StartRender");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    int32_t ret = MSERR_OK;
    if (isLpp_) {
        ret = syncMgr_->GetShareBuffer(shareBufferFd_);
        FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ GetShareBuffer failed");
    }
    FALSE_RETURN_V_MSG(surface_ != nullptr, MSERR_INVALID_OPERATION, "surface_ nullptr");
    surface_->SetLppShareFd(shareBufferFd_, true);
    ret = vdec_->StartRender();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ StartRender failed");
    ret = syncMgr_->StartRender();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ StartRender failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::Pause()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Pause");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        FALSE_RETURN_V_MSG(!isPaused_, MSERR_OK, "HiLppVideoStreamerImpl is EOS");
        isPaused_ = true;
    }
    auto ret = syncMgr_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Pause failed");
    dataMgr_->Pause();
    ret = vdec_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Pause failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::Resume()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Resume");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        isPaused_ = false;
    }
    auto ret = syncMgr_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Resume failed");
    ret = vdec_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ StartDecode failed");
    ret = dataMgr_->Resume();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Resume failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::Flush()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Flush");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    dataMgr_->Flush();
    auto ret = vdec_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Flush failed");
    ret = syncMgr_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Flush failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::Stop()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Stop");
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr, MSERR_INVALID_OPERATION, "syncMgr_ nullptr");
    auto ret = syncMgr_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Stop failed");
    ret = vdec_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Stop failed");
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::Reset()
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::Reset");
    FALSE_RETURN_V_MSG(vdec_ != nullptr, MSERR_INVALID_OPERATION, "vdec_ nullptr");
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr, MSERR_INVALID_OPERATION, "syncMgr_ nullptr");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr, MSERR_INVALID_OPERATION, "dataMgr_ nullptr");
    FALSE_RETURN_V_MSG(surface_ != nullptr, MSERR_INVALID_OPERATION, "surface_ nullptr");
    surface_->SetLppShareFd(shareBufferFd_, false);
    auto ret = syncMgr_->Reset();
    syncMgr_.reset();
    std::mutex surfaceBufferMutex;
    std::condition_variable surfaceCond;
    bool bufferConsumed = false;
    OnReleaseFunc releaseCallback = [&surfaceBufferMutex, &surfaceCond, &bufferConsumed](sptr<SurfaceBuffer> &buffer) {
        std::lock_guard<std::mutex> lock(surfaceBufferMutex);
        if (bufferConsumed) {
            return GSError::GSERROR_OK;
        }
        bufferConsumed = true;
        surfaceCond.notify_all();
        return GSError::GSERROR_OK;
    };
    surface_->RegisterReleaseListener(releaseCallback);
    {
        std::unique_lock<std::mutex> lock(surfaceBufferMutex);
        bool waitRes = surfaceCond.wait_for(lock, std::chrono::milliseconds(SURFACE_CONSUME_WAIT_MS),
            [&bufferConsumed]() { return bufferConsumed; });
        FALSE_LOG_MSG(waitRes, "wait surface consumer timeout");
    }
    surface_->UnRegisterReleaseListener();
    ret = vdec_->Release();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Release failed");
    dataMgr_->Reset();
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::SetPlaybackSpeed(const float playbackSpeed)
{
    MEDIA_LOG_I("HiLppVideoStreamerImpl::SetPlaybackSpeed" PUBLIC_LOG_F, playbackSpeed);
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr && vdec_ != nullptr, MSERR_INVALID_OPERATION, "syncMgr_ nullptr");
    auto ret = syncMgr_->SetPlaybackSpeed(playbackSpeed);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ SetPlaybackSpeed failed");
    vdec_->SetPlaybackSpeed(playbackSpeed);
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::SetSyncAudioStreamer(int streamerId)
{
    (void)streamerId;
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    FALSE_RETURN_V_MSG(syncMgr_ != nullptr && vdec_ != nullptr, MSERR_INVALID_OPERATION, "syncMgr_ nullptr");
    int32_t ret = vdec_->SetTargetPts(targetPts);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ SetTargetPts failed");
    syncMgr_->SetTargetStartFrame(targetPts, timeoutMs);
    return MSERR_OK;
}
int32_t HiLppVideoStreamerImpl::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOG_D("HiLppVideoStreamerImpl::ReturnFrames");
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr, MSERR_INVALID_OPERATION, "dataMgr_ nullptr");
    FALSE_RETURN_V_MSG(framePacket != nullptr, MSERR_INVALID_OPERATION, "framePacket nullptr");
    auto ret = dataMgr_->ProcessNewData(framePacket);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ ReturnFrames failed");
    return MSERR_OK;
}

std::shared_ptr<ILppSyncManager> HiLppVideoStreamerImpl::GetLppSyncManager()
{
    return syncMgr_;
}

void HiLppVideoStreamerImpl::OnEvent(const Event &event)
{
    MEDIA_LOG_D("OnEvent entered, event type is: %{public}d", event.type);
    switch (event.type) {
        case EventType::EVENT_DATA_NEEDED : {
            HandleDataNeededEvent(event);
            break;
        }
        case EventType::EVENT_FIRST_FRAME_READY : {
            HandleFirstFrameReadyEvent(event);
            break;
        }
        case EventType::EVENT_VIDEO_RENDERING_START : {
            HandleRenderStartedEvent(event);
            break;
        }
        case EventType::EVENT_COMPLETE : {
            HandleCompleteEvent(event);
            break;
        }
        case EventType::EVENT_RESOLUTION_CHANGE : {
            HandleResolutionChangeEvent(event);
            break;
        }
        case EventType::EVENT_VIDEO_TARGET_ARRIVED : {
            HandleTargetArrivedEvent(event);
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

void HiLppVideoStreamerImpl::HandleDataNeededEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    auto [maxBufferSize, maxFrameNum] = AnyCast<std::pair<int64_t, int64_t>>(event.param);
    callbackLooper_->OnDataNeeded(maxBufferSize, maxFrameNum);
}

void HiLppVideoStreamerImpl::HandleFirstFrameReadyEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    (void)event;
    callbackLooper_->OnFirstFrameReady();
}

void HiLppVideoStreamerImpl::HandleRenderStartedEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    (void)event;
    callbackLooper_->OnRenderStarted();
}

void HiLppVideoStreamerImpl::HandleCompleteEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    (void)event;
    FALSE_RETURN_MSG(EosPause() == MSERR_OK, "EosPause failed");
    callbackLooper_->OnEos();
}

void HiLppVideoStreamerImpl::HandleResolutionChangeEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    Format format = AnyCast<Format>(event.param);
    callbackLooper_->OnStreamChanged(format);
}

void HiLppVideoStreamerImpl::HandleTargetArrivedEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    std::pair<int64_t, bool> targetArrivedPair =
        AnyCast<std::pair<int64_t, bool>>(event.param);
    callbackLooper_->OnTargetArrived(targetArrivedPair.first, targetArrivedPair.second);
}

void HiLppVideoStreamerImpl::HandleErrorEvent(const Event &event)
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper_ nullptr");
    std::pair<MediaServiceErrCode, std::string> errorPair =
        AnyCast<std::pair<MediaServiceErrCode, std::string>>(event.param);
    MEDIA_LOG_I("HiLppVideoStreamer errorcode: %{public}d, errorMsg: %{public}s",
        static_cast<int32_t>(errorPair.first), errorPair.second.c_str());
    callbackLooper_->OnError(errorPair.first, errorPair.second);
}

int32_t HiLppVideoStreamerImpl::EosPause()
{
    FALSE_RETURN_V_MSG(dataMgr_ != nullptr && vdec_ != nullptr && syncMgr_ != nullptr, MSERR_INVALID_OPERATION,
        "vdec_ nullptr");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        FALSE_RETURN_V_MSG(!isPaused_, MSERR_OK, "HiLppVideoStreamerImpl is paused when eos, return OK");
        isPaused_ = true;
    }
    auto ret = syncMgr_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "syncMgr_ Pause failed");
    ret = vdec_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "vdec_ Pause failed");
    ret = dataMgr_->Pause();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "dataMgr_ Pause failed");
    return MSERR_OK;
}
}  // namespace Media
}  // namespace OHOS