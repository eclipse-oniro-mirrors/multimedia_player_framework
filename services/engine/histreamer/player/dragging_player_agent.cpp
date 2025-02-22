/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#define HST_LOG_TAG "DraggingPlayerAgent"

#include <dlfcn.h>
 
#include "common/log.h"
#include "dragging_player_agent.h"
#include "osal/task/pipeline_threadpool.h"
 
#ifdef SUPPORT_AVPLAYER_DRM
#include "i_keysession_service.h"
#endif

namespace {
const std::string REFERENCE_LIB_PATH = std::string(DRAGGING_PLAYER_PATH);
const std::string FILESEPARATOR = "/";
const std::string REFERENCE_LIB_NAME = "libvideo_dragging_player.z.so";
const std::string REFENCE_LIB_ABSOLUTE_PATH = REFERENCE_LIB_PATH + FILESEPARATOR + REFERENCE_LIB_NAME;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DraggingPlayerAgent"};
}
 
namespace OHOS {
namespace Media {
using namespace Pipeline;
 
void *DraggingPlayerAgent::handler_ = nullptr;
DraggingPlayerAgent::CreateFunc DraggingPlayerAgent::createFunc_ = nullptr;
DraggingPlayerAgent::DestroyFunc DraggingPlayerAgent::destroyFunc_ = nullptr;
DraggingPlayerAgent::CheckSupportedFunc DraggingPlayerAgent::checkSupportedFunc_ = nullptr;
bool DraggingPlayerAgent::loaded_ = false;
std::mutex DraggingPlayerAgent::mtx_;
 
class VideoStreamReadyCallbackImpl : public VideoStreamReadyCallback {
public:
    explicit VideoStreamReadyCallbackImpl(const std::shared_ptr<DraggingDelegator> draggingDelegator)
        : draggingDelegator_(draggingDelegator) {}
    bool IsVideoStreamDiscardable(const std::shared_ptr<AVBuffer> buffer) override
    {
        auto draggingDelegator = draggingDelegator_.lock();
        if (draggingDelegator != nullptr && buffer != nullptr) {
            return draggingDelegator->IsVideoStreamDiscardable(buffer);
        }
        return false;
    }
private:
    std::weak_ptr<DraggingDelegator> draggingDelegator_;
};
 
class VideoFrameReadyCallbackImpl : public VideoFrameReadyCallback {
public:
    explicit VideoFrameReadyCallbackImpl(const std::shared_ptr<DraggingDelegator> draggingDelegator)
        : draggingDelegator_(draggingDelegator) {}
    void ConsumeVideoFrame(const std::shared_ptr<AVBuffer> buffer, uint32_t bufferIndex) override
    {
        auto draggingDelegator = draggingDelegator_.lock();
        if (draggingDelegator != nullptr && buffer != nullptr) {
            return draggingDelegator->ConsumeVideoFrame(buffer, bufferIndex);
        }
    }
private:
    std::weak_ptr<DraggingDelegator> draggingDelegator_;
};
 
shared_ptr<DraggingPlayerAgent> DraggingPlayerAgent::Create(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId)
{
    FALSE_RETURN_V_MSG_E(demuxer != nullptr && decoder != nullptr, nullptr, "Invalid demuxer filter instance.");
    shared_ptr<DraggingPlayerAgent> agent = make_shared<DraggingPlayerAgent>(pipeline, demuxer, decoder, playerId);
    FALSE_RETURN_V(DraggingPlayerAgent::LoadSymbol(), agent);
    FALSE_RETURN_V(DraggingPlayerAgent::IsDraggingSupported(demuxer, decoder), agent);
    agent->draggingMode_ = DraggingMode::DRAGGING_CONTINUOUS;
    return agent;
}

bool DraggingPlayerAgent::IsDraggingSupported(const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder)
{
    FALSE_RETURN_V_MSG_E(demuxer != nullptr && decoder != nullptr, false, "demuxer or decoder is null");
    FALSE_RETURN_V_MSG_E(demuxer->IsLocalFd(), false, "source is not local fd");
    if (!LoadSymbol() || checkSupportedFunc_ == nullptr) {
        return false;
    }
    return checkSupportedFunc_(demuxer.get(), decoder.get());
}

DraggingPlayerAgent::DraggingPlayerAgent(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId)
    : pipeline_(pipeline), demuxer_(demuxer), decoder_(decoder), playerId_(playerId)
{
}

DraggingPlayerAgent::~DraggingPlayerAgent()
{
    if (!isReleased_) {
        Release();
    }
    if (delegator_ != nullptr) {
        delegator_ = nullptr;
    }
}

Status DraggingPlayerAgent::Init()
{
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr && decoder_ != nullptr,
        Status::ERROR_INVALID_PARAMETER, "Invalid demuxer filter instance.");
    delegator_ = DraggingDelegatorFactory::CreateDelegator(pipeline_, demuxer_, decoder_, playerId_, draggingMode_);
    FALSE_RETURN_V_MSG_E(delegator_ != nullptr, Status::ERROR_INVALID_DATA, "delegator_ is null");
    Status ret = delegator_->Init();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "delegator_ init failed");
    return ret;
}
 
void DraggingPlayerAgent::UpdateSeekPos(int64_t seekMs)
{
    FALSE_RETURN_MSG(delegator_ != nullptr, "delegator_ is null");
    delegator_->UpdateSeekPos(seekMs);
}
 
void DraggingPlayerAgent::Release()
{
    std::unique_lock<std::mutex> lock(draggingMutex_);
    delegator_->Release();
    isReleased_ = true;
}

DraggingMode DraggingPlayerAgent::GetDraggingMode()
{
    return draggingMode_;
}
 
void *DraggingPlayerAgent::LoadLibrary()
{
    char path[PATH_MAX] = {0x00};
    const char *inputPath = REFENCE_LIB_ABSOLUTE_PATH.c_str();
    if (strlen(inputPath) > PATH_MAX || realpath(inputPath, path) == nullptr) {
        MEDIA_LOG_E("dlopen failed due to Invalid path");
        return nullptr;
    }
    auto ptr = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (ptr == nullptr) {
        MEDIA_LOG_E("dlopen failed due to %{public}s", ::dlerror());
    }
    handler_ = ptr;
    return ptr;
}
 
bool DraggingPlayerAgent::CheckSymbol(void *handler)
{
    if (handler) {
        std::string createFuncName = "CreateDraggingPlayer";
        std::string destroyFuncName = "DestroyDraggingPlayer";
        std::string checkSupportedFuncName = "IsDraggingSupported";
        CreateFunc createFunc = nullptr;
        DestroyFunc destroyFunc = nullptr;
        CheckSupportedFunc checkSupportedFunc = nullptr;
        createFunc = (CreateFunc)(::dlsym(handler, createFuncName.c_str()));
        destroyFunc = (DestroyFunc)(::dlsym(handler, destroyFuncName.c_str()));
        checkSupportedFunc = (CheckSupportedFunc)(::dlsym(handler, checkSupportedFuncName.c_str()));
        if (checkSupportedFunc != nullptr) {
            checkSupportedFunc_ = checkSupportedFunc;
        }
        if (createFunc && destroyFunc) {
            MEDIA_LOG_D("CheckSymbol:  createFuncName %{public}s", createFuncName.c_str());
            MEDIA_LOG_D("CheckSymbol:  destroyFuncName %{public}s", destroyFuncName.c_str());
            createFunc_ = createFunc;
            destroyFunc_ = destroyFunc;
            return true;
        }
    }
    return false;
}
 
bool DraggingPlayerAgent::LoadSymbol()
{
    lock_guard<mutex> lock(mtx_);
    if (loaded_ && handler_ == nullptr) {
        return false;
    }
    if (handler_ == nullptr) {
        loaded_ = true;
        if (!CheckSymbol(LoadLibrary())) {
            MEDIA_LOG_E("Load Reference parser so fail");
            return false;
        }
    }
    return true;
}

shared_ptr<DraggingDelegator> DraggingDelegatorFactory::CreateDelegator(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId,
    DraggingMode &draggingMode)
{
    FALSE_RETURN_V_MSG_E(draggingMode != DraggingMode::DRAGGING_NONE, nullptr, "Invalid draggingMode.");
    shared_ptr<DraggingDelegator> delegator = nullptr;
    if (draggingMode == DraggingMode::DRAGGING_CONTINUOUS) {
        shared_ptr<DraggingDelegator> delegator
            = SeekContinuousDelegator::Create(pipeline, demuxer, decoder, playerId);
        FALSE_RETURN_V_NOLOG(delegator == nullptr, delegator);
    }
    draggingMode = DraggingMode::DRAGGING_CLOSEST;
    return SeekClosestDelegator::Create(pipeline, demuxer, decoder, playerId);
}

shared_ptr<SeekContinuousDelegator> SeekContinuousDelegator::Create(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId)
{
    shared_ptr<SeekContinuousDelegator> delegator
        = make_shared<SeekContinuousDelegator>(pipeline, demuxer, decoder, playerId);
    FALSE_RETURN_V_MSG_E(delegator != nullptr && delegator->draggingPlayer_ != nullptr,
        nullptr, "delegator is nullptr");
    Status ret = delegator->Init();
    if (ret != Status::OK) {
        delegator = nullptr;
    }
    return delegator;
}

SeekContinuousDelegator::SeekContinuousDelegator(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId)
    : DraggingDelegator(pipeline, demuxer, decoder, playerId)
{
    if (DraggingPlayerAgent::createFunc_ != nullptr) {
        draggingPlayer_ = DraggingPlayerAgent::createFunc_();
    }
}

SeekContinuousDelegator::~SeekContinuousDelegator()
{
    if (!isReleased_) {
        Release();
    }
    PipeLineThreadPool::GetInstance().DestroyThread(threadName_);
    if (draggingPlayer_ != nullptr) {
        DraggingPlayerAgent::destroyFunc_(draggingPlayer_);
        draggingPlayer_ = nullptr;
    }
}

Status SeekContinuousDelegator::Init()
{
    FALSE_RETURN_V_MSG_E(demuxer_ != nullptr && decoder_ != nullptr,
        Status::ERROR_INVALID_PARAMETER, "Invalid demuxer filter instance.");
    Status ret = draggingPlayer_->Init(demuxer_, decoder_);
    if (ret != Status::OK) {
        MEDIA_LOG_E("liyudebug DraggingPlayerAgent::Init failed");
        return ret;
    }
    MEDIA_LOG_I("DraggingPlayerAgent::Init register");
    videoStreamReadyCb_ = std::make_shared<VideoStreamReadyCallbackImpl>(shared_from_this());
    demuxer_->RegisterVideoStreamReadyCallback(videoStreamReadyCb_);
    videoFrameReadyCb_ = std::make_shared<VideoFrameReadyCallbackImpl>(shared_from_this());
    decoder_->RegisterVideoFrameReadyCallback(videoFrameReadyCb_);
    threadName_ = "DraggingTask_" + playerId_;
    monitorTask_ = std::make_unique<Task>("draggingThread", threadName_, TaskType::GLOBAL, TaskPriority::NORMAL, false);
    monitorTask_->Start();
    return Status::OK;
}

void SeekContinuousDelegator::UpdateSeekPos(int64_t seekMs)
{
    std::unique_lock<std::mutex> lock(draggingMutex_);
    FALSE_RETURN(draggingPlayer_ != nullptr);
    seekCnt_.fetch_add(1);
    draggingPlayer_->UpdateSeekPos(seekMs);
    if (monitorTask_ != nullptr) {
        int64_t seekCnt = seekCnt_.load();
        lock.unlock();
        monitorTask_->SubmitJob([this, seekCnt]() { StopDragging(seekCnt); }, 33333); // 33333 means 33333us, 33ms
    }
}

void SeekContinuousDelegator::Release()
{
    if (monitorTask_) {
        monitorTask_->Stop();
    }
    std::unique_lock<std::mutex> lock(draggingMutex_);
    if (draggingPlayer_ != nullptr) {
        draggingPlayer_->Release();
    }
    if (draggingPlayer_ != nullptr) {
        auto res = demuxer_->PauseDragging();
        FALSE_LOG_MSG(res == Status::OK, "PauseDragging failed");
    }
    if (demuxer_ != nullptr) {
        demuxer_->DeregisterVideoStreamReadyCallback();
    }
    if (decoder_ != nullptr) {
        decoder_->DeregisterVideoFrameReadyCallback();
    }
    isReleased_ = true;
}

void SeekContinuousDelegator::ConsumeVideoFrame(const std::shared_ptr<AVBuffer> avBuffer, uint32_t bufferIndex)
{
    FALSE_RETURN(draggingPlayer_ != nullptr);
    draggingPlayer_->ConsumeVideoFrame(avBuffer, bufferIndex);
}

bool SeekContinuousDelegator::IsVideoStreamDiscardable(const std::shared_ptr<AVBuffer> avBuffer)
{
    FALSE_RETURN_V_MSG_E(draggingPlayer_ != nullptr, false, "Invalid draggingPlayer_ instance.");
    return draggingPlayer_->IsVideoStreamDiscardable(avBuffer);
}

void SeekContinuousDelegator::StopDragging(int64_t seekCnt)
{
    std::unique_lock<std::mutex> lock(draggingMutex_);
    FALSE_RETURN(!isReleased_);
    FALSE_RETURN(draggingPlayer_ != nullptr);
    if (seekCnt_.load() != seekCnt) {
        return;
    }
    draggingPlayer_->StopDragging();
}

shared_ptr<SeekClosestDelegator> SeekClosestDelegator::Create(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const string &playerId)
{
    shared_ptr<SeekClosestDelegator> delegator
        = make_shared<SeekClosestDelegator>(pipeline, demuxer, decoder, playerId);
    FALSE_RETURN_V_MSG_E(delegator != nullptr, delegator, "delegator is nullptr");
    Status ret = delegator->Init();
    if (ret != Status::OK) {
        delegator = nullptr;
    }
    return delegator;
}

SeekClosestDelegator::SeekClosestDelegator(
    const shared_ptr<OHOS::Media::Pipeline::Pipeline> pipeline,
    const shared_ptr<DemuxerFilter> demuxer,
    const shared_ptr<DecoderSurfaceFilter> decoder,
    const std::string &playerId)
    : DraggingDelegator(pipeline, demuxer, decoder, playerId)
{
}

SeekClosestDelegator::~SeekClosestDelegator()
{
    if (!isReleased_) {
        Release();
    }
    PipeLineThreadPool::GetInstance().DestroyThread(threadName_);
}

Status SeekClosestDelegator::Init()
{
    threadName_ = "SeekTask_" + playerId_;
    seekTask_ = std::make_unique<Task>("seekThread", threadName_, TaskType::GLOBAL, TaskPriority::NORMAL, false);
    seekTask_->Start();
    return Status::OK;
}

void SeekClosestDelegator::UpdateSeekPos(int64_t seekMs)
{
    lock_guard<mutex> lock(queueMutex_);
    seekTimeMsQue_.push_back(seekMs);
    if (seekTimeMsQue_.size() == 1) {
        seekTask_->SubmitJob([this]() { SeekJob(); });
    }
}

void SeekClosestDelegator::Release()
{
    if (seekTask_) {
        seekTask_->Stop();
    }
    int64_t lastSeekTimeMs = -1;
    {
        lock_guard<mutex> lock(queueMutex_);
        if (seekTimeMsQue_.size() > 0) {
            lastSeekTimeMs = seekTimeMsQue_.back();
            seekTimeMsQue_.clear();
        }
    }
    DoSeek(lastSeekTimeMs);
    isReleased_ = true;
}

void SeekClosestDelegator::SeekJob()
{
    int64_t seekTimeMs = -1;
    {
        lock_guard<mutex> lock(queueMutex_);
        if (seekTimeMsQue_.size() <= 0) {
            return;
        }
        seekTimeMs = seekTimeMsQue_.back();
        seekTimeMsQue_.clear();
    }
    DoSeek(seekTimeMs);
}

void SeekClosestDelegator::DoSeek(int64_t seekTimeMs)
{
    FALSE_RETURN_MSG(seekTimeMs >= 0, "invalid seekTimeMs");
    FALSE_RETURN_MSG(pipeline_ != nullptr && demuxer_ != nullptr && decoder_ != nullptr, "key objects is null");
    lock_guard<mutex> lock(seekClosestMutex_);
    int64_t seekTimeUs = 0;
    FALSE_RETURN_MSG(seekTimeMs != curSeekTimeMs_, "the same seek time with last seek;");
    curSeekTimeMs_ = seekTimeMs;
    FALSE_RETURN_MSG(Plugins::Us2HstTime(seekTimeMs, seekTimeUs), "cast seekTime ms to us failed");
    pipeline_->Flush();
    decoder_->SetSeekTime(seekTimeUs);
    int64_t realSeekTimeUs = seekTimeUs;
    Status res = demuxer_->SeekTo(seekTimeUs, Plugins::SeekMode::SEEK_CLOSEST_INNER, realSeekTimeUs);
    FALSE_RETURN_MSG(res == Status::OK, "demuxer seekto error.");
    pipeline_->Preroll(true);
}
}  // namespace Media
}  // namespace OHOS