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
#include "lpp_vdec_adapter.h"
#include "common/log.h"
#include "media_errors.h"
#include "media_lpp_errors.h"
#include "i_lpp_video_streamer.h"
#include "osal/utils/steady_clock.h"
#include "osal/utils/dump_buffer.h"
#include "param_wrapper.h"
#include "syspara/parameters.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVDec"};
const std::string DUMP_PARAM = "a";
constexpr int64_t US_TO_MS = 1000;
constexpr int64_t SEC_TO_US = 1000 * 1000;
static const int32_t MAX_ADVANCE_US = 80000; // max advance us at render time
const std::string VIDEO_INPUT_BUFFER_QUEUE_NAME = "VideoDecoderInputBufferQueue";
}  // namespace

namespace OHOS {
namespace Media {

class LppVideoDecConsumerListener : public OHOS::Media::IConsumerListener {
public:
    explicit LppVideoDecConsumerListener(std::weak_ptr<LppVideoDecoderAdapter> videoDecoderAdapter)
    {
        videoDecoderAdapter_ = videoDecoderAdapter;
    }
    ~LppVideoDecConsumerListener()
    {
        MEDIA_LOG_I("~LppVideoDecConsumerListener");
    }
    void OnBufferAvailable() override
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        MEDIA_LOG_D("LppVideoDecConsumerListener OnBufferAvailable");
        videoDecoderAdapter->OnQueueBufferAvailable();
    }

private:
    std::weak_ptr<LppVideoDecoderAdapter> videoDecoderAdapter_;
};

class LppVideoDecoderCallback : public MediaAVCodec::MediaCodecCallback {
public:
    explicit LppVideoDecoderCallback(std::weak_ptr<LppVideoDecoderAdapter> videoDecoderAdapter)
    {
        videoDecoderAdapter_ = videoDecoderAdapter;
    }
    ~LppVideoDecoderCallback()
    {
        MEDIA_LOG_I("~LppVideoDecoderCallback");
    }
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
    {
        auto videoDecAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecAdapter != nullptr, "videoDecAdapter is nullptr");
        MEDIA_LOG_D("LppVideoDecoderCallback::OnError errorType=" PUBLIC_LOG_D32 " errorCode=" PUBLIC_LOG_D32,
            static_cast<int32_t>(errorType), errorCode);
        videoDecAdapter->OnError(errorType, errorCode);
    }
    void OnOutputFormatChanged(const MediaAVCodec::Format &format)
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        videoDecoderAdapter->OnOutputFormatChanged(format);
    }
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        videoDecoderAdapter->OnInputBufferAvailable(index, buffer);
    }
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)\
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        videoDecoderAdapter->OnOutputBufferAvailable(index, buffer);
    }
    void OnOutputBufferBinded(std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap)
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        videoDecoderAdapter->OnOutputBufferBinded(bufferMap);
    }
    void OnOutputBufferUnbinded()
    {
        auto videoDecoderAdapter = videoDecoderAdapter_.lock();
        FALSE_RETURN_MSG(videoDecoderAdapter != nullptr, "videoDecoderAdapter is nullptr");
        videoDecoderAdapter->OnOutputBufferUnbinded();
    }

private:
    std::weak_ptr<LppVideoDecoderAdapter> videoDecoderAdapter_;
};

LppVideoDecoderAdapter::LppVideoDecoderAdapter(const std::string &streamerId, bool isLpp)
    : streamerId_(streamerId), isLppEnabled_(isLpp)
{
    MEDIA_LOG_I("LppVideoDecoderAdapter " PUBLIC_LOG_S " initialized.", streamerId_.c_str());
    std::string enableDump;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_video_lpp_dump", enableDump, "false");
    dumpBufferNeeded_ = ret == 0 ? enableDump == "true" : false;
    dumpFileNameOutput_ = streamerId_ + "_DUMP_OUTPUT.bin";
}

LppVideoDecoderAdapter::~LppVideoDecoderAdapter()
{
    MEDIA_LOG_I("LppVideoDecoderAdapter Instances destroy.");
}

int32_t LppVideoDecoderAdapter::Init(const std::string &mime, bool &switchToCommon)
{
    videoDecoder_ = MediaAVCodec::VideoDecoderFactory::CreateByMime(mime);
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_UNSUPPORT_VID_DEC_TYPE, "videoDecoder_ nullptr");
    if (isLppEnabled_) {
        MEDIA_LOG_I("LppVideoDecoderAdapter CreateByMime, try lpp enabled");
        int32_t ret = videoDecoder_->SetLowPowerPlayerMode(true);
        FALSE_LOG_MSG_W(ret == MediaAVCodec::AVCS_ERR_OK, "try SetLowPowerPlayerMode failed, switch  to common");
        switchToCommon = ret != MediaAVCodec::AVCS_ERR_OK;
    }
    isLppEnabled_ = isLppEnabled_ ? !switchToCommon : isLppEnabled_;
    auto decoderCallback = std::make_shared<LppVideoDecoderCallback>(weak_from_this());
    FALSE_RETURN_V_MSG(decoderCallback != nullptr, MSERR_NO_MEMORY, "decoderCallback create failed");
    int32_t ret = videoDecoder_->SetCallback(decoderCallback);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, MSERR_VID_DEC_FAILED, "videoDecoder_ SetCodecCallback failed");

    decodertask_ = std::make_unique<Task>("LppADec", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_NO_MEMORY, "decodertask_ is nullptr");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Configure(const Format &param)
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    int32_t isHdrVivid = 0;
    bool getRes = param.GetIntValue(Tag::VIDEO_IS_HDR_VIVID, isHdrVivid);
    bool enableHdrVivid = OHOS::system::GetBoolParameter("debug.media_service.enable_hdr_vivid", false);
    FALSE_RETURN_V_MSG(!getRes || isHdrVivid == 0 || enableHdrVivid, MSERR_VID_DEC_FAILED, "HDRVivid not support");
    int32_t ret = videoDecoder_->Configure(param);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "Configure failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::SetVideoSurface(sptr<Surface> surface)
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    int32_t ret = videoDecoder_->SetOutputSurface(surface);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "SetVideoSurface failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Prepare()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    int32_t ret = videoDecoder_->Prepare();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "Prepare failed");
    ret = PrepareBufferQueue();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "PrepareBufferQueue failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::StartDecode()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Start();
    int32_t ret = videoDecoder_->Start();
    firstStarted_ = true;
    if (initTargetPts_ != -1) {
        int32_t seekRes = SetTargetPts(initTargetPts_);
        FALSE_RETURN_V_MSG(seekRes == MSERR_OK, seekRes, "Seek failed");
        initTargetPts_ = -1;
    }
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "StartDecode failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::RenderFirstFrame()
{
    MEDIA_LOG_I("LppVideoDecoderAdapter::RenderFirstFrame");
    FALSE_RETURN_V_MSG(firstFrameDecoded_, MSERR_INVALID_OPERATION, "first frame not decoded");
    FALSE_RETURN_V_MSG(!firstFrameRenderred_, MSERR_INVALID_OPERATION, "first frame renderred");
    uint32_t idx = 0;
    {
        std::lock_guard lock(outputMutex_);
        FALSE_RETURN_V_MSG(PopHeadFrame(idx, 0, false), MSERR_INVALID_OPERATION, "no frame left");
        firstFrameRenderred_ = true;
    }
    videoDecoder_->ReleaseOutputBuffer(idx, true);
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::StartRender()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    uint32_t idx = 0;
    bool hasFrame = false;
    {
        std::lock_guard lock(outputMutex_);
        firstFrameRenderred_ = true;
        renderStarted_ = true;
        hasFrame = PopHeadFrame(idx, GetSysTimeNs(), true);
    }
    if (hasFrame) {
        videoDecoder_->ReleaseOutputBuffer(idx, true);
    }
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_VIDEO_RENDERING_START, MSERR_OK});
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Pause()
{
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Pause();
    lastRenderTimeNs_.store(0);
    lastPts_.store(0);
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Resume()
{
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Start();
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Flush()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    int32_t ret = videoDecoder_->Flush();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AVCSErrorToMSError(ret), "Flush failed");
    FlushTask();
    lastRenderTimeNs_.store(0);
    lastPts_.store(0);
    {
        std::lock_guard lock(outputMutex_);
        firstFrameDecoded_ = false;
        firstFrameRenderred_ = false;
        renderStarted_ = false;
        outputBuffers_.clear();
        if (inputBufferQueueConsumer_ != nullptr) {
            for (auto &buffer : bufferVector_) {
                inputBufferQueueConsumer_->DetachBuffer(buffer);
            }
            bufferVector_.clear();
            inputBufferQueueConsumer_->SetQueueSize(0);
        }
    }
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Stop()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    auto ret = videoDecoder_->Stop();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AVCSErrorToMSError(ret), "Flush failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Reset()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    auto ret = videoDecoder_->Reset();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "Reset failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::SetParameter(const Format &param)
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    auto ret = videoDecoder_->SetParameter(param);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AVCSErrorToMSError(ret), "SetParameter failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::GetChannelId(int32_t &channelId)
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    auto ret = videoDecoder_->GetChannelId(channelId);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AVCSErrorToMSError(ret), "GetChannelId failed");
    return MSERR_OK;
}

int32_t LppVideoDecoderAdapter::Release()
{
    MEDIA_LOG_I("Release");
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "Release failed");
    auto ret = videoDecoder_->Release();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "Release failed");
    return MSERR_OK;
}

void LppVideoDecoderAdapter::SetChannelIdDone()
{
    MEDIA_LOG_I("LppVideoDecoderAdapter::SetChannelIdDone");
    setChannelIdDone_.store(true);
    OnQueueBufferAvailable();
}

int32_t LppVideoDecoderAdapter::PrepareBufferQueue()
{
    inputBufferQueue_ = AVBufferQueue::Create(0, MemoryType::UNKNOWN_MEMORY, VIDEO_INPUT_BUFFER_QUEUE_NAME, true);
    FALSE_RETURN_V_MSG(inputBufferQueue_ != nullptr, MSERR_NO_MEMORY, "inputBufferQueue_ is nullptr.");
    inputBufferQueueConsumer_ = inputBufferQueue_->GetConsumer();
    FALSE_RETURN_V_MSG(inputBufferQueueConsumer_ != nullptr, MSERR_AUD_DEC_FAILED,
        "inputBufferQueueConsumer_ is nullptr.");

    sptr<IConsumerListener> consumerListener =
        OHOS::sptr<LppVideoDecConsumerListener>::MakeSptr(weak_from_this());
    FALSE_RETURN_V_MSG(consumerListener != nullptr, MSERR_NO_MEMORY, "consumerListener is nullptr");
    Status statusRes = inputBufferQueueConsumer_->SetBufferAvailableListener(consumerListener);
    FALSE_RETURN_V_MSG(statusRes == Status::OK, MSERR_AUD_DEC_FAILED, "SetBufferAvailableListener is failed");
    return MSERR_OK;
}

sptr<Media::AVBufferQueueProducer> LppVideoDecoderAdapter::GetInputBufferQueue()
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, nullptr, "videoDecoder_ is nullptr");
    sptr<Media::AVBufferQueueProducer> inputBufferQueueProducer = inputBufferQueue_->GetProducer();
    FALSE_RETURN_V_MSG(inputBufferQueueProducer != nullptr, nullptr, "inputBufferQueueProducer is nullptr");
    return inputBufferQueueProducer;
}

void LppVideoDecoderAdapter::OnQueueBufferAvailable()
{
    int64_t jobIdx = GeneratedJobIdx();
    FALSE_RETURN_MSG(decodertask_ != nullptr, "decodertask_ is nullptr");
    decodertask_->SubmitJob([this, jobIdx] {
            FALSE_RETURN_NOLOG(!IsJobFlushed(jobIdx));
            HandleQueueBufferAvailable();
        }, 0, false);
}

void LppVideoDecoderAdapter::HandleQueueBufferAvailable()
{
    FALSE_RETURN_MSG(videoDecoder_ != nullptr, "inputBufferQueueConsumer_ is nullptr.");
    FALSE_RETURN_MSG(inputBufferQueueConsumer_ != nullptr, "inputBufferQueueConsumer_ is nullptr.");
    FALSE_RETURN_MSG_D(setChannelIdDone_, "SetChannelId not done");

    std::shared_ptr<AVBuffer> tmpBuffer;
    Status statusRes = inputBufferQueueConsumer_->AcquireBuffer(tmpBuffer);
    FALSE_RETURN_MSG_D(statusRes == Status::OK && tmpBuffer != nullptr && tmpBuffer->meta_ != nullptr,
        "AcquireBuffer failed");

    int32_t index;
    bool getDataRes = tmpBuffer->meta_->GetData(Tag::REGULAR_TRACK_ID, index);
    FALSE_RETURN_MSG(getDataRes, "get index failed.");
    int32_t res = videoDecoder_->QueueInputBuffer(static_cast<uint32_t>(index));
    FALSE_RETURN_MSG(res == MediaAVCodec::AVCS_ERR_OK, "videoDecoder_ QueueInputBuffer failed");
    DumpBufferIfNeeded(dumpFileNameOutput_, tmpBuffer);
    OnQueueBufferAvailable();
}

void LppVideoDecoderAdapter::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    MEDIA_LOG_D("LppVideoDecoderAdapter::OnInputBufferAvailable index=" PUBLIC_LOG_U32, index);
    FALSE_RETURN_MSG(buffer != nullptr && buffer->meta_ != nullptr, "meta_ is nullptr.");
    FALSE_RETURN_MSG(inputBufferQueueConsumer_ != nullptr, "inputBufferQueueConsumer_ is nullptr.");
    std::lock_guard lock(inputMutex_);
    buffer->meta_->SetData(Tag::REGULAR_TRACK_ID, static_cast<int32_t>(index));
    if (inputBufferQueueConsumer_->IsBufferInQueue(buffer)) {
        inputBufferQueueConsumer_->ReleaseBuffer(buffer);
        return;
    }
    uint32_t size = inputBufferQueueConsumer_->GetQueueSize() + 1;
    inputBufferQueueConsumer_->SetQueueSizeAndAttachBuffer(size, buffer, false);
    bufferVector_.push_back(buffer);
}

void LppVideoDecoderAdapter::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    FALSE_RETURN_MSG(buffer != nullptr, "buffer is nullptr.");
    MEDIA_LOG_D("LppVideoDecoderAdapter::OnOutputBufferAvailable index=" PUBLIC_LOG_U32 " pts=" PUBLIC_LOG_D64,
        index, buffer->pts_);
    bool needRenderCurrentFrame = false;
    {
        std::lock_guard lock(outputMutex_);
        needRenderCurrentFrame = outputBuffers_.empty() && firstFrameRenderred_ && renderStarted_;
        outputBuffers_.push_back(std::make_pair(index, buffer));
        MEDIA_LOG_D("outputBuffers_.size=" PUBLIC_LOG_U32, outputBuffers_.size());
    }
    NotifyFirstFrameDecoded();
    FALSE_RETURN_NOLOG(needRenderCurrentFrame);
    MEDIA_LOG_D("ScheduleRenderFrameJob when OnOutputBufferAvailable");
    ScheduleRenderFrameJob(index, buffer);
}

void LppVideoDecoderAdapter::ScheduleRenderFrameJob(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    FALSE_RETURN_NOLOG(!HandleEosFrame(index, buffer));
    FALSE_RETURN_NOLOG(!HandleCommonFrame(index, buffer));
    FALSE_RETURN_NOLOG(!HandleLppFrame(index, buffer));
}

bool LppVideoDecoderAdapter::HandleEosFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    bool isEosBuffer = (buffer->flag_ & static_cast<uint32_t>(Plugins::AVBufferFlag::EOS)) > 0;
    FALSE_RETURN_V_NOLOG(isEosBuffer, false);
    MEDIA_LOG_I("LppVideoDecoderAdapter::HandleEos");
    int64_t waitTime = lastRenderTimeNs_.load() == 0 ? 0 : (GetSysTimeNs() - lastRenderTimeNs_.load()) / US_TO_MS;
    waitTime = waitTime >= 0 ? waitTime : 0;
    int64_t jobIdx = GeneratedJobIdx();
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, false, "decodertask_ is nullptr");
    lastCommonPts_.store(buffer->pts_);
    decodertask_->SubmitJob([this, jobIdx] {
            FALSE_RETURN_MSG(!IsJobFlushed(jobIdx), "video eos job is flushed");
            FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
            uint32_t idx = 0;
            {
                std::lock_guard lock(outputMutex_);
                FALSE_RETURN_MSG(PopHeadFrame(idx, 0, false), "no frame left");
            }
            videoDecoder_->ReleaseOutputBuffer(idx, false);
            MEDIA_LOG_I("LppVideoDecoderAdapter eos");
            eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_COMPLETE, MSERR_OK});
        }, waitTime, false);
    return true;
}

int64_t LppVideoDecoderAdapter::GetLastCommonPts()
{
    MEDIA_LOG_D("GetLastCommonPts" PUBLIC_LOG_D64, lastCommonPts_.load());
    return lastCommonPts_.load();
}

bool LppVideoDecoderAdapter::HandleCommonFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    FALSE_RETURN_V_NOLOG(!isLppEnabled_, false);
    int64_t diffTimeNs = 0;
    bool isCalclated = false;
    CalcAnchorDiffTimeNs(buffer->pts_, diffTimeNs, isCalclated);
    CalcPreFrameDiffTimeNs(buffer->pts_, diffTimeNs, isCalclated);
    int64_t currentTimeNs = GetSysTimeNs();
    int64_t renderTimeNs = diffTimeNs + currentTimeNs;
    int64_t lastRenderTimeNs = lastRenderTimeNs_.load();
    renderTimeNs = lastRenderTimeNs > 0 && renderTimeNs < lastRenderTimeNs ? lastRenderTimeNs + 1 : renderTimeNs;
    int64_t advanceTime = renderTimeNs > currentTimeNs ? renderTimeNs - currentTimeNs : 0;
    int64_t waitTimeNs = advanceTime > MAX_ADVANCE_US ? advanceTime - MAX_ADVANCE_US : 0;
    MEDIA_LOG_D("render common frame pts=" PUBLIC_LOG_U32 " renderTimeNs=" PUBLIC_LOG_D64 " diffTimeNs=" PUBLIC_LOG_D64
        " waitTimeNs=" PUBLIC_LOG_D64, buffer->pts_, renderTimeNs, diffTimeNs, waitTimeNs);
    int64_t jobIdx = GeneratedJobIdx();
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, false, "decodertask_ is nullptr");
    decodertask_->SubmitJob([this, jobIdx, renderTimeNs] {
            FALSE_RETURN_MSG(!IsJobFlushed(jobIdx), "video eos job is flushed");
            ProcessCommonFrame(renderTimeNs);
        }, waitTimeNs / US_TO_MS, false);
    return true;
}

void LppVideoDecoderAdapter::ProcessCommonFrame(int64_t renderTimeNs)
{
    uint32_t idx = 0;
    {
        std::lock_guard lock(outputMutex_);
        FALSE_RETURN_MSG(PopHeadFrame(idx, renderTimeNs, true), "no frame left");
    }
    videoDecoder_->RenderOutputBufferAtTime(idx, renderTimeNs);
}

bool LppVideoDecoderAdapter::HandleLppFrame(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    FALSE_RETURN_V_NOLOG(isLppEnabled_, false);
    int64_t diffTimeNs = 0;
    bool isCalclated = false;
    CalcAnchorDiffTimeNs(buffer->pts_, diffTimeNs, isCalclated);
    CalcPreFrameDiffTimeNs(buffer->pts_, diffTimeNs, isCalclated);
    int64_t waitTime = diffTimeNs > 0 ? diffTimeNs : 0;
    int64_t jobIdx = GeneratedJobIdx();
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, false, "decodertask_ is nullptr");
    decodertask_->SubmitJob([this, jobIdx] {
            FALSE_RETURN_MSG(!IsJobFlushed(jobIdx), "video eos job is flushed");
            ProcessLppFrame();
        }, waitTime / US_TO_MS, false);
    return true;
}

void LppVideoDecoderAdapter::ProcessLppFrame()
{
    uint32_t idx = 0;
    {
        std::lock_guard lock(outputMutex_);
        FALSE_RETURN_MSG(PopHeadFrame(idx, GetSysTimeNs(), true), "no frame left");
    }
    videoDecoder_->ReleaseOutputBuffer(idx, true);
}

void LppVideoDecoderAdapter::NotifyFirstFrameDecoded()
{
    FALSE_RETURN_NOLOG(!firstFrameDecoded_);
    firstFrameDecoded_ = true;
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    MEDIA_LOG_I("LppVideoDecoderAdapter first frame ready");
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_FIRST_FRAME_READY, MSERR_OK});
}

bool LppVideoDecoderAdapter::PopHeadFrame(uint32_t &idx, int64_t renderTimeNs, bool cyclic)
{
    FALSE_RETURN_V_MSG(!outputBuffers_.empty(), false, "outputBuffers_ is empty");
    auto [tmpIdx, buffer] = outputBuffers_.front();
    FALSE_RETURN_V_MSG(buffer != nullptr, false, "buffer is nullptr");
    FALSE_RETURN_V_MSG(tmpIdx >= 0, false, "tmpIdx is invalid");
    idx = static_cast<uint32_t>(tmpIdx);
    lastRenderTimeNs_.store(renderTimeNs);
    lastPts_.store(buffer->pts_);
    outputBuffers_.pop_front();
    FALSE_RETURN_V_NOLOG(!outputBuffers_.empty() && cyclic, true);
    auto [nextIdx, nextBuffer] = outputBuffers_.front();
    ScheduleRenderFrameJob(nextIdx, nextBuffer);
    return true;
}

int64_t LppVideoDecoderAdapter::GetSysTimeNs()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void LppVideoDecoderAdapter::CalcAnchorDiffTimeNs(int64_t pts, int64_t &diffTimeNs, bool &isCalclated)
{
    FALSE_RETURN_NOLOG(!isCalclated);
    auto syncMgr = syncMgr_.lock();
    FALSE_RETURN_MSG(syncMgr != nullptr, "syncMgr_ is empty");
    int64_t ahchorPts = 0;
    int64_t anchorClock = 0;
    syncMgr->GetTimeAnchor(ahchorPts, anchorClock);
    FALSE_RETURN_MSG(anchorClock > 0, "anchor not update");
    int64_t renderClock = (pts - ahchorPts) / speed_.load() + anchorClock;
    timespec tm{};
    clock_gettime(CLOCK_BOOTTIME, &tm);
    int64_t curClock = tm.tv_sec * SEC_TO_US + tm.tv_nsec / US_TO_MS;
    diffTimeNs = (renderClock - curClock) * US_TO_MS;
    isCalclated = true;
}

void LppVideoDecoderAdapter::CalcPreFrameDiffTimeNs(int64_t pts, int64_t &diffTimeNs, bool &isCalclated)
{
    FALSE_RETURN_NOLOG(!isCalclated);
    int64_t lastRenderTimeNs = lastRenderTimeNs_.load();
    FALSE_RETURN_NOLOG(lastRenderTimeNs != 0);
    int64_t lastPts = lastPts_.load();
    int64_t renderTimeNs = (pts - lastPts) / speed_.load() * US_TO_MS * 2 + lastRenderTimeNs;
    int64_t sysTimeNs = GetSysTimeNs();
    diffTimeNs = renderTimeNs - sysTimeNs;
    isCalclated = true;
}

void LppVideoDecoderAdapter::OnOutputBufferBinded(std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap)
{
    auto syncMgr = syncMgr_.lock();
    FALSE_RETURN_MSG(syncMgr != nullptr, "syncMgr_ is empty");
    syncMgr->BindOutputBuffers(bufferMap);
}

void LppVideoDecoderAdapter::OnOutputBufferUnbinded()
{
    auto syncMgr = syncMgr_.lock();
    FALSE_RETURN_MSG(syncMgr != nullptr, "syncMgr_ is empty");
    syncMgr->UnbindOutputBuffers();
}

void LppVideoDecoderAdapter::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    MEDIA_LOG_I("LppVideoDecoderAdapter::OnError errorCode=" PUBLIC_LOG_D32, errorCode);
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    MediaServiceErrCode err = AVCSErrorToMSError(errorCode);
    std::string errMsg = MSErrorToString(err);
    std::pair<MediaServiceErrCode, std::string> errPair = std::make_pair(err, errMsg);
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_ERROR, errPair});
}

void LppVideoDecoderAdapter::OnOutputFormatChanged(const Format &format)
{
    MEDIA_LOG_I("LppVideoDecoderAdapter OnOutputFormatChanged");
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_RESOLUTION_CHANGE, format});
}

void LppVideoDecoderAdapter::FlushTask()
{
    std::lock_guard lock(jobIdxMutex_);
    jobIdxBase_ = jobIdx_;
}

int64_t LppVideoDecoderAdapter::GeneratedJobIdx()
{
    std::lock_guard lock(jobIdxMutex_);
    return ++jobIdx_;
}

bool LppVideoDecoderAdapter::IsJobFlushed(int64_t jobIdx)
{
    std::lock_guard lock(jobIdxMutex_);
    return jobIdx <= jobIdxBase_;
}

void LppVideoDecoderAdapter::SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}

void LppVideoDecoderAdapter::SetSyncManager(std::shared_ptr<ILppSyncManager> syncMgr)
{
    syncMgr_ = syncMgr;
}

void LppVideoDecoderAdapter::SetPlaybackSpeed(float speed)
{
    MEDIA_LOG_I("LppVideoDecoderAdapter::SetPlaybackSpeed speed " PUBLIC_LOG_F, speed);
    speed_.store(speed);
}

void LppVideoDecoderAdapter::DumpBufferIfNeeded(const std::string &fileName, const std::shared_ptr<AVBuffer>& buffer)
{
    FALSE_RETURN_NOLOG(dumpBufferNeeded_);
    DumpAVBufferToFile(DUMP_PARAM, fileName, buffer);
}

int32_t LppVideoDecoderAdapter::SetTargetPts(int64_t targetPts)
{
    FALSE_RETURN_V_MSG(videoDecoder_ != nullptr, MSERR_INVALID_OPERATION, "videoDecoder_ nullptr");
    if (!firstStarted_) {
        initTargetPts_ = targetPts;
        return MSERR_OK;
    }
    Format format;
    format.PutLongValue("video_seek_pts", targetPts);
    auto ret = videoDecoder_->SetParameter(format);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "Seek failed");
    return MSERR_OK;
}
}  // namespace Media
}  // namespace OHOS