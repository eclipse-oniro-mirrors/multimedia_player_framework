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
#include "lpp_video_data_manager.h"
#include "common/log.h"
#include "media_errors.h"
#include "osal/utils/steady_clock.h"
#include "osal/utils/dump_buffer.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVDataMgr"};
const std::string DUMP_PARAM = "a";
constexpr uint32_t MAX_BUFFER_SIZE = 2 * 1024 * 1024;
constexpr uint32_t MAX_FRAME_NUM = 500;
}  // namespace

namespace OHOS {
namespace Media {

class VideoDecoderInputProducerListener : public IRemoteStub<IProducerListener> {
public:
    explicit VideoDecoderInputProducerListener(std::weak_ptr<LppVideoDataManager> videoDataMgr)
    {
        videoDataMgr_ = videoDataMgr;
    }
    ~VideoDecoderInputProducerListener()
    {
        MEDIA_LOG_I("~VideoDecoderInputProducerListener");
    }
    void OnBufferAvailable() override
    {
        auto videoDataMgr = videoDataMgr_.lock();
        FALSE_RETURN_MSG(videoDataMgr != nullptr, "videoDataMgr is nullptr");
        MEDIA_LOG_D("VideoDecoderInputProducerListener OnBufferAvailable");
        videoDataMgr->OnBufferAvailable();
    }
 
private:
    std::weak_ptr<LppVideoDataManager> videoDataMgr_;
};

LppVideoDataManager::LppVideoDataManager(const std::string &streamerId, bool isLpp)
    : streamerId_(streamerId), isLpp_(isLpp)
{
    std::string pktIn;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_video_lpp_packet_input", pktIn, "false");
    disablePacketInput_ = ret == 0 ? pktIn == "true" : false;
    disablePacketInput_ |= !isLpp_;
    std::string enableDump;
    ret = OHOS::system::GetStringParameter("debug.media_service.enable_video_lpp_dump", enableDump, "false");
    dumpBufferNeeded_ = ret == 0 ? enableDump == "true" : false;
    dumpFileNameOutput_ = streamerId_ + "_DUMP_OUTPUT.bin";
}

LppVideoDataManager::~LppVideoDataManager()
{
    MEDIA_LOG_I("~LppVideoDataManager");
}

int32_t LppVideoDataManager::Configure(const Format &params)
{
    (void)params;
    return MSERR_OK;
}

int32_t LppVideoDataManager::Prepare()
{
    MEDIA_LOG_I("LppAudioDataManager Instances destroy.");
    dataTask_ = std::make_unique<Task>("LppVData", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_NO_MEMORY, "dataTask_ is nullptr");
    return MSERR_OK;
}

int32_t LppVideoDataManager::SetDecoderInputProducer(sptr<Media::AVBufferQueueProducer> producer)
{
    FALSE_RETURN_V_MSG(producer != nullptr, MSERR_INVALID_VAL, "producer is nullptr");
    inputProducer_ = producer;

    sptr<IProducerListener> producerListener =
        OHOS::sptr<VideoDecoderInputProducerListener>::MakeSptr(weak_from_this());
    FALSE_RETURN_V_MSG(producerListener != nullptr, MSERR_NO_MEMORY, "producerListener is nullptr");
    Status statusRes = inputProducer_->SetBufferAvailableListener(producerListener);
    FALSE_RETURN_V_MSG(statusRes == Status::OK, MSERR_VID_DEC_FAILED, "SetBufferAvailableListener is failed");
    return MSERR_OK;
}

int32_t LppVideoDataManager::StartDecode()
{
    MEDIA_LOG_I("LppVideoDataManager::Start");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Start();
    OnBufferAvailable();
    return MSERR_OK;
}

int32_t LppVideoDataManager::Pause()
{
    MEDIA_LOG_I("LppVideoDataManager::Pause");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Pause();
    return MSERR_OK;
}

int32_t LppVideoDataManager::Resume()
{
    MEDIA_LOG_I("LppVideoDataManager::Resume");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Start();
    OnBufferAvailable();
    return MSERR_OK;
}

int32_t LppVideoDataManager::Flush()
{
    {
        std::unique_lock<std::mutex> lk(dataPacketMutex_);
        MEDIA_LOG_I("flush data mgr");
        dataPacket_ = nullptr;
        isRequiringData_ = false;
    }
    return MSERR_OK;
}

int32_t LppVideoDataManager::Stop()
{
    MEDIA_LOG_I("LppVideoDataManager::Stop");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Stop();
    return MSERR_OK;
}

int32_t LppVideoDataManager::Reset()
{
    return MSERR_OK;
}

int32_t LppVideoDataManager::ProcessNewData(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOG_D("ProcessNewData, new datapacket arrived");
    FALSE_RETURN_V_MSG(framePacket != nullptr, MSERR_INVALID_OPERATION, "framePacket is nullptr");
    std::unique_lock<std::mutex> lk(dataPacketMutex_);
    dataPacket_ = framePacket;
    isRequiringData_ = false;
    OnBufferAvailable();
    return MSERR_OK;
}

void LppVideoDataManager::OnBufferAvailable()
{
    FALSE_RETURN_MSG(dataTask_ != nullptr, "dataTask_ is nullptr");
    dataTask_->SubmitJob([this] {
            HandleBufferAvailable();
        }, 0, false);
}

void LppVideoDataManager::HandleBufferAvailable()
{
    std::lock_guard<std::mutex> lk(dataPacketMutex_);
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    FALSE_RETURN_MSG(inputProducer_ != nullptr, "inputProducer_ is nullptr");
    FALSE_RETURN_NOLOG(!isRequiringData_);
    if (dataPacket_ == nullptr || dataPacket_->IsEmpty()) {
        MEDIA_LOG_D("dataPacket_ is empty, trigger callback");
        isRequiringData_ = true;
        std::pair<int64_t, int64_t> dataNeedInfo {MAX_BUFFER_SIZE, MAX_FRAME_NUM};
        eventReceiver_->OnEvent({"VideoSource", EventType::EVENT_DATA_NEEDED, dataNeedInfo});
        dataPacket_ = nullptr;
        return;
    }
    std::shared_ptr<AVBuffer> emptyOutputBuffer = nullptr;
    AVBufferConfig avBufferConfig;
    Status ret = inputProducer_->RequestBuffer(emptyOutputBuffer, avBufferConfig, 0);
    FALSE_RETURN_NOLOG(ret == Status::OK && emptyOutputBuffer != nullptr);
    if (disablePacketInput_) {
        dataPacket_->WriteOneFrameToAVBuffer(emptyOutputBuffer);
    } else {
        dataPacket_->WriteToByteBuffer(emptyOutputBuffer);
    }
    ret = inputProducer_->PushBuffer(emptyOutputBuffer, true);
    FALSE_RETURN_MSG(ret == Status::OK, "PushBuffer to bufferQueue failed");
    OnBufferAvailable();
}

void LppVideoDataManager::DumpBufferIfNeeded(const std::string &fileName, const std::shared_ptr<AVBuffer>& buffer)
{
    FALSE_RETURN_NOLOG(dumpBufferNeeded_);
    DumpAVBufferToFile(DUMP_PARAM, fileName, buffer);
}

void LppVideoDataManager::SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}
}  // namespace Media
}  // namespace OHOS