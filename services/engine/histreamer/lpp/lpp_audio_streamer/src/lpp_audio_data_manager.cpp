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
#include "lpp_audio_data_manager.h"
#include "common/log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppADataMgr"};
constexpr uint32_t MAX_BUFFER_SIZE = 1024 * 1024 * 10;
}  // namespace

namespace OHOS {
namespace Media {

class DecoderInputProducerListener : public IRemoteStub<IProducerListener> {
public:
    explicit DecoderInputProducerListener(std::weak_ptr<LppAudioDataManager> audioDataMgr)
    {
        audioDataMgr_ = audioDataMgr;
    }
    virtual ~DecoderInputProducerListener() = default;
    void OnBufferAvailable() override
    {
        auto audioDataMgr = audioDataMgr_.lock();
        FALSE_RETURN_MSG(audioDataMgr != nullptr, "audioDataMgr is nullptr");
        MEDIA_LOG_D("DecoderInputProducerListener OnBufferAvailable");
        audioDataMgr->OnBufferAvailable();
    }

private:
    std::weak_ptr<LppAudioDataManager> audioDataMgr_;
};

LppAudioDataManager::LppAudioDataManager(const std::string &streamerId) : streamerId_(streamerId)
{
    MEDIA_LOG_I("LppAudioDataManager " PUBLIC_LOG_S " initialized.", streamerId_.c_str());
}

LppAudioDataManager::~LppAudioDataManager()
{
    MEDIA_LOG_I("LppAudioDataManager Instances destroy.");
}

int32_t LppAudioDataManager::Prepare()
{
    dataTask_ = std::make_unique<Task>("LppAData", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_NO_MEMORY, "dataTask_ is nullptr");
    return MSERR_OK;
}

int32_t LppAudioDataManager::SetDecoderInputProducer(sptr<Media::AVBufferQueueProducer> producer)
{
    FALSE_RETURN_V_MSG(producer != nullptr, MSERR_INVALID_VAL, "producer is nullptr");
    inputProducer_ = producer;

    sptr<IProducerListener> producerListener =
        OHOS::sptr<DecoderInputProducerListener>::MakeSptr(weak_from_this());
    FALSE_RETURN_V_MSG(producerListener != nullptr, MSERR_NO_MEMORY, "producerListener is nullptr");
    Status statusRes = inputProducer_->SetBufferAvailableListener(producerListener);
    FALSE_RETURN_V_MSG(statusRes == Status::OK, MSERR_INVALID_OPERATION, "SetBufferAvailableListener is failed");
    return MSERR_OK;
}

int32_t LppAudioDataManager::Start()
{
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Start();
    OnBufferAvailable();
    return MSERR_OK;
}

int32_t LppAudioDataManager::Pause()
{
    MEDIA_LOG_I("pause data mgr");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Pause();
    return MSERR_OK;
}

int32_t LppAudioDataManager::Resume()
{
    MEDIA_LOG_I("LppAudioDataManager::Resume");
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Start();
    return MSERR_OK;
}

int32_t LppAudioDataManager::Flush()
{
    {
        std::unique_lock<std::mutex> lk(dataPacketMutex_);
        MEDIA_LOG_I("flush data mgr");
        dataPacket_ = nullptr;
        isRequiringData_ = false;
    }
    return MSERR_OK;
}

int32_t LppAudioDataManager::Stop()
{
    FALSE_RETURN_V_MSG(dataTask_ != nullptr, MSERR_INVALID_OPERATION, "dataTask_ is nullptr");
    dataTask_->Stop();
    return MSERR_OK;
}

int32_t LppAudioDataManager::Reset()
{
    return MSERR_OK;
}

int32_t LppAudioDataManager::ProcessNewData(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOG_D("ProcessNewData, new datapacket arrived");
    FALSE_RETURN_V_MSG(framePacket != nullptr, MSERR_INVALID_VAL, "framePacket is nullptr");
    std::unique_lock<std::mutex> lk(dataPacketMutex_);
    dataPacket_ = framePacket;
    isRequiringData_ = false;
    OnBufferAvailable();
    return MSERR_OK;
}

void LppAudioDataManager::OnBufferAvailable()
{
    FALSE_RETURN_MSG(dataTask_ != nullptr, "dataTask_ nullptr");
    dataTask_->SubmitJob([this] {
            HandleBufferAvailable();
        }, 0, false);
}

void LppAudioDataManager::HandleBufferAvailable()
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    FALSE_RETURN_MSG(inputProducer_ != nullptr, "inputProducer_ is nullptr");
    std::lock_guard<std::mutex> lk(dataPacketMutex_);
    FALSE_RETURN_NOLOG(!isRequiringData_);
    if (dataPacket_ == nullptr || dataPacket_->IsEmpty()) {
        MEDIA_LOG_D("dataPacket_ is empty, trigger callback");
        isRequiringData_ = true;
        eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_DATA_NEEDED, MAX_BUFFER_SIZE});
        dataPacket_ = nullptr;
        return;
    }
    std::shared_ptr<AVBuffer> emptyOutputBuffer = nullptr;
    AVBufferConfig avBufferConfig;
    Status ret = inputProducer_->RequestBuffer(emptyOutputBuffer, avBufferConfig, 0);
    FALSE_RETURN_NOLOG(ret == Status::OK && emptyOutputBuffer != nullptr);
    dataPacket_->WriteOneFrameToAVBuffer(emptyOutputBuffer);
    ret = inputProducer_->PushBuffer(emptyOutputBuffer, true);
    FALSE_RETURN_MSG(ret == Status::OK, "PushBuffer to bufferQueue failed");
    OnBufferAvailable();
}

void LppAudioDataManager::SetEventReceiver(std::shared_ptr<EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}
}  // namespace Media
}  // namespace OHOS