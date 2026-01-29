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
#include "lpp_adec_adapter.h"
#include "avcodec_errors.h"
#include "common/log.h"
#include "media_errors.h"
#include "media_lpp_errors.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppADec"};
}

namespace OHOS {
namespace Media {

class LppAudioDecConsumerListener : public OHOS::Media::IConsumerListener {
public:
    explicit LppAudioDecConsumerListener(std::weak_ptr<LppAudioDecoderAdapter> audioDecoderAdapter)
    {
        audioDecoderAdapter_ = audioDecoderAdapter;
    }
    ~LppAudioDecConsumerListener() = default;

    void OnBufferAvailable() override
    {
        auto audioDecoderAdapter = audioDecoderAdapter_.lock();
        FALSE_RETURN_MSG(audioDecoderAdapter != nullptr, "audioDecAdaptor is nullptr");
        MEDIA_LOG_D("LppAudioDecConsumerListener OnBufferAvailable");
        audioDecoderAdapter->OnBufferAvailable(false);
    }

private:
    std::weak_ptr<LppAudioDecoderAdapter> audioDecoderAdapter_;
};

class LppAudioDecProducerListener : public IRemoteStub<IProducerListener> {
public:
    explicit LppAudioDecProducerListener(std::weak_ptr<LppAudioDecoderAdapter> audioDecoderAdapter)
    {
        audioDecoderAdapter_ = audioDecoderAdapter;
    }
    virtual ~LppAudioDecProducerListener() = default;
    void OnBufferAvailable() override
    {
        auto audioDecoderAdapter = audioDecoderAdapter_.lock();
        FALSE_RETURN_MSG(audioDecoderAdapter != nullptr, "audioDecAdaptor is nullptr");
        MEDIA_LOG_D("LppAudioDecProducerListener OnBufferAvailable");
        audioDecoderAdapter->OnBufferAvailable(true);
    }

private:
    std::weak_ptr<LppAudioDecoderAdapter> audioDecoderAdapter_;
};

class AudioDecoderCallback : public AudioBaseCodecCallback {
public:
    explicit AudioDecoderCallback(std::weak_ptr<LppAudioDecoderAdapter> audioDecAdaptor)
        : audioDecAdaptor_(audioDecAdaptor)
    {
        MEDIA_LOG_I("AudioDecoderCallback");
    }

    ~AudioDecoderCallback()
    {
        MEDIA_LOG_I("~AudioDecoderCallback");
    }

    void OnError(CodecErrorType errorType, int32_t errorCode) override
    {
        auto audioDecAdaptor = audioDecAdaptor_.lock();
        FALSE_RETURN_MSG(audioDecAdaptor != nullptr, "audioDecAdaptor is nullptr");
        audioDecAdaptor->OnError(errorType, errorCode);
    }

    void OnOutputBufferDone(const std::shared_ptr<AVBuffer> &outputBuffer) override
    {
        (void)outputBuffer;
    }

    void OnOutputFormatChanged(const std::shared_ptr<Meta> &format) override
    {
        (void)format;
    }

private:
    std::weak_ptr<LppAudioDecoderAdapter> audioDecAdaptor_;
};

LppAudioDecoderAdapter::LppAudioDecoderAdapter(const std::string &streamerId) : streamerId_(streamerId)
{
    MEDIA_LOG_I("LppAudioDecoderAdapter " PUBLIC_LOG_S " initialized.", streamerId_.c_str());
}

LppAudioDecoderAdapter::~LppAudioDecoderAdapter()
{
    MEDIA_LOG_I("~LppAudioDecoderAdapter.");
    FALSE_RETURN_MSG(audiocodec_ != nullptr, "audiocodec_ nullptr");
    auto ret = audiocodec_->Release();
    FALSE_RETURN_MSG(ret == MediaAVCodec::AVCS_ERR_OK, "audiocodec_ Release failed");
    outputBufferQueueProducer_ = nullptr;
}

void LppAudioDecoderAdapter::OnError(CodecErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    MEDIA_LOG_I("LppAudioDecoderAdapter::OnError errorCode: %{public}d", errorCode);
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    MediaServiceErrCode err = AVCSErrorToMSError(errorCode);
    std::string errMsg = MSErrorToString(err);
    std::pair<MediaServiceErrCode, std::string> errPair = std::make_pair(err, errMsg);
    eventReceiver_->OnEvent({"AudioDecoder", EventType::EVENT_ERROR, errPair});
}

int32_t LppAudioDecoderAdapter::SetParameter(const Format &params)
{
    (void)params;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    MEDIA_LOG_I("SetParameter");
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    int32_t ret = audiocodec_->SetParameter(parameter);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ SetParameter failed");
    return ret;
}

int32_t LppAudioDecoderAdapter::Init(const std::string &name)
{
    MEDIA_LOG_I("Init name is " PUBLIC_LOG_S, name.c_str());
    audiocodec_ = std::make_shared<MediaCodec>();
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_NO_MEMORY, "audiocodec_ create failed");
    auto ret = audiocodec_->Init(name, false);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Init failed");

    decodertask_ = std::make_unique<Task>("LppADec", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_NO_MEMORY, "decodertask_ is nullptr");

    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Configure(const Format &params)
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    auto meta = const_cast<Format &>(params).GetMeta();
    auto ret = audiocodec_->Configure(meta);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Configure failed");
    auto decoderCallback = std::make_shared<AudioDecoderCallback>(weak_from_this());
    FALSE_RETURN_V_MSG(decoderCallback != nullptr, MSERR_NO_MEMORY, "decoderCallback create failed");
    ret = audiocodec_->SetCodecCallback(decoderCallback);
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret),
        "audiocodec_ SetCodecCallback failed");
    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::SetOutputBufferQueue(const sptr<Media::AVBufferQueueProducer> &bufferQueueProducer)
{
    FALSE_RETURN_V(bufferQueueProducer != nullptr, MSERR_INVALID_VAL);
    outputBufferQueueProducer_ = bufferQueueProducer;
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    int32_t ret = audiocodec_->SetOutputBufferQueue(bufferQueueProducer);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AVCSErrorToMSError(ret), "audiocodec_ SetOutputBufferQueue failed");
    return MSERR_OK;
}

sptr<Media::AVBufferQueueProducer> LppAudioDecoderAdapter::GetInputBufferQueue()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, nullptr, "audiocodec_ is nullptr");
    sptr<Media::AVBufferQueueProducer> inputBufferQueueProducer = audiocodec_->GetInputBufferQueue();
    FALSE_RETURN_V_MSG(inputBufferQueueProducer != nullptr, nullptr, "inputBufferQueueProducer is nullptr");
    return inputBufferQueueProducer;
}

int32_t LppAudioDecoderAdapter::Prepare()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    int32_t ret = audiocodec_->Prepare();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Prepare failed");

    sptr<IConsumerListener> consumerListener =
        OHOS::sptr<LppAudioDecConsumerListener>::MakeSptr(weak_from_this());
    FALSE_RETURN_V_MSG(consumerListener != nullptr, MSERR_NO_MEMORY, "consumerListener is nullptr");
    sptr<Media::AVBufferQueueConsumer> inputConsumer = audiocodec_->GetInputBufferQueueConsumer();
    FALSE_RETURN_V_MSG(inputConsumer != nullptr, MSERR_NO_MEMORY, "inputConsumer is nullptr");
    Status statusRes = inputConsumer->SetBufferAvailableListener(consumerListener);
    FALSE_RETURN_V_MSG(statusRes == Status::OK, MSERR_INVALID_OPERATION, "SetBufferAvailableListener is failed");

    sptr<IProducerListener> producerListener =
        OHOS::sptr<LppAudioDecProducerListener>::MakeSptr(weak_from_this());
    FALSE_RETURN_V_MSG(producerListener != nullptr, MSERR_NO_MEMORY, "producerListener is nullptr");
    sptr<Media::AVBufferQueueProducer> outputProducer = audiocodec_->GetOutputBufferQueueProducer();
    FALSE_RETURN_V_MSG(outputProducer != nullptr, MSERR_NO_MEMORY, "outputProducer is nullptr");
    statusRes = outputProducer->SetBufferAvailableListener(producerListener);
    FALSE_RETURN_V_MSG(statusRes == Status::OK, MSERR_INVALID_OPERATION, "SetBufferAvailableListener is failed");

    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Start()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    int32_t ret = audiocodec_->Start();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Start failed");
    decodertask_->Start();
    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Pause()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Pause();
    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Resume()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Start();
    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Flush()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    int32_t ret = audiocodec_->Flush();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Flush failed");
    FlushTask();
    return MSERR_OK;
}

int32_t LppAudioDecoderAdapter::Stop()
{
    FALSE_RETURN_V_MSG(audiocodec_ != nullptr, MSERR_INVALID_OPERATION, "audiocodec_ is nullptr");
    FALSE_RETURN_V_MSG(decodertask_ != nullptr, MSERR_INVALID_OPERATION, "decodertask_ is nullptr");
    decodertask_->Stop();
    int32_t ret = audiocodec_->Stop();
    FALSE_RETURN_V_MSG(ret == MediaAVCodec::AVCS_ERR_OK, AVCSErrorToMSError(ret), "audiocodec_ Stop failed");
    return MSERR_OK;
}

void LppAudioDecoderAdapter::OnBufferAvailable(bool isOutputBuffer)
{
    int64_t jobIdx = GeneratedJobIdx();
    FALSE_RETURN_MSG(decodertask_ != nullptr, "decodertask_ is nullptr");
    decodertask_->SubmitJob([this, isOutputBuffer, jobIdx] {
            bool isFlushed = IsJobFlushed(jobIdx);
            HandleBufferAvailable(isOutputBuffer, isFlushed);
        }, 0, false);
}

void LppAudioDecoderAdapter::HandleBufferAvailable(bool isOutputBuffer, bool isFlushed)
{
    FALSE_RETURN_MSG(audiocodec_ != nullptr, "audiocodec_ is nullptr");
    audiocodec_->ProcessInputBufferInner(isOutputBuffer, isFlushed);
}

void LppAudioDecoderAdapter::FlushTask()
{
    std::lock_guard lock(jobIdxMutex_);
    jobIdxBase_ = jobIdx_;
}

int64_t LppAudioDecoderAdapter::GeneratedJobIdx()
{
    std::lock_guard lock(jobIdxMutex_);
    return ++jobIdx_;
}

bool LppAudioDecoderAdapter::IsJobFlushed(int64_t jobIdx)
{
    std::lock_guard lock(jobIdxMutex_);
    return jobIdx <= jobIdxBase_;
}

void LppAudioDecoderAdapter::SetEventReceiver(std::shared_ptr<EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}
} // namespace Media
} // namespace OHOS