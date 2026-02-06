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

#include <algorithm>

#include "lpp_audio_render_adapter.h"
#include "common/log.h"
#include "media_errors.h"
#include "media_lpp_errors.h"
#include "audio_renderer.h"
#include "audio_info.h"
#include "audio_errors.h"
#include "osal/utils/steady_clock.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppARender"};
const std::string INPUT_BUFFER_QUEUE_NAME = "LppAudioRenderInputBufferQueue";
constexpr int32_t DEFAULT_BUFFER_QUEUE_SIZE = 20;
constexpr int32_t CALLBACK_BUFFER_DURATION_IN_MILLISECONDS = 20;
constexpr int64_t US_TO_MS = 1000;  // 1000 us per ms
constexpr int64_t SEC_TO_US = 1000 * 1000;
constexpr int64_t ANCHOR_UPDATE_PERIOD_US = 200000;  // Update time anchor every 200 ms
constexpr int32_t AUDIO_SAMPLE_8_BIT = 1;
constexpr int32_t AUDIO_SAMPLE_16_BIT = 2;
constexpr int32_t AUDIO_SAMPLE_24_BIT = 3;
constexpr int32_t AUDIO_SAMPLE_32_BIT = 4;
}  // namespace

namespace OHOS {
namespace Media {

class LppAudioRenderBufferListener : public IConsumerListener {
public:
    explicit LppAudioRenderBufferListener(std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter)
    {
        audioRenderAdapter_ = audioRenderAdapter;
    }
    void OnBufferAvailable() override
    {
        MEDIA_LOG_D("LppAudioRenderBufferListener OnBufferAvailable");
        auto renderAdaptor = audioRenderAdapter_.lock();
        FALSE_RETURN_MSG(renderAdaptor != nullptr, "invalid renderAdaptor");
        renderAdaptor->OnBufferAvailable();
    }

private:
    std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter_;
};

class LppAudioRendererDataCallback : public AudioStandard::AudioRendererWriteCallback {
public:
    explicit LppAudioRendererDataCallback(std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter)
    {
        audioRenderAdapter_ = audioRenderAdapter;
    }

    void OnWriteData(size_t length) override
    {
        MEDIA_LOG_D("LppAudioRendererDataCallback OnWriteData");
        auto audioRenderAdapter = audioRenderAdapter_.lock();
        FALSE_RETURN_MSG(audioRenderAdapter != nullptr, "invalid renderAdaptor");
        audioRenderAdapter->OnWriteData(length);
    }

private:
    std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter_;
};

class LppAudioRendererEventCallback : public AudioStandard::AudioRendererCallback,
    public AudioStandard::AudioRendererErrorCallback,
    public AudioStandard::AudioRendererOutputDeviceChangeCallback,
    public AudioStandard::AudioRendererPolicyServiceDiedCallback,
    public AudioStandard::AudioRendererFirstFrameWritingCallback {
public:
    explicit LppAudioRendererEventCallback(std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter)
    {
        audioRenderAdapter_ = audioRenderAdapter;
    }

    void OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent) override
    {
        MEDIA_LOG_I("OnInterrupt forceType is " PUBLIC_LOG_U32, static_cast<uint32_t>(interruptEvent.forceType));
        auto audioRenderAdapter = audioRenderAdapter_.lock();
        FALSE_RETURN_MSG(audioRenderAdapter != nullptr, "invalid renderAdaptor");
        audioRenderAdapter->OnInterrupt(interruptEvent);
    }

    void OnStateChange(const OHOS::AudioStandard::RendererState state,
        const OHOS::AudioStandard::StateChangeCmdType cmdType) override
    {
        MEDIA_LOG_I("RenderState is " PUBLIC_LOG_U32, static_cast<uint32_t>(state));
    }

    void OnOutputDeviceChange(const AudioStandard::AudioDeviceDescriptor &deviceInfo,
        const AudioStandard::AudioStreamDeviceChangeReason reason) override
    {
        MEDIA_LOG_I("DeviceChange reason is " PUBLIC_LOG_D32, static_cast<int32_t>(reason));
        auto audioRenderAdapter = audioRenderAdapter_.lock();
        FALSE_RETURN_MSG(audioRenderAdapter != nullptr, "invalid renderAdaptor");
        audioRenderAdapter->OnOutputDeviceChange(deviceInfo, reason);
    }

    void OnError(const AudioStandard::AudioErrors errorCode) override
    {
        MEDIA_LOG_D("OnError, errorCode: %{public}d", static_cast<int32_t>(errorCode));
        auto audioRenderAdapter = audioRenderAdapter_.lock();
        FALSE_RETURN_MSG(audioRenderAdapter != nullptr, "invalid renderAdaptor");
        audioRenderAdapter->OnError(errorCode);
    }

    void OnAudioPolicyServiceDied() override
    {
        MEDIA_LOG_I("OnAudioPolicyServiceDied enter");
    }
    void OnFirstFrameWriting(uint64_t latency) override
    {
        MEDIA_LOG_I("OnFirstFrameWriting latency: " PUBLIC_LOG_U64, latency);
    }
private:
    std::weak_ptr<LppAudioRenderAdapter> audioRenderAdapter_;
};

LppAudioRenderAdapter::LppAudioRenderAdapter(const std::string &streamerId)
{
    MEDIA_LOG_I("LppAudioRenderAdapter " PUBLIC_LOG_S " construct.", streamerId_.c_str());
    streamerId_ = streamerId;
    std::string isOffload;
    auto ret = OHOS::system::GetStringParameter("debug.lpp.use_movie_offload", isOffload, "false");
    isOffload_ = ret == 0 ? isOffload == "true" : false;
    MEDIA_LOG_I("audio isOffload_: " PUBLIC_LOG_D32, isOffload_);
}

LppAudioRenderAdapter::~LppAudioRenderAdapter()
{
    MEDIA_LOG_I("LppAudioRenderAdapter Instances destroy.");
}

int32_t LppAudioRenderAdapter::Init()
{
    MEDIA_LOG_I("LppAudioRenderAdapter initialized.");
    audioRenderer_ = AudioStandard::AudioRenderer::Create(rendererOptions_);
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_NO_MEMORY, "audio renderer Start nullptr");
    audioRenderer_->SetOffloadAllowed(true);
    audioRenderer_->SetInterruptMode(static_cast<AudioStandard::InterruptMode>(0));
    sampleRate_ = rendererOptions_.streamInfo.samplingRate;
    audioChannelCount_ = rendererOptions_.streamInfo.channels;
    sampleFormatBytes_ = GetSampleFormatBytes(rendererOptions_.streamInfo.format);
    FALSE_RETURN_V_MSG(sampleRate_ > 0 && audioChannelCount_ > 0 && sampleFormatBytes_ > 0, MSERR_INVALID_VAL,
        "invalid audio parameter");
    return MSERR_OK;
}

void LppAudioRenderAdapter::ReleaseRender()
{
    if (audioRenderer_ != nullptr && audioRenderer_->GetStatus() != AudioStandard::RendererState::RENDERER_RELEASED) {
        MEDIA_LOG_I("AudioRenderer::Release start");
        FALSE_RETURN_MSG(audioRenderer_->Release(), "AudioRenderer::Release failed");
        MEDIA_LOG_I("AudioRenderer::Release end");
    }
    audioRenderer_.reset();
}

int32_t LppAudioRenderAdapter::Prepare()
{
    MEDIA_LOG_I("LppAudioRenderAdapter::Prepare");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audioRenderer_ is nullptr");
    auto types = AudioStandard::AudioRenderer::GetSupportedEncodingTypes();
    bool supportPCM =
        std::find(types.begin(), types.end(), AudioStandard::AudioEncodingType::ENCODING_PCM) != types.end();
    FALSE_RETURN_V_MSG(supportPCM, MSERR_INVALID_VAL, "audio renderer do not support pcm encoding");

    renderTask_ = std::make_unique<Task>("LppARend", streamerId_, TaskType::SINGLETON, TaskPriority::NORMAL, false);
    FALSE_RETURN_V_MSG(renderTask_ != nullptr, MSERR_NO_MEMORY, "renderTask_ is nullptr");

    auto audioRendererDataCallback = std::make_shared<LppAudioRendererDataCallback>(weak_from_this());
    auto ret = audioRenderer_->SetRenderMode(AudioStandard::RENDER_MODE_CALLBACK);
    FALSE_RETURN_V_MSG(ret == AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret), "SetRenderMode fail.");
    ret = audioRenderer_->SetRendererWriteCallback(audioRendererDataCallback);
    FALSE_RETURN_V_MSG(ret == AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret),
        "SetRenderWriteCallback fail.");
    ret = audioRenderer_->SetBufferDuration(CALLBACK_BUFFER_DURATION_IN_MILLISECONDS);
    FALSE_RETURN_V_MSG(ret == AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret), "SetBufferDuration fail.");

    auto audioRendererEventCallback = std::make_shared<LppAudioRendererEventCallback>(weak_from_this());
    ret = audioRenderer_->SetRendererCallback(audioRendererEventCallback);
    ret = audioRenderer_->RegisterOutputDeviceChangeWithInfoCallback(audioRendererEventCallback);
    ret = audioRenderer_->SetRendererFirstFrameWritingCallback(audioRendererEventCallback);
    ret = audioRenderer_->RegisterAudioPolicyServerDiedCb(getprocpid(), audioRendererEventCallback);
    FALSE_RETURN_V_MSG(ret == AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret), "SetEventCallback fail.");

    return PrepareInputBufferQueue();
}

int32_t LppAudioRenderAdapter::Start()
{
    MEDIA_LOG_D("Start entered.");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audioRenderer_ is nullptr");
    FALSE_RETURN_V_MSG(renderTask_ != nullptr, MSERR_INVALID_OPERATION, "renderTask_ is nullptr");
    anchorPts_ = Plugins::HST_TIME_NONE;
    bool ret = audioRenderer_->Start();
    FALSE_RETURN_V_MSG(ret, MSERR_START_FAILED, "AudioRenderer::Start failed");
    renderTask_->Start();
    MEDIA_LOG_I("AudioRenderer::Start end");
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::Pause()
{
    MEDIA_LOG_I("LppAudioRenderAdapter::Pause");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audioRenderer_ is nullptr");
    FALSE_RETURN_V_MSG(renderTask_ != nullptr, MSERR_INVALID_OPERATION, "renderTask_ is nullptr");
    forceUpdateTimeAnchorNextTime_ = true;
    renderTask_->Pause();
    FALSE_RETURN_V_MSG(audioRenderer_->GetStatus() != AudioStandard::RendererState::RENDERER_PAUSED,
        MSERR_OK, "audio renderer no need pause");
    FALSE_RETURN_V_MSG_W(audioRenderer_->Pause(), MSERR_PAUSE_FAILED, "renderer pause fail.");
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::Resume()
{
    MEDIA_LOG_I("LppAudioRenderAdapter::Resume");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audio renderer Start nullptr");
    FALSE_RETURN_V_MSG(renderTask_ != nullptr, MSERR_INVALID_OPERATION, "renderTask_ is nullptr");
    anchorPts_ = Plugins::HST_TIME_NONE;
    bool ret = audioRenderer_->Start();
    FALSE_RETURN_V_MSG(ret, MSERR_START_FAILED, "AudioRenderer::Start failed");
    renderTask_->Start();
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::Flush()
{
    MEDIA_LOG_I("LppAudioRenderAdapter::Flush");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audioRenderer_ is nullptr");
    bool ret = audioRenderer_->Flush();
    FALSE_RETURN_V_MSG(ret, MSERR_AUD_RENDER_FAILED, "AudioRenderer::Flush failed");
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        isEos_ = false;
        currentQueuedBufferOffset_ = 0;
        availDataSize_.store(0);
        ClearAvailableOutputBuffers();
    }
    ClearInputBuffer();
    ResetTimeInfo();
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::Stop()
{
    MEDIA_LOG_I("Stop entered.");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "audioRenderer_ is nullptr");
    bool res = true;
    if (audioRenderer_->GetStatus() == OHOS::AudioStandard::RENDERER_RUNNING) {
        MEDIA_LOG_I("pause entered.");
        res = audioRenderer_->Pause();
        FALSE_RETURN_V_MSG(res, MSERR_PAUSE_FAILED, "audioRenderer_ pause failed");
    }
    FALSE_RETURN_V_MSG(audioRenderer_->GetStatus() != AudioStandard::RendererState::RENDERER_STOPPED, MSERR_OK,
        "AudioRenderer is already in stopped state.");
    res =  audioRenderer_->Stop();
    FALSE_RETURN_V_MSG(res, MSERR_STOP_FAILED, "audioRenderer_ Stop failed");
    ResetTimeInfo();
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::PrepareInputBufferQueue()
{
    FALSE_RETURN_V_MSG(inputBufferQueue_ == nullptr, MSERR_INVALID_OPERATION, "InputBufferQueue already create");
    int32_t inputBufferSize = DEFAULT_BUFFER_QUEUE_SIZE;
    MemoryType memoryType = MemoryType::SHARED_MEMORY;
#ifndef MEDIA_OHOS
    memoryType = MemoryType::VIRTUAL_MEMORY;
#endif
    MEDIA_LOG_I("PrepareInputBufferQueue ");
    inputBufferQueue_ = AVBufferQueue::Create(inputBufferSize, memoryType, INPUT_BUFFER_QUEUE_NAME);
    FALSE_RETURN_V_MSG(inputBufferQueue_ != nullptr, MSERR_NO_MEMORY, "AudioRenderer::Start failed");
    inputBufferQueueProducer_ = inputBufferQueue_->GetProducer();
    inputBufferQueueConsumer_ = inputBufferQueue_->GetConsumer();
    sptr<IConsumerListener> listener = new LppAudioRenderBufferListener(weak_from_this());
    inputBufferQueueConsumer_->SetBufferAvailableListener(listener);
    return MSERR_OK;
}

sptr<AVBufferQueueProducer> LppAudioRenderAdapter::GetBufferQueueProducer()
{
    return inputBufferQueueProducer_;
}

int32_t LppAudioRenderAdapter::Deinit()
{
    MEDIA_LOG_I("Deinit entered");
    ReleaseRender();
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::Reset()
{
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::SetParameter(const Format &params)
{
    int32_t tmp = 0;
    rendererOptions_.rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MOVIE;
    if (isOffload_) {
        MEDIA_LOG_I("audio SetParameter rendererFlags AUDIO_FLAG_PCM_OFFLOAD");
        rendererOptions_.rendererInfo.rendererFlags = AudioStandard::AUDIO_FLAG_PCM_OFFLOAD;
    }
    rendererOptions_.streamInfo.encoding = AudioStandard::ENCODING_PCM;
    params.GetIntValue("sample_rate", tmp);
    rendererOptions_.streamInfo.samplingRate = static_cast<AudioStandard::AudioSamplingRate>(tmp);
    params.GetIntValue("audio_sample_format", tmp);
    rendererOptions_.streamInfo.format = static_cast<AudioStandard::AudioSampleFormat>(tmp);
    params.GetIntValue("channel_count", tmp);
    rendererOptions_.streamInfo.channels = static_cast<AudioStandard::AudioChannel>(tmp);
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::SetSpeed(float speed)
{
    MEDIA_LOG_I("SetSpeed speed = " PUBLIC_LOG_F, speed);
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_NO_MEMORY, "audiorender is nullptr");
    int32_t ret = audioRenderer_->SetSpeed(speed);
    FALSE_RETURN_V_MSG(ret == OHOS::AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret),
        "set speed failed with code " PUBLIC_LOG_D32, ret);
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::SetVolume(const float volume)
{
    MEDIA_LOG_D("SetVolume entered.");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_NO_MEMORY, "audiorender is nullptr");
    int32_t ret = audioRenderer_->SetVolume(volume);
    FALSE_RETURN_V_MSG_E(ret == OHOS::AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret),
        "set volume failed with code " PUBLIC_LOG_D32, ret);
    MEDIA_LOG_D("SetVolume succ");
    volume_ = volume;
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::SetLoudnessGain(const float loudnessGain)
{
    MEDIA_LOG_D("SetLoudnessGain entered.");
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_NO_MEMORY, "audiorender is nullptr");
    int32_t ret = audioRenderer_->SetLoudnessGain(loudnessGain);
    FALSE_RETURN_V_MSG_E(ret == OHOS::AudioStandard::SUCCESS, AudioStandardStatusToMSError(ret),
        "set loudnessGain failed with code " PUBLIC_LOG_D32, ret);
    MEDIA_LOG_D("SetLoudnessGain succ");
    loudnessGain_ = loudnessGain;
    return MSERR_OK;
}

int32_t LppAudioRenderAdapter::GetAudioPosition(timespec &time, uint32_t &framePosition)
{
    FALSE_RETURN_V_MSG(audioRenderer_ != nullptr, MSERR_INVALID_OPERATION, "GetAudioPosition audioRender_ is nullptr");
    AudioStandard::Timestamp audioPositionTimestamp;
    int32_t ret = audioRenderer_->GetAudioTimestampInfo(
        audioPositionTimestamp, AudioStandard::Timestamp::Timestampbase::BOOTTIME);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, AudioStandardStatusToMSError(ret), "GetAudioPosition failed");
    time = audioPositionTimestamp.time;
    int64_t currentRenderClockTime = time.tv_sec * SEC_TO_US + time.tv_nsec / US_TO_MS;  // convert to us
    MEDIA_LOG_I("BOOTTIME is " PUBLIC_LOG_D64, currentRenderClockTime);
    framePosition = audioPositionTimestamp.framePosition;
    return MSERR_OK;
}

void LppAudioRenderAdapter::ReleaseCacheBuffer(bool isSwapBuffer)
{
    if (isSwapBuffer) {
        FALSE_RETURN_MSG(!swapOutputBuffers_.empty(), "swapOutputBuffers_ has no buffer");
        swapOutputBuffers_.pop();
        return;
    }
    auto buffer = availOutputBuffers_.front();
    availOutputBuffers_.pop();
    FALSE_RETURN_MSG(buffer != nullptr, "release buffer, but buffer is null");
    MEDIA_LOG_D("the pts is " PUBLIC_LOG_D64 " buffer is release", buffer->pts_);
    Status ret = inputBufferQueueConsumer_->ReleaseBuffer(buffer);
    FALSE_RETURN_MSG(ret == Status::OK, "release avbuffer failed");
    return;
}

void LppAudioRenderAdapter::OnWriteData(size_t length)
{
    FALSE_RETURN_MSG(audioRenderer_ != nullptr, "audioRenderer_ is nullptr");
    FALSE_RETURN_NOLOG(CheckBufferSize(length));
    AudioStandard::BufferDesc bufDesc;
    audioRenderer_->GetBufferDesc(bufDesc);
    int64_t bufferPts = Plugins::HST_TIME_NONE;
    FillAudioBuffer(length, bufDesc, bufferPts);
    Enqueue(bufDesc);
    UpdateTimeAnchor(bufferPts);
    DropEosBuffer();
}

void LppAudioRenderAdapter::OnBufferAvailable()
{
    FALSE_RETURN_MSG(renderTask_ != nullptr, "renderTask_ is nullptr");
    renderTask_->SubmitJob([this] {
            HandleBufferAvailable();
        }, 0, false);
}

void LppAudioRenderAdapter::HandleBufferAvailable()
{
    FALSE_RETURN_MSG(inputBufferQueueConsumer_ != nullptr, "inputBufferQueueConsumer_ is nullptr");
    std::shared_ptr<AVBuffer> filledInputBuffer;
    Status ret = inputBufferQueueConsumer_->AcquireBuffer(filledInputBuffer);
    FALSE_RETURN_NOLOG(ret == Status::OK && filledInputBuffer != nullptr);

    if (filledInputBuffer->memory_ == nullptr || filledInputBuffer->pts_ < 0) {
        MEDIA_LOG_W("release invalid buffer, pts = " PUBLIC_LOG_D64, filledInputBuffer->pts_);
        inputBufferQueueConsumer_->ReleaseBuffer(filledInputBuffer);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        isEos_ = isEos_ ? isEos_ :
            (filledInputBuffer->flag_ & static_cast<uint32_t>(Plugins::AVBufferFlag::EOS)) > 0;
        availOutputBuffers_.push(filledInputBuffer);
        availDataSize_.fetch_add(filledInputBuffer->memory_->GetSize());
        MEDIA_LOG_W("inputbuffer pts = %{public}d size = %{public}d cached buffer num = %{public}d size = %{public}d",
            static_cast<int32_t>(filledInputBuffer->pts_), static_cast<int32_t>(filledInputBuffer->memory_->GetSize()),
            static_cast<int32_t>(availOutputBuffers_.size()), static_cast<int32_t>(availDataSize_.load()));
        DriveBufferCircle();
    }
    OnBufferAvailable();
}

bool LppAudioRenderAdapter::CheckBufferSize(size_t length)
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    size_t availDataSize = availDataSize_.load();
    if (!isAudioVivid_) {
        maxCbDataSize_ = std::max(maxCbDataSize_, length);
    } else {
        maxCbDataSize_ = std::min(length, availDataSize_.load());
    }
    DriveBufferCircle();
    return availDataSize >= length || isEos_;
}

void LppAudioRenderAdapter::FillAudioBuffer(size_t size, AudioStandard::BufferDesc &bufferDesc, int64_t &bufferPts)
{
    FALSE_RETURN_MSG(size != 0 && size == bufferDesc.bufLength, "bufferDesc or request size is unavailable");
    std::lock_guard<std::mutex> lock(dataMutex_);
    bufferDesc.dataLength = 0;
    do {
        bool isSwapBuffer = false;
        FALSE_RETURN_MSG(!swapOutputBuffers_.empty() || !availOutputBuffers_.empty(), "buffer queue is empty");
        std::shared_ptr<AVBuffer> cacheBuffer;
        if (!swapOutputBuffers_.empty()) {
            cacheBuffer = swapOutputBuffers_.front();
            isSwapBuffer = true;
        } else {
            cacheBuffer = availOutputBuffers_.front();
        }
        if ((cacheBuffer->flag_ & static_cast<uint32_t>(Plugins::AVBufferFlag::EOS)) > 0) {
            MEDIA_LOG_I("Recv EOS size: " PUBLIC_LOG_D32 " dataLength: " PUBLIC_LOG_D32
                " bufferlength: " PUBLIC_LOG_D32, static_cast<int32_t>(size),
                static_cast<int32_t>(bufferDesc.dataLength), static_cast<int32_t>(bufferDesc.bufLength));
            
            break;
        }
        size_t cacheBufferSize = 0;
        if (IsBufferAvailable(cacheBuffer, cacheBufferSize) &&
            !IsBufferDataDrained(bufferDesc, cacheBuffer, size, cacheBufferSize, bufferPts)) {
            break;
        }
        ReleaseCacheBuffer(isSwapBuffer);
    } while (size > 0 && !isAudioVivid_);
}

void LppAudioRenderAdapter::Enqueue(AudioStandard::BufferDesc &bufferDesc)
{
    FALSE_RETURN_MSG(audioRenderer_ != nullptr, "audioRenderer_ is nullptr");
    writtenCnt_ += static_cast<int64_t>(bufferDesc.dataLength);
    audioRenderer_->Enqueue(bufferDesc);
}

void LppAudioRenderAdapter::DriveBufferCircle()
{
    FALSE_RETURN_NOLOG(!isEos_);
    FALSE_RETURN_NOLOG(!availOutputBuffers_.empty() && inputBufferQueue_ != nullptr);
    FALSE_RETURN_NOLOG(availOutputBuffers_.size() >= inputBufferQueue_->GetQueueSize());
    size_t availDataSize = availDataSize_.load();
    FALSE_RETURN_NOLOG(availDataSize < maxCbDataSize_);
    std::shared_ptr<AVBuffer> oldestBuffer = availOutputBuffers_.front();
    FALSE_RETURN_MSG(oldestBuffer != nullptr && oldestBuffer->memory_ != nullptr
        && oldestBuffer->memory_->GetSize() > 0, "buffer or memory is nullptr");
    std::shared_ptr<AVBuffer> swapBuffer = CopyBuffer(oldestBuffer);
    FALSE_RETURN_MSG(swapBuffer != nullptr, "CopyBuffer failed, swapBuffer is nullptr");
    availOutputBuffers_.pop();
    swapOutputBuffers_.push(swapBuffer);
    FALSE_RETURN_MSG(inputBufferQueueConsumer_ != nullptr, "bufferQueue consumer is nullptr");
    inputBufferQueueConsumer_->ReleaseBuffer(oldestBuffer);
}

std::shared_ptr<AVBuffer> LppAudioRenderAdapter::CopyBuffer(const std::shared_ptr<AVBuffer> buffer)
{
    FALSE_RETURN_V_MSG_E(buffer != nullptr && buffer->memory_ != nullptr 
        && buffer->memory_->GetSize() > 0, nullptr, "buffer or memory is nullptr");
    std::shared_ptr<Meta> meta = buffer->meta_;
    std::vector<uint8_t> metaData;
    FALSE_RETURN_V_MSG_W(meta == nullptr || !meta->GetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData), nullptr,
        "copy buffer not support for audiovivid");
    AVBufferConfig avBufferConfig;
    avBufferConfig.capacity = static_cast<int32_t>(buffer->memory_->GetSize());
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
#ifndef MEDIA_OHOS
    avBufferConfig.memoryType = MemoryType::VIRTUAL_MEMORY;
#endif
    std::shared_ptr<AVBuffer> swapBuffer = AVBuffer::CreateAVBuffer(avBufferConfig);
    FALSE_RETURN_V_MSG_E(swapBuffer != nullptr && swapBuffer->memory_ != nullptr, nullptr, "create swapBuffer failed");
    swapBuffer->pts_ = buffer->pts_;
    swapBuffer->dts_ = buffer->dts_;
    swapBuffer->duration_ = buffer->duration_;
    swapBuffer->flag_ = buffer->flag_;
    FALSE_RETURN_V_MSG_E(swapBuffer->memory_->GetCapacity() >= buffer->memory_->GetSize(), nullptr, "no enough memory");
    errno_t res = memcpy_s(swapBuffer->memory_->GetAddr(),
        swapBuffer->memory_->GetCapacity(),
        buffer->memory_->GetAddr(),
        buffer->memory_->GetSize());
    FALSE_RETURN_V_MSG_E(res == EOK, nullptr, "copy data failed");
    swapBuffer->memory_->SetSize(buffer->memory_->GetSize());
    return swapBuffer;
}

bool LppAudioRenderAdapter::IsBufferAvailable(std::shared_ptr<AVBuffer> &buffer, size_t &cacheBufferSize)
{
    FALSE_RETURN_V_MSG_D(buffer != nullptr && buffer->memory_ != nullptr, false, "buffer is null.");
    int32_t bufferSize = buffer->memory_->GetSize();
    FALSE_RETURN_V_MSG_D(bufferSize >= currentQueuedBufferOffset_, false, "buffer is empty, skip this buffer.");
    cacheBufferSize = static_cast<size_t>(bufferSize - currentQueuedBufferOffset_);
    return true;
}

bool LppAudioRenderAdapter::IsBufferDataDrained(AudioStandard::BufferDesc &bufferDesc,
    std::shared_ptr<AVBuffer> &buffer, size_t &size, size_t &cacheBufferSize, int64_t &bufferPts)
{
    FALSE_RETURN_V_MSG(cacheBufferSize <= size || !isAudioVivid_, false, "copy from cache buffer may fail.");
    return isAudioVivid_ ? CopyAudioVividBufferData(bufferDesc, buffer, size, cacheBufferSize, bufferPts) :
        CopyBufferData(bufferDesc, buffer, size, cacheBufferSize, bufferPts);
}

bool LppAudioRenderAdapter::CopyBufferData(AudioStandard::BufferDesc &bufferDesc, std::shared_ptr<AVBuffer> &buffer,
    size_t &size, size_t &cacheBufferSize, int64_t &bufferPts)
{
    size_t availableSize = cacheBufferSize > size ? size : cacheBufferSize;
    FALSE_RETURN_V_MSG(bufferDesc.dataLength >= 0 && currentQueuedBufferOffset_ >= 0,
        false, "bufferDesc.dataLength or currentQueuedBufferOffset_ is less than 0.");
    auto ret = memcpy_s(bufferDesc.buffer + bufferDesc.dataLength, availableSize,
        buffer->memory_->GetAddr() + currentQueuedBufferOffset_, availableSize);
    FALSE_RETURN_V_MSG(ret == 0, false, "copy from cache buffer may fail.");
    bufferPts = (bufferPts == Plugins::HST_TIME_NONE) ? buffer->pts_ : bufferPts;
    bufferDesc.dataLength += availableSize;
    availDataSize_.fetch_sub(availableSize);
    if (cacheBufferSize > size) {
        currentQueuedBufferOffset_ += static_cast<int32_t>(size);
        size = 0;
        return false;
    }
    currentQueuedBufferOffset_ = 0;
    size -= cacheBufferSize;
    return true;
}

bool LppAudioRenderAdapter::CopyAudioVividBufferData(AudioStandard::BufferDesc &bufferDesc,
    std::shared_ptr<AVBuffer> &buffer, size_t &size, size_t &cacheBufferSize, int64_t &bufferPts)
{
    FALSE_RETURN_V_MSG(bufferDesc.dataLength >= 0 && currentQueuedBufferOffset_ >= 0,
        false, "bufferDesc.dataLength or currentQueuedBufferOffset_ is less than 0.");
    auto ret = memcpy_s(bufferDesc.buffer + bufferDesc.dataLength, cacheBufferSize,
        buffer->memory_->GetAddr() + currentQueuedBufferOffset_, cacheBufferSize);
    FALSE_RETURN_V_MSG(ret == 0, false, "copy from cache buffer may fail.");
    bufferPts = (bufferPts == Plugins::HST_TIME_NONE) ? buffer->pts_ : bufferPts;
    bufferDesc.dataLength += cacheBufferSize;
    size -= cacheBufferSize;
    availDataSize_.fetch_sub(cacheBufferSize);
    currentQueuedBufferOffset_ = 0;
    auto meta = buffer->meta_;
    std::vector<uint8_t> metaData;
    meta->GetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData);
    if (metaData.size() == bufferDesc.metaLength && bufferDesc.metaLength > 0) {
        ret = memcpy_s(bufferDesc.metaBuffer, bufferDesc.metaLength,
            metaData.data(), bufferDesc.metaLength);
        FALSE_RETURN_V_MSG(ret == 0, false, "copy from cache buffer may fail.");
    }
    return true;
}

void LppAudioRenderAdapter::ClearAvailableOutputBuffers()
{
    FALSE_RETURN(inputBufferQueueConsumer_ != nullptr);
    while (!swapOutputBuffers_.empty()) {
        swapOutputBuffers_.pop();
    }
    while (!availOutputBuffers_.empty()) {
        ReleaseCacheBuffer();
    }
}

void LppAudioRenderAdapter::ClearInputBuffer()
{
    MEDIA_LOG_I("LppAudioRenderAdapter::ClearInputBuffer enter");

    FALSE_RETURN_MSG_W(inputBufferQueueProducer_ != nullptr, "ClearInputBuffer failed: producer is nullptr");
    inputBufferQueueProducer_->Clear();

    FALSE_RETURN_MSG_W(inputBufferQueueConsumer_ != nullptr, "ClearInputBuffer failed: consumer is nullptr");
    std::shared_ptr<AVBuffer> filledInputBuffer;
    while (Status::OK == inputBufferQueueConsumer_->AcquireBuffer(filledInputBuffer)) {
        inputBufferQueueConsumer_->ReleaseBuffer(filledInputBuffer);
    }
}

int32_t LppAudioRenderAdapter::GetSampleFormatBytes(AudioStandard::AudioSampleFormat format)
{
    int32_t formatBytes = 0;
    switch (format) {
        case AudioStandard::AudioSampleFormat::SAMPLE_U8:
            formatBytes = AUDIO_SAMPLE_8_BIT;
            break;
        case AudioStandard::AudioSampleFormat::SAMPLE_S16LE:
            formatBytes = AUDIO_SAMPLE_16_BIT;
            break;
        case AudioStandard::AudioSampleFormat::SAMPLE_S24LE:
            formatBytes = AUDIO_SAMPLE_24_BIT;
            break;
        case AudioStandard::AudioSampleFormat::SAMPLE_S32LE:
        case AudioStandard::AudioSampleFormat::SAMPLE_F32LE:
            formatBytes = AUDIO_SAMPLE_32_BIT;
            break;
        default:
            break;
    }
    return formatBytes;
}

void LppAudioRenderAdapter::UpdateTimeAnchor(int64_t bufferPts)
{
    FALSE_RETURN_MSG(bufferPts != Plugins::HST_TIME_NONE, "invalid bufferPts");
    startPts_ = startPts_ == Plugins::HST_TIME_NONE ? bufferPts : startPts_;
    int64_t writtenTime = writtenCnt_ * SEC_TO_US / sampleFormatBytes_ / sampleRate_ / audioChannelCount_;
    curPts_ = writtenTime + startPts_;
    int64_t nowClockTime = GetCurrentClockTimeUs();
    curClock_ = nowClockTime;
    bool needUpdate = forceUpdateTimeAnchorNextTime_ || (lastReportedClockTime_ == Plugins::HST_TIME_NONE) ||
                      (nowClockTime - lastReportedClockTime_ >= ANCHOR_UPDATE_PERIOD_US);
    forceUpdateTimeAnchorNextTime_ = false;
    FALSE_RETURN_NOLOG(needUpdate);
    
    timespec time{};
    uint32_t position;
    auto ret = GetAudioPosition(time, position);
    FALSE_RETURN_MSG(ret == MSERR_OK, "GetAudioPosition failed");
    anchorClock_ = time.tv_sec * SEC_TO_US + time.tv_nsec / US_TO_MS;  // convert to us
    anchorPts_ = startPts_ + static_cast<int64_t>(position) * SEC_TO_US / sampleRate_;
    MEDIA_LOG_I("anchorPts is " PUBLIC_LOG_D64 " and anchorClock is " PUBLIC_LOG_D64 " and startPts is " PUBLIC_LOG_D64,
        anchorPts_, anchorClock_, startPts_);
    lastReportedClockTime_ = nowClockTime;
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    std::pair<int64_t, int64_t> anchor {anchorPts_, anchorClock_};
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_ANCHOR_UPDATE, anchor});
}

void LppAudioRenderAdapter::GetLatency(int64_t &latency)
{
    MEDIA_LOG_D("GetLatency anchorPts_=" PUBLIC_LOG_D64 " anchorClock_=" PUBLIC_LOG_D64 " curPts_=" PUBLIC_LOG_D64
        " curClock_=" PUBLIC_LOG_D64, anchorPts_, anchorClock_, curPts_, curClock_);
    FALSE_RETURN_MSG(curPts_ != Plugins::HST_TIME_NONE && anchorPts_ != Plugins::HST_TIME_NONE
        && curClock_ != Plugins::HST_TIME_NONE && anchorClock_ != Plugins::HST_TIME_NONE, "GetLatency after start!");
    latency = (curPts_- anchorPts_ - (curClock_ - anchorClock_)) / speed_;
}

int64_t LppAudioRenderAdapter::GetCurrentClockTimeUs()
{
    timespec tm{};
    clock_gettime(CLOCK_BOOTTIME, &tm);
    return tm.tv_sec * SEC_TO_US + tm.tv_nsec / US_TO_MS;  // convert to us
}

int32_t LppAudioRenderAdapter::GetCurrentPosition(int64_t &currentPosition)
{
    FALSE_RETURN_V_MSG(anchorPts_ != Plugins::HST_TIME_NONE && anchorClock_ != Plugins::HST_TIME_NONE,
        MSERR_INVALID_STATE, "GetCurrentPosition after start!");
    int64_t nowClockTime = GetCurrentClockTimeUs();
    currentPosition = anchorPts_ + (nowClockTime - anchorClock_) * speed_;
    return MSERR_OK;
}

void LppAudioRenderAdapter::DropEosBuffer()
{
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        FALSE_RETURN_NOLOG(isEos_);
        FALSE_RETURN_NOLOG(!availOutputBuffers_.empty());
        auto cacheBuffer = availOutputBuffers_.front();
        FALSE_RETURN(cacheBuffer != nullptr);
        bool isEosBuffer = (cacheBuffer->flag_ & static_cast<uint32_t>(Plugins::AVBufferFlag::EOS)) > 0;
        FALSE_RETURN_NOLOG(isEosBuffer);
        availOutputBuffers_.pop();
        inputBufferQueueConsumer_->ReleaseBuffer(cacheBuffer);
    }
    FALSE_RETURN_MSG(renderTask_ != nullptr, "renderTask_ is nullptr");
    int64_t latency = 0;
    GetLatency(latency);
    renderTask_->SubmitJobOnce([this] {
            HandleEos();
        }, latency, false);
}

void LppAudioRenderAdapter::HandleEos()
{
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        FALSE_RETURN_MSG(isEos_, "flush during wait");
    }
    FALSE_RETURN_MSG(audioRenderer_ != nullptr, "audio renderer is nullptr");
    audioRenderer_->Drain();
    audioRenderer_->Pause();
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_COMPLETE, MSERR_OK});
}

void LppAudioRenderAdapter::ResetTimeInfo()
{
    forceUpdateTimeAnchorNextTime_ = true;
    startPts_ = Plugins::HST_TIME_NONE;
    curClock_ = Plugins::HST_TIME_NONE;
    anchorClock_ = Plugins::HST_TIME_NONE;
    anchorPts_ = Plugins::HST_TIME_NONE;
    lastReportedClockTime_ = Plugins::HST_TIME_NONE;
    curPts_ = Plugins::HST_TIME_NONE;
    writtenCnt_ = 0;
}

void LppAudioRenderAdapter::SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}

void LppAudioRenderAdapter::OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent)
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    std::pair<int64_t, int64_t> interruptInfo
        = std::make_pair(static_cast<int64_t>(interruptEvent.forceType), static_cast<int64_t>(interruptEvent.hintType));
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_AUDIO_INTERRUPT, interruptInfo});
}

void LppAudioRenderAdapter::OnStateChange(const OHOS::AudioStandard::RendererState state,
    const OHOS::AudioStandard::StateChangeCmdType cmdType)
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_AUDIO_STATE_CHANGE, state});
}

void LppAudioRenderAdapter::OnOutputDeviceChange(const AudioStandard::AudioDeviceDescriptor &deviceInfo,
    const AudioStandard::AudioStreamDeviceChangeReason reason)
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_AUDIO_DEVICE_CHANGE, static_cast<int64_t>(reason)});
}

void LppAudioRenderAdapter::OnError(const AudioStandard::AudioErrors errorCode)
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    MediaServiceErrCode err = AudioStandardErrorToMSError(static_cast<int32_t>(errorCode));
    std::string errMsg = MSErrorToString(err);
    std::pair<MediaServiceErrCode, std::string> errPair = std::make_pair(err, errMsg);
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_ERROR, errPair});
}

void LppAudioRenderAdapter::OnAudioPolicyServiceDied()
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_AUDIO_SERVICE_DIED, MSERR_OK});
}

void LppAudioRenderAdapter::OnFirstFrameWriting(uint64_t latency)
{
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"AudioRender", EventType::EVENT_AUDIO_FIRST_FRAME, latency});
}
}  // namespace Media
}  // namespace OHOS