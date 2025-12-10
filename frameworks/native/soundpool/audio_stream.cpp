
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

#include "audio_renderer_manager.h"
#include "audio_shared_memory.h"
#include "audio_stream.h"
#include "media_errors.h"
#include "media_log.h"
#include "securec.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "AudioStream"};
    static const int32_t ERROE_GLOBAL_ID = -1;
    static const int32_t NORMAL_PLAY_RENDERER_FLAGS = 0;
}

namespace OHOS {
namespace Media {
AudioStream::AudioStream(const Format &trackFormat, int32_t &soundID, int32_t &streamID,
    std::shared_ptr<ThreadPool> streamStopThreadPool) : trackFormat_(trackFormat),
    soundID_(soundID), streamID_(streamID), streamStopThreadPool_(streamStopThreadPool), pcmBufferFrameIndex_(0)
{
    MEDIA_LOGI("AudioStream Constructor, soundID is %{public}d, streamID is %{public}d", soundID, streamID);
    streamState_.store(StreamState::PREPARED);
}

AudioStream::~AudioStream()
{
    MEDIA_LOGI("AudioStream Destructor, soundID is %{public}d, streamID is %{public}d", soundID_, streamID_);
    Release();
}

void AudioStream::SetPcmBuffer(const std::shared_ptr<AudioBufferEntry> &pcmBuffer, size_t pcmBufferSize)
{
    pcmBuffer_ = pcmBuffer;
    pcmBufferSize_ = pcmBufferSize;
}

void AudioStream::SetManager(std::weak_ptr<StreamIDManager> streamIDManager)
{
    manager_ = streamIDManager;
}

void AudioStream::ConfigurePlayParameters(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    MEDIA_LOGI("AudioStream::ConfigurePlayParameters");
    std::lock_guard lock(streamLock_);
    audioRendererInfo_ = audioRendererInfo;
    playParameters_ = playParams;
}

void AudioStream::ConfigurePlayParametersWithoutLock(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    MEDIA_LOGI("AudioStream::ConfigurePlayParametersWithoutLock");
    audioRendererInfo_ = audioRendererInfo;
    playParameters_ = playParams;
}

int32_t AudioStream::PreparePlayInner(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    MEDIA_LOGI("AudioStream::PreparePlayInner start");
    if (audioRenderer_ != nullptr) {
        MEDIA_LOGI("AudioStream::PreparePlayInner, audiorenderer exits");
        DealPlayParamsBeforePlay(playParams);
        return MSERR_OK;
    }
    GetAvailableAudioRenderer(audioRendererInfo, playParams);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "audioRenderer_ is nullptr");
    DealPlayParamsBeforePlay(playParams);
    return MSERR_OK;
}

void AudioStream::DealPlayParamsBeforePlay(const PlayParams &playParams)
{
    MediaTrace trace("AudioStream::DealPlayParamsBeforePlay");
    audioRenderer_->SetOffloadAllowed(false);
    audioRenderer_->SetLoopTimes(playParams.loop);
    loop_ = playParams.loop;
    audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(playParams.rate));
    audioRenderer_->SetVolume(playParams.leftVolume);
    priority_ = playParams.priority;
    audioRenderer_->SetParallelPlayFlag(true);
    audioRenderer_->SetAudioHapticsSyncId(playParams.audioHapticsSyncId);
}

AudioStandard::AudioRendererRate AudioStream::CheckAndAlignRendererRate(const int32_t rate)
{
    AudioStandard::AudioRendererRate renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
    switch (rate) {
        case AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL:
            renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
            break;
        case AudioStandard::AudioRendererRate::RENDER_RATE_DOUBLE:
            renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_DOUBLE;
            break;
        case AudioStandard::AudioRendererRate::RENDER_RATE_HALF:
            renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_HALF;
            break;
        default:
            renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
            break;
    }
    return renderRate;
}

void AudioStream::GetAvailableAudioRenderer(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    MEDIA_LOGI("AudioStream::GetAvailableAudioRenderer start");
    MediaTrace trace("AudioStream::GetAvailableAudioRenderer");
    bool result = true;
    if (audioRenderer_ == nullptr) {
        audioRenderer_ = CreateAudioRenderer(audioRendererInfo, playParams);
        if (audioRenderer_ == nullptr) {
            MEDIA_LOGE("CreateAudioRenderer failed, release old auidoRenderer");
            audioRenderer_ = CreateAudioRenderer(audioRendererInfo, playParams);
        }
        CHECK_AND_RETURN_LOG(audioRenderer_ != nullptr, "audioRenderer_ is nullptr");
        PrepareAudioRenderer(audioRenderer_);
    }
}

void AudioStream::PrepareAudioRenderer(std::shared_ptr<AudioStandard::AudioRenderer> &audioRenderer)
{
    MediaTrace trace("AudioStream::PrepareAudioRenderer");
    size_t targetSize = 0;
    int32_t ret = audioRenderer->GetBufferSize(targetSize);
    audioRenderer->SetRenderMode(AudioStandard::AudioRenderMode::RENDER_MODE_STATIC);  // static buffer mode
    if (ret == 0 && targetSize != 0 && !audioRenderer->IsFastRenderer()) {
        size_t bufferDuration = 20;  // 20 -> 20ms
        audioRenderer->SetBufferDuration(bufferDuration);
        MEDIA_LOGI("Buffer size is %{public}zu, duration is %{public}zu", targetSize, bufferDuration);
    }
    int32_t retFirstCallback = audioRenderer->SetRendererFirstFrameWritingCallback(shared_from_this());
    int32_t retRenderCallback = audioRenderer->SetRendererCallback(shared_from_this());
}

bool AudioStream::IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    AudioStandard::AudioStreamType streamType = AudioStandard::AudioSystemManager::GetStreamType(
        audioRendererInfo.contentType, audioRendererInfo.streamUsage);
    if (streamType == AudioStandard::AudioStreamType::STREAM_MUSIC ||
        streamType == AudioStandard::AudioStreamType::STREAM_MOVIE ||
        streamType == AudioStandard::AudioStreamType::STREAM_SPEECH) {
            return true;
        }
    return false;
}

void AudioStream::DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
    const AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    int32_t sampleRate;
    int32_t sampleFormat;
    int32_t channelCount;
    // Set to PCM encoding
    rendererOptions.streamInfo.encoding = AudioStandard::AudioEncodingType::ENCODING_PCM;
    // Get sample rate from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_SAMPLE_RATE, sampleRate);
    rendererOptions.streamInfo.samplingRate = static_cast<AudioStandard::AudioSamplingRate>(sampleRate);
    // Get sample format from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, sampleFormat);
    // Align audiorender capability
    sampleFormat_ = static_cast<AudioStandard::AudioSampleFormat>(sampleFormat);
    rendererOptions.streamInfo.format = sampleFormat_;
    // Get channel count from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, channelCount);
    audioChannel_ = static_cast<AudioStandard::AudioChannel>(channelCount);
    rendererOptions.streamInfo.channels = audioChannel_;
    // contentType streamUsage rendererFlags come from user.
    if (IsAudioRendererCanMix(audioRendererInfo)) {
        rendererOptions.strategy.concurrencyMode = AudioStandard::AudioConcurrencyMode::MIX_WITH_OTHERS;
    }
    rendererOptions.rendererInfo.contentType = audioRendererInfo.contentType;
    rendererOptions.rendererInfo.streamUsage = audioRendererInfo.streamUsage;
    rendererOptions.privacyType = AudioStandard::PRIVACY_TYPE_PUBLIC;
    rendererFlags_ = audioRendererInfo.rendererFlags;
    rendererOptions.rendererInfo.rendererFlags = rendererFlags_;
    rendererOptions.rendererInfo.playerType = AudioStandard::PlayerType::PLAYER_TYPE_SOUND_POOL;
    rendererOptions.rendererInfo.expectedPlaybackDurationBytes = static_cast<uint64_t>(pcmBufferSize_);
}

std::shared_ptr<AudioStandard::AudioRenderer> AudioStream::CreateAudioRenderer(
    const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams)
{
    MEDIA_LOGI("AudioStream::CreateAudioRenderer start");
    MediaTrace trace("AudioStream::CreateAudioRenderer");
    AudioStandard::AudioRendererOptions rendererOptions = {};
    DealAudioRendererParams(rendererOptions, audioRendererInfo);

    SoundPoolXCollie soundPoolXCollie("AudioRenderer::Create time out",
        [](void *) {
            MEDIA_LOGI("AudioRenderer::Create time out");
        });
    CHECK_AND_RETURN_RET_LOG(pcmBuffer_ != nullptr && pcmBufferSize_ > 0, nullptr,
        "pcmBuffer_ or pcmBufferSize_ is invalid");
    std::shared_ptr<AudioStandard::AudioSharedMemory> sharedMemory =
        AudioStandard::AudioSharedMemory::CreateFromLocal(pcmBufferSize_, "SoundPool");
    std::shared_ptr<AudioStandard::AudioRenderer> audioRenderer = AudioStandard::AudioRenderer::Create(rendererOptions,
        sharedMemory, shared_from_this());
    int32_t ret = memcpy_s(sharedMemory->GetBase(), pcmBufferSize_, pcmBuffer_->buffer, pcmBufferSize_);
    MEDIA_LOGI("ret is %{public}d, pcmBufferSize_ is %{public}zu", ret, pcmBufferSize_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "Failed to copy pcm buffer from pcmBuffer to shared memory");
    soundPoolXCollie.CancelXCollieTimer();

    if (audioRenderer == nullptr) {
        MEDIA_LOGE("create audiorenderer failed, try again.");
        if (rendererFlags_ == AudioStandard::AUDIO_FLAG_VKB_FAST
            || rendererFlags_ == AudioStandard::AUDIO_FLAG_VKB_NORMAL) {
            rendererFlags_ = AudioStandard::AUDIO_FLAG_VKB_NORMAL;
        } else {
            rendererFlags_ = NORMAL_PLAY_RENDERER_FLAGS;
        }
        rendererOptions.rendererInfo.rendererFlags = rendererFlags_;
        SoundPoolXCollie soundPoolXCollieNormal("AudioRenderer::Create normal time out",
            [](void *) {
                MEDIA_LOGI("AudioRenderer::Create normal time out");
            });
            std::shared_ptr<AudioStandard::AudioSharedMemory> sharedMemory =
        AudioStandard::AudioSharedMemory::CreateFromLocal(pcmBufferSize_, "SoundPool");
        audioRenderer = AudioStandard::AudioRenderer::Create(rendererOptions, sharedMemory, shared_from_this());
        ret = memcpy_s(sharedMemory->GetBase(), pcmBufferSize_, pcmBuffer_->buffer, pcmBufferSize_);
        MEDIA_LOGI("ret is %{public}d, pcmBufferSize_ is %{public}zu", ret, pcmBufferSize_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "Failed to copy pcm buffer from pcmBuffer to shared memory");
        soundPoolXCollieNormal.CancelXCollieTimer();
    }

    CHECK_AND_RETURN_RET_LOG(audioRenderer != nullptr, nullptr, "Invalid audioRenderer.");
    return audioRenderer;
}

int32_t AudioStream::DoPlay()
{
    MediaTrace trace("AudioStream::DoPlay");
    MEDIA_LOGI("AudioStream::DoPlay start");
    std::lock_guard lock(streamLock_);
    if (streamState_.load() != StreamState::PREPARED) {
        MEDIA_LOGI("AudioStream::DoPlay end, invalid stream(%{public}d), streamState is %{public}d", streamID_,
            streamState_.load());
        return MSERR_INVALID_VAL;
    }
    if (audioRenderer_ == nullptr) {
        MEDIA_LOGI("AudioStream::DoPlay, audioRenderer_ is nullptr, try again");
        PreparePlayInner(audioRendererInfo_, playParameters_);
        CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL,
            "AudioStream::DoPlay, audioRenderer_ is nullptr");
    }
    
    size_t bufferSize = 0;
    audioRenderer_->GetBufferSize(bufferSize);
    MEDIA_LOGI("AudioStream::DoPlay, streamID_ is %{public}d, bufferSize is %{public}zu, "
        "pcmBufferFrameIndex_ is %{public}zu, pcmBufferSize_ is %{public}zu", streamID_, bufferSize,
        pcmBufferFrameIndex_, pcmBufferSize_);
    SoundPoolXCollie soundPoolXCollie("AudioStream audioRenderer::Start time out",
        [](void *) {
            MEDIA_LOGI("AudioStream::DoPlay, audioRenderer::Start time out");
        });
    streamState_.store(StreamState::PLAYING);
    if (!audioRenderer_->Start()) {
        MEDIA_LOGI("AudioStream::DoPlay, audioRenderer_->Start()");
        soundPoolXCollie.CancelXCollieTimer();
        streamState_.store(StreamState::RELEASED);
        return HandleRendererNotStart();
    }
    soundPoolXCollie.CancelXCollieTimer();
    MEDIA_LOGI("AudioStream::DoPlay end, streamID is %{public}d", streamID_);
    return MSERR_OK;
}

int32_t AudioStream::HandleRendererNotStart()
{
    OHOS::AudioStandard::RendererState state = audioRenderer_->GetStatus();
    if (state == OHOS::AudioStandard::RendererState::RENDERER_RUNNING) {
        MEDIA_LOGI("HandleRendererNotStart, audioRenderer us running, streamID is %{public}d", streamID_);
        if (callback_ != nullptr) {
            MEDIA_LOGI("call OnPlayFinished, streamID is %{public}d", streamID_);
            callback_->OnPlayFinished(streamID_);
        }
        return MSERR_OK;
    }
    MEDIA_LOGE("audioRenderer start failed, streamID is %{public}d", streamID_);
    if (callback_ != nullptr) {
        MEDIA_LOGI("call OnError, streamID is %{public}d", streamID_);
        callback_->OnError(MSERR_INVALID_VAL);
        SoundPoolUtils::ErrorInfo errorInfo{MSERR_INVALID_VAL, soundID_, streamID_, ERROR_TYPE::PLAY_ERROR, callback_};
        SoundPoolUtils::SendErrorInfo(errorInfo);
    }
    if (streamCallback_ != nullptr) {
        streamCallback_->OnError(MSERR_INVALID_VAL);
    }
    return MSERR_INVALID_VAL;
}

int32_t AudioStream::Stop()
{
    MediaTrace trace("AudioStream::Stop");
    std::lock_guard lock(streamLock_);
    MEDIA_LOGI("AudioStream::Stop, streamID is %{public}d", streamID_);
    if (audioRenderer_ != nullptr && streamState_.load() == StreamState::PLAYING) {
        SoundPoolXCollie soundPoolXCollie("AudioStream audioRenderer::Pause or Stop time out",
            [](void *) {
                MEDIA_LOGI("AudioStream::Stop time out");
            });
        audioRenderer_->Stop();
        soundPoolXCollie.CancelXCollieTimer();
        pcmBufferFrameIndex_ = 0;
        if (callback_ != nullptr) {
            MEDIA_LOGI("callback_ call OnPlayFinished.");
            callback_->OnPlayFinished(streamID_);
        }
        if (streamCallback_ != nullptr) {
            MEDIA_LOGI("streamCallback_ call OnPlayFinished.");
            streamCallback_->OnPlayFinished(streamID_);
        }
    }
    MEDIA_LOGI("AudioStream::Stop end, streamID is %{public}d", streamID_);
    return MSERR_OK;
}

void AudioStream::OnFirstFrameWriting(uint64_t latency)
{
    MEDIA_LOGI("AudioStream::OnFirstFrameWriting, streamID_ is %{public}d", streamID_);
    CHECK_AND_RETURN_LOG(frameWriteCallback_ != nullptr, "frameWriteCallback is null.");
    frameWriteCallback_->OnFirstAudioFrameWritingCallback(latency);
}

void AudioStream::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("AudioStream::OnInterrupt, streamID_ is %{public}d, eventType is %{public}d, forceType is %{public}d,"
        "hintType is %{public}d", streamID_, interruptEvent.eventType, interruptEvent.forceType,
        interruptEvent.hintType);
    if (interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE ||
        interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_STOP) {
        ThreadPool::Task pcmBufferInterruptTask = [this] { this->Stop(); };
        if (auto ptr = streamStopThreadPool_.lock()) {
            ptr->AddTask(pcmBufferInterruptTask);
        }
    }
}

void AudioStream::OnStateChange(const AudioStandard::RendererState state,
    const AudioStandard::StateChangeCmdType cmdType)
{
    MEDIA_LOGI("AudioStream::OnStateChange, state:%{public}d", state);
}

int32_t AudioStream::Release()
{
    MediaTrace trace("AudioStream::Release");
    MEDIA_LOGI("AudioStream::Release start, streamID is %{public}d", streamID_);
    std::lock_guard lock(streamLock_);

    // Use audioRenderer to release and don't lock, so it will not cause dead lock. if here locked, audioRenderer
    // will wait callback thread stop, and the callback thread can't get the lock, it will cause dead lock
    if (audioRenderer_ != nullptr) {
        SoundPoolXCollie soundPoolXCollie("Release audioRenderer::Stop time out",
            [](void *) {
                MEDIA_LOGI("Release audioRenderer::Stop time out");
            });
        audioRenderer_->Stop();
        soundPoolXCollie.CancelXCollieTimer();
        SoundPoolXCollie soundPoolXCollieRelease("AudioStream::Release time out",
        [](void *) {
            MEDIA_LOGI("Release audioRenderer::Release time out");
        });
        audioRenderer_->Release();
        soundPoolXCollieRelease.CancelXCollieTimer();
        audioRenderer_ = nullptr;
    }

    if (pcmBuffer_ != nullptr) pcmBuffer_.reset();
    if (callback_ != nullptr) callback_.reset();
    if (streamCallback_ != nullptr) streamCallback_.reset();
    if (frameWriteCallback_ != nullptr) frameWriteCallback_.reset();
    MEDIA_LOGI("AudioStream::Release end, streamID is %{public}d", streamID_);
    return MSERR_OK;
}

int32_t AudioStream::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t AudioStream::SetStreamCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    streamCallback_ = callback;
    return MSERR_OK;
}

int32_t AudioStream::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}

void AudioStream::SetSourceDuration(int64_t durationMs)
{
    sourceDurationMs_ = durationMs;
}

int32_t AudioStream::GetSoundID()
{
    return soundID_;
}

int32_t AudioStream::GetStreamID()
{
    return streamID_;
}

int32_t AudioStream::SetVolume(float leftVolume, float rightVolume)
{
    std::lock_guard lock(streamLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "SetVolume Invalid audioRenderer_");
    // audio cannot support left & right volume, all use left volume.
    (void) rightVolume;
    int32_t ret = audioRenderer_->SetVolume(leftVolume);
    MEDIA_LOGI("AudioStream::SetVolume, ret is %{public}d", ret);
    return ret;
}

int32_t AudioStream::SetRate(const AudioStandard::AudioRendererRate &renderRate)
{
    std::lock_guard lock(streamLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "SetRate Invalid audioRenderer_");
    int32_t ret = audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(renderRate));
    MEDIA_LOGI("AudioStream::SetRate, ret is %{public}d", ret);
    return ret;
}

int32_t AudioStream::SetPriority(int32_t priority)
{
    MEDIA_LOGI("AudioStream::SetPriority start");
    std::lock_guard lock(streamLock_);
    priority_ = priority;
    return MSERR_OK;
}

int32_t AudioStream::SetPriorityWithoutLock(int32_t priority)
{
    priority_ = priority;
    return MSERR_OK;
}

int32_t AudioStream::SetLoop(int32_t loop)
{
    std::lock_guard lock(streamLock_);
    loop_ = loop;
    return MSERR_OK;
}

int32_t AudioStream::GetPriority()
{
    return priority_;
}

void AudioStream::SetStreamState(StreamState state)
{
    streamState_.store(state);
}

StreamState AudioStream::GetStreamState()
{
    return streamState_.load();
}

void AudioStream::OnStaticBufferEvent(AudioStandard::StaticBufferEventId eventId)
{
    switch (eventId) {
        case AudioStandard::StaticBufferEventId::BUFFER_END_EVENT:
            MEDIA_LOGI("BUFFER_END_EVENT");
            break;
        case AudioStandard::StaticBufferEventId::LOOP_END_EVENT:
            MEDIA_LOGI("LOOP_END_EVENT");
            Stop();
            break;
        default:
            break;
    }
}
} // namespace Media
} // namespace OHOS
