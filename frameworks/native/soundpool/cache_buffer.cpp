
/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "cache_buffer.h"
#include "media_log.h"
#include "media_errors.h"
#include "securec.h"
#include "audio_renderer_manager.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "CacheBuffer"};
    static const int32_t ERROE_GLOBAL_ID = -1;
}

namespace OHOS {
namespace Media {
CacheBuffer::CacheBuffer(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID,
    std::shared_ptr<ThreadPool> cacheBufferStopThreadPool) : trackFormat_(trackFormat),
    soundID_(soundID), streamID_(streamID), cacheBufferStopThreadPool_(cacheBufferStopThreadPool),
    cacheDataFrameIndex_(0), havePlayedCount_(0)
{
    MEDIA_LOGI("Construction CacheBuffer soundID:%{public}d, streamID:%{public}d", soundID, streamID);
}

CacheBuffer::~CacheBuffer()
{
    MEDIA_LOGI("Destruction CacheBuffer soundID:%{public}d, streamID:%{public}d", soundID_, streamID_);
    Release();
}

void CacheBuffer::SetSoundData(const std::shared_ptr<AudioBufferEntry> &cacheData, const size_t &cacheDataTotalSize)
{
    fullCacheData_ = cacheData;
    cacheDataTotalSize_ = cacheDataTotalSize;
}

void CacheBuffer::SetManager(std::weak_ptr<StreamIDManager> streamIDManager)
{
    manager_ = streamIDManager;
}

int32_t CacheBuffer::GetGlobalId(int32_t soundID)
{
    if (auto sharedManager = manager_.lock()) {
        return sharedManager->GetGlobalId(soundID);
    } else {
        return ERROE_GLOBAL_ID;
    }
}

void CacheBuffer::DelGlobalId(int32_t globalId)
{
    if (auto sharedManager = manager_.lock()) {
        sharedManager->DelGlobalId(globalId);
    }
}

void CacheBuffer::SetGlobalId(int32_t soundID, int32_t globalId)
{
    if (auto sharedManager = manager_.lock()) {
        sharedManager->SetGlobalId(soundID, globalId);
    }
}

bool CacheBuffer::IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo)
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

void CacheBuffer::DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
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
    rendererOptions.streamInfo.channels = static_cast<AudioStandard::AudioChannel>(channelCount);
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
    rendererOptions.rendererInfo.expectedPlaybackDurationBytes = static_cast<uint64_t>(cacheDataTotalSize_);
}

std::unique_ptr<AudioStandard::AudioRenderer> CacheBuffer::CreateAudioRenderer(
    const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams)
{
    MediaTrace trace("CacheBuffer::CreateAudioRenderer");
    AudioStandard::AudioRendererOptions rendererOptions = {};
    DealAudioRendererParams(rendererOptions, audioRendererInfo);
    std::string cacheDir = "/data/storage/el2/base/temp";
    if (playParams.cacheDir != "") {
        cacheDir = playParams.cacheDir;
    }

    SoundPoolXCollie soundPoolXCollie("AudioRenderer::Create time out",
        [](void *) {
            MEDIA_LOGI("AudioRenderer::Create time out");
        });
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer =
        AudioStandard::AudioRenderer::Create(cacheDir, rendererOptions);
    soundPoolXCollie.CancelXCollieTimer();

    if (audioRenderer == nullptr) {
        MEDIA_LOGE("create audiorenderer failed, try again.");
        rendererFlags_ = NORMAL_PLAY_RENDERER_FLAGS;
        rendererOptions.rendererInfo.rendererFlags = rendererFlags_;
        SoundPoolXCollie soundPoolXCollieNormal("AudioRenderer::Create normal time out",
            [](void *) {
                MEDIA_LOGI("AudioRenderer::Create normal time out");
            });
        audioRenderer = AudioStandard::AudioRenderer::Create(cacheDir, rendererOptions);
        soundPoolXCollieNormal.CancelXCollieTimer();
    }

    CHECK_AND_RETURN_RET_LOG(audioRenderer != nullptr, nullptr, "Invalid audioRenderer.");
    return audioRenderer;
}

void CacheBuffer::PrepareAudioRenderer(std::unique_ptr<AudioStandard::AudioRenderer> &audioRenderer)
{
    size_t targetSize = 0;
    int32_t ret = audioRenderer->GetBufferSize(targetSize);
    audioRenderer->SetRenderMode(AudioStandard::AudioRenderMode::RENDER_MODE_CALLBACK);
    if (ret == 0 && targetSize != 0 && !audioRenderer->IsFastRenderer()) {
        size_t bufferDuration = 20; // 20 -> 20ms
        audioRenderer->SetBufferDuration(bufferDuration);
        MEDIA_LOGI("Using buffer size:%{public}zu, duration %{public}zu", targetSize, bufferDuration);
    }
    int32_t retCallback = audioRenderer->SetRendererWriteCallback(shared_from_this());
    int32_t retFirstCallback = audioRenderer->SetRendererFirstFrameWritingCallback(shared_from_this());
    int32_t retRenderCallback = audioRenderer->SetRendererCallback(shared_from_this());
    MEDIA_LOGI("CacheBuffer::CreateAudioRenderer retCallback:%{public}d, retFirstCallback:%{public}d,"
        " retRenderCallback:%{public}d", retCallback, retFirstCallback, retRenderCallback);
}

void CacheBuffer::GetAvailableAudioRenderer(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    MediaTrace trace("CacheBuffer::GetAvailableAudioRenderer");
    MEDIA_LOGI("CacheBuffer::GetAvailableAudioRenderer start");
    bool result = true;
    while (result) {
        int32_t globalId = GetGlobalId(soundID_);
        if (globalId > 0) {
            audioRenderer_ = AudioRendererManager::GetInstance().GetAudioRendererInstance(globalId);
            if (audioRenderer_ != nullptr) {
                MEDIA_LOGI("CacheBuffer::GetAvailableAudioRenderer useOld audiorenderer,"
                    "globalId:%{public}d, soundID:%{public}d", globalId, soundID_);
                break;
            } else {
                DelGlobalId(globalId);
            }
        } else {
            result = false;
        }
    }
    if (audioRenderer_ == nullptr) {
        MEDIA_LOGI("CacheBuffer::GetAvailableAudioRenderer CreateAudioRenderer New start");
        audioRenderer_ = CreateAudioRenderer(audioRendererInfo, playParams);
        if (audioRenderer_ == nullptr) {
            AudioRendererManager::GetInstance().RemoveOldAudioRenderer();
            MEDIA_LOGE("CacheBuffer::GetAvailableAudioRenderer CreateAudioRenderer fail, release old auidoRenderer");
            audioRenderer_ = CreateAudioRenderer(audioRendererInfo, playParams);
        }
        MEDIA_LOGI("CacheBuffer::GetAvailableAudioRenderer CreateAudioRenderer New end");
    }
    MEDIA_LOGI("CacheBuffer::GetAvailableAudioRenderer end");
}

int32_t CacheBuffer::PreparePlayInner(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    if (audioRenderer_ != nullptr) {
        MEDIA_LOGI("CacheBuffer::PreparePlayInner has audiorenderer available");
        DealPlayParamsBeforePlay(playParams);
        return MSERR_OK;
    }
    GetAvailableAudioRenderer(audioRendererInfo, playParams);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "Invalid GetAvailableAudioRenderer");
    PrepareAudioRenderer(audioRenderer_);
    DealPlayParamsBeforePlay(playParams);
    return MSERR_OK;
}

int32_t CacheBuffer::PreparePlay(const AudioStandard::AudioRendererInfo &audioRendererInfo,
    const PlayParams &playParams)
{
    std::lock_guard lock(cacheBufferLock_);
    playParameters_ = playParams;
    audioRendererInfo_ = audioRendererInfo;
    return PreparePlayInner(audioRendererInfo, playParams);
}

int32_t CacheBuffer::DoPlay(const int32_t streamID)
{
    MediaTrace trace("CacheBuffer::DoPlay");
    CHECK_AND_RETURN_RET_LOG(streamID == streamID_, MSERR_INVALID_VAL, "Invalid streamID, failed to DoPlay.");
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_RET_LOG(fullCacheData_ != nullptr, MSERR_INVALID_VAL, "fullCacheData_ is nullptr.");
    if (audioRenderer_ == nullptr) {
        MEDIA_LOGI("CacheBuffer::DoPlay audioRenderer_ is nullptr, try again");
        PreparePlayInner(audioRendererInfo_, playParameters_);
    }
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "Invalid audioRenderer.");
    size_t bufferSize;
    audioRenderer_->GetBufferSize(bufferSize);
    MEDIA_LOGI("CacheBuffer::DoPlay, streamID_:%{public}d, bufferSize:%{public}zu, cacheDataFrameIndex_:%{public}zu,"
        " cacheDataTotalSize_:%{public}zu", streamID_, bufferSize, cacheDataFrameIndex_, cacheDataTotalSize_);
    audioRenderer_->SetSourceDuration(sourceDurationMs_);
    cacheDataFrameIndex_ = 0;
    havePlayedCount_ = 0;
    isRunning_.store(true);
    SoundPoolXCollie soundPoolXCollie("audioRenderer::Start time out",
        [](void *) {
            MEDIA_LOGI("audioRenderer::Start time out");
        });
    if (!audioRenderer_->Start()) {
        soundPoolXCollie.CancelXCollieTimer();
        OHOS::AudioStandard::RendererState state = audioRenderer_->GetStatus();
        if (state == OHOS::AudioStandard::RendererState::RENDERER_RUNNING) {
            MEDIA_LOGI("CacheBuffer::DoPlay audioRenderer has started, streamID:%{public}d", streamID);
            isRunning_.store(true);
            if (callback_ != nullptr) {
                MEDIA_LOGI("CacheBuffer::DoPlay callback_ OnPlayFinished, streamID:%{public}d", streamID);
                callback_->OnPlayFinished(streamID_);
            }
            return MSERR_OK;
        } else {
            MEDIA_LOGE("CacheBuffer::DoPlay audioRenderer start failed, streamID:%{public}d", streamID);
            isRunning_.store(false);
            if (callback_ != nullptr) {
                MEDIA_LOGI("CacheBuffer::DoPlay failed, call callback, streamID:%{public}d", streamID);
                callback_->OnError(MSERR_INVALID_VAL);
            }
            if (cacheBufferCallback_ != nullptr) cacheBufferCallback_->OnError(MSERR_INVALID_VAL);
            return MSERR_INVALID_VAL;
        }
    } else {
        soundPoolXCollie.CancelXCollieTimer();
    }
    MEDIA_LOGI("CacheBuffer::DoPlay success, streamID:%{public}d", streamID);
    return MSERR_OK;
}

void CacheBuffer::DealPlayParamsBeforePlay(const PlayParams &playParams)
{
    audioRenderer_->SetOffloadAllowed(false);
    loop_ = playParams.loop;
    audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(playParams.rate));
    audioRenderer_->SetVolume(playParams.leftVolume);
    priority_ = playParams.priority;
    audioRenderer_->SetParallelPlayFlag(playParams.parallelPlayFlag);
}

AudioStandard::AudioRendererRate CacheBuffer::CheckAndAlignRendererRate(const int32_t rate)
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

void CacheBuffer::OnWriteData(size_t length)
{
    if (audioRenderer_ == nullptr) {
        MEDIA_LOGE("audioRenderer is nullptr.");
        return;
    }
    if (!isRunning_.load()) {
        MEDIA_LOGE("audioRenderer is stop.");
        return;
    }
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_LOG(fullCacheData_ != nullptr, "fullCacheData_ is nullptr");
    if (cacheDataFrameIndex_ >= static_cast<size_t>(fullCacheData_->size)) {
        if (loop_ >= 0 && havePlayedCount_ >= loop_) {
            MEDIA_LOGI("CacheBuffer stream write finish, cacheDataFrameIndex_:%{public}zu,"
                " havePlayedCount_:%{public}d, loop:%{public}d, streamID_:%{public}d, length: %{public}zu",
                cacheDataFrameIndex_, havePlayedCount_, loop_, streamID_, length);
            int32_t streamIDStop = streamID_;
            ThreadPool::Task cacheBufferStopTask = [this, streamIDStop] { this->Stop(streamIDStop); };
            if (auto ptr = cacheBufferStopThreadPool_.lock()) {
                ptr->AddTask(cacheBufferStopTask);
            }
            return;
        }
        cacheDataFrameIndex_ = 0;
        havePlayedCount_++;
    }
    DealWriteData(length);
}

void CacheBuffer::DealWriteData(size_t length)
{
    CHECK_AND_RETURN_LOG(audioRenderer_ != nullptr, "DealWriteData audioRenderer_ is nullptr");
    AudioStandard::BufferDesc bufDesc;
    audioRenderer_->GetBufferDesc(bufDesc);
    if (bufDesc.buffer != nullptr && fullCacheData_ != nullptr && fullCacheData_->buffer != nullptr) {
        if (static_cast<size_t>(fullCacheData_->size) - cacheDataFrameIndex_ >= length) {
            int32_t ret = memcpy_s(bufDesc.buffer, length,
                fullCacheData_->buffer + cacheDataFrameIndex_, length);
            CHECK_AND_RETURN_LOG(ret == MSERR_OK, "memcpy failed total length.");
            bufDesc.bufLength = length;
            bufDesc.dataLength = length;
            cacheDataFrameIndex_ += length;
        } else {
            size_t copyLength = static_cast<size_t>(fullCacheData_->size) - cacheDataFrameIndex_;
            int32_t ret = AudioStandard::AudioRenderer::MuteAudioBuffer(bufDesc.buffer, 0, length, sampleFormat_);
            CHECK_AND_RETURN_LOG(ret == AudioStandard::SUCCESS, "fill mute buffer failed.");
            ret = memcpy_s(bufDesc.buffer, length, fullCacheData_->buffer + cacheDataFrameIndex_,
                copyLength);
            CHECK_AND_RETURN_LOG(ret == MSERR_OK, "memcpy failed not enough length.");
            bufDesc.bufLength = length;
            bufDesc.dataLength = length;
            cacheDataFrameIndex_ += copyLength;
        }
        audioRenderer_->Enqueue(bufDesc);
    } else {
        MEDIA_LOGE("OnWriteData, cacheDataFrameIndex_: %{public}zu, length: %{public}zu,"
            " bufDesc.buffer:%{public}d, fullCacheData_:%{public}d, fullCacheData_->buffer:%{public}d,"
            " streamID_:%{public}d",
            cacheDataFrameIndex_, length, bufDesc.buffer != nullptr, fullCacheData_ != nullptr,
            fullCacheData_->buffer != nullptr, streamID_);
    }
}

void CacheBuffer::OnFirstFrameWriting(uint64_t latency)
{
    MEDIA_LOGI("CacheBuffer::OnFirstFrameWriting, streamID_:%{public}d", streamID_);
    CHECK_AND_RETURN_LOG(frameWriteCallback_ != nullptr, "frameWriteCallback is null.");
    frameWriteCallback_->OnFirstAudioFrameWritingCallback(latency);
}

void CacheBuffer::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("CacheBuffer::OnInterrupt, streamID_:%{public}d, eventType:%{public}d, forceType:%{public}d,"
        "hintType:%{public}d", streamID_, interruptEvent.eventType, interruptEvent.forceType,
        interruptEvent.hintType);
    if (interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE ||
        interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_STOP) {
        MEDIA_LOGI("CacheBuffer::OnInterrupt, interrupt cacheBuffer, streamID_:%{public}d", streamID_);
        int32_t streamIDInterrupt = streamID_;
        ThreadPool::Task cacheBufferInterruptTask = [this, streamIDInterrupt] { this->Stop(streamIDInterrupt); };
        if (auto ptr = cacheBufferStopThreadPool_.lock()) {
            ptr->AddTask(cacheBufferInterruptTask);
        }
    }
}

void CacheBuffer::OnStateChange(const AudioStandard::RendererState state,
    const AudioStandard::StateChangeCmdType cmdType)
{
    MEDIA_LOGI("CacheBuffer::OnStateChange, state:%{public}d", state);
}

int32_t CacheBuffer::Stop(const int32_t streamID)
{
    MediaTrace trace("CacheBuffer::Stop");
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_RET_LOG(streamID == streamID_, MSERR_INVALID_VAL, "Invalid streamID_.");
    MEDIA_LOGI("CacheBuffer::Stop streamID:%{public}d", streamID_);
    if (audioRenderer_ != nullptr && isRunning_.load()) {
        isRunning_.store(false);
        SoundPoolXCollie soundPoolXCollie("audioRenderer::Pause or Stop time out",
            [](void *) {
                MEDIA_LOGI("audioRenderer::Pause or Stop time out");
            });
        if (audioRenderer_->IsFastRenderer()) {
            MEDIA_LOGI("audioRenderer fast renderer pause.");
            audioRenderer_->Pause();
            audioRenderer_->Flush();
        } else {
            MEDIA_LOGI("audioRenderer normal stop.");
            audioRenderer_->Stop();
        }
        soundPoolXCollie.CancelXCollieTimer();
        cacheDataFrameIndex_ = 0;
        havePlayedCount_ = 0;
        if (callback_ != nullptr) {
            MEDIA_LOGI("cachebuffer callback_ OnPlayFinished.");
            callback_->OnPlayFinished(streamID_);
        }
        int32_t globalId = AudioRendererManager::GetInstance().GetGlobalId();
        AudioRendererManager::GetInstance().SetAudioRendererInstance(globalId, std::move(audioRenderer_));
        SetGlobalId(soundID_, globalId);
        if (cacheBufferCallback_ != nullptr) {
            MEDIA_LOGI("cachebuffer cacheBufferCallback_ OnPlayFinished.");
            cacheBufferCallback_->OnPlayFinished(streamID_);
        }
    }
    return MSERR_OK;
}

int32_t CacheBuffer::SetVolume(const int32_t streamID, const float leftVolume, const float rightVolume)
{
    std::lock_guard lock(cacheBufferLock_);
    int32_t ret = MSERR_OK;
    if (streamID == streamID_) {
        if (audioRenderer_ != nullptr) {
            // audio cannot support left & right volume, all use left volume.
            (void) rightVolume;
            ret = audioRenderer_->SetVolume(leftVolume);
        }
    }
    return ret;
}

int32_t CacheBuffer::SetRate(const int32_t streamID, const AudioStandard::AudioRendererRate renderRate)
{
    std::lock_guard lock(cacheBufferLock_);
    int32_t ret = MSERR_OK;
    if (streamID == streamID_) {
        if (audioRenderer_ != nullptr) {
            ret = audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(renderRate));
        }
    }
    return ret;
}

int32_t CacheBuffer::SetPriority(const int32_t streamID, const int32_t priority)
{
    std::lock_guard lock(cacheBufferLock_);
    if (streamID == streamID_) {
        priority_ = priority;
    }
    return MSERR_OK;
}

int32_t CacheBuffer::SetLoop(const int32_t streamID, const int32_t loop)
{
    std::lock_guard lock(cacheBufferLock_);
    if (streamID == streamID_) {
        loop_ = loop;
        havePlayedCount_ = 0;
    }
    return MSERR_OK;
}

int32_t CacheBuffer::SetParallelPlayFlag(const int32_t streamID, const bool parallelPlayFlag)
{
    std::lock_guard lock(cacheBufferLock_);
    if (streamID == streamID_) {
        MEDIA_LOGI("CacheBuffer parallelPlayFlag:%{public}d.", parallelPlayFlag);
        if (audioRenderer_ != nullptr) {
            audioRenderer_->SetParallelPlayFlag(parallelPlayFlag);
        }
    }
    return MSERR_OK;
}

int32_t CacheBuffer::Release()
{
    MediaTrace trace("CacheBuffer::Release");
    // Define a temporary variable.Let audioRenderer_ to audioRenderer can protect audioRenderer_ concurrently
    // modified.So will not cause null pointers.
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer;
    {
        std::lock_guard lock(cacheBufferLock_);
        audioRenderer = std::move(audioRenderer_);
        audioRenderer_ = nullptr;
        isRunning_.store(false);
    }

    MEDIA_LOGI("CacheBuffer::Release start, streamID:%{public}d", streamID_);
    // Use audioRenderer to release and don't lock, so it will not cause dead lock. if here locked, audioRenderer
    // will wait callback thread stop, and the callback thread can't get the lock, it will cause dead lock
    if (audioRenderer != nullptr) {
        SoundPoolXCollie soundPoolXCollie("Release audioRenderer::Stop time out",
            [](void *) {
                MEDIA_LOGI("Release audioRenderer::Stop time out");
            });
        audioRenderer->Stop();
        soundPoolXCollie.CancelXCollieTimer();
        SoundPoolXCollie soundPoolXCollieRelease("Release audioRenderer::Release time out",
        [](void *) {
            MEDIA_LOGI("Release audioRenderer::Release time out");
        });
        audioRenderer->Release();
        soundPoolXCollieRelease.CancelXCollieTimer();
        audioRenderer = nullptr;
    }

    std::lock_guard lock(cacheBufferLock_);
    if (!cacheData_.empty()) cacheData_.clear();
    if (fullCacheData_ != nullptr) fullCacheData_.reset();
    if (callback_ != nullptr) callback_.reset();
    if (cacheBufferCallback_ != nullptr) cacheBufferCallback_.reset();
    if (frameWriteCallback_ != nullptr) frameWriteCallback_.reset();
    MEDIA_LOGI("CacheBuffer::Release end, streamID:%{public}d", streamID_);
    return MSERR_OK;
}

int32_t CacheBuffer::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t CacheBuffer::SetCacheBufferCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    cacheBufferCallback_ = callback;
    return MSERR_OK;
}

int32_t CacheBuffer::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}

void CacheBuffer::SetSourceDuration(int64_t durationMs)
{
    sourceDurationMs_ = durationMs;
}

} // namespace Media
} // namespace OHOS
