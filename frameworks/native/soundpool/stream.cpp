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

#include "stream.h"
#include "media_log.h"
#include "media_errors.h"
#include "securec.h"
#include "audio_renderer_manager.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "Stream"};
    static const int32_t NORMAL_PLAY_RENDERER_FLAGS = 0;
    static const int32_t ERROE_GLOBAL_ID = -1;
}

namespace OHOS {
namespace Media {
Stream::Stream(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID,
    std::shared_ptr<ThreadPool> streamStopThreadPool) : trackFormat_(trackFormat),
    soundID_(soundID), streamID_(streamID), streamStopThreadPool_(streamStopThreadPool),
    cacheDataFrameIndex_(0), havePlayedCount_(0)
{
    MEDIA_LOGI("Construction Stream soundID:%{public}d, streamID:%{public}d", soundID, streamID);
    int32_t sampleFormat;
    bool res = trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, sampleFormat);
    CHECK_AND_RETURN_LOG(res == true, "Stream::Stream trackFormat_.GetIntValue error, res:%{public}d", res);
    sampleFormat_ = static_cast<AudioStandard::AudioSampleFormat>(sampleFormat);
}

Stream::~Stream()
{
    MEDIA_LOGI("Stream::~Stream soundID:%{public}d, streamID:%{public}d", soundID_, streamID_);
}

void Stream::SetSoundData(const std::shared_ptr<AudioBufferEntry> &cacheData, const size_t &cacheDataTotalSize)
{
    fullCacheData_ = cacheData;
    cacheDataTotalSize_ = cacheDataTotalSize;
}

void Stream::SetPlayParamAndRendererInfo(const PlayParams &playParameters,
    const AudioStandard::AudioRendererInfo &audioRenderInfo)
{
    playParameters_ = playParameters;
    priority_ = playParameters.priority;
    audioRendererInfo_ = audioRenderInfo;
}

void Stream::SetManager(std::weak_ptr<ParallelStreamManager> parallelStreamManager)
{
    manager_ = parallelStreamManager;
}

int32_t Stream::GetGlobalId(int32_t soundID)
{
    if (auto sharedManager = manager_.lock()) {
        return sharedManager->GetGlobalId(soundID);
    } else {
        return ERROE_GLOBAL_ID;
    }
}

void Stream::DelGlobalId(int32_t globalId)
{
    if (auto sharedManager = manager_.lock()) {
        sharedManager->DelGlobalId(globalId);
    }
}

void Stream::SetGlobalId(int32_t soundID, int32_t globalId)
{
    if (auto sharedManager = manager_.lock()) {
        sharedManager->SetGlobalId(soundID, globalId);
    }
}

void Stream::PreparePlay()
{
    MediaTrace trace("Stream::PreparePlay");
    bool result = true;
    while (result) {
        int32_t globalId = GetGlobalId(soundID_);
        if (globalId > 0) {
            audioRenderer_ = AudioRendererManager::GetInstance().GetAudioRendererInstance(globalId);
            if (audioRenderer_ != nullptr) {
                MEDIA_LOGI("Stream::PreparePlay useOld audiorenderer globalId:%{public}d, soundID:%{public}d",
                    globalId, soundID_);
                break;
            } else {
                DelGlobalId(globalId);
            }
        } else {
            result = false;
        }
    }
    if (audioRenderer_ == nullptr) {
        MEDIA_LOGI("Stream::PreparePlay CreateAudioRenderer New start");
        audioRenderer_ = CreateAudioRenderer(audioRendererInfo_, playParameters_);
        if (audioRenderer_ == nullptr) {
            AudioRendererManager::GetInstance().RemoveOldAudioRenderer();
            MEDIA_LOGE("Stream::PreparePlay CreateAudioRenderer fail, release old audioRenderer");
            audioRenderer_ = CreateAudioRenderer(audioRendererInfo_, playParameters_);
        }
        MEDIA_LOGI("Stream::PreparePlay CreateAudioRenderer New end");
    }
    CHECK_AND_RETURN_LOG(audioRenderer_ != nullptr, "Stream::PreparePlay create or get audioRenderer fail");
    PrepareAudioRenderer(audioRenderer_);
    DealPlayParamsBeforePlay(playParameters_);
}

bool Stream::IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo)
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

void Stream::DealAudioRendererParams(AudioStandard::AudioRendererOptions &rendererOptions,
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

std::unique_ptr<AudioStandard::AudioRenderer> Stream::CreateAudioRenderer(
    const AudioStandard::AudioRendererInfo &audioRendererInfo, const PlayParams &playParams)
{
    MediaTrace trace("Stream::CreateAudioRenderer");
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

void Stream::PrepareAudioRenderer(std::unique_ptr<AudioStandard::AudioRenderer> &audioRenderer)
{
    MediaTrace trace("Stream::PrepareAudioRenderer");
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
    MEDIA_LOGI("Stream::PrepareAudioRenderer retCallback:%{public}d, retFirstCallback:%{public}d,"
        " retRenderCallback:%{public}d", retCallback, retFirstCallback, retRenderCallback);
}

AudioStandard::AudioRendererRate Stream::CheckAndAlignRendererRate(const int32_t rate)
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

void Stream::DealPlayParamsBeforePlay(const PlayParams &playParams)
{
    MediaTrace trace("Stream::DealPlayParamsBeforePlay");
    audioRenderer_->SetOffloadAllowed(false);
    loop_ = playParams.loop;
    audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(playParams.rate));
    audioRenderer_->SetVolume(playParams.leftVolume);
    priority_ = playParams.priority;
    audioRenderer_->SetParallelPlayFlag(playParams.parallelPlayFlag);
    audioRenderer_->SetAudioHapticsSyncId(playParams.audioHapticsSyncId);
}

int32_t Stream::DoPlay()
{
    MediaTrace trace("Stream::DoPlay");
    std::lock_guard lock(streamLock_);
    PreparePlay();
    if (fullCacheData_ == nullptr || audioRenderer_ == nullptr) {
        MEDIA_LOGE("Stream::DoPlay failed, cacheData or audioRender nullptr, streamID:%{public}d", streamID_);
        if (callback_ != nullptr) {
            callback_->OnError(MSERR_INVALID_VAL);
            SoundPoolUtils::ErrorInfo errorInfo{MSERR_INVALID_VAL, soundID_,
                streamID_, ERROR_TYPE::PLAY_ERROR, callback_};
            SoundPoolUtils::SendErrorInfo(errorInfo);
        }
        if (streamCallback_ != nullptr) {
            streamCallback_->OnError(MSERR_INVALID_VAL);
        }
        return MSERR_INVALID_VAL;
    }
    size_t bufferSize;
    audioRenderer_->GetBufferSize(bufferSize);
    MEDIA_LOGI("Stream::DoPlay, streamID_:%{public}d, bufferSize:%{public}zu, cacheDataFrameIndex_:%{public}zu,"
        " cacheDataTotalSize_:%{public}zu", streamID_, bufferSize, cacheDataFrameIndex_, cacheDataTotalSize_);
    cacheDataFrameIndex_ = 0;
    havePlayedCount_ = 0;
    isRunning_.store(true);
    SoundPoolXCollie soundPoolXCollie("Stream audioRenderer::Start time out",
        [](void *) {
            MEDIA_LOGI("Stream audioRenderer::Start time out");
        });
    if (!audioRenderer_->Start()) {
        soundPoolXCollie.CancelXCollieTimer();
        MEDIA_LOGE("Stream::DoPlay audioRenderer start failed, streamID:%{public}d", streamID_);
        isRunning_.store(false);
        if (callback_ != nullptr) {
            MEDIA_LOGE("Stream::DoPlay failed, call callback, streamID:%{public}d", streamID_);
            callback_->OnError(MSERR_INVALID_VAL);
            SoundPoolUtils::ErrorInfo errorInfo{MSERR_INVALID_VAL, soundID_,
                streamID_, ERROR_TYPE::PLAY_ERROR, callback_};
            SoundPoolUtils::SendErrorInfo(errorInfo);
        }
        if (streamCallback_ != nullptr) {
            streamCallback_->OnError(MSERR_INVALID_VAL);
        }
        return MSERR_INVALID_VAL;
    }
    soundPoolXCollie.CancelXCollieTimer();
    MEDIA_LOGI("Stream::DoPlay success, streamID:%{public}d", streamID_);
    return MSERR_OK;
}

int32_t Stream::Stop()
{
    MediaTrace trace("Stream::Stop");
    std::lock_guard lock(streamLock_);
    MEDIA_LOGI("Stream::Stop start streamID:%{public}d", streamID_);
    if (audioRenderer_ != nullptr && isRunning_.load()) {
        isRunning_.store(false);
        SoundPoolXCollie soundPoolXCollie("Stream audioRenderer::Pause or Stop time out",
            [](void *) {
                MEDIA_LOGI("Stream audioRenderer::Pause or Stop time out");
            });
        if (audioRenderer_->IsFastRenderer()) {
            MEDIA_LOGI("Stream audioRenderer fast renderer pause.");
            audioRenderer_->Pause();
            audioRenderer_->Flush();
        } else {
            MEDIA_LOGI("Stream audioRenderer normal stop.");
            audioRenderer_->Stop();
        }
        soundPoolXCollie.CancelXCollieTimer();
        if (callback_ != nullptr) {
            MEDIA_LOGI("Stream callback_ OnPlayFinished.");
            callback_->OnPlayFinished(streamID_);
        }
        int32_t globalId = AudioRendererManager::GetInstance().GetGlobalId();
        AudioRendererManager::GetInstance().SetAudioRendererInstance(globalId, std::move(audioRenderer_));
        SetGlobalId(soundID_, globalId);
        audioRenderer_ = nullptr;
        fullCacheData_ = nullptr;
        if (streamCallback_ != nullptr) {
            MEDIA_LOGI("Stream streamCallback_ OnPlayFinished.");
            streamCallback_->OnPlayFinished(streamID_);
        }
    }
    MEDIA_LOGI("Stream::Stop end streamID:%{public}d", streamID_);
    return MSERR_OK;
}

void Stream::OnWriteData(size_t length)
{
    CHECK_AND_RETURN_LOG(audioRenderer_ != nullptr, "audioRenderer is nullptr");
    CHECK_AND_RETURN_LOG(isRunning_.load() == true, "audioRenderer is stop");
    CHECK_AND_RETURN_LOG(startStopFlag_.load() == false,
        "Stream::OnWriteData has start stop, streamID:%{public}d", streamID_);
    if (cacheDataFrameIndex_ >= static_cast<size_t>(fullCacheData_->size)) {
        streamLock_.lock();
        if (loop_ >= 0 && havePlayedCount_ >= loop_) {
            MEDIA_LOGI("Stream stream write finish, cacheDataFrameIndex_:%{public}zu,"
                " havePlayedCount_:%{public}d, loop:%{public}d, streamID_:%{public}d, length: %{public}zu",
                cacheDataFrameIndex_, havePlayedCount_, loop_, streamID_, length);
            streamLock_.unlock();
            AddStopTask();
            return;
        }
        cacheDataFrameIndex_ = 0;
        havePlayedCount_++;
        streamLock_.unlock();
    }
    DealWriteData(length);
}

void Stream::AddStopTask()
{
    if (auto ptr = streamStopThreadPool_.lock()) {
        ThreadPool::Task streamStopTask = [weakThis = std::weak_ptr<Stream>(shared_from_this())] {
            if (auto thisPtr = weakThis.lock()) {
                thisPtr->Stop();
            } else {
                MEDIA_LOGI("Stream object has been destroyed, skipping Stop.");
            }
        };
        ptr->AddTask(streamStopTask);
        startStopFlag_.store(true);
    } else {
        MEDIA_LOGI("streamStopThreadPool_ is not available.");
        startStopFlag_.store(true);
    }
}

void Stream::DealWriteData(size_t length)
{
    std::lock_guard lock(streamLock_);
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
    } else if (fullCacheData_ != nullptr) {
        MEDIA_LOGE("Stream OnWriteData, cacheDataFrameIndex_: %{public}zu, length: %{public}zu,"
            " bufDesc.buffer:%{public}d, fullCacheData_:1, fullCacheData_->buffer:%{public}d,"
            " streamID_:%{public}d",
            cacheDataFrameIndex_, length, bufDesc.buffer != nullptr,
            fullCacheData_->buffer != nullptr, streamID_);
    } else {
        MEDIA_LOGE("Stream OnWriteData, cacheDataFrameIndex_: %{public}zu, length: %{public}zu,"
            " bufDesc.buffer:%{public}d, fullCacheData_:0, streamID_:%{public}d",
            cacheDataFrameIndex_, length, bufDesc.buffer != nullptr, streamID_);
    }
}

void Stream::OnFirstFrameWriting(uint64_t latency)
{
    MEDIA_LOGI("Stream::OnFirstFrameWriting, streamID_:%{public}d", streamID_);
    CHECK_AND_RETURN_LOG(frameWriteCallback_ != nullptr, "frameWriteCallback is null.");
    frameWriteCallback_->OnFirstAudioFrameWritingCallback(latency);
}

void Stream::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("Stream::OnInterrupt, streamID_:%{public}d, eventType:%{public}d, forceType:%{public}d,"
        "hintType:%{public}d", streamID_, interruptEvent.eventType, interruptEvent.forceType,
        interruptEvent.hintType);
    if (interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE ||
        interruptEvent.hintType == AudioStandard::InterruptHint::INTERRUPT_HINT_STOP) {
        MEDIA_LOGI("Stream::OnInterrupt, interrupt Stream, streamID_:%{public}d", streamID_);
        AddStopTask();
    }
}

void Stream::OnStateChange(const AudioStandard::RendererState state,
    const AudioStandard::StateChangeCmdType cmdType)
{
    MEDIA_LOGI("Stream::OnStateChange, state:%{public}d", state);
}

int32_t Stream::SetVolume(const float leftVolume, const float rightVolume)
{
    std::lock_guard lock(streamLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "SetVolume Invalid audioRenderer");
    (void) rightVolume;
    int32_t ret = audioRenderer_->SetVolume(leftVolume);
    MEDIA_LOGI("Stream::SetVolume, ret:%{public}d", ret);
    return ret;
}

int32_t Stream::SetRate(const AudioStandard::AudioRendererRate renderRate)
{
    std::lock_guard lock(streamLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "SetRate Invalid audioRenderer");
    int32_t ret = audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(renderRate));
    MEDIA_LOGI("Stream::SetRate, ret:%{public}d", ret);
    return ret;
}

int32_t Stream::SetPriority(const int32_t priority)
{
    std::lock_guard lock(streamLock_);
    priority_ = priority;
    return MSERR_OK;
}

int32_t Stream::SetLoop(const int32_t loop)
{
    std::lock_guard lock(streamLock_);
    loop_ = loop;
    havePlayedCount_ = 0;
    return MSERR_OK;
}

int32_t Stream::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int32_t Stream::SetStreamCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    streamCallback_ = callback;
    return MSERR_OK;
}

int32_t Stream::SetFrameWriteCallback(const std::shared_ptr<ISoundPoolFrameWriteCallback> &callback)
{
    frameWriteCallback_ = callback;
    return MSERR_OK;
}

int32_t Stream::GetSoundID()
{
    return soundID_;
}

int32_t Stream::GetStreamID()
{
    return streamID_;
}

int32_t Stream::GetPriority()
{
    return priority_;
}

} // namespace Media
} // namespace OHOS
