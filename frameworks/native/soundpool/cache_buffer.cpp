
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

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "CacheBuffer"};
}

namespace OHOS {
namespace Media {
CacheBuffer::CacheBuffer(const Format &trackFormat,
    const std::deque<std::shared_ptr<AudioBufferEntry>> &cacheData,
    const size_t &cacheDataTotalSize, const int32_t &soundID, const int32_t &streamID) : trackFormat_(trackFormat),
    cacheData_(cacheData), cacheDataTotalSize_(cacheDataTotalSize), soundID_(soundID), streamID_(streamID),
    cacheDataFrameIndex_(0), havePlayedCount_(0)

{
    MEDIA_LOGI("Construction CacheBuffer");
}

CacheBuffer::~CacheBuffer()
{
    MEDIA_LOGI("Destruction CacheBuffer dec");
    Release();
}

std::unique_ptr<AudioStandard::AudioRenderer> CacheBuffer::CreateAudioRenderer(const int32_t streamID,
    const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams)
{
    CHECK_AND_RETURN_RET_LOG(streamID == streamID_, nullptr,
        "Invalid streamID, failed to create normal audioRenderer.");
    int32_t sampleRate;
    int32_t sampleFormat;
    int32_t channelCount;
    AudioStandard::AudioRendererOptions rendererOptions = {};
    // Set to PCM encoding
    rendererOptions.streamInfo.encoding = AudioStandard::AudioEncodingType::ENCODING_PCM;
    // Get sample rate from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_SAMPLE_RATE, sampleRate);
    rendererOptions.streamInfo.samplingRate = static_cast<AudioStandard::AudioSamplingRate>(sampleRate);
    // Get sample format from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, sampleFormat);
    // Align audiorender capability
    rendererOptions.streamInfo.format = static_cast<AudioStandard::AudioSampleFormat>(sampleFormat);
    // Get channel count from trackFormat and set it to audiorender.
    trackFormat_.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, channelCount);
    rendererOptions.streamInfo.channels = static_cast<AudioStandard::AudioChannel>(channelCount);
    // contentType streamUsage rendererFlags come from user.
    rendererOptions.rendererInfo.contentType = audioRendererInfo.contentType;
    rendererOptions.rendererInfo.streamUsage = audioRendererInfo.streamUsage;
    rendererOptions.privacyType = AudioStandard::PRIVACY_TYPE_PUBLIC;
    std::string cacheDir = "/data/storage/el2/base/temp";
    if (playParams.cacheDir != "") {
        cacheDir = playParams.cacheDir;
    }

    rendererFlags_ = audioRendererInfo.rendererFlags;
    rendererOptions.rendererInfo.rendererFlags = rendererFlags_;
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer =
        AudioStandard::AudioRenderer::Create(cacheDir, rendererOptions);

    if (audioRenderer == nullptr) {
        MEDIA_LOGE("create audiorenderer failed, try again.");
        rendererFlags_ = NORMAL_PLAY_RENDERER_FLAGS;
        rendererOptions.rendererInfo.rendererFlags = rendererFlags_;
        audioRenderer = AudioStandard::AudioRenderer::Create(cacheDir, rendererOptions);
    }

    CHECK_AND_RETURN_RET_LOG(audioRenderer != nullptr, nullptr, "Invalid audioRenderer.");
    size_t targetSize = 0;
    int32_t ret = audioRenderer->GetBufferSize(targetSize);
    audioRenderer->SetRenderMode(AudioStandard::AudioRenderMode::RENDER_MODE_CALLBACK);
    if (ret == 0 && targetSize != 0 && !audioRenderer->IsFastRenderer()) {
        size_t bufferDuration = 20; // 20 -> 20ms
        audioRenderer->SetBufferDuration(bufferDuration);
        MEDIA_LOGI("Using buffer size:%{public}zu, duration %{public}zu", targetSize, bufferDuration);
    }
    ret = audioRenderer->SetRendererWriteCallback(shared_from_this());
    if (ret != MSERR_OK) {
        MEDIA_LOGE("audio renderer write callback fail, ret %{public}d.", ret);
    }
    ret = audioRenderer->SetRendererFirstFrameWritingCallback(shared_from_this());
    if (ret != MSERR_OK) {
        MEDIA_LOGE("audio renderer first frame write callback fail, ret %{public}d.", ret);
    }
    return audioRenderer;
}

int32_t CacheBuffer::PreparePlay(const int32_t streamID, const AudioStandard::AudioRendererInfo audioRendererInfo,
    const PlayParams playParams)
{
    // create audioRenderer
    if (audioRenderer_ == nullptr) {
        audioRenderer_ = CreateAudioRenderer(streamID, audioRendererInfo, playParams);
        ReCombineCacheData();
    } else {
        MEDIA_LOGI("audio render inited.");
    }
    // deal play params
    DealPlayParamsBeforePlay(streamID, playParams);
    return MSERR_OK;
}

int32_t CacheBuffer::DoPlay(const int32_t streamID)
{
    CHECK_AND_RETURN_RET_LOG(streamID == streamID_, MSERR_INVALID_VAL, "Invalid streamID, failed to DoPlay.");
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_RET_LOG(fullCacheData_ != nullptr, MSERR_INVALID_VAL, "fullCacheData_ is nullptr.");
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "Invalid audioRenderer.");
    cacheDataFrameIndex_ = 0;
    havePlayedCount_ = 0;
    isRunning_.store(true);
    if (!audioRenderer_->Start()) {
        OHOS::AudioStandard::RendererState state = audioRenderer_->GetStatus();
        if (state == OHOS::AudioStandard::RendererState::RENDERER_RUNNING) {
            MEDIA_LOGI("CacheBuffer::DoPlay audioRenderer has started");
            isRunning_.store(true);
            if (callback_ != nullptr) {
                MEDIA_LOGI("CacheBuffer::DoPlay callback_ OnPlayFinished.");
                callback_->OnPlayFinished();
            }
            return MSERR_OK;
        } else {
            MEDIA_LOGE("CacheBuffer::DoPlay audioRenderer start failed");
            isRunning_.store(false);
            if (callback_ != nullptr) {
                MEDIA_LOGI("CacheBuffer::DoPlay failed, call callback");
                callback_->OnError(MSERR_INVALID_VAL);
            }
            if (cacheBufferCallback_ != nullptr) cacheBufferCallback_->OnError(MSERR_INVALID_VAL);
            return MSERR_INVALID_VAL;
        }
    }
    MEDIA_LOGI("CacheBuffer::DoPlay success");
    return MSERR_OK;
}

int32_t CacheBuffer::ReCombineCacheData()
{
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "Invalid audioRenderer.");
    CHECK_AND_RETURN_RET_LOG(!cacheData_.empty(), MSERR_INVALID_VAL, "empty cache data.");

    uint8_t *fullBuffer = new(std::nothrow) uint8_t[cacheDataTotalSize_];
    CHECK_AND_RETURN_RET_LOG(fullBuffer != nullptr, MSERR_INVALID_VAL, "Invalid fullBuffer");
    int32_t copyIndex = 0;
    int32_t remainBufferSize = static_cast<int32_t>(cacheDataTotalSize_);
    MEDIA_LOGI("ReCombine start copyIndex:%{public}d, remainSize:%{public}d", copyIndex, remainBufferSize);
    for (std::shared_ptr<AudioBufferEntry> bufferEntry : cacheData_) {
        if (bufferEntry != nullptr && bufferEntry->size > 0 && bufferEntry->buffer != nullptr) {
            if (remainBufferSize < bufferEntry->size) {
                delete[] fullBuffer;
                MEDIA_LOGE("ReCombine not enough remainBufferSize:%{public}d, bufferEntry->size:%{public}d",
                    remainBufferSize, bufferEntry->size);
                return MSERR_INVALID_VAL;
            }
            int32_t ret = memcpy_s(fullBuffer + copyIndex, remainBufferSize,
                bufferEntry->buffer, bufferEntry->size);
            if (ret != MSERR_OK) {
                delete[] fullBuffer;
                MEDIA_LOGE("ReCombine memcpy failed");
                return MSERR_INVALID_VAL;
            }
            copyIndex += bufferEntry->size;
            remainBufferSize -= bufferEntry->size;
        } else {
            MEDIA_LOGE("ReCombineCacheData, bufferEntry size:%{public}d, buffer:%{public}d",
                bufferEntry->size, bufferEntry->buffer != nullptr);
        }
    }
    MEDIA_LOGI("ReCombine finish copyIndex:%{public}d, remainSize:%{public}d", copyIndex, remainBufferSize);

    fullCacheData_ = std::make_shared<AudioBufferEntry>(fullBuffer, cacheDataTotalSize_);

    if (!cacheData_.empty()) {
        cacheData_.clear();
    }

    return MSERR_OK;
}

int32_t CacheBuffer::DealPlayParamsBeforePlay(const int32_t streamID, const PlayParams playParams)
{
    std::lock_guard lock(cacheBufferLock_);
    CHECK_AND_RETURN_RET_LOG(audioRenderer_ != nullptr, MSERR_INVALID_VAL, "Invalid audioRenderer.");
    audioRenderer_->SetOffloadAllowed(false);
    loop_ = playParams.loop;
    audioRenderer_->SetRenderRate(CheckAndAlignRendererRate(playParams.rate));
    audioRenderer_->SetVolume(playParams.leftVolume);
    priority_ = playParams.priority;
    audioRenderer_->SetParallelPlayFlag(playParams.parallelPlayFlag);
    return MSERR_OK;
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
    if (cacheDataFrameIndex_ >= static_cast<size_t>(fullCacheData_->size)) {
        cacheBufferLock_.lock();
        if (loop_ >= 0 && havePlayedCount_ >= loop_) {
            MEDIA_LOGI("CacheBuffer stream write finish, cacheDataFrameIndex_:%{public}zu,"
                " havePlayedCount_:%{public}d, loop:%{public}d, streamID_:%{public}d, length: %{public}zu",
                cacheDataFrameIndex_, havePlayedCount_, loop_, streamID_, length);
            cacheBufferLock_.unlock();
            Stop(streamID_);
            return;
        }
        cacheDataFrameIndex_ = 0;
        havePlayedCount_++;
        cacheBufferLock_.unlock();
    }
    DealWriteData(length);
}

void CacheBuffer::DealWriteData(size_t length)
{
    std::lock_guard lock(cacheBufferLock_);
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
            int32_t ret = memset_s(bufDesc.buffer, length, 0, length);
            CHECK_AND_RETURN_LOG(ret == MSERR_OK, "memset failed.");
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
            " bufDesc.buffer:%{public}d, fullCacheData_:%{public}d, fullCacheData_->buffer:%{public}d",
            cacheDataFrameIndex_, length, bufDesc.buffer != nullptr, fullCacheData_ != nullptr,
            fullCacheData_->buffer != nullptr);
    }
}

void CacheBuffer::OnFirstFrameWriting(uint64_t latency)
{
    {
        std::lock_guard lock(cacheBufferLock_);
        CHECK_AND_RETURN_LOG(audioRenderer_ != nullptr, "OnFirstFrameWriting audioRenderer_ is nullptr");
        size_t bufferSize;
        audioRenderer_->GetBufferSize(bufferSize);
        MEDIA_LOGI("CacheBuffer::OnFirstFrameWriting bufferSize:%{public}zu, streamID_:%{public}d",
            bufferSize, streamID_);
    }
    CHECK_AND_RETURN_LOG(frameWriteCallback_ != nullptr, "frameWriteCallback is null.");
    frameWriteCallback_->OnFirstAudioFrameWritingCallback(latency);
}

int32_t CacheBuffer::Stop(const int32_t streamID)
{
    std::lock_guard lock(cacheBufferLock_);
    if (streamID == streamID_) {
        if (audioRenderer_ != nullptr && isRunning_.load()) {
            isRunning_.store(false);
            if (audioRenderer_->IsFastRenderer()) {
                MEDIA_LOGI("audioRenderer fast renderer pause.");
                audioRenderer_->Pause();
                audioRenderer_->Flush();
            } else {
                MEDIA_LOGI("audioRenderer normal stop.");
                audioRenderer_->Stop();
            }
            cacheDataFrameIndex_ = 0;
            havePlayedCount_ = 0;
            if (callback_ != nullptr) {
                MEDIA_LOGI("cachebuffer callback_ OnPlayFinished.");
                callback_->OnPlayFinished();
            }
            if (cacheBufferCallback_ != nullptr) {
                MEDIA_LOGI("cachebuffer cacheBufferCallback_ OnPlayFinished.");
                cacheBufferCallback_->OnPlayFinished();
            }
        }
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
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
    int32_t ret = MSERR_INVALID_VAL;
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
        audioRenderer->Stop();
        audioRenderer->Release();
        audioRenderer = nullptr;
    }

    std::lock_guard lock(cacheBufferLock_);
    if (!cacheData_.empty()) cacheData_.clear();
    if (fullCacheData_ != nullptr) fullCacheData_.reset();
    if (callback_ != nullptr) callback_.reset();
    if (cacheBufferCallback_ != nullptr) cacheBufferCallback_.reset();
    if (frameWriteCallback_ != nullptr) frameWriteCallback_.reset();
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
} // namespace Media
} // namespace OHOS
