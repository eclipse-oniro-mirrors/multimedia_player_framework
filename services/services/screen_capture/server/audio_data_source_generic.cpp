/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "audio_data_source_generic.h"

#include <algorithm>
#include <cinttypes>
#include <limits>

#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "AudioDataSourceGeneric"};
}

namespace OHOS {
namespace Media {
constexpr int64_t AUDIO_INTERVAL_IN_NS = 21333334;
constexpr int64_t FRAME_LOSS_THRESHOLD = 2 * AUDIO_INTERVAL_IN_NS;

void AudioBufferLogStats::Log() const
{
    MEDIA_LOGI("get audio buffer times type: %{public}d source: %{public}d, size: %{public}" PRIu64,
        static_cast<int32_t>(type), static_cast<int32_t>(source), size);
}

void AudioBufferLogStats::Update(AudioOutputTag tag, AudioCaptureSourceType src)
{
    if (tag != type || src != source) {
        Log();
        type = tag;
        source = src;
        size = 1;
    } else {
        size++;
    }
}

AudioDataSourceGeneric::AudioDataSourceGeneric(AudioCombinePolicy policy, bool recorderFileWithVideo)
    : policy_(policy), recorderFileWithVideo_(recorderFileWithVideo)
{
}

AudioDataSourceGeneric::~AudioDataSourceGeneric()
{
    logStats_.Log();
}

void AudioDataSourceGeneric::SetListener(std::shared_ptr<IAudioDataSourceListener> listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    listener_ = std::move(listener);
}

void AudioDataSourceGeneric::SetVideoFirstFramePts(int64_t firstFramePts)
{
    firstVideoFramePts_.store(firstFramePts);
    MEDIA_LOGI("SetVideoFirstFramePts firstVideoFramePts: %{public}" PRId64, firstFramePts);
}

void AudioDataSourceGeneric::Pause()
{
    pauseStartTime_.store(GetCurrentTimeNs());
    MEDIA_LOGI("Pause pauseStartTime=%{public}" PRId64, pauseStartTime_.load());
}

void AudioDataSourceGeneric::Resume()
{
    int64_t start = pauseStartTime_.exchange(0);
    if (start == 0) {
        MEDIA_LOGE("Resume called without prior Pause");
        return;
    }
    int64_t duration = GetCurrentTimeNs() - start;
    pauseDuration_.fetch_add(duration);
    MEDIA_LOGI("Resume duration=%{public}" PRId64 " pauseDuration=%{public}" PRId64, duration, pauseDuration_.load());
}

void AudioDataSourceGeneric::Stop()
{
    active_.store(false);
    MEDIA_LOGI("AudioDataSourceGeneric Stop");
}

void AudioDataSourceGeneric::OnBufferAvailable(AudioCaptureSourceType type)
{
    std::shared_ptr<IAudioDataSourceListener> listener;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cacheBuffer_ || ReadAudioBuffer() == AudioDataSourceReadAtActionState::OK) {
            listener = listener_.lock();
        }
    }
    if (listener) {
        listener->OnAudioDataReady();
    }
}

void AudioDataSourceGeneric::SetCapture(AudioCaptureSourceType type, std::shared_ptr<AudioCapturerWrapper> capture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(captures_.begin(), captures_.end(),
        [&type](const CaptureSlot &s) { return s.type == type; });
    if (it != captures_.end() && it->capture) {
        it->capture->SetBufferAvailableCallback(nullptr);
    }
    if (capture) {
        capture->SetBufferAvailableCallback(shared_from_this());
    }
    if (it != captures_.end()) {
        it->capture = std::move(capture);
    } else {
        captures_.push_back({type, std::move(capture), CaptureSlotState::INACTIVE, nullptr, 0});
    }
}

bool AudioDataSourceGeneric::AcquireReady()
{
    bool anyReady = false;
    for (auto &slot : captures_) {
        slot.currentBuf.reset();
        if (!slot.capture || !slot.capture->IsRecording()) {
            slot.state = CaptureSlotState::INACTIVE;
            slot.lastTs = 0;
            continue;
        }
        std::shared_ptr<CacheBuffer> buf;
        if (slot.capture->AcquireAudioBuffer(buf) != MSERR_OK || !buf) {
            continue;
        }
        buf->sourcetype = slot.type;
        if (slot.state == CaptureSlotState::STABLE && slot.lastTs != 0 &&
            buf->timestamp - slot.lastTs > FRAME_LOSS_THRESHOLD) {
            slot.state = CaptureSlotState::UNSTABLE;
            MEDIA_LOGI("AcquireReady frame loss gap:%{public}" PRId64 " lastTs:%{public}" PRId64,
                buf->timestamp - slot.lastTs, slot.lastTs);
        }
        slot.lastTs = buf->timestamp;
        slot.currentBuf = std::move(buf);
        if (slot.state == CaptureSlotState::INACTIVE) {
            slot.state = CaptureSlotState::UNSTABLE;
        }
        anyReady = true;
    }
    return anyReady;
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::ReadAudioBuffer()
{
    MEDIA_LOGD("ReadAudioBuffer start");
    if (!active_.load()) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (recorderFileWithVideo_ && firstVideoFramePts_.load() == -1) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (!AcquireReady()) {
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    if (recorderFileWithVideo_ && !avSynced_) {
        auto state = VideoAudioSyncIfNeed();
        if (state != AudioDataSourceReadAtActionState::OK) {
            return state;
        }
        if (cacheBuffer_) {
            return AudioDataSourceReadAtActionState::OK;
        }
    }
    if (policy_ == AudioCombinePolicy::MIX_ALL) {
        size_t activeCount = 0;
        size_t acquired = 0;
        for (const auto &slot : captures_) {
            if (slot.state != CaptureSlotState::INACTIVE) {
                activeCount++;
            }
            if (slot.currentBuf) {
                acquired++;
            }
        }
        if (acquired < activeCount) {
            return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
        }
    }
    return AlignOrCombine();
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::VideoAudioSyncIfNeed()
{
    int64_t audioTime = std::numeric_limits<int64_t>::max();
    bool found = false;
    for (const auto &slot : captures_) {
        if (slot.currentBuf && slot.currentBuf->timestamp < audioTime) {
            audioTime = slot.currentBuf->timestamp;
            found = true;
        }
    }
    CHECK_AND_RETURN_RET_NOLOG(found, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    int64_t timeWindow = firstVideoFramePts_.load() - audioTime;
    MEDIA_LOGI("VideoAudioSyncIfNeed timeWindow: %{public}" PRId64 " audioTime: %{public}" PRId64, timeWindow,
        audioTime);
    avSynced_ = true;
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) {
        for (auto &slot : captures_) {
            if (slot.currentBuf && slot.capture) {
                slot.capture->DropBufferUntil(firstVideoFramePts_.load());
            }
        }
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (policy_ == AudioCombinePolicy::MIX_ALL) {
        return AlignOrCombine();
    }
    return AudioDataSourceReadAtActionState::OK;
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::AlignOrCombine()
{
    CaptureSlot *refSlot = nullptr;
    for (auto &slot : captures_) {
        if (slot.currentBuf && (!refSlot || slot.currentBuf->timestamp < refSlot->currentBuf->timestamp)) {
            refSlot = &slot;
        }
    }
    CHECK_AND_RETURN_RET_LOG(refSlot, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG,
        "AlignOrCombine no present source");
    int64_t refTs = refSlot->currentBuf->timestamp;
    for (auto &slot : captures_) {
        if (!slot.currentBuf || &slot == refSlot) {
            continue;
        }
        if (policy_ == AudioCombinePolicy::PASSTHROUGH) {
            if (slot.capture) {
                slot.capture->ReleaseAudioBuffer();
            }
            slot.currentBuf.reset();
            continue;
        }
        if (slot.state == CaptureSlotState::STABLE) {
            continue;
        }
        int64_t diff = slot.currentBuf->timestamp - refTs;
        if (diff >= AUDIO_INTERVAL_IN_NS) {
            slot.currentBuf.reset();
            MEDIA_LOGI("AlignOrCombine hold ahead diff:%{public}" PRId64 " refTs:%{public}" PRId64, diff, refTs);
        }
    }
    return Combine();
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::Combine()
{
    std::vector<const CacheBuffer *> srcs;
    int64_t ts = std::numeric_limits<int64_t>::max();
    CaptureSlot *singleSlot = nullptr;
    for (auto &slot : captures_) {
        if (!slot.currentBuf) {
            continue;
        }
        if (slot.currentBuf->timestamp < ts) {
            ts = slot.currentBuf->timestamp;
        }
        srcs.push_back(slot.currentBuf.get());
        singleSlot = &slot;
    }
    if (srcs.empty()) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (srcs.size() == 1) {
        cacheBuffer_ = singleSlot->currentBuf;
        lastEmit_ = {AudioOutputTag::SINGLE, singleSlot->currentBuf->sourcetype, ts};
    } else {
        auto mixData = std::make_unique<uint8_t[]>(srcs.front()->length);
        MixAudio(srcs, mixData.get());
        cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(mixData), srcs.front()->length, ts,
            srcs.front()->sourcetype);
        lastEmit_ = {AudioOutputTag::MIXED, AudioCaptureSourceType::SOURCE_DEFAULT, ts};
    }
    for (auto &slot : captures_) {
        if (slot.currentBuf) {
            slot.state = CaptureSlotState::STABLE;
            if (slot.capture) {
                slot.capture->ReleaseAudioBuffer();
            }
            slot.currentBuf.reset();
        }
    }
    return AudioDataSourceReadAtActionState::OK;
}

void AudioDataSourceGeneric::MixAudio(const std::vector<const CacheBuffer *> &srcs, uint8_t *out)
{
    CHECK_AND_RETURN(!srcs.empty());
    int16_t *dst = reinterpret_cast<int16_t *>(out);
    int32_t totalLen = srcs.front()->length / static_cast<int32_t>(sizeof(int16_t));
    constexpr int32_t max = 32767;
    constexpr int32_t min = -32768;
    constexpr int32_t splitNum = 32;
    double coefficient = 1;
    for (int32_t i = 0; i < totalLen; i++) {
        int32_t temp = 0;
        for (const auto *src : srcs) {
            if (src && src->length >= (i + 1) * static_cast<int32_t>(sizeof(int16_t))) {
                temp += reinterpret_cast<const int16_t *>(src->Data())[i];
            }
        }
        int32_t output = static_cast<int32_t>(temp * coefficient);
        if (output > max) {
            coefficient = static_cast<double>(max) / static_cast<double>(output);
            output = max;
        }
        if (output < min) {
            coefficient = static_cast<double>(min) / static_cast<double>(output);
            output = min;
        }
        if (coefficient < 1) {
            coefficient += (static_cast<double>(1) - coefficient) / splitNum;
        }
        dst[i] = static_cast<int16_t>(output);
    }
}

void AudioDataSourceGeneric::SetMixAudioTypeLog(AudioOutputTag bufferType)
{
    logStats_.Update(bufferType,
        (bufferType == AudioOutputTag::SINGLE) ? lastEmit_.source : AudioCaptureSourceType::SOURCE_DEFAULT);
}

int64_t AudioDataSourceGeneric::LostFrameNum(const int64_t &timestamp)
{
    int64_t pauseDuration = pauseDuration_.load();
    if (firstVideoFramePts_.load() < 0 || timestamp < 0 || pauseDuration < 0 || writedFrameTime_ < 0) {
        return 0;
    }
    return (timestamp - pauseDuration - writedFrameTime_ - firstVideoFramePts_.load()) / AUDIO_INTERVAL_IN_NS;
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (buffer == nullptr || buffer->memory_ == nullptr) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    auto lostNum = LostFrameNum(cacheBuffer_->timestamp);
    if (lostNum > 0) {
        if (zeroBuffer_.size() < length) {
            zeroBuffer_.assign(length, 0);
        }
        buffer->memory_->Write(zeroBuffer_.data(), length, 0);
        writedFrameTime_ += AUDIO_INTERVAL_IN_NS;
        SetMixAudioTypeLog(AudioOutputTag::SILENT);
        return AudioDataSourceReadAtActionState::OK;
    }
    if (!cacheBuffer_->WriteTo(buffer->memory_, length)) {
        if (zeroBuffer_.size() < length) {
            zeroBuffer_.assign(length, 0);
        }
        buffer->memory_->Write(zeroBuffer_.data(), length, 0);
        writedFrameTime_ += AUDIO_INTERVAL_IN_NS;
        cacheBuffer_.reset();
        ReadAudioBuffer();
        return AudioDataSourceReadAtActionState::OK;
    }
    cacheBuffer_.reset();
    zeroBuffer_.clear();
    writedFrameTime_ += AUDIO_INTERVAL_IN_NS;
    SetMixAudioTypeLog(lastEmit_.type);
    ReadAudioBuffer();
    return AudioDataSourceReadAtActionState::OK;
}

int32_t AudioDataSourceGeneric::GetSize(int64_t &size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_ || cacheBuffer_->length <= 0) {
        return MSERR_UNKNOWN;
    }
    size = cacheBuffer_->length;
    return MSERR_OK;
}

} // namespace Media
} // namespace OHOS
