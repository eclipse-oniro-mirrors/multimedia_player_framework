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
constexpr int64_t AUDIO_INTERVAL_IN_NS = 20000000;
constexpr int64_t FRAME_LOSS_THRESHOLD = 2;
constexpr int64_t SILENT_FRAME_CHUNK = 5;

void AudioBufferLogStats::Log() const
{
    MEDIA_LOGI("get audio buffer times type: %{public}d source: %{public}d, size: %{public}" PRIu64,
        static_cast<int32_t>(type), static_cast<int32_t>(source), size);
}

void AudioBufferLogStats::Update(AudioOutputTag tag, AudioCaptureSourceType src, uint64_t count)
{
    if (tag != type || src != source) {
        Log();
        type = tag;
        source = src;
        size = count;
    } else {
        size += count;
    }
}

void AudioBufferLogStats::Emit(AudioOutputTag tag, AudioCaptureSourceType src)
{
    emitType = tag;
    emitSource = src;
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (firstVideoFramePts_ < 0) {
        firstVideoFramePts_ = firstFramePts;
        MEDIA_LOGI("SetVideoFirstFramePts firstVideoFramePts: %{public}" PRId64, firstFramePts);
        return;
    }
    pauseDuration_ = firstFramePts - firstVideoFramePts_ - writedFrameTime_;
    remainingSilentFrames_ = 0;
    pauseDurationPending_ = false;
    MEDIA_LOGI("SetVideoFirstFramePts update pauseDuration: %{public}" PRId64, pauseDuration_);
}

void AudioDataSourceGeneric::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);
    pauseDurationPending_ = true;
    MEDIA_LOGI("AudioDataSourceGeneric Pause");
}

void AudioDataSourceGeneric::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    pauseDurationPending_ = true;
    MEDIA_LOGI("AudioDataSourceGeneric Resume");
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
        if (pauseDurationPending_) {
            return;
        }
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

void AudioDataSourceGeneric::SetOutputFormat(int32_t sampleRate, int32_t channels)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (sampleRate > 0 && channels > 0) {
        silentFrameSize_ = sampleRate * channels * sizeof(int16_t) * AUDIO_INTERVAL_IN_NS / SEC_TO_NS;
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
            buf->timestamp - slot.lastTs > FRAME_LOSS_THRESHOLD * buf->intervalNs) {
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
    if (recorderFileWithVideo_ && firstVideoFramePts_ == -1) {
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
    int64_t intervalNs = 0;
    bool found = false;
    for (const auto &slot : captures_) {
        if (slot.currentBuf && slot.currentBuf->timestamp < audioTime) {
            audioTime = slot.currentBuf->timestamp;
            intervalNs = slot.currentBuf->intervalNs;
            found = true;
        }
    }
    CHECK_AND_RETURN_RET_NOLOG(found, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    int64_t timeWindow = firstVideoFramePts_ - audioTime;
    MEDIA_LOGI("VideoAudioSyncIfNeed timeWindow: %{public}" PRId64 " audioTime: %{public}" PRId64, timeWindow,
        audioTime);
    avSynced_ = true;
    if (timeWindow >= intervalNs) {
        for (auto &slot : captures_) {
            if (slot.currentBuf && slot.capture) {
                slot.capture->DropBufferUntil(firstVideoFramePts_);
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
        if (diff >= refSlot->currentBuf->intervalNs) {
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
        logStats_.Emit(AudioOutputTag::SINGLE, singleSlot->currentBuf->sourcetype);
    } else {
        auto mixData = std::make_unique<uint8_t[]>(srcs.front()->length);
        MixAudio(srcs, mixData.get());
        cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(mixData), srcs.front()->length, ts,
            srcs.front()->intervalNs, srcs.front()->sourcetype);
        logStats_.Emit(AudioOutputTag::MIXED, AudioCaptureSourceType::SOURCE_DEFAULT);
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

int64_t AudioDataSourceGeneric::LostFrameNum(const int64_t &timestamp)
{
    if (remainingSilentFrames_ > 0) {
        return std::min(remainingSilentFrames_, SILENT_FRAME_CHUNK);
    }
    int64_t pauseDuration = pauseDuration_;
    if (firstVideoFramePts_ < 0 || timestamp < 0 || pauseDuration < 0 || writedFrameTime_ < 0) {
        return 0;
    }
    int64_t lostNum = (timestamp - pauseDuration - writedFrameTime_ - firstVideoFramePts_) / AUDIO_INTERVAL_IN_NS;
    if (lostNum >= FRAME_LOSS_THRESHOLD && silentFrameSize_ > 0) {
        remainingSilentFrames_ = lostNum;
        MEDIA_LOGI("LostFrameNum trigger silence fill, lostNum:%{public}" PRId64 " timestamp:%{public}" PRId64
                   " writedFrameTime_:%{public}" PRId64,
            lostNum, timestamp, writedFrameTime_);
        return std::min(lostNum, SILENT_FRAME_CHUNK);
    }
    return 0;
}

bool AudioDataSourceGeneric::FillSilence(const std::shared_ptr<AVBuffer> &buffer, int64_t size)
{
    uint8_t *addr = buffer->memory_->GetAddr();
    if (addr == nullptr || size <= 0) {
        MEDIA_LOGE("FillSilence invalid, addr:%{public}s size:%{public}" PRId64, addr ? "ok" : "null", size);
        return false;
    }
    if (memset_s(addr, static_cast<size_t>(size), 0, static_cast<size_t>(size)) != EOK) {
        MEDIA_LOGE("FillSilence memset_s failed, size:%{public}" PRId64, size);
        return false;
    }
    return true;
}

AudioDataSourceReadAtActionState AudioDataSourceGeneric::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_ || pauseDurationPending_) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (buffer == nullptr || buffer->memory_ == nullptr) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    int64_t lostNum = LostFrameNum(cacheBuffer_->timestamp);
    if (lostNum > 0) {
        FillSilence(buffer, lostNum * silentFrameSize_);
        writedFrameTime_ += lostNum * AUDIO_INTERVAL_IN_NS;
        remainingSilentFrames_ -= lostNum;
        logStats_.Update(AudioOutputTag::SILENT, AudioCaptureSourceType::SOURCE_DEFAULT, lostNum);
        return AudioDataSourceReadAtActionState::OK;
    }
    int64_t intervalNs = cacheBuffer_->intervalNs;
    if (!cacheBuffer_->WriteTo(buffer->memory_, length)) {
        FillSilence(buffer, length);
        writedFrameTime_ += intervalNs;
        cacheBuffer_.reset();
        ReadAudioBuffer();
        return AudioDataSourceReadAtActionState::OK;
    }
    cacheBuffer_.reset();
    writedFrameTime_ += intervalNs;
    logStats_.Update(logStats_.emitType, logStats_.emitSource);
    ReadAudioBuffer();
    return AudioDataSourceReadAtActionState::OK;
}

int32_t AudioDataSourceGeneric::GetSize(int64_t &size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_ || cacheBuffer_->length <= 0 || pauseDurationPending_) {
        return MSERR_UNKNOWN;
    }
    int64_t lostNum = LostFrameNum(cacheBuffer_->timestamp);
    if (lostNum > 0) {
        size = lostNum * silentFrameSize_;
    } else {
        size = cacheBuffer_->length;
    }
    return MSERR_OK;
}

} // namespace Media
} // namespace OHOS
