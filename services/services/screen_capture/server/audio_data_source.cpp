/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "audio_data_source.h"
#include "locale_config.h"
#include "media_log.h"
#include "media_utils.h"
#include "screen_capture_server.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "AudioDataSource"};
}

namespace OHOS::Media {

AudioDataSource::~AudioDataSource()
{
    MEDIA_LOGI("get audio buffer times type: %{public}d, size: %{public}" PRIu64, audioType_.load(),
        audioTypeSize_.load());
}

void AudioDataSource::SetListener(std::shared_ptr<IAudioDataSourceListener> listener)
{
    listener_ = std::move(listener);
}

void AudioDataSource::OnBufferAvailable(AudioCaptureSourceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (cacheBuffer_) {
        NotifyDataReady();
        return;
    }
    if (ReadAudioBuffer() == AudioDataSourceReadAtActionState::OK) {
        NotifyDataReady();
    }
}

void AudioDataSource::SetAppPid(int32_t appid)
{
    appPid_ = appid;
}

int32_t AudioDataSource::GetAppPid()
{
    return appPid_;
}

uint32_t AudioDataSource::GetAudioRendererState()
{
    return audioRendererState_.load();
}

void AudioDataSource::SetAudioRendererState(uint32_t state)
{
    audioRendererState_.store(state);
}

bool AudioDataSource::IsInWaitMicSyncState()
{
    return isInWaitMicSyncState_.load();
}

void AudioDataSource::SetVideoFirstFramePts(int64_t firstFramePts)
{
    firstVideoFramePts_.store(firstFramePts);
    MEDIA_LOGI("SetVideoFirstFramePts video to ScreenCapture firstVideoFramePts: %{public}" PRId64, firstFramePts);
}

void AudioDataSource::SetAudioFirstFramePts(int64_t firstFramePts)
{
    if (firstAudioFramePts_ == -1) {
        firstAudioFramePts_ = firstFramePts;
        MEDIA_LOGI("firstAudioFramePts_: %{public}" PRId64, firstFramePts);
    }
}

void AudioDataSource::Pause()
{
    pauseStartTime_.store(GetCurrentTimeNs());
    MEDIA_LOGI("AudioDataSource::Pause, pauseStartTime=%{public}" PRId64, pauseStartTime_.load());
}

void AudioDataSource::Resume()
{
    int64_t duration = GetCurrentTimeNs() - pauseStartTime_.load();
    pauseDuration_.fetch_add(duration);
    MEDIA_LOGI("AudioDataSource::Resume, duration=%{public}" PRId64 ", pauseDuration=%{public}" PRId64, duration,
        pauseDuration_.load());
}

void AudioDataSource::NotifyDataReady()
{
    if (auto listener = listener_.lock()) {
        listener->OnAudioDataReady();
    }
}

void AudioDataSource::SetInnerCapture(std::shared_ptr<AudioCapturerWrapper> capture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (innerCapture_) {
        innerCapture_->SetBufferAvailableCallback(nullptr);
    }
    innerCapture_ = std::move(capture);
    if (innerCapture_) {
        innerCapture_->SetBufferAvailableCallback(shared_from_this());
    }
}

void AudioDataSource::SetMicCapture(std::shared_ptr<AudioCapturerWrapper> capture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (micCapture_) {
        micCapture_->SetBufferAvailableCallback(nullptr);
    }
    micCapture_ = std::move(capture);
    if (micCapture_) {
        micCapture_->SetBufferAvailableCallback(shared_from_this());
    }
}

AudioDataSourceReadAtActionState AudioDataSource::WriteInnerAudio(std::shared_ptr<CacheBuffer> &innerAudioBuffer)
{
    if (innerAudioBuffer == nullptr) {
        MEDIA_LOGE("innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<CacheBuffer> tmp = nullptr;
    SetAudioFirstFramePts(innerAudioBuffer->timestamp); // update firstAudioFramePts in case re-sync
    return MixModeBufferWrite(innerAudioBuffer, tmp);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMicAudio(std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (micAudioBuffer == nullptr) {
        MEDIA_LOGE("micAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<CacheBuffer> tmp = nullptr;
    SetAudioFirstFramePts(micAudioBuffer->timestamp);
    return MixModeBufferWrite(tmp, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMixAudio(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    CHECK_AND_RETURN_RET_LOG(innerAudioBuffer != nullptr && micAudioBuffer != nullptr,
        AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioBuffer or micAudioBuffer nullptr");
    SetAudioFirstFramePts(std::min(micAudioBuffer->timestamp, innerAudioBuffer->timestamp));
    return MixModeBufferWrite(innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::InnerMicAudioSync(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer->timestamp < 0 || micAudioBuffer->timestamp < 0) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    int64_t timeWindow = micAudioBuffer->timestamp - innerAudioBuffer->timestamp;
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // mic before inner
        CHECK_AND_RETURN_RET_NOLOG(micCapture_ != nullptr, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        auto count = micCapture_->DropBufferUntil(innerAudioBuffer->timestamp);
        MEDIA_LOGI("mic before inner timeDiff: %{public}" PRId64 " DropBufferUntil inner time: %{public}" PRId64
                   " lastAudioPts: %{public}" PRId64 " count: %{public}" PRId32,
            timeWindow, innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load(), count);
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS) { // Write mix
        return WriteMixAudio(innerAudioBuffer, micAudioBuffer);
    } else { // Write Inner data Before mic timeWindow >= AUDIO_INTERVAL_IN_NS
        return WriteInnerAudio(innerAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncMixMode(int64_t timeWindow,
    std::shared_ptr<CacheBuffer> &innerAudioBuffer, std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        // fall through → ReadWriteAudioBufferMixCore 产出 cacheBuffer_
        // ReadAt 的 LostFrameNum 会填充静音帧
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (micAudioBuffer && micCapture_) {
            micCapture_->DropBufferUntil(firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && innerCapture_) {
            innerCapture_->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else {
        return ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
    }
}

int64_t AudioDataSource::GetFirstAudioTime(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer && micAudioBuffer) {
        if (innerAudioBuffer->timestamp > micAudioBuffer->timestamp) {
            mixModeAddAudioMicFrame_ = true;
            return micAudioBuffer->timestamp;
        }
        mixModeAddAudioMicFrame_ = false;
        return innerAudioBuffer->timestamp;
    }
    if (innerAudioBuffer && !micAudioBuffer) {
        mixModeAddAudioMicFrame_ = false;
        return innerAudioBuffer->timestamp;
    }
    if (!innerAudioBuffer && micAudioBuffer) {
        mixModeAddAudioMicFrame_ = true;
        return micAudioBuffer->timestamp;
    }
    return -1;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMixCore(
    std::shared_ptr<CacheBuffer> &innerAudioBuffer, std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer == nullptr && micAudioBuffer) {
        return WriteMicAudio(micAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer == nullptr) {
        if (screenCaptureServer_->IsStopAcquireAudioBufferFlag() && isInWaitMicSyncState_.load()) {
            return WriteInnerAudio(innerAudioBuffer);
        }
        if (screenCaptureServer_->IsMicrophoneSwitchTurnOn()) {
            int64_t currentAudioTime = GetCurrentTimeNs();
            if (currentAudioTime - innerAudioBuffer->timestamp < MAX_INNER_AUDIO_TIMEOUT_IN_NS) { // 2s
                isInWaitMicSyncState_.store(true);
                return AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL;
            } else {
                MEDIA_LOGD("isInWaitMicSyncState close");
                isInWaitMicSyncState_.store(false);
            }
        }
        return WriteInnerAudio(innerAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer) {
        return InnerMicAudioSync(innerAudioBuffer, micAudioBuffer);
    }
    if (innerAudioBuffer == nullptr && micAudioBuffer == nullptr) {
        MEDIA_LOGD("acquire none inner mic buffer");
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    return AudioDataSourceReadAtActionState::OK;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMix(
    std::shared_ptr<CacheBuffer> &innerAudioBuffer, std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (micCapture_ && micCapture_->IsRecording() && micCapture_->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
        MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
    }
    if (innerCapture_ && innerCapture_->IsRecording() &&
        innerCapture_->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
        MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed, wait inner ready");
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    CHECK_AND_RETURN_RET_NOLOG(innerAudioBuffer || micAudioBuffer, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1) { // video audio sync
        int64_t audioTime = GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
        CHECK_AND_RETURN_RET_NOLOG(audioTime != -1, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        int64_t timeWindow = firstVideoFramePts_.load() - audioTime;
        MEDIA_LOGI("ReadWriteAudioBufferMix video to audio timeWindow: %{public}" PRId64
                   " firstAudioFramePts: %{public}" PRId64,
            timeWindow, audioTime);
        return VideoAudioSyncMixMode(timeWindow, innerAudioBuffer, micAudioBuffer);
    }
    return ReadWriteAudioBufferMixCore(innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMixMode()
{
    std::shared_ptr<CacheBuffer> innerAudioBuffer = nullptr;
    std::shared_ptr<CacheBuffer> micAudioBuffer = nullptr;
    AudioDataSourceReadAtActionState ret = ReadWriteAudioBufferMix(innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGD("AudioDataSource ReadAtMixMode ret: %{public}d", static_cast<int32_t>(ret));
    return ret;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMicMode()
{
    if (micCapture_ == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (micCapture_->IsRecording()) {
        std::shared_ptr<CacheBuffer> micAudioBuffer = nullptr;
        if (micCapture_->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer mic success");
        if (micAudioBuffer == nullptr) {
            MEDIA_LOGE("micAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write mic cur:%{public}" PRId64 " last: %{public}" PRId64, micAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::MIC);
        cacheBuffer_ = micAudioBuffer;
        CHECK_AND_RETURN_RET_LOG(micCapture_->ReleaseAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "micAudioCapture ReleaseAudioBuffer failed");
        micAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncInnerMode(int64_t timeWindow,
    std::shared_ptr<CacheBuffer> &innerAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        // fall through → 写 inner 音频
        // ReadAt 的 LostFrameNum 会填充静音帧
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (innerCapture_) {
            innerCapture_->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        CHECK_AND_RETURN_RET_LOG(innerAudioBuffer != nullptr, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG,
            "innerAudioBuffer nullptr");
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64, innerAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        cacheBuffer_ = innerAudioBuffer;
        SetAudioFirstFramePts(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        innerCapture_->ReleaseAudioBuffer();
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtInnerMode()
{
    if (innerCapture_ == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (innerCapture_->IsRecording()) {
        std::shared_ptr<CacheBuffer> innerAudioBuffer = nullptr;
        if (innerCapture_->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer inner success");
        if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1 && innerAudioBuffer) {
            int64_t timeWindow = firstVideoFramePts_.load() - innerAudioBuffer->timestamp;
            return VideoAudioSyncInnerMode(timeWindow, innerAudioBuffer);
        }
        if (innerAudioBuffer == nullptr) {
            MEDIA_LOGE("innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64, innerAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        cacheBuffer_ = innerAudioBuffer;
        CHECK_AND_RETURN_RET_LOG(innerCapture_->ReleaseAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioCapture ReleaseAudioBuffer failed");
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAudioBuffer()
{
    MEDIA_LOGD("AudioDataSource ReadAt start");
    if (!screenCaptureServer_->IsState(CAP_ACTIVE)) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstVideoFramePts_.load() == -1) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    AudioDataSourceReadAtActionState ret;
    if (type_ == AVScreenCaptureMixMode::MIX_MODE) {
        ret = ReadAtMixMode();
    } else if (type_ == AVScreenCaptureMixMode::INNER_MODE) {
        ret = ReadAtInnerMode();
    } else if (type_ == AVScreenCaptureMixMode::MIC_MODE) {
        ret = ReadAtMicMode();
    } else {
        ret = AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    if (ret == AudioDataSourceReadAtActionState::OK && cacheBuffer_) {
        MEDIA_LOGD("ReadAudioBuffer OK, cacheBuffer_ length: %{public}d", cacheBuffer_->length);
    }
    return ret;
}

void AudioDataSource::HandlePastMicBuffer(std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (micAudioBuffer->timestamp < lastWriteAudioFramePts_.load() &&
        micAudioBuffer->timestamp < lastMicAudioFramePts_.load() + AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS &&
        lastWriteType_.load() == AVScreenCaptureMixBufferType::INNER) {
        if (micCapture_) {
            micCapture_->ReleaseAudioBuffer();
        }
        MEDIA_LOGD("ABuffer drop mix mic error cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        micAudioBuffer = nullptr;
    } // drop past mic data when switch,keep when mic stable
}

void AudioDataSource::HandleSwitchToSpeakerOptimise(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (GetAudioRendererState() == 0 && innerCapture_ && screenCaptureServer_->IsMicrophoneSwitchTurnOn() &&
        micAudioBuffer != nullptr && lastWriteType_.load() == AVScreenCaptureMixBufferType::MIX) {
        if (stableStopInnerSwitchCount_ > INNER_SWITCH_MIC_REQUIRE_COUNT) { // optimise inner while use speaker
            MEDIA_LOGI("ABuffer stop mix inner optimise cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
            if (cacheBuffer_) {
                cacheBuffer_.reset();
            }
            screenCaptureServer_->PostSyncAudioCaptures();
            stableStopInnerSwitchCount_ = 0;
        } else {
            stableStopInnerSwitchCount_++;
        }
    }
}

void AudioDataSource::HandleBufferTimeStamp(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (micAudioBuffer) {
        HandlePastMicBuffer(micAudioBuffer);
    }
    if (innerAudioBuffer) {
        if (innerAudioBuffer->timestamp < lastWriteAudioFramePts_.load() && GetAudioRendererState() == 0) {
            if (innerCapture_) {
                innerCapture_->ReleaseAudioBuffer();
            }
            MEDIA_LOGD("ABuffer drop mix inner error cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
        }
    }
    if (innerAudioBuffer && micAudioBuffer) {
        HandleSwitchToSpeakerOptimise(innerAudioBuffer, micAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::MixModeBufferWrite(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    if (innerAudioBuffer && micAudioBuffer) {
        auto mixData = std::make_unique<uint8_t[]>(innerAudioBuffer->length);
        CHECK_AND_RETURN_RET_LOG(mixData != nullptr, AudioDataSourceReadAtActionState::RETRY_SKIP,
            "mixData memory allocation failed");
        int32_t channels = 2;
        MixAudio(*innerAudioBuffer, *micAudioBuffer, mixData.get(), channels);
        MEDIA_LOGD("ABuffer write mix mix cur:%{public}" PRId64 " mic:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::MIX);
        cacheBuffer_ = std::make_shared<CacheBuffer>(std::move(mixData), innerAudioBuffer->length,
            innerAudioBuffer->timestamp, innerAudioBuffer->sourcetype);
    } else if (innerAudioBuffer) {
        MEDIA_LOGD("ABuffer write mix inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        stableStopInnerSwitchCount_ = 0;
        cacheBuffer_ = innerAudioBuffer;
    } else if (micAudioBuffer) {
        MEDIA_LOGD("ABuffer write mix mic cur:%{public}" PRId64 " last: %{public}" PRId64, micAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::MIC);
        stableStopInnerSwitchCount_ = 0;
        cacheBuffer_ = micAudioBuffer;
    } else {
        MEDIA_LOGE("without buffer write");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    ReleaseAudioBuffer(innerAudioBuffer, micAudioBuffer);
    return AudioDataSourceReadAtActionState::OK;
}

void AudioDataSource::SetMixAudioTypeLog(AVScreenCaptureMixBufferType bufferType)
{
    if (bufferType != audioType_) {
        MEDIA_LOGI("get audio buffer times type: %{public}d, size: %{public}" PRIu64, audioType_.load(),
            audioTypeSize_.load());
        audioType_.store(bufferType);
        audioTypeSize_ = 1;
    } else {
        audioTypeSize_++;
    }
}

void AudioDataSource::ReleaseAudioBuffer(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
    std::shared_ptr<CacheBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer) {
        if (innerCapture_) {
            innerCapture_->ReleaseAudioBuffer();
        }
        innerAudioBuffer = nullptr;
    }
    if (micAudioBuffer) {
        if (micCapture_) {
            micCapture_->ReleaseAudioBuffer();
        }
        micAudioBuffer = nullptr;
    }
}

int32_t AudioDataSource::GetSize(int64_t &size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_ || cacheBuffer_->length <= 0) {
        return MSERR_UNKNOWN;
    }
    size = cacheBuffer_->length;
    return MSERR_OK;
}

void AudioDataSource::MixAudio(const CacheBuffer &inner, const CacheBuffer &mic, uint8_t *out, int32_t channels)
{
    const int16_t *src[2] = {reinterpret_cast<const int16_t *>(inner.Data()),
        reinterpret_cast<const int16_t *>(mic.Data())};
    int16_t *dst = reinterpret_cast<int16_t *>(out);
    if (channels == 0 || src[0] == nullptr || src[1] == nullptr) {
        return;
    }
    constexpr int32_t max = 32767;
    constexpr int32_t min = -32768;
    constexpr int32_t splitNum = 32;
    double coefficient = 1;
    const int32_t totalLen = inner.length / static_cast<int32_t>(sizeof(int16_t));
    for (int32_t i = 0; i < totalLen; i++) {
        int32_t temp = 0;
        for (int32_t ch = 0; ch < channels; ch++) {
            if (ch != 1 || mic.length >= i * channels + static_cast<int32_t>(sizeof(int16_t))) {
                temp += src[ch][i];
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

int64_t AudioDataSource::LostFrameNum(const int64_t &timestamp)
{
    int64_t pauseDuration = pauseDuration_.load();
    if (firstAudioFramePts_ < 0 || timestamp < 0 || pauseDuration < 0 || writedFrameTime_ < 0) {
        return 0;
    }
    return (timestamp - pauseDuration - writedFrameTime_ - firstAudioFramePts_) / FILL_AUDIO_FRAME_DURATION_IN_NS;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cacheBuffer_) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (buffer == nullptr || buffer->memory_ == nullptr) {
        return AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL;
    }
    if (!cacheBuffer_->WriteTo(buffer->memory_, length)) {
        if (zeroBuffer_.size() < length) {
            zeroBuffer_.assign(length, 0);
        }
        buffer->memory_->Write(zeroBuffer_.data(), length, 0);
        writedFrameTime_ += FILL_AUDIO_FRAME_DURATION_IN_NS;
        cacheBuffer_.reset();
        ReadAudioBuffer();
        return AudioDataSourceReadAtActionState::OK;
    }
    auto lostNum = LostFrameNum(cacheBuffer_->timestamp);
    if (lostNum > 0) {
        if (zeroBuffer_.size() < length) {
            zeroBuffer_.assign(length, 0);
        }
        buffer->memory_->Write(zeroBuffer_.data(), length, 0);
        writedFrameTime_ += FILL_AUDIO_FRAME_DURATION_IN_NS;
        SetMixAudioTypeLog(AVScreenCaptureMixBufferType::SILENT);
        return AudioDataSourceReadAtActionState::OK;
    }
    cacheBuffer_->WriteTo(buffer->memory_, length);
    cacheBuffer_.reset();
    zeroBuffer_.clear();
    writedFrameTime_ += FILL_AUDIO_FRAME_DURATION_IN_NS;
    SetMixAudioTypeLog(lastWriteType_.load());
    ReadAudioBuffer();
    return AudioDataSourceReadAtActionState::OK;
}
} // namespace OHOS::Media
