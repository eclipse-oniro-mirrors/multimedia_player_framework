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
#include "screen_capture_server_base.h"
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

int32_t AudioDataSource::RegisterAudioRendererEventListener(const int32_t clientPid,
    const std::shared_ptr<AudioRendererStateChangeCallback> &callback)
{
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "audio callback is null");
    int32_t ret = AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(clientPid, callback);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfos);
    screenCaptureServer_->AudioRendererStateUpdate(audioRendererChangeInfos);
    return ret;
}

int32_t AudioDataSource::UnregisterAudioRendererEventListener(const int32_t clientPid)
{
    MEDIA_LOGI("client id: %{public}d", clientPid);
    return AudioStreamManager::GetInstance()->UnregisterAudioRendererEventListener(clientPid);
}

void AudioDataSource::SetVideoFirstFramePts(int64_t firstFramePts)
{
    firstVideoFramePts_.store(firstFramePts);
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    int64_t curTime = timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
    MEDIA_LOGI("SetVideoFirstFramePts video to ScreenCapture timeWindow: %{public}" PRId64
               " firstVideoFramePts: %{public}" PRId64,
        curTime - firstFramePts, firstFramePts);
}

void AudioDataSource::SetAudioFirstFramePts(int64_t firstFramePts)
{
    if (firstAudioFramePts_.load() == -1) {
        firstAudioFramePts_.store(firstFramePts);
        MEDIA_LOGI("firstAudioFramePts_: %{public}" PRId64, firstFramePts);
    }
}

int64_t AudioDataSource::GetCurrentTimeNs()
{
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    return timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
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

AudioDataSourceReadAtActionState AudioDataSource::WriteInnerAudio(uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    if (innerAudioBuffer == nullptr) {
        MEDIA_LOGE("innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(innerAudioBuffer->timestamp); // update firstAudioFramePts in case re-sync
    return MixModeBufferWrite(innerAudioBuffer, tmp);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMicAudio(uint32_t length,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer == nullptr) {
        MEDIA_LOGE("micAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(micAudioBuffer->timestamp);
    return MixModeBufferWrite(tmp, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMixAudio(uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    CHECK_AND_RETURN_RET_LOG(innerAudioBuffer != nullptr && micAudioBuffer != nullptr,
        AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioBuffer or micAudioBuffer nullptr");
    SetAudioFirstFramePts(std::min(micAudioBuffer->timestamp, innerAudioBuffer->timestamp));
    return MixModeBufferWrite(innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::InnerMicAudioSync(uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    int64_t timeWindow = micAudioBuffer->timestamp - innerAudioBuffer->timestamp;
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // mic before inner
        const auto &capture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
        CHECK_AND_RETURN_RET_NOLOG(capture != nullptr, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        auto count = capture->DropBufferUntil(innerAudioBuffer->timestamp);
        MEDIA_LOGI("mic before inner timeDiff: %{public}" PRId64 " DropBufferUntil inner time: %{public}" PRId64
                   " lastAudioPts: %{public}" PRId64 " count: %{public}" PRId32,
            timeWindow, innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load(), count);
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS) { // Write mix
        return WriteMixAudio(length, innerAudioBuffer, micAudioBuffer);
    } else { // Write Inner data Before mic timeWindow >= AUDIO_INTERVAL_IN_NS
        return WriteInnerAudio(length, innerAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncMixMode(uint32_t length, int64_t timeWindow,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (micAudioBuffer && micCapture && mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("mic AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            micCapture->AddBufferFrom(-1 * timeWindow, length, firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && innerCapture && !mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("inner AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            innerCapture->AddBufferFrom(-1 * timeWindow, length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (micAudioBuffer && micCapture) {
            micCapture->DropBufferUntil(firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && innerCapture) {
            innerCapture->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else {
        return ReadWriteAudioBufferMixCore(length, innerAudioBuffer, micAudioBuffer);
    }
}

int64_t AudioDataSource::GetFirstAudioTime(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
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

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMixCore(uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer == nullptr && micAudioBuffer) {
        return WriteMicAudio(length, micAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer == nullptr) {
        if (screenCaptureServer_->IsStopAcquireAudioBufferFlag() && isInWaitMicSyncState_.load()) {
            return WriteInnerAudio(length, innerAudioBuffer);
        }
        if (screenCaptureServer_->IsMicrophoneSwitchTurnOn()) {
            int64_t currentAudioTime = 0;
            auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
            if (innerCapture) {
                innerCapture->GetCurrentAudioTime(currentAudioTime);
            }
            if (currentAudioTime - innerAudioBuffer->timestamp < MAX_INNER_AUDIO_TIMEOUT_IN_NS) { // 2s
                isInWaitMicSyncState_.store(true);
                return AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL;
            } else {
                MEDIA_LOGD("isInWaitMicSyncState close");
                isInWaitMicSyncState_.store(false);
            }
        }
        return WriteInnerAudio(length, innerAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer) {
        return InnerMicAudioSync(length, innerAudioBuffer, micAudioBuffer);
    }
    if (innerAudioBuffer == nullptr && micAudioBuffer == nullptr) {
        MEDIA_LOGD("acquire none inner mic buffer");
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    return AudioDataSourceReadAtActionState::OK;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMix(uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
    if (micCapture && micCapture->IsRecording() && micCapture->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
        MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
    }
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (innerCapture && innerCapture->IsRecording() && innerCapture->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
        MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
    }
    CHECK_AND_RETURN_RET_NOLOG(innerAudioBuffer || micAudioBuffer, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1) { // video audio sync
        int64_t audioTime = GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
        CHECK_AND_RETURN_RET_NOLOG(audioTime != -1, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        struct timespec timestamp = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &timestamp);
        int64_t curTime = timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
        MEDIA_LOGI("ReadWriteAudioBufferMix audio to ScreenCapture timeWindow: %{public}" PRId64
                   " firstAudioFramePts: %{public}" PRId64,
            curTime - audioTime, audioTime);
        int64_t timeWindow = firstVideoFramePts_.load() - audioTime;
        MEDIA_LOGI("ReadWriteAudioBufferMix video to audio timeWindow: %{public}" PRId64, timeWindow);
        return VideoAudioSyncMixMode(length, timeWindow, innerAudioBuffer, micAudioBuffer);
    }
    return ReadWriteAudioBufferMixCore(length, innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMixMode(uint32_t length)
{
    std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
    std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
    AudioDataSourceReadAtActionState ret = ReadWriteAudioBufferMix(length, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGD("AudioDataSource ReadAtMixMode ret: %{public}d", static_cast<int32_t>(ret));
    return ret;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMicMode(uint32_t length)
{
    auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
    if (micCapture == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (micCapture->IsRecording()) {
        std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
        if (micCapture->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
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
        audioBufferQ_.emplace_back(micAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(micCapture->ReleaseAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "micAudioCapture ReleaseAudioBuffer failed");
        micAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncInnerMode(uint32_t length, int64_t timeWindow,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (innerAudioBuffer && innerCapture) {
            innerCapture->AddBufferFrom(-1 * timeWindow, length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (innerCapture) {
            innerCapture->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        CHECK_AND_RETURN_RET_LOG(innerAudioBuffer != nullptr, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG,
            "innerAudioBuffer nullptr");
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64, innerAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        audioBufferQ_.emplace_back(innerAudioBuffer);
        SetAudioFirstFramePts(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        innerCapture->ReleaseAudioBuffer();
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtInnerMode(uint32_t length)
{
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (innerCapture == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (innerCapture->IsRecording()) {
        std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
        if (innerCapture->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer inner success");
        if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1 && innerAudioBuffer) {
            int64_t timeWindow = firstVideoFramePts_.load() - innerAudioBuffer->timestamp;
            return VideoAudioSyncInnerMode(length, timeWindow, innerAudioBuffer);
        }
        if (innerAudioBuffer == nullptr) {
            MEDIA_LOGE("innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64, innerAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        audioBufferQ_.emplace_back(innerAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(innerCapture->ReleaseAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioCapture ReleaseAudioBuffer failed");
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAudioBuffer(const uint32_t &length)
{
    MEDIA_LOGD("AudioDataSource ReadAt start");
    if (!screenCaptureServer_->IsState(CAP_ACTIVE)) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstVideoFramePts_.load() == -1) { // video frame not come
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (type_ == AVScreenCaptureMixMode::MIX_MODE) {
        return ReadAtMixMode(length);
    }
    if (type_ == AVScreenCaptureMixMode::INNER_MODE) {
        return ReadAtInnerMode(length);
    }
    if (type_ == AVScreenCaptureMixMode::MIC_MODE) {
        return ReadAtMicMode(length);
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

void AudioDataSource::HandlePastMicBuffer(std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer->timestamp < lastWriteAudioFramePts_.load() &&
        micAudioBuffer->timestamp < lastMicAudioFramePts_.load() + AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS &&
        lastWriteType_.load() == AVScreenCaptureMixBufferType::INNER) {
        auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
        if (micCapture) {
            micCapture->ReleaseAudioBuffer();
        }
        MEDIA_LOGD("ABuffer drop mix mic error cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        micAudioBuffer = nullptr;
    } // drop past mic data when switch,keep when mic stable
}

void AudioDataSource::HandleSwitchToSpeakerOptimise(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (GetAudioRendererState() == 0 && innerCapture && screenCaptureServer_->IsMicrophoneSwitchTurnOn() &&
        micAudioBuffer->buffer && lastWriteType_.load() == AVScreenCaptureMixBufferType::MIX) {
        if (stableStopInnerSwitchCount_ > INNER_SWITCH_MIC_REQUIRE_COUNT) { // optimise inner while use speaker
            MEDIA_LOGI("ABuffer stop mix inner optimise cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
            innerCapture->Stop();
            stableStopInnerSwitchCount_ = 0;
        } else {
            stableStopInnerSwitchCount_++;
        }
    }
}

void AudioDataSource::HandleBufferTimeStamp(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer) {
        HandlePastMicBuffer(micAudioBuffer);
    }
    if (innerAudioBuffer) {
        if (innerAudioBuffer->timestamp < lastWriteAudioFramePts_.load() && GetAudioRendererState() == 0) {
            auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
            if (innerCapture) {
                innerCapture->ReleaseAudioBuffer();
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

AudioDataSourceReadAtActionState AudioDataSource::MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    if (innerAudioBuffer && innerAudioBuffer->buffer && micAudioBuffer && micAudioBuffer->buffer) {
        auto mixData = std::make_unique<uint8_t[]>(innerAudioBuffer->length);
        CHECK_AND_RETURN_RET_LOG(mixData != nullptr, AudioDataSourceReadAtActionState::RETRY_SKIP,
            "mixData memory allocation failed");
        int channels = 2;
        MixAudio(innerAudioBuffer, micAudioBuffer, reinterpret_cast<char *>(mixData.get()), channels);
        MEDIA_LOGD("ABuffer write mix mix cur:%{public}" PRId64 " mic:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::MIX);
        audioBufferQ_.emplace_back(mixData, innerAudioBuffer->timestamp);
    } else if (innerAudioBuffer && innerAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::INNER);
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(innerAudioBuffer);
    } else if (micAudioBuffer && micAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix mic cur:%{public}" PRId64 " last: %{public}" PRId64, micAudioBuffer->timestamp,
            lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_.store(AVScreenCaptureMixBufferType::MIC);
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(micAudioBuffer);
    } else {
        MEDIA_LOGE("without buffer write");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    SetMixAudioTypeLog();
    ReleaseAudioBuffer(innerAudioBuffer, micAudioBuffer);
    return AudioDataSourceReadAtActionState::OK;
}

void AudioDataSource::SetMixAudioTypeLog()
{
    if (lastWriteType_ != audioType_) {
        MEDIA_LOGI("get audio buffer times type: %{public}d, size: %{public}" PRIu64, audioType_.load(),
            audioTypeSize_.load());
        audioType_.store(lastWriteType_);
        audioTypeSize_ = 1;
    } else {
        audioTypeSize_++;
    }
}

void AudioDataSource::ReleaseAudioBuffer(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer) {
        auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
        if (innerCapture) {
            innerCapture->ReleaseAudioBuffer();
        }
        innerAudioBuffer = nullptr;
    }
    if (micAudioBuffer) {
        auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
        if (micCapture) {
            micCapture->ReleaseAudioBuffer();
        }
        micAudioBuffer = nullptr;
    }
}

int32_t AudioDataSource::GetSize(int64_t &size)
{
    int32_t ret = MSERR_UNKNOWN;
    auto innerCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::INNER);
    if (innerCapture) {
        size_t bufferLen = 0;
        ret = innerCapture->GetBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    auto micCapture = screenCaptureServer_->GetAudioCapture(CaptureRole::MIC);
    if (micCapture) {
        size_t bufferLen = 0;
        ret = micCapture->GetBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    return ret;
}

void AudioDataSource::MixAudio(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer, char *mixData, int channels)
{
    MEDIA_LOGD("AudioDataSource MixAudio");
    int const max = 32767;
    int const min = -32768;
    double const splitNum = 32;
    int const doubleChannels = 2;
    double coefficient = 1;
    char *srcData[2] = {
        reinterpret_cast<char *>(innerAudioBuffer->buffer), reinterpret_cast<char *>(micAudioBuffer->buffer)
    };
    if (channels == 0) {
        return;
    }

    const int32_t totalLen = static_cast<int32_t>(innerAudioBuffer->length / (sizeof(short) / sizeof(char)));
    for (int32_t totalNum = 0; totalNum < totalLen; totalNum++) {
        int temp = 0;
        for (int channelNum = 0; channelNum < channels; channelNum++) {
            CHECK_AND_CONTINUE(!(channelNum == 1 && micAudioBuffer->length <= totalNum * channels));
            temp += *reinterpret_cast<short *>(srcData[channelNum] + totalNum * channels);
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
        *reinterpret_cast<short *>(mixData + totalNum * doubleChannels) = static_cast<short>(output);
    }
}

int32_t AudioDataSource::LostFrameNum(const int64_t &timestamp)
{
    return static_cast<int32_t>(
        (timestamp - pauseDuration_ - (writedFrameTime_ + firstAudioFramePts_)) / FILL_AUDIO_FRAME_DURATION_IN_NS);
}

void AudioDataSource::FillLostBuffer(const int64_t &lostNum, const int64_t &timestamp, const uint32_t &bufferSize)
{
    CHECK_AND_RETURN_LOG(bufferSize > 0, "AudioDataSource::FillLostBuffer: bufferSize is invalid");
    MEDIA_LOGI("AudioDataSource::FillLostBuffer: lostNum=%{public}" PRId64 ", timestamp=%{public}" PRId64
               ", bufferSize=%{public}" PRId32,
        lostNum, timestamp, bufferSize);
    auto pts = timestamp;
    for (int64_t i = 0; i < lostNum; i++) {
        auto buffer = std::make_unique<uint8_t[]>(bufferSize);
        pts -= FILL_AUDIO_FRAME_DURATION_IN_NS;
        audioBufferQ_.emplace_front(buffer, pts);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr && buffer->memory_ != nullptr,
        AudioDataSourceReadAtActionState::RETRY_SKIP, "buffer or buffer->memory_ nullptr");
    if (!audioBufferQ_.empty()) {
        auto &audioBuffer = audioBufferQ_.front();
        auto lostNum = LostFrameNum(audioBuffer.timestamp);
        if (lostNum >= FILL_LOST_FRAME_COUNT_THRESHOLD) {
            FillLostBuffer(lostNum, audioBuffer.timestamp, length);
        }
        audioBufferQ_.front().WriteTo(buffer->memory_, length);
        audioBufferQ_.pop_front();
        writedFrameTime_ += FILL_AUDIO_FRAME_DURATION_IN_NS;
        return AudioDataSourceReadAtActionState::OK;
    }
    const auto &ret = ReadAudioBuffer(length);
    CHECK_AND_RETURN_RET_NOLOG(ret == AudioDataSourceReadAtActionState::OK, ret);
    if (!audioBufferQ_.empty()) {
        return ReadAt(buffer, length);
    }
    return ret;
}

AudioDataSource::CacheBuffer::CacheBuffer(const std::shared_ptr<AudioBuffer> &buf)
    : refBuf_(buf), timestamp(buf->timestamp)
{
}

AudioDataSource::CacheBuffer::CacheBuffer(std::unique_ptr<uint8_t[]> &buf, const int64_t &timestamp)
    : buf_(std::move(buf)), timestamp(timestamp)
{
}

void AudioDataSource::CacheBuffer::WriteTo(const std::shared_ptr<AVMemory> &avMem, const uint32_t &len)
{
    if (buf_) {
        avMem->Write(buf_.get(), len, 0);
    } else if (refBuf_) {
        avMem->Write(refBuf_->buffer, len, 0);
    } else {
        MEDIA_LOGE("AudioDataSource::CacheBuffer::WriteTo: buffer is null");
    }
}
} // namespace OHOS::Media
