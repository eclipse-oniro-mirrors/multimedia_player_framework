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

void AudioDataSource::SpeakerStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    uint32_t changeInfoSize = allAudioRendererChangeInfos.size();
    if (changeInfoSize == 0) {
        return;
    }
    bool speakerAlive = HasSpeakerStream(allAudioRendererChangeInfos);
    if (speakerAlive != speakerAliveStatus_) {
        speakerAliveStatus_ = speakerAlive;
        CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
        screenCaptureServer_->OnSpeakerAliveStatusChanged(speakerAlive);
        if (speakerAlive) {
            MEDIA_LOGI("HEADSET Change to Speaker.");
        } else {
            MEDIA_LOGI("Speaker Change to HEADSET.");
        }
    }
}

#ifdef SUPPORT_CALL
void AudioDataSource::TelCallAudioStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: allAudioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("Client pid : %{public}d, State : %{public}d, usage : %{public}d",
            changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->rendererInfo.streamUsage));
        if (changeInfo->rendererInfo.streamUsage ==
            AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION &&
            (changeInfo->rendererState == RendererState::RENDERER_RUNNING ||
            changeInfo->rendererState == RendererState::RENDERER_PREPARED)) {
            screenCaptureServer_->TelCallAudioStateUpdated(true);
            return;
        }
    }
    screenCaptureServer_->TelCallAudioStateUpdated(false);
}
#endif

bool AudioDataSource::HasSpeakerStream(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    uint32_t changeInfoIndex = 0;
    uint32_t headSetCount = 0;
    bool hasSpeakerStream = true;
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: audioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("ChangeInfo Id: %{public}d, Client pid : %{public}d, State : %{public}d, DeviceType : %{public}d",
            changeInfoIndex, changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->outputDeviceInfo.deviceType_));
        if (changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADPHONES ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_ARM_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_NEARLINK) {
            headSetCount++;
        }
        changeInfoIndex++;
    }
    if (headSetCount == changeInfoIndex) { // only if all streams in headset
        hasSpeakerStream = false;
    }
    return hasSpeakerStream;
}

void AudioDataSource::VoIPStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    std::lock_guard<std::mutex> lock(voipStatusChangeMutex_);
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    bool isInVoIPCall = HasVoIPStream(allAudioRendererChangeInfos);
    if (isInVoIPCall_.load() == isInVoIPCall) {
        return;
    }
    isInVoIPCall_.store(isInVoIPCall);
    CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
    screenCaptureServer_->OnVoIPStatusChanged(isInVoIPCall);
}

bool AudioDataSource::HasVoIPStream(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: audioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("Client pid : %{public}d, State : %{public}d, usage : %{public}d",
            changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->rendererInfo.streamUsage));
        if (changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION ||
		    changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION) {
            return true;
        }
    }
    return false;
}

void AudioDataSource::SetAppPid(int32_t appid)
{
    appPid_ = appid;
}

int32_t AudioDataSource::GetAppPid()
{
    return appPid_ ;
}

bool AudioDataSource::GetIsInVoIPCall()
{
    return isInVoIPCall_.load();
}

bool AudioDataSource::IsInWaitMicSyncState()
{
    return isInWaitMicSyncState_;
}

bool AudioDataSource::GetSpeakerAliveStatus()
{
    return speakerAliveStatus_;
}

void AudioDataSource::SetAppName(std::string appName)
{
    appName_ = appName;
}

int32_t AudioDataSource::RegisterAudioRendererEventListener(const int32_t clientPid,
    const std::shared_ptr<AudioRendererStateChangeCallback> &callback)
{
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "audio callback is null");
    int32_t ret = AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(clientPid, callback);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
        SpeakerStateUpdate(audioRendererChangeInfos);
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) == 0 && region == "CN") {
        VoIPStateUpdate(audioRendererChangeInfos);
    }
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
        " firstVideoFramePts: %{public}" PRId64, curTime - firstFramePts, firstFramePts);
}

void AudioDataSource::SetAudioFirstFramePts(int64_t firstFramePts)
{
    if (firstAudioFramePts_.load() == -1) {
        firstAudioFramePts_.store(firstFramePts);
        MEDIA_LOGI("firstAudioFramePts_: %{public}" PRId64, firstFramePts);
    }
}

ScreenCaptureServer* AudioDataSource::GetScreenCaptureServer()
{
    return screenCaptureServer_;
}

AudioDataSourceReadAtActionState AudioDataSource::WriteInnerAudio(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(innerAudioBuffer->timestamp); // update firstAudioFramePts in case re-sync
    return MixModeBufferWrite(innerAudioBuffer, tmp, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMicAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || micAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or micAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(micAudioBuffer->timestamp);
    return MixModeBufferWrite(tmp, micAudioBuffer, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMixAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr || micAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    SetAudioFirstFramePts(std::min(micAudioBuffer->timestamp, innerAudioBuffer->timestamp));
    return MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::InnerMicAudioSync(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    int64_t timeWindow = micAudioBuffer->timestamp - innerAudioBuffer->timestamp;
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // mic before inner
        const auto &capture = screenCaptureServer_->GetMicAudioCapture();
        CHECK_AND_RETURN_RET_NOLOG(capture != nullptr, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        auto count = capture->DropBufferUntil(innerAudioBuffer->timestamp);
        MEDIA_LOGI("mic before inner timeDiff: %{public}" PRId64 " DropBufferUntil inner time: %{public}" PRId64
                   " lastAudioPts: %{public}" PRId64 " count: %{public}" PRId32,
                   timeWindow, innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load(), count);
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS) { // Write mix
        return WriteMixAudio(buffer, length, innerAudioBuffer, micAudioBuffer);
    } else { // Write Inner data Before mic timeWindow >= AUDIO_INTERVAL_IN_NS
        return WriteInnerAudio(buffer, length, innerAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncMixMode(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (micAudioBuffer && screenCaptureServer_->GetMicAudioCapture() && mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("mic AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            screenCaptureServer_->GetMicAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture() && !mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("inner AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            screenCaptureServer_->GetInnerAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (micAudioBuffer && screenCaptureServer_->GetMicAudioCapture()) {
            screenCaptureServer_->GetMicAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        return ReadWriteAudioBufferMixCore(buffer, length, innerAudioBuffer, micAudioBuffer);
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

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMixCore(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer == nullptr && micAudioBuffer) {
        return WriteMicAudio(buffer, length, micAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer == nullptr) {
        if (screenCaptureServer_->IsStopAcquireAudioBufferFlag() && isInWaitMicSyncState_) {
            return WriteInnerAudio(buffer, length, innerAudioBuffer);
        }
        if (screenCaptureServer_->IsMicrophoneSwitchTurnOn()) {
            int64_t currentAudioTime = 0;
            screenCaptureServer_->GetInnerAudioCapture()->GetCurrentAudioTime(currentAudioTime);
            if (currentAudioTime - innerAudioBuffer->timestamp < MAX_INNER_AUDIO_TIMEOUT_IN_NS) { // 2s
                isInWaitMicSyncState_ = true;
                return AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL;
            } else {
                MEDIA_LOGD("isInWaitMicSyncState close");
                isInWaitMicSyncState_ = false;
            }
        }
        return WriteInnerAudio(buffer, length, innerAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer) {
        return InnerMicAudioSync(buffer, length, innerAudioBuffer, micAudioBuffer);
    }
    if (innerAudioBuffer == nullptr && micAudioBuffer == nullptr) {
        MEDIA_LOGD("acquire none inner mic buffer");
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    return AudioDataSourceReadAtActionState::OK;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMix(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (screenCaptureServer_->IsMicrophoneCaptureRunning()) {
        if (screenCaptureServer_->GetMicAudioCapture()->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
        }
    }
    if (screenCaptureServer_->IsInnerCaptureRunning()) {
        if (screenCaptureServer_->GetInnerAudioCapture()->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
        }
    }
    CHECK_AND_RETURN_RET_NOLOG(innerAudioBuffer || micAudioBuffer, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1) { // video audio sync
        int64_t audioTime = GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
        CHECK_AND_RETURN_RET_NOLOG(audioTime != -1, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        struct timespec timestamp = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &timestamp);
        int64_t curTime = timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
        MEDIA_LOGI("ReadWriteAudioBufferMix audio to ScreenCapture timeWindow: %{public}" PRId64
            " firstAudioFramePts: %{public}" PRId64, curTime - audioTime, audioTime);
        int64_t timeWindow = firstVideoFramePts_.load() - audioTime;
        MEDIA_LOGI("ReadWriteAudioBufferMix video to audio timeWindow: %{public}" PRId64, timeWindow);
        return VideoAudioSyncMixMode(buffer, length, timeWindow, innerAudioBuffer, micAudioBuffer);
    }
    return ReadWriteAudioBufferMixCore(buffer, length, innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMixMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
    std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
    AudioDataSourceReadAtActionState ret = ReadWriteAudioBufferMix(buffer, length, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGD("AudioDataSource ReadAtMixMode ret: %{public}d", static_cast<int32_t>(ret));
    return ret;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMicMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    if (screenCaptureServer_->GetMicAudioCapture() == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (screenCaptureServer_->IsMicrophoneCaptureRunning()) {
        std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
        if (screenCaptureServer_->GetMicAudioCapture()->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer mic success");
        if (buffer->memory_ == nullptr || micAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or micAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write mic cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
        audioBufferQ_.emplace_back(micAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(screenCaptureServer_->ReleaseMicAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "micAudioCapture ReleaseAudioBuffer failed");
        micAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncInnerMode(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        audioBufferQ_.emplace_back(innerAudioBuffer);
        SetAudioFirstFramePts(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        screenCaptureServer_->ReleaseInnerAudioBuffer();
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtInnerMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    if (screenCaptureServer_->GetInnerAudioCapture() == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (screenCaptureServer_->IsInnerCaptureRunning()) {
        std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
        if (screenCaptureServer_->GetInnerAudioCapture()->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer inner success");
        if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1 && innerAudioBuffer) {
            int64_t timeWindow = firstVideoFramePts_.load() - innerAudioBuffer->timestamp;
            return VideoAudioSyncInnerMode(buffer, length, timeWindow, innerAudioBuffer);
        }
        if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        audioBufferQ_.emplace_back(innerAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(screenCaptureServer_->ReleaseInnerAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioCapture ReleaseAudioBuffer failed");
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAudioBuffer(
    std::shared_ptr<AVBuffer> &buffer, const uint32_t &length)
{
    MEDIA_LOGD("AudioDataSource ReadAt start");
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, AudioDataSourceReadAtActionState::RETRY_SKIP,
        "ReadAt screenCaptureServer null");
    if (screenCaptureServer_->GetSCServerCaptureState() != AVScreenCaptureState::STARTED) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstVideoFramePts_.load() == -1) { // video frame not come
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (type_ == AVScreenCaptureMixMode::MIX_MODE) {
        return ReadAtMixMode(buffer, length);
    }
    if (type_ == AVScreenCaptureMixMode::INNER_MODE) {
        return ReadAtInnerMode(buffer, length);
    }
    if (type_ == AVScreenCaptureMixMode::MIC_MODE) {
        return ReadAtMicMode(buffer, length);
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

void AudioDataSource::HandlePastMicBuffer(std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer->timestamp < lastWriteAudioFramePts_.load() &&
        micAudioBuffer->timestamp < lastMicAudioFramePts_.load() + AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS &&
        lastWriteType_ == AVScreenCaptureMixBufferType::INNER) { // drop past mic data when switch,keep when mic stable
        screenCaptureServer_->ReleaseMicAudioBuffer();
        MEDIA_LOGD("ABuffer drop mix mic error cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        micAudioBuffer = nullptr;
    }
}

void AudioDataSource::HandleSwitchToSpeakerOptimise(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (speakerAliveStatus_ && screenCaptureServer_ && screenCaptureServer_->IsMicrophoneSwitchTurnOn() &&
        !isInVoIPCall_ && micAudioBuffer->buffer &&
        lastWriteType_ == AVScreenCaptureMixBufferType::MIX && screenCaptureServer_->GetInnerAudioCapture()) {
        if (stableStopInnerSwitchCount_ > INNER_SWITCH_MIC_REQUIRE_COUNT) { // optimise inner while use speaker
            MEDIA_LOGI("ABuffer stop mix inner optimise cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
            screenCaptureServer_->StopInnerAudioCapture();
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
        if (innerAudioBuffer->timestamp < lastWriteAudioFramePts_.load()
            && !GetIsInVoIPCall() && speakerAliveStatus_) {
            screenCaptureServer_->ReleaseInnerAudioBuffer(); // drop past inner data while use speaker
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
    std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem)
{
    HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    if (innerAudioBuffer && innerAudioBuffer->buffer && micAudioBuffer && micAudioBuffer->buffer) {
        auto mixData = std::make_unique<uint8_t[]>(innerAudioBuffer->length);
        CHECK_AND_RETURN_RET_LOG(mixData != nullptr, AudioDataSourceReadAtActionState::RETRY_SKIP,
            "mixData memory allocation failed");
        int channels = 2;
        MixAudio(innerAudioBuffer, micAudioBuffer, reinterpret_cast<char*>(mixData.get()), channels);
        MEDIA_LOGD("ABuffer write mix mix cur:%{public}" PRId64 " mic:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIX;
        audioBufferQ_.emplace_back(mixData, innerAudioBuffer->timestamp);
    } else if (innerAudioBuffer && innerAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix inner cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(innerAudioBuffer);
    } else if (micAudioBuffer && micAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix mic cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(micAudioBuffer);
    } else {
        MEDIA_LOGE("without buffer write");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    if (innerAudioBuffer) {
        screenCaptureServer_->ReleaseInnerAudioBuffer();
        innerAudioBuffer = nullptr;
    }
    if (micAudioBuffer) {
        screenCaptureServer_->ReleaseMicAudioBuffer();
        micAudioBuffer = nullptr;
    }
    return AudioDataSourceReadAtActionState::OK;
}

int32_t AudioDataSource::GetSize(int64_t &size)
{
    size_t bufferLen = 0;
    int32_t ret = MSERR_UNKNOWN;
    if (screenCaptureServer_->GetInnerAudioCapture()) {
        ret = screenCaptureServer_->GetInnerAudioCaptureBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    if (screenCaptureServer_->GetMicAudioCapture()) {
        ret = screenCaptureServer_->GetMicAudioCaptureBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    return ret;
}

void AudioDataSource::MixAudio(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer, char* mixData, int channels)
{
    MEDIA_LOGD("AudioDataSource MixAudio");
    int const max = 32767;
    int const min = -32768;
    double const splitNum = 32;
    int const doubleChannels = 2;
    double coefficient = 1;
    int totalNum = 0;
    char* srcData[2] = {
        reinterpret_cast<char*>(innerAudioBuffer->buffer),
        reinterpret_cast<char*>(micAudioBuffer->buffer)
    };
    if (channels == 0) {
        return;
    }

    for (totalNum = 0; totalNum < innerAudioBuffer->length / (sizeof(short) / sizeof(char)); totalNum++) {
        int temp = 0;
        for (int channelNum = 0; channelNum < channels; channelNum++) {
            CHECK_AND_CONTINUE(!(channelNum == 1 && micAudioBuffer->length <= totalNum * channels));
            temp += *reinterpret_cast<short*>(srcData[channelNum] + totalNum * channels);
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
        *reinterpret_cast<short*>(mixData + totalNum * doubleChannels) = static_cast<short>(output);
    }
}

int32_t AudioDataSource::LostFrameNum(const int64_t &timestamp)
{
    return static_cast<int32_t>(
        (timestamp - (writedFrameTime_ + firstAudioFramePts_)) / FILL_AUDIO_FRAME_DURATION_IN_NS);
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
    const auto &ret = ReadAudioBuffer(buffer, length);
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
}
