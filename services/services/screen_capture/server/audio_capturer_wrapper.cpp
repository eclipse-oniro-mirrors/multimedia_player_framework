/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "audio_capturer_wrapper.h"

#include "ipc_skeleton.h"
#include "locale_config.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "scope_guard.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureACW"};
}

namespace OHOS {
namespace Media {
constexpr int64_t SEC_TO_NS = 1000000000;

int64_t GetCurrentTimeNs()
{
    struct timespec ts = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * SEC_TO_NS + static_cast<int64_t>(ts.tv_nsec);
}

void AudioCapturerCallbackImpl::OnInterrupt(const InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("OnInterrupt hintType:%{public}d, eventType:%{public}d, forceType:%{public}d", interruptEvent.hintType,
        interruptEvent.eventType, interruptEvent.forceType);
}

void AudioCapturerCallbackImpl::OnStateChange(const CapturerState state)
{
    MEDIA_LOGI("OnStateChange state:%{public}d", state);
}

int32_t AudioCapturerWrapper::Start(const OHOS::AudioStandard::AppInfo &appInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsRecording()) {
        MEDIA_LOGE("Start failed, is running, threadName:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }
    appInfo_ = appInfo;
    std::shared_ptr<AudioCapturer> audioCapturer = CreateAudioCapturer(appInfo);
    CHECK_AND_RETURN_RET_LOG(audioCapturer != nullptr, MSERR_UNKNOWN_AUDIO_CREATE,
        "Start failed, create AudioCapturer failed");
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"] == bundleName_) {
        std::vector<SourceType> targetSources = {SourceType::SOURCE_TYPE_MIC, SourceType::SOURCE_TYPE_VOICE_CALL,
            SourceType::SOURCE_TYPE_VOICE_MESSAGE, SourceType::SOURCE_TYPE_CAMCORDER};
        if (isInVoIPCall_.load()) {
            targetSources.push_back(SourceType::SOURCE_TYPE_VOICE_COMMUNICATION);
        }
        int32_t ret = audioCapturer->SetAudioSourceConcurrency(targetSources);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("SetAudioSourceConcurrency failed, ret:%{public}d, threadName:%{public}s", ret,
                threadName_.c_str());
        }
    }
    {
        std::unique_lock<std::shared_mutex> capturerLock(audioCapturerMutex_);
        audioCapturer_ = audioCapturer;
    }
    captureState_.store(CAPTURER_RECORDING);
    if (!audioCapturer->Start()) {
        MEDIA_LOGE("Start failed, AudioCapturer Start failed, threadName:%{public}s", threadName_.c_str());
        {
            std::unique_lock<std::shared_mutex> capturerLock(audioCapturerMutex_);
            audioCapturer_ = nullptr;
        }
        captureState_.store(CAPTURER_STOPED);
        audioCapturer->Release();
        OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
        return MSERR_UNKNOWN_AUDIO_START;
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Start success, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsStop() || captureState_.load() == AudioCapturerWrapperState::CAPTURER_UNKNOWN) {
        return MSERR_OK;
    }
    captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPPING);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop S, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    std::shared_ptr<AudioCapturer> capturer;
    {
        std::unique_lock<std::shared_mutex> capturerLock(audioCapturerMutex_);
        capturer = audioCapturer_;
        audioCapturer_ = nullptr;
    }
    if (capturer != nullptr) {
        capturer->Stop();
    }
    {
        std::unique_lock<std::mutex> bufferLock(bufferMutex_);
        MEDIA_LOGD("0x%{public}06" PRIXPTR " Stop pop, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
        while (!availBuffers_.empty()) {
            availBuffers_.pop_front();
        }
        bufferCond_.notify_all();
    }
    if (capturer != nullptr) {
        capturer->Release();
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop E, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    captureState_.store(AudioCapturerWrapperState::CAPTURER_STOPED);
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::UpdateAudioCapturerConfig(ScreenCaptureContentFilter &filter)
{
    MEDIA_LOGI("AudioCapturerWrapper::UpdateAudioCapturerConfig start");
    AudioPlaybackCaptureConfig config;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        contentFilter_ = filter;
        SetInnerStreamUsage(config.filterOptions.usages);
        if (contentFilter_.filteredAudioContents.find(
                AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO) !=
            contentFilter_.filteredAudioContents.end()) {
            config.filterOptions.pids.push_back(appInfo_.appPid);
            config.filterOptions.pidFilterMode = OHOS::AudioStandard::FilterMode::EXCLUDE;
            MEDIA_LOGI("UpdateAudioCapturerConfig exclude current app audio");
        }
    }
    std::shared_ptr<AudioCapturer> capturer;
    {
        std::shared_lock<std::shared_mutex> capturerLock(audioCapturerMutex_);
        CHECK_AND_RETURN_RET_LOG(audioCapturer_ != nullptr, MSERR_INVALID_VAL,
            "AudioCapturerWrapper::UpdateAudioCapturerConfig audioCapturer_ is nullptr");
        capturer = audioCapturer_;
    }
    int32_t ret = capturer->UpdatePlaybackCaptureConfig(config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL,
        "AudioCapturerWrapper::UpdateAudioCapturerConfig failed");
    MEDIA_LOGI("AudioCapturerWrapper::UpdateAudioCapturerConfig success");
    return MSERR_OK;
}

AudioCapturerWrapperState AudioCapturerWrapper::GetAudioCapturerState()
{
    return captureState_.load();
}

void AudioCapturerWrapper::SetInnerStreamUsage(std::vector<OHOS::AudioStandard::StreamUsage> &usages)
{
    // If do not call this function, the audio framework use MUSIC/MOVIE/GAME/AUDIOBOOK
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_MUSIC);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_ALARM);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_MOVIE);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_GAME);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_AUDIOBOOK);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_NAVIGATION);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_VOICE_ASSISTANT);
    usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MESSAGE);
    if (contentFilter_.filteredAudioContents.find(
            AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO) ==
        contentFilter_.filteredAudioContents.end()) {
        usages.push_back(OHOS::AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION);
    }
    if (isInVoIPCall_.load()) {
        usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION);
        usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION);
    }
}

OHOS::AudioStandard::AudioCapturerOptions AudioCapturerWrapper::BuildCapturerOptions(
    OHOS::AudioStandard::AppInfo &appInfo)
{
    OHOS::AudioStandard::AudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo.samplingRate = static_cast<AudioSamplingRate>(audioInfo_.audioSampleRate);
    capturerOptions.streamInfo.channels = static_cast<AudioChannel>(audioInfo_.audioChannels);
    capturerOptions.streamInfo.encoding = AudioEncodingType::ENCODING_PCM;
    capturerOptions.streamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
    if (audioInfo_.audioSource == AudioCaptureSourceType::SOURCE_DEFAULT ||
        audioInfo_.audioSource == AudioCaptureSourceType::MIC) {
        capturerOptions.capturerInfo.sourceType = isInVoIPCall_.load() ? SourceType::SOURCE_TYPE_VOICE_COMMUNICATION
                                                                       : SourceType::SOURCE_TYPE_MIC;
    } else if (audioInfo_.audioSource == AudioCaptureSourceType::ALL_PLAYBACK ||
        audioInfo_.audioSource == AudioCaptureSourceType::APP_PLAYBACK) {
        capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE;
        SetInnerStreamUsage(capturerOptions.playbackCaptureConfig.filterOptions.usages);
        if (isInVoIPCall_.load()) {
            appInfo.appTokenId = IPCSkeleton::GetSelfTokenID();
            appInfo.appFullTokenId = IPCSkeleton::GetSelfTokenID();
        }
    }
    if (contentFilter_.filteredAudioContents.find(
            AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO) !=
        contentFilter_.filteredAudioContents.end()) {
        capturerOptions.playbackCaptureConfig.filterOptions.pids.push_back(appInfo.appPid);
        capturerOptions.playbackCaptureConfig.filterOptions.pidFilterMode = OHOS::AudioStandard::FilterMode::EXCLUDE;
        MEDIA_LOGI("createAudioCapturer exclude current app audio");
    }
    capturerOptions.capturerInfo.capturerFlags = 0;
    capturerOptions.strategy = {AudioConcurrencyMode::MIX_WITH_OTHERS};
    return capturerOptions;
}

bool AudioCapturerWrapper::SetupCapturerCallbacks(const std::shared_ptr<AudioCapturer> &capturer)
{
    auto callback = std::make_shared<AudioCapturerCallbackImpl>();
    if (capturer->SetCapturerCallback(callback) != MSERR_OK) {
        MEDIA_LOGE("SetCapturerCallback failed, threadName:%{public}s", threadName_.c_str());
        return false;
    }
    if (capturer->SetCaptureMode(AudioCaptureMode::CAPTURE_MODE_CALLBACK) != MSERR_OK) {
        MEDIA_LOGE("SetCaptureMode failed, threadName:%{public}s", threadName_.c_str());
        return false;
    }
    auto readCallback = std::make_shared<AudioCapturerReadCallbackImpl>(shared_from_this());
    if (capturer->SetCapturerReadCallback(readCallback) != MSERR_OK) {
        MEDIA_LOGE("SetCapturerReadCallback failed, threadName:%{public}s", threadName_.c_str());
        return false;
    }
    return true;
}

std::shared_ptr<AudioCapturer> AudioCapturerWrapper::CreateAudioCapturer(const OHOS::AudioStandard::AppInfo &appInfo)
{
    bundleName_ = GetClientBundleName(appInfo.appUid);
    OHOS::AudioStandard::AppInfo newInfo = appInfo;
    auto capturerOptions = BuildCapturerOptions(newInfo);
    std::shared_ptr<AudioCapturer> audioCapturer = AudioCapturer::Create(capturerOptions, newInfo);
    CHECK_AND_RETURN_RET_LOG(audioCapturer != nullptr, nullptr, "AudioCapturer::Create failed");
    if (!SetupCapturerCallbacks(audioCapturer)) {
        audioCapturer->Release();
        return nullptr;
    }
    return audioCapturer;
}

void AudioCapturerWrapper::PartiallyPrintLog(int32_t lineNumber, std::string str)
{
    if (captureAudioLogCountMap_.count(lineNumber) == 0) {
        captureAudioLogCountMap_[lineNumber] = 0;
    }
    if (captureAudioLogCountMap_[lineNumber] % AC_LOG_SKIP_NUM == 0) {
        MEDIA_LOGE("%{public}s", str.c_str());
        captureAudioLogCountMap_[lineNumber] = 0;
    }
    captureAudioLogCountMap_[lineNumber]++;
}

std::shared_ptr<CacheBuffer> AudioCapturerWrapper::CreateCacheBuffer(const OHOS::AudioStandard::BufferDesc &bufDesc,
    int64_t audioTimestamp, const std::shared_ptr<OHOS::AudioStandard::AudioCapturer> &capturer)
{
    if (bufDesc.bufLength > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
        MEDIA_LOGE("CreateCacheBuffer bufLength too large: %{public}zu", bufDesc.bufLength);
        return nullptr;
    }
    auto bufferLen = static_cast<int32_t>(bufDesc.bufLength);
    ON_SCOPE_EXIT(0)
    {
        capturer->Enqueue(bufDesc);
    };
    if (isMute_.load()) {
        return std::make_shared<CacheBuffer>(nullptr, bufferLen, audioTimestamp, audioInfo_.audioSource);
    }
    auto ownedBuf = std::make_unique<uint8_t[]>(bufferLen);
    if (memcpy_s(ownedBuf.get(), bufferLen, bufDesc.buffer, bufferLen) != EOK) {
        return nullptr;
    }
    return std::make_shared<CacheBuffer>(std::move(ownedBuf), bufferLen, audioTimestamp, audioInfo_.audioSource);
}

void AudioCapturerWrapper::NotifyBufferAvailable(const std::shared_ptr<AudioBufferAvailableCallback> &cb)
{
    if (!IsRecording()) {
        return;
    }
    if (screenCaptureCb_) {
        screenCaptureCb_->OnAudioBufferAvailable(true, audioInfo_.audioSource);
    }
    if (cb) {
        cb->OnBufferAvailable(audioInfo_.audioSource);
    }
}

void AudioCapturerWrapper::OnReadData(size_t length)
{
    (void)length;
    OHOS::AudioStandard::BufferDesc bufDesc;
    OHOS::AudioStandard::Timestamp timestamp;
    std::shared_ptr<AudioCapturer> capturer;
    {
        std::shared_lock<std::shared_mutex> capturerLock(audioCapturerMutex_);
        CHECK_AND_RETURN_LOG(audioCapturer_ != nullptr, "OnReadData audioCapturer_ is nullptr, name:%{public}s",
            threadName_.c_str());
        capturer = audioCapturer_;
    }
    if (capturer->GetBufferDesc(bufDesc) != MSERR_OK) {
        MEDIA_LOGE("OnReadData GetBufferDesc failed, name:%{public}s", threadName_.c_str());
        return;
    }
    bool timeRet = capturer->GetTimeStampInfo(timestamp, OHOS::AudioStandard::Timestamp::Timestampbase::MONOTONIC);
    if (bufDesc.bufLength == 0 || bufDesc.buffer == nullptr || !timeRet || !IsRecording()) {
        capturer->Enqueue(bufDesc);
        return;
    }
    int64_t audioTimestamp = static_cast<int64_t>(timestamp.time.tv_sec) * SEC_TO_NS +
        static_cast<int64_t>(timestamp.time.tv_nsec);
    if (audioInfo_.audioSource != AudioCaptureSourceType::SOURCE_DEFAULT &&
        audioInfo_.audioSource != AudioCaptureSourceType::MIC) {
        audioTimestamp += INNER_AUDIO_READ_TO_HEAR_TIME;
    }
    auto cacheBuf = CreateCacheBuffer(bufDesc, audioTimestamp, capturer);
    CHECK_AND_RETURN_LOG(cacheBuf != nullptr, "OnReadData CreateCacheBuffer failed, name:%{public}s",
        threadName_.c_str());
    std::shared_ptr<AudioBufferAvailableCallback> cb;
    {
        std::unique_lock<std::mutex> lock(bufferMutex_);
        if (!IsRecording()) {
            MEDIA_LOGD("OnReadData is not running after acquire, drop frame, name:%{public}s", threadName_.c_str());
            return;
        }
        if (availBuffers_.size() > MAX_AUDIO_BUFFER_SIZE) {
            PartiallyPrintLog(__LINE__, "consume slow, drop oldest audio frame" + threadName_);
            availBuffers_.pop_front();
        }
        availBuffers_.push_back(cacheBuf);
        cb = bufferAvailableCb_.lock();
    }
    bufferCond_.notify_all();
    NotifyBufferAvailable(cb);
}

void AudioCapturerWrapper::SetBufferAvailableCallback(std::shared_ptr<AudioBufferAvailableCallback> cb)
{
    std::lock_guard<std::mutex> lock(bufferMutex_);
    bufferAvailableCb_ = cb;
}

void AudioCapturerWrapper::SetIsMute(bool isMute)
{
    isMute_.store(isMute);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetIsMute: %{public}d", FAKE_POINTER(this), isMute_.load());
}

int32_t AudioCapturerWrapper::UseUpAllLeftBufferUntil(int64_t audioTime)
{
    std::unique_lock<std::mutex> lock(bufferMutex_);
    CHECK_AND_RETURN_RET(IsRecording(), MSERR_OK);
    MEDIA_LOGI("UseUpAllLeftBufferUntil audioTime: %{public}" PRId64 ", threadName:%{public}s", audioTime,
        threadName_.c_str());
    if (bufferCond_.wait_for(lock, std::chrono::milliseconds(STOP_WAIT_TIMEOUT_IN_MS), [this, audioTime]() {
            return availBuffers_.empty() ||
                (availBuffers_.front() != nullptr && availBuffers_.front()->timestamp >= audioTime);
        })) {
        return MSERR_OK;
    }
    return MSERR_UNKNOWN;
}
int32_t AudioCapturerWrapper::DropBufferUntil(int64_t audioTime)
{
    int32_t dropCount = 0;
    {
        std::unique_lock<std::mutex> lock(bufferMutex_);
        CHECK_AND_RETURN_RET(IsRecording(), dropCount);
        MEDIA_LOGD("0x%{public}06" PRIXPTR " DropBufferUntil S, name:%{public}s", FAKE_POINTER(this),
            threadName_.c_str());
        while (!availBuffers_.empty() && availBuffers_.front() != nullptr &&
            availBuffers_.front()->timestamp < audioTime) {
            availBuffers_.pop_front();
            dropCount++;
        }
        MEDIA_LOGD("0x%{public}06" PRIXPTR " DropBufferUntil E, name:%{public}s", FAKE_POINTER(this),
            threadName_.c_str());
    }
    if (dropCount > 0) {
        bufferCond_.notify_all();
    }
    return dropCount;
}

int32_t AudioCapturerWrapper::AcquireAudioBuffer(std::shared_ptr<CacheBuffer> &cacheBuf)
{
    std::unique_lock<std::mutex> lock(bufferMutex_);
    CHECK_AND_RETURN_RET_LOG(IsRecording(), MSERR_UNKNOWN, "AcquireAudioBuffer failed, not running");
    if (availBuffers_.empty()) {
        return MSERR_UNKNOWN;
    }
    CHECK_AND_RETURN_RET_LOG(availBuffers_.front() != nullptr, MSERR_UNKNOWN,
        "AcquireAudioBuffer availBuffers_.front() is nullptr %{public}s", threadName_.c_str());
    cacheBuf = availBuffers_.front();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Acquire Buffer E, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::ReleaseAudioBuffer()
{
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Release Buffer S, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    CHECK_AND_RETURN_RET_LOG(IsRecording(), MSERR_UNKNOWN, "ReleaseAudioBuffer failed, not running");
    CHECK_AND_RETURN_RET_LOG(!availBuffers_.empty() && availBuffers_.front() != nullptr, MSERR_UNKNOWN,
        "ReleaseAudioBuffer failed, no frame to release");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " ABuffer release name:%{public}s time: %{public}" PRId64, FAKE_POINTER(this),
        threadName_.c_str(), availBuffers_.front()->timestamp);
    availBuffers_.pop_front();
    bufferCond_.notify_all();
    return MSERR_OK;
}

void AudioCapturerWrapper::SetIsInVoIPCall(bool isInVoIPCall)
{
    isInVoIPCall_.store(isInVoIPCall);
}

void AudioCapturerWrapper::OnStartFailed(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    if (screenCaptureCb_ != nullptr) {
        screenCaptureCb_->OnError(errorType, errorCode);
    }
}

AudioCapturerWrapper::~AudioCapturerWrapper()
{
    Stop();
    captureState_.store(CAPTURER_RELEASED);
    bufferCond_.notify_all();
}

bool AudioCapturerWrapper::IsRecording()
{
    return captureState_.load() == AudioCapturerWrapperState::CAPTURER_RECORDING;
}

bool AudioCapturerWrapper::IsStop()
{
    auto state = captureState_.load();
    return state == AudioCapturerWrapperState::CAPTURER_STOPPING || state == AudioCapturerWrapperState::CAPTURER_STOPED;
}

} // namespace Media
} // namespace OHOS
