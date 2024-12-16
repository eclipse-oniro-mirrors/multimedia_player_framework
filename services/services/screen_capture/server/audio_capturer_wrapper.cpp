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

#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "ipc_skeleton.h"
#include "locale_config.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureACW"};
}

namespace OHOS {
namespace Media {

void AudioCapturerCallbackImpl::OnInterrupt(const InterruptEvent &interruptEvent)
{
    MEDIA_LOGI("AudioCapturerCallbackImpl OnInterrupt hintType:%{public}d, eventType:%{public}d, forceType:%{public}d",
        interruptEvent.hintType, interruptEvent.eventType, interruptEvent.forceType);
}

void AudioCapturerCallbackImpl::OnStateChange(const CapturerState state)
{
    MEDIA_LOGI("AudioCapturerCallbackImpl OnStateChange state:%{public}d", state);
    switch (state) {
        case CAPTURER_PREPARED:
            MEDIA_LOGD("AudioCapturerCallbackImpl OnStateChange CAPTURER_PREPARED");
            break;
        default:
            MEDIA_LOGD("AudioCapturerCallbackImpl OnStateChange NOT A VALID state");
            break;
    }
}

int32_t AudioCapturerWrapper::Start(const OHOS::AudioStandard::AppInfo &appInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isRunning_.load()) {
        MEDIA_LOGE("Start failed, is running, threadName:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }

    appInfo_ = appInfo;
    std::shared_ptr<AudioCapturer> audioCapturer = CreateAudioCapturer(appInfo);
    CHECK_AND_RETURN_RET_LOG(audioCapturer != nullptr, MSERR_UNKNOWN, "Start failed, create AudioCapturer failed");
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(bundleName_) == 0) {
        std::vector<SourceType> targetSources = {
            SourceType::SOURCE_TYPE_MIC,
            SourceType::SOURCE_TYPE_VOICE_RECOGNITION,
            SourceType::SOURCE_TYPE_VOICE_MESSAGE,
            SourceType::SOURCE_TYPE_CAMCORDER
        };
        std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
        if (region == "CN") {
            targetSources.push_back(SourceType::SOURCE_TYPE_VOICE_COMMUNICATION);
        }
        int32_t ret = audioCapturer->SetAudioSourceConcurrency(targetSources);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("SetAudioSourceConcurrency failed, ret:%{public}d, threadName:%{public}s", ret,
                threadName_.c_str());
        }
    }
    if (!audioCapturer->Start()) {
        MEDIA_LOGE("Start failed, AudioCapturer Start failed, threadName:%{public}s", threadName_.c_str());
        audioCapturer->Release();
        audioCapturer = nullptr;
        OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
        return MSERR_UNKNOWN;
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Start success, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());

    isRunning_.store(true);
    readAudioLoop_ = std::make_unique<std::thread>([this] { this->CaptureAudio(); });
    audioCapturer_ = audioCapturer;
    captureState_.store(CAPTURER_RECORDING);
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause S, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    if (isRunning_.load()) {
        isRunning_.store(false);
        if (readAudioLoop_ != nullptr && readAudioLoop_->joinable()) {
            readAudioLoop_->join();
            readAudioLoop_.reset();
            readAudioLoop_ = nullptr;
        }
        if (audioCapturer_ != nullptr) {
            if (!audioCapturer_->Pause()) {
                MEDIA_LOGE("AudioCapturer Pause failed, threadName:%{public}s", threadName_.c_str());
            }
        }
    }
    captureState_.store(CAPTURER_PAUSED);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause E, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isRunning_.load()) {
        MEDIA_LOGE("Resume failed, is running, threadName:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }
    CHECK_AND_RETURN_RET_LOG(audioCapturer_ != nullptr, MSERR_UNKNOWN, "Resume failed, audioCapturer_ is nullptr");

    if (!audioCapturer_->Start()) {
        MEDIA_LOGE("AudioCapturer Start failed, threadName:%{public}s", threadName_.c_str());
        OnStartFailed(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL, SCREEN_CAPTURE_ERR_UNKNOWN);
        return MSERR_UNKNOWN;
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Resume success, threadName:%{public}s", FAKE_POINTER(this),
        threadName_.c_str());

    isRunning_.store(true);
    readAudioLoop_ = std::make_unique<std::thread>([this] { this->CaptureAudio(); });
    captureState_.store(CAPTURER_RECORDING);
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop S, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    isRunning_.store(false);
    if (readAudioLoop_ != nullptr && readAudioLoop_->joinable()) {
        readAudioLoop_->join();
        readAudioLoop_.reset();
        readAudioLoop_ = nullptr;
    }
    if (audioCapturer_ != nullptr) {
        audioCapturer_->Stop();
        audioCapturer_->Release();
        audioCapturer_ = nullptr;
    }
    std::unique_lock<std::mutex> bufferLock(bufferMutex_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Stop pop, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    while (!availBuffers_.empty()) {
        if (availBuffers_.front() != nullptr) {
            free(availBuffers_.front()->buffer);
            availBuffers_.front()->buffer = nullptr;
        }
        availBuffers_.pop();
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop E, threadName:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    captureState_.store(CAPTURER_STOPED);
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::UpdateAudioCapturerConfig(ScreenCaptureContentFilter &filter)
{
    MEDIA_LOGI("AudioCapturerWrapper::UpdateAudioCapturerConfig start");
    contentFilter_ = filter;
    AudioPlaybackCaptureConfig config;
    SetInnerStreamUsage(config.filterOptions.usages);
    if (contentFilter_.filteredAudioContents.find(
        AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO) !=
        contentFilter_.filteredAudioContents.end()) {
        config.filterOptions.pids.push_back(appInfo_.appPid);
        config.filterOptions.pidFilterMode = OHOS::AudioStandard::FilterMode::EXCLUDE;
        MEDIA_LOGI("UpdateAudioCapturerConfig exclude current app audio");
    }
    CHECK_AND_RETURN_RET_LOG(audioCapturer_ != nullptr, MSERR_INVALID_VAL,
        "AudioCapturerWrapper::UpdateAudioCapturerConfig audioCapturer_ is nullptr");
    int32_t ret = audioCapturer_->UpdatePlaybackCaptureConfig(config);
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
    if (contentFilter_.filteredAudioContents.find(
        AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_NOTIFICATION_AUDIO) ==
        contentFilter_.filteredAudioContents.end()) {
        usages.push_back(OHOS::AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION);
    }
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(bundleName_) == 0 && region == "CN") {
        usages.push_back(AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION);
    }
}

std::shared_ptr<AudioCapturer> AudioCapturerWrapper::CreateAudioCapturer(const OHOS::AudioStandard::AppInfo &appInfo)
{
    bundleName_ = GetClientBundleName(appInfo.appUid);
    OHOS::AudioStandard::AppInfo newInfo = appInfo;
    AudioCapturerOptions capturerOptions;
    capturerOptions.streamInfo.samplingRate = static_cast<AudioSamplingRate>(audioInfo_.audioSampleRate);
    capturerOptions.streamInfo.channels = static_cast<AudioChannel>(audioInfo_.audioChannels);
    capturerOptions.streamInfo.encoding = AudioEncodingType::ENCODING_PCM;
    capturerOptions.streamInfo.format = AudioSampleFormat::SAMPLE_S16LE;
    if (audioInfo_.audioSource == AudioCaptureSourceType::SOURCE_DEFAULT ||
        audioInfo_.audioSource == AudioCaptureSourceType::MIC) {
        if (isInVoIPCall_.load()) {
            capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_VOICE_COMMUNICATION;
        } else {
            capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_MIC; // Audio Source Type Mic is 0
        }
    } else if (audioInfo_.audioSource == AudioCaptureSourceType::ALL_PLAYBACK ||
        audioInfo_.audioSource == AudioCaptureSourceType::APP_PLAYBACK) {
        capturerOptions.capturerInfo.sourceType = SourceType::SOURCE_TYPE_PLAYBACK_CAPTURE;
        SetInnerStreamUsage(capturerOptions.playbackCaptureConfig.filterOptions.usages);
        std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
        if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(bundleName_) == 0 && region == "CN") {
            newInfo.appTokenId = IPCSkeleton::GetSelfTokenID();
            newInfo.appFullTokenId = IPCSkeleton::GetSelfTokenID();
        }
    }
    if (contentFilter_.filteredAudioContents.find(
        AVScreenCaptureFilterableAudioContent::SCREEN_CAPTURE_CURRENT_APP_AUDIO) !=
        contentFilter_.filteredAudioContents.end()) {
        capturerOptions.playbackCaptureConfig.filterOptions.pids.push_back(appInfo.appPid);
        capturerOptions.playbackCaptureConfig.filterOptions.pidFilterMode =
            OHOS::AudioStandard::FilterMode::EXCLUDE;
        MEDIA_LOGI("createAudioCapturer exclude current app audio");
    }
    capturerOptions.capturerInfo.capturerFlags = 0;
    capturerOptions.strategy = { AudioConcurrencyMode::MIX_WITH_OTHERS };
    std::shared_ptr<AudioCapturer> audioCapturer = AudioCapturer::Create(capturerOptions, newInfo);
    CHECK_AND_RETURN_RET_LOG(audioCapturer != nullptr, nullptr, "AudioCapturer::Create failed");
    std::shared_ptr<AudioCapturerCallbackImpl> callback = std::make_shared<AudioCapturerCallbackImpl>();
    int ret = audioCapturer->SetCapturerCallback(callback);
    if (ret != MSERR_OK) {
        audioCapturer->Release();
        MEDIA_LOGE("SetCapturerCallback failed, threadName:%{public}s", threadName_.c_str());
        return nullptr;
    }
    audioCaptureCallback_ = callback;
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

int32_t AudioCapturerWrapper::RelativeSleep(int64_t nanoTime)
{
    int32_t ret = -1; // -1 for bad result.
    CHECK_AND_RETURN_RET_LOG(nanoTime > 0, ret,
        "ACW AbsoluteSleep invalid sleep time :%{public}" PRId64 " ns", nanoTime);
    struct timespec time;
    time.tv_sec = nanoTime / AUDIO_NS_PER_SECOND;
    time.tv_nsec = nanoTime - (time.tv_sec * AUDIO_NS_PER_SECOND); // Avoids % operation.
    clockid_t clockId = CLOCK_MONOTONIC;
    const int relativeFlag = 0; // flag of relative sleep.
    ret = clock_nanosleep(clockId, relativeFlag, &time, nullptr);
    if (ret != 0) {
        MEDIA_LOGI("ACW RelativeSleep may failed, ret is :%{public}d", ret);
    }
    return ret;
}

int32_t AudioCapturerWrapper::CaptureAudio()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " CaptureAudio S, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    std::string name = threadName_.substr(0, std::min(threadName_.size(), static_cast<size_t>(MAX_THREAD_NAME_LENGTH)));
    pthread_setname_np(pthread_self(), name.c_str());
    size_t bufferLen;
    CHECK_AND_RETURN_RET_LOG(audioCapturer_ != nullptr && audioCapturer_->GetBufferSize(bufferLen) >= 0,
        MSERR_NO_MEMORY, "CaptureAudio GetBufferSize failed");
    Timestamp timestamp;
    std::shared_ptr<AudioBuffer> audioBuffer;
    while (true) {
        CHECK_AND_RETURN_RET_LOG(isRunning_.load(), MSERR_OK, "CaptureAudio is not running, stop capture %{public}s",
            name.c_str());
        uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferLen));
        CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MSERR_OK, "CaptureAudio buffer is no memory, stop capture"
            " %{public}s", name.c_str());
        audioBuffer = std::make_shared<AudioBuffer>(buffer, 0, 0, audioInfo_.audioSource);
        memset_s(audioBuffer->buffer, bufferLen, 0, bufferLen);
        int32_t bufferRead = audioCapturer_->Read(*(audioBuffer->buffer), bufferLen, true);
        if (bufferRead <= 0) {
            RelativeSleep(OHOS::Media::AUDIO_CAPTURE_READ_FAILED_WAIT_TIME);
            PartiallyPrintLog(__LINE__, "CaptureAudio read audio buffer failed " + name);
            continue;
        }
        audioBuffer->length = bufferRead;
        audioCapturer_->GetAudioTime(timestamp, Timestamp::Timestampbase::MONOTONIC);
        int64_t audioTime = timestamp.time.tv_nsec + timestamp.time.tv_sec * SEC_TO_NANOSECOND;
        audioBuffer->timestamp = audioTime;
        {
            std::unique_lock<std::mutex> lock(bufferMutex_);
            CHECK_AND_RETURN_RET_LOG(isRunning_.load(), MSERR_OK, "CaptureAudio is not running, ignore and stop"
                " %{public}s", name.c_str());
            if (availBuffers_.size() > MAX_AUDIO_BUFFER_SIZE) {
                PartiallyPrintLog(__LINE__, "consume slow, drop audio frame" + name);
                continue;
            }
            availBuffers_.push(audioBuffer);
        }
        bufferCond_.notify_all();
        CHECK_AND_RETURN_RET_LOG(isRunning_.load(), MSERR_OK, "CaptureAudio is not running, ignore and stop"
            " %{public}s", name.c_str());
        CHECK_AND_RETURN_RET_LOG(screenCaptureCb_ != nullptr, MSERR_OK,
            "no consumer, will drop audio frame %{public}s", name.c_str());
        screenCaptureCb_->OnAudioBufferAvailable(true, audioInfo_.audioSource);
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " CaptureAudio E, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer)
{
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(bufferMutex_);
    CHECK_AND_RETURN_RET_LOG(isRunning_.load(), MSERR_UNKNOWN, "AcquireAudioBuffer failed, not running");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Acquire Buffer S, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());

    if (!bufferCond_.wait_for(lock, std::chrono::milliseconds(OPERATION_TIMEOUT_IN_MS),
        [this] { return !availBuffers_.empty() || captureState_.load() == CAPTURER_RELEASED; })) {
        MEDIA_LOGE("AcquireAudioBuffer timeout, threadName:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }
    if (availBuffers_.empty()) {
        MEDIA_LOGE("CAPTURER_RELEASED, threadName:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }
    audioBuffer = availBuffers_.front();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Acquire Buffer E, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::GetBufferSize(size_t &size)
{
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetBufferSize Buffer S, name:%{public}s",
        FAKE_POINTER(this), threadName_.c_str());
    if (!isRunning_.load()) {
        MEDIA_LOGD("GetBufferSize failed, not running, name:%{public}s", threadName_.c_str());
        return MSERR_UNKNOWN;
    }
    CHECK_AND_RETURN_RET_LOG(audioCapturer_ != nullptr && audioCapturer_->GetBufferSize(size) >= 0,
        MSERR_NO_MEMORY, "CaptureAudio GetBufferSize failed");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " GetBufferSize Buffer E, name:%{public}s",
        FAKE_POINTER(this), threadName_.c_str());
    return MSERR_OK;
}

int32_t AudioCapturerWrapper::ReleaseAudioBuffer()
{
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Release Buffer S, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
    CHECK_AND_RETURN_RET_LOG(isRunning_.load(), MSERR_UNKNOWN, "ReleaseAudioBuffer failed, not running");
    CHECK_AND_RETURN_RET_LOG(!availBuffers_.empty(), MSERR_UNKNOWN, "ReleaseAudioBuffer failed, no frame to release");
    availBuffers_.pop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Release Buffer E, name:%{public}s", FAKE_POINTER(this), threadName_.c_str());
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

void MicAudioCapturerWrapper::OnStartFailed(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    (void)errorCode;
    if (screenCaptureCb_ != nullptr) {
        screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
    }
}
} // namespace Media
} // namespace OHOS