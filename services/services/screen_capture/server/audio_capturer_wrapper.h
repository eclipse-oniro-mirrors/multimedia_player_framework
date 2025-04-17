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

#ifndef SCREEN_CAPTURE_AUDIO_CAPTURER_WRAPPER_H
#define SCREEN_CAPTURE_AUDIO_CAPTURER_WRAPPER_H

#include <mutex>
#include <cstdlib>
#include <thread>
#include <string>
#include <map>
#include <memory>
#include <atomic>
#include <queue>

#include "audio_capturer.h"
#include "screen_capture.h"
#include "securec.h"

#define AUDIO_NS_PER_SECOND (static_cast<uint64_t>(1000000000))

namespace OHOS {
namespace Media {
using namespace AudioStandard;

const int64_t AUDIO_CAPTURE_READ_FAILED_WAIT_TIME = 20000000; // 20000000 us 20ms

class AudioCapturerCallbackImpl : public AudioCapturerCallback {
public:
    void OnInterrupt(const InterruptEvent &interruptEvent) override;
    void OnStateChange(const CapturerState state) override;
};

enum AudioCapturerWrapperState : int32_t {
    CAPTURER_UNKNOWN = -1,
    CAPTURER_RECORDING = 0,
    CAPTURER_PAUSED = 1,
    CAPTURER_STOPED = 2,
    CAPTURER_RELEASED = 3,
};

class AudioCapturerWrapper {
public:
    explicit AudioCapturerWrapper(AudioCaptureInfo &audioInfo,
        std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb, std::string &&name,
        ScreenCaptureContentFilter filter)
        : screenCaptureCb_(screenCaptureCb), audioInfo_(audioInfo), threadName_(std::move(name)),
        contentFilter_(filter) {}
    virtual ~AudioCapturerWrapper();
    int32_t Start(const OHOS::AudioStandard::AppInfo &appInfo);
    int32_t Stop();
    int32_t UpdateAudioCapturerConfig(ScreenCaptureContentFilter &filter);
    int32_t CaptureAudio();
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer);
    int32_t GetBufferSize(size_t &size);
    int32_t ReleaseAudioBuffer();
    void SetIsInVoIPCall(bool isInVoIPCall);
#ifdef SUPPORT_CALL
    void SetIsInTelCall(bool isInTelCall);
#endif
    AudioCapturerWrapperState GetAudioCapturerState();
    int32_t UseUpAllLeftBufferUntil(int64_t audioTime);
    int32_t GetCurrentAudioTime(int64_t &currentAudioTime);
    int32_t DropBufferUntil(int64_t audioTime);
    int32_t AddBufferFrom(int64_t timeWindow, int64_t bufferSize, int64_t fromTime);

protected:
    virtual void OnStartFailed(ScreenCaptureErrorType errorType, int32_t errorCode);

private:
    std::shared_ptr<OHOS::AudioStandard::AudioCapturer> CreateAudioCapturer(
        const OHOS::AudioStandard::AppInfo &appInfo);
    void SetInnerStreamUsage(std::vector<OHOS::AudioStandard::StreamUsage> &usages);
    void PartiallyPrintLog(int32_t lineNumber, std::string str);
    int32_t RelativeSleep(int64_t nanoTime);
    int32_t GetCaptureAudioBuffer(std::shared_ptr<AudioBuffer> audioBuffer, size_t bufferLen);

protected:
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_;

private:
    std::mutex mutex_;
    std::atomic<bool> isRunning_ = false;
    AudioCaptureInfo audioInfo_;
    std::string threadName_;
    std::unique_ptr<std::thread> readAudioLoop_ = nullptr;
    std::shared_ptr<OHOS::AudioStandard::AudioCapturer> audioCapturer_ = nullptr;
    std::shared_ptr<OHOS::Media::AudioCapturerCallbackImpl> audioCaptureCallback_ = nullptr;
    ScreenCaptureContentFilter contentFilter_;
    OHOS::AudioStandard::AppInfo appInfo_;

    std::mutex bufferMutex_;
    std::condition_variable bufferCond_;
    std::deque<std::shared_ptr<AudioBuffer>> availBuffers_;
    std::string bundleName_;
    std::atomic<bool> isInVoIPCall_ = false;
#ifdef SUPPORT_CALL
    std::atomic<bool> isInTelCall_ = false;
#endif
    std::atomic<AudioCapturerWrapperState> captureState_ {CAPTURER_UNKNOWN};

    /* used for hilog output */
    std::map<int32_t, int32_t> captureAudioLogCountMap_;

    static constexpr int64_t INNER_AUDIO_READ_TO_HEAR_TIME = 240000000; // 240ms
    static constexpr uint32_t WRAPPER_PUSH_AUDIO_SAMPLE_INTERVAL_IN_US = 5000; // 5ms
    static constexpr uint32_t MAX_THREAD_NAME_LENGTH = 15;
    static constexpr uint32_t MAX_AUDIO_BUFFER_SIZE = 128;
    static constexpr uint32_t SEC_TO_NANOSECOND = 1000000000; // 10^9ns
    static constexpr uint32_t OPERATION_TIMEOUT_IN_MS = 5; // 5ms
    static constexpr int32_t AC_LOG_SKIP_NUM = 1000;
    static constexpr uint32_t STOP_WAIT_TIMEOUT_IN_MS = 500; // 500ms
    static constexpr int64_t AUDIO_CAPTURE_READ_FRAME_TIME = 21333333; // 21333333 ns 21ms
    static constexpr int32_t MAX_AUDIO_BUFFER_LEN = 10 * 1024 * 1024; // 10M
};

class MicAudioCapturerWrapper : public AudioCapturerWrapper {
public:
    explicit MicAudioCapturerWrapper(AudioCaptureInfo &audioInfo,
        std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb, std::string &&name,
        ScreenCaptureContentFilter filter)
        : AudioCapturerWrapper(audioInfo, screenCaptureCb, std::move(name),
        filter) {}
    ~MicAudioCapturerWrapper() override {}

protected:
    void OnStartFailed(ScreenCaptureErrorType errorType, int32_t errorCode) override;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_AUDIO_CAPTURER_WRAPPER_H
