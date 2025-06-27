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
#ifndef LPP_AUDIO_RENDER_ADAPTER_H
#define LPP_AUDIO_RENDER_ADAPTER_H

#include <string>
#include <queue>

#include "refbase.h"
#include "audio_renderer.h"
#include "audio_info.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_producer.h"
#include "plugin/plugin_time.h"
#include "format.h"
#include "common/event.h"
#include "filter/filter.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;

class LppAudioRenderAdapter : public std::enable_shared_from_this<LppAudioRenderAdapter> {
public:
    explicit LppAudioRenderAdapter(const std::string &streamerId);
    ~LppAudioRenderAdapter();

    int32_t Init();
    void ReleaseRender();
    int32_t Prepare();
    int32_t PrepareInputBufferQueue();
    int32_t Start();
    int32_t Stop();
    int32_t Reset();
    int32_t SetParameter(const Format &param);
    int32_t Pause();
    int32_t PauseTransitent();
    int32_t Flush();
    int32_t Resume();
    int32_t Write(const std::shared_ptr<AVBuffer> &input);
    int32_t SetRequestDataCallback(const std::shared_ptr<AudioStandard::AudioRendererWriteCallback> &callback);

    int32_t Deinit();
    int32_t SetSpeed(float speed);
    int32_t SetVolume(const float volume);
    int32_t GetCurrentPosition(int64_t &currentPositionMs);

    void OnWriteData(size_t length);
    void OnBufferAvailable();
    void SetEventReceiver(std::shared_ptr<EventReceiver> eventReceiver);

    sptr<AVBufferQueueProducer> GetBufferQueueProducer();

    void OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent);
    void OnStateChange(const OHOS::AudioStandard::RendererState state,
        const OHOS::AudioStandard::StateChangeCmdType cmdType);
    void OnOutputDeviceChange(const AudioStandard::AudioDeviceDescriptor &deviceInfo,
        const AudioStandard::AudioStreamDeviceChangeReason reason);
    void OnAudioPolicyServiceDied();
    void OnFirstFrameWriting(uint64_t latency);

private:
    void HandleBufferAvailable();
    bool CheckBufferSize(size_t length);
    int32_t GetBufferDesc(AudioStandard::BufferDesc &bufDesc);
    void ReleaseCacheBuffer(bool isSwapBuffer = false);
    int32_t GetAudioPosition(timespec &time, uint32_t &framePosition);
    void GetLatency(int64_t &latency);
    void ClearAvailableOutputBuffers();
    void ClearInputBuffer();
    void FillAudioBuffer(size_t size, AudioStandard::BufferDesc &bufferDesc, int64_t &bufferPts);
    void Enqueue(AudioStandard::BufferDesc &bufferDesc);
    void UpdateTimeAnchor(int64_t bufferPts);
    void DriveBufferCircle();
    void DropEosBuffer();
    void HandleEos();
    std::shared_ptr<AVBuffer> CopyBuffer(const std::shared_ptr<AVBuffer> buffer);
    bool IsBufferAvailable(std::shared_ptr<AVBuffer> &buffer, size_t &cacheBufferSize);
    bool IsBufferDataDrained(AudioStandard::BufferDesc &bufferDesc, std::shared_ptr<AVBuffer> &buffer, size_t &size,
        size_t &cacheBufferSize, int64_t &bufferPts);
    bool CopyAudioVividBufferData(AudioStandard::BufferDesc &bufferDesc, std::shared_ptr<AVBuffer> &buffer,
        size_t &size, size_t &cacheBufferSize, int64_t &bufferPts);
    bool CopyBufferData(AudioStandard::BufferDesc &bufferDesc, std::shared_ptr<AVBuffer> &buffer,
        size_t &size, size_t &cacheBufferSize, int64_t &bufferPts);
    void ResetTimeInfo();
    int32_t GetSampleFormatBytes(AudioStandard::AudioSampleFormat format);
    int64_t GetCurrentClockTimeUs();

    bool isOffload_{false};
    std::string streamerId_{};
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer_{nullptr};
    AudioStandard::AudioRendererOptions rendererOptions_{};
    std::mutex dataMutex_ {};
    std::shared_ptr<AVBufferQueue> inputBufferQueue_ {};
    sptr<AVBufferQueueProducer> inputBufferQueueProducer_ {};
    sptr<AVBufferQueueConsumer> inputBufferQueueConsumer_ {};
    std::unique_ptr<Task> renderTask_ {nullptr};
    std::queue<std::shared_ptr<AVBuffer>> availOutputBuffers_ {};
    std::queue<std::shared_ptr<AVBuffer>> swapOutputBuffers_ {};
    std::atomic<size_t> availDataSize_ {0};
    size_t maxCbDataSize_ {0};
    bool isEos_ {false};
    bool isAudioVivid_ {false};
    int32_t sampleRate_ {0};
    int32_t audioChannelCount_ {0};
    int32_t sampleFormatBytes_ {0};
    int64_t writtenCnt_ {0};
    int64_t startPts_ {Plugins::HST_TIME_NONE};
    int64_t curPts_ {Plugins::HST_TIME_NONE};
    int64_t curClock_ {Plugins::HST_TIME_NONE};
    int64_t anchorClock_ {Plugins::HST_TIME_NONE};
    int64_t anchorPts_ {Plugins::HST_TIME_NONE};
    int64_t lastReportedClockTime_ {Plugins::HST_TIME_NONE};
    int32_t currentQueuedBufferOffset_ {0};
    std::atomic<bool> forceUpdateTimeAnchorNextTime_ {true};
    std::shared_ptr<EventReceiver> eventReceiver_ {nullptr};
    float speed_ {1.0f};
    float volume_ = {1.0f};
};
}  // namespace Media
}  // namespace OHOS
#endif