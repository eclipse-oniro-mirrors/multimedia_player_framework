/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef AUDIO_RENDERER_MANAGER_MOCK_H
#define AUDIO_RENDERER_MANAGER_MOCK_H

#include <atomic>
#include <cstdint>
#include <memory>

#include "audio_renderer.h"

namespace OHOS {
namespace Media {

class MockAudioRenderer : public AudioStandard::AudioRenderer {
public:
    inline static std::atomic<int32_t> releaseCount_{0};
    bool releaseResult_ = true;

    static void ResetReleaseCount()
    {
        releaseCount_.store(0);
    }

    static int32_t GetReleaseCount()
    {
        return releaseCount_.load();
    }

    void SetAudioPrivacyType(AudioStandard::AudioPrivacyType privacyType) override
    {
    }

    AudioStandard::AudioPrivacyType GetAudioPrivacyType() override
    {
        return {};
    }

    int32_t SetParams(const AudioStandard::AudioRendererParams params) override
    {
        return 0;
    }

    int32_t SetRendererCallback(const std::shared_ptr<AudioStandard::AudioRendererCallback> &callback) override
    {
        return 0;
    }

    int32_t GetParams(AudioStandard::AudioRendererParams &params) const override
    {
        return 0;
    }

    int32_t GetRendererInfo(AudioStandard::AudioRendererInfo &rendererInfo) const override
    {
        return 0;
    }

    int32_t GetStreamInfo(AudioStandard::AudioStreamInfo &streamInfo) const override
    {
        return 0;
    }

    bool Start(AudioStandard::StateChangeCmdType cmdType) override
    {
        return false;
    }

    int32_t Write(uint8_t *buffer, size_t bufferSize) override
    {
        return 0;
    }

    int32_t Write(uint8_t *pcmBuffer, size_t pcmBufferSize, uint8_t *metaBuffer, size_t metaBufferSize) override
    {
        return 0;
    }

    AudioStandard::RendererState GetStatus() const override
    {
        return {};
    }

    bool GetAudioTime(AudioStandard::Timestamp &timestamp, AudioStandard::Timestamp::Timestampbase base) const override
    {
        return false;
    }

    bool GetAudioPosition(AudioStandard::Timestamp &timestamp, AudioStandard::Timestamp::Timestampbase base) override
    {
        return false;
    }

    int32_t GetLatency(uint64_t &latency) const override
    {
        return 0;
    }

    bool Drain() const override
    {
        return false;
    }

    bool Flush() const override
    {
        return false;
    }

    bool PauseTransitent(AudioStandard::StateChangeCmdType cmdType) override
    {
        return false;
    }

    bool Pause(AudioStandard::StateChangeCmdType cmdType) override
    {
        return false;
    }

    bool Stop() override
    {
        return false;
    }

    int32_t GetBufferSize(size_t &bufferSize) const override
    {
        return 0;
    }

    int32_t GetAudioStreamId(uint32_t &sessionID) const override
    {
        return 0;
    }

    int32_t GetFrameCount(uint32_t &frameCount) const override
    {
        return 0;
    }

    int32_t SetAudioRendererDesc(AudioStandard::AudioRendererDesc audioRendererDesc) override
    {
        return 0;
    }

    int32_t SetStreamType(AudioStandard::AudioStreamType audioStreamType) override
    {
        return 0;
    }

    int32_t SetVolume(float volume) const override
    {
        return 0;
    }

    int32_t SetVolumeMode(int32_t mode) override
    {
        return 0;
    }

    float GetVolume() const override
    {
        return 0.0f;
    }

    int32_t SetRenderRate(AudioStandard::AudioRendererRate renderRate) const override
    {
        return 0;
    }

    AudioStandard::AudioRendererRate GetRenderRate() const override
    {
        return {};
    }

    int32_t SetLoopTimes(int64_t bufferLoopTimes) override
    {
        return 0;
    }

    int32_t SetRendererSamplingRate(uint32_t sampleRate) const override
    {
        return 0;
    }

    uint32_t GetRendererSamplingRate() const override
    {
        return 0;
    }

    int32_t SetRendererPositionCallback(int64_t markPosition,
        const std::shared_ptr<AudioStandard::RendererPositionCallback> &callback) override
    {
        return 0;
    }

    void UnsetRendererPositionCallback() override
    {
    }

    void SetPreferredFrameSize(int32_t frameSize) override
    {
    }

    int32_t SetRendererPeriodPositionCallback(int64_t frameNumber,
        const std::shared_ptr<AudioStandard::RendererPeriodPositionCallback> &callback) override
    {
        return 0;
    }

    void UnsetRendererPeriodPositionCallback() override
    {
    }

    int32_t SetBufferDuration(uint64_t bufferDuration) const override
    {
        return 0;
    }

    int32_t SetRenderMode(AudioStandard::AudioRenderMode renderMode) override
    {
        return 0;
    }

    AudioStandard::AudioRenderMode GetRenderMode() const override
    {
        return {};
    }

    int32_t SetRendererWriteCallback(
        const std::shared_ptr<AudioStandard::AudioRendererWriteCallback> &callback) override
    {
        return 0;
    }

    int32_t SetRendererFirstFrameWritingCallback(
        const std::shared_ptr<AudioStandard::AudioRendererFirstFrameWritingCallback> &callback) override
    {
        return 0;
    }

    int32_t GetBufferDesc(AudioStandard::BufferDesc &bufDesc) override
    {
        return 0;
    }

    int32_t Enqueue(const AudioStandard::BufferDesc &bufDesc) override
    {
        return 0;
    }

    int32_t Clear() const override
    {
        return 0;
    }

    int32_t GetBufQueueState(AudioStandard::BufferQueueState &bufState) const override
    {
        return 0;
    }

    void SetInterruptMode(AudioStandard::InterruptMode mode) override
    {
    }

    int32_t SetParallelPlayFlag(bool parallelPlayFlag) override
    {
        return 0;
    }

    int32_t SetLowPowerVolume(float volume) const override
    {
        return 0;
    }

    float GetLowPowerVolume() const override
    {
        return 0.0f;
    }

    int32_t SetOffloadAllowed(bool isAllowed) override
    {
        return 0;
    }

    int32_t SetOffloadMode(int32_t state, bool isAppBack) const override
    {
        return 0;
    }

    int32_t UnsetOffloadMode() const override
    {
        return 0;
    }

    float GetSingleStreamVolume() const override
    {
        return 0.0f;
    }

    float GetMinStreamVolume() const override
    {
        return 0.0f;
    }

    float GetMaxStreamVolume() const override
    {
        return 0.0f;
    }

    uint32_t GetUnderflowCount() const override
    {
        return 0;
    }

    int32_t GetCurrentOutputDevices(AudioStandard::AudioDeviceDescriptor &deviceInfo) const override
    {
        return 0;
    }

    AudioStandard::AudioEffectMode GetAudioEffectMode() const override
    {
        return {};
    }

    int64_t GetFramesWritten() const override
    {
        return 0;
    }

    int32_t SetAudioEffectMode(AudioStandard::AudioEffectMode effectMode) const override
    {
        return 0;
    }

    void SetAudioRendererErrorCallback(
        std::shared_ptr<AudioStandard::AudioRendererErrorCallback> errorCallback) override
    {
    }

    int32_t RegisterOutputDeviceChangeWithInfoCallback(
        const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &callback) override
    {
        return 0;
    }

    int32_t UnregisterOutputDeviceChangeWithInfoCallback(
        const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &callback) override
    {
        return 0;
    }

    int32_t UnregisterOutputDeviceChangeWithInfoCallback() override
    {
        return 0;
    }

    int32_t RegisterAudioPolicyServerDiedCb(const int32_t clientPid,
        const std::shared_ptr<AudioStandard::AudioRendererPolicyServiceDiedCallback> &callback) override
    {
        return 0;
    }

    int32_t UnregisterAudioPolicyServerDiedCb(const int32_t clientPid) override
    {
        return 0;
    }

    int32_t SetChannelBlendMode(AudioStandard::ChannelBlendMode blendMode) override
    {
        return 0;
    }

    int32_t SetVolumeWithRamp(float volume, int32_t duration) override
    {
        return 0;
    }

    int32_t SetSpeed(float speed) override
    {
        return 0;
    }

    int32_t SetPitch(float pitch) override
    {
        return 0;
    }

    float GetSpeed() override
    {
        return 0.0f;
    }

    bool IsFastRenderer() override
    {
        return false;
    }

    void SetSilentModeAndMixWithOthers(bool on) override
    {
    }

    bool GetSilentModeAndMixWithOthers() override
    {
        return false;
    }

    void EnableVoiceModemCommunicationStartStream(bool enable) override
    {
    }

    bool IsNoStreamRenderer() const override
    {
        return false;
    }

    bool Mute(AudioStandard::StateChangeCmdType) override
    {
        return false;
    }

    bool Unmute(AudioStandard::StateChangeCmdType) override
    {
        return false;
    }

    int32_t GetAudioTimestampInfo(
        AudioStandard::Timestamp &timestamp,
        AudioStandard::Timestamp::Timestampbase base) const override
    {
        return 0;
    }

    bool Release() override
    {
        releaseCount_.fetch_add(1);
        return releaseResult_;
    }

    void SetFastStatusChangeCallback(
        const std::shared_ptr<AudioStandard::AudioRendererFastStatusChangeCallback>& callback) override
    {
    }

    void SetAudioHapticsSyncId(int32_t audioHapticsSyncId) override
    {
    }

    void ResetFirstFrameState() override
    {
    }
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_RENDERER_MANAGER_MOCK_H
