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

#ifndef MOCK_AUDIORENDER_H
#define MOCK_AUDIORENDER_H

#include <gmock/gmock.h>

namespace OHOS {
namespace Media {

class MockAudioRender : public AudioStandard::AudioRenderer {
public:
    MOCK_METHOD(void, SetAudioPrivacyType, (AudioStandard::AudioPrivacyType privacyType), (override));
    MOCK_METHOD(AudioStandard::AudioPrivacyType, GetAudioPrivacyType, (), (override));
    MOCK_METHOD(int32_t, SetParams, (const AudioStandard::AudioRendererParams params), (override));
    MOCK_METHOD(int32_t, SetRendererCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetParams, (AudioStandard::AudioRendererParams &params), (const, override));
    MOCK_METHOD(int32_t, GetRendererInfo, (AudioStandard::AudioRendererInfo &rendererInfo), (const, override));
    MOCK_METHOD(int32_t, GetStreamInfo, (AudioStandard::AudioStreamInfo &streamInfo), (const, override));
    MOCK_METHOD(bool, Start, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, Write, (uint8_t *buffer, size_t bufferSize), (override));
    MOCK_METHOD(int32_t, Write,
        (uint8_t *pcmBuffer, size_t pcmBufferSize, uint8_t *metaBuffer, size_t metaBufferSize), (override));
    MOCK_METHOD(AudioStandard::RendererState, GetStatus, (), (const, override));
    MOCK_METHOD(bool, GetAudioTime,
        (AudioStandard::Timestamp &timestamp, AudioStandard::Timestamp::Timestampbase base), (const, override));
    MOCK_METHOD(bool, GetAudioPosition,
        (AudioStandard::Timestamp &timestamp, AudioStandard::Timestamp::Timestampbase base), (override));
    MOCK_METHOD(int32_t, GetLatency, (uint64_t &latency), (const, override));
    MOCK_METHOD(bool, Drain, (), (const, override));
    MOCK_METHOD(bool, Flush, (), (const, override));
    MOCK_METHOD(bool, PauseTransitent, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(bool, Pause, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(bool, Stop, (), (override));
    MOCK_METHOD(int32_t, GetBufferSize, (size_t &bufferSize), (const, override));
    MOCK_METHOD(int32_t, GetAudioStreamId, (uint32_t &sessionID), (const, override));
    MOCK_METHOD(int32_t, GetFrameCount, (uint32_t &frameCount), (const, override));
    MOCK_METHOD(int32_t, SetAudioRendererDesc, (AudioStandard::AudioRendererDesc audioRendererDesc), (override));
    MOCK_METHOD(int32_t, SetStreamType, (AudioStandard::AudioStreamType audioStreamType), (override));
    MOCK_METHOD(int32_t, SetVolume, (float volume), (const, override));
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), (override));
    MOCK_METHOD(float, GetVolume, (), (const, override));
    MOCK_METHOD(int32_t, SetRenderRate, (AudioStandard::AudioRendererRate renderRate), (const, override));
    MOCK_METHOD(AudioStandard::AudioRendererRate, GetRenderRate, (), (const, override));
    MOCK_METHOD(int32_t, SetLoopTimes, (int64_t bufferLoopTimes), (override));
    MOCK_METHOD(int32_t, SetRendererSamplingRate, (uint32_t sampleRate), (const, override));
    MOCK_METHOD(uint32_t, GetRendererSamplingRate, (), (const, override));
    MOCK_METHOD(int32_t, SetRendererPositionCallback, (int64_t markPosition,
        const std::shared_ptr<AudioStandard::RendererPositionCallback> &callback), (override));
    MOCK_METHOD(void, UnsetRendererPositionCallback, (), (override));
    MOCK_METHOD(void, SetPreferredFrameSize, (int32_t frameSize), (override));
    MOCK_METHOD(int32_t, SetRendererPeriodPositionCallback, (int64_t frameNumber,
        const std::shared_ptr<AudioStandard::RendererPeriodPositionCallback> &callback), (override));
    MOCK_METHOD(void, UnsetRendererPeriodPositionCallback, (), (override));
    MOCK_METHOD(int32_t, SetBufferDuration, (uint64_t bufferDuration), (const, override));
    MOCK_METHOD(int32_t, SetRenderMode, (AudioStandard::AudioRenderMode renderMode), (override));
    MOCK_METHOD(AudioStandard::AudioRenderMode, GetRenderMode, (), (const, override));
    MOCK_METHOD(int32_t, SetRendererWriteCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererWriteCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetRendererFirstFrameWritingCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererFirstFrameWritingCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetBufferDesc, (AudioStandard::BufferDesc &bufDesc), (override));
    MOCK_METHOD(int32_t, Enqueue, (const AudioStandard::BufferDesc &bufDesc), (override));
    MOCK_METHOD(int32_t, Clear, (), (const, override));
    MOCK_METHOD(int32_t, GetBufQueueState, (AudioStandard::BufferQueueState &bufState), (const, override));
    MOCK_METHOD(void, SetInterruptMode, (AudioStandard::InterruptMode mode), (override));
    MOCK_METHOD(int32_t, SetParallelPlayFlag, (bool parallelPlayFlag), (override));
    MOCK_METHOD(int32_t, SetLowPowerVolume, (float volume), (const, override));
    MOCK_METHOD(float, GetLowPowerVolume, (), (const, override));
    MOCK_METHOD(int32_t, SetOffloadAllowed, (bool isAllowed), (override));
    MOCK_METHOD(int32_t, SetOffloadMode, (int32_t state, bool isAppBack), (const, override));
    MOCK_METHOD(int32_t, UnsetOffloadMode, (), (const, override));
    MOCK_METHOD(float, GetSingleStreamVolume, (), (const, override));
    MOCK_METHOD(float, GetMinStreamVolume, (), (const, override));
    MOCK_METHOD(float, GetMaxStreamVolume, (), (const, override));
    MOCK_METHOD(uint32_t, GetUnderflowCount, (), (const, override));
    MOCK_METHOD(int32_t, GetCurrentOutputDevices, (AudioStandard::AudioDeviceDescriptor &deviceInfo),
        (const, override));
    MOCK_METHOD(AudioStandard::AudioEffectMode, GetAudioEffectMode, (), (const, override));
    MOCK_METHOD(int64_t, GetFramesWritten, (), (const, override));
    MOCK_METHOD(int32_t, SetAudioEffectMode, (AudioStandard::AudioEffectMode effectMode), (const, override));
    MOCK_METHOD(void, SetAudioRendererErrorCallback,
        (std::shared_ptr<AudioStandard::AudioRendererErrorCallback> errorCallback), (override));
    MOCK_METHOD(int32_t, RegisterOutputDeviceChangeWithInfoCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnregisterOutputDeviceChangeWithInfoCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnregisterOutputDeviceChangeWithInfoCallback, (), (override));
    MOCK_METHOD(int32_t, RegisterAudioPolicyServerDiedCb, (const int32_t clientPid,
        const std::shared_ptr<AudioStandard::AudioRendererPolicyServiceDiedCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnregisterAudioPolicyServerDiedCb, (const int32_t clientPid), (override));
    MOCK_METHOD(int32_t, SetChannelBlendMode, (AudioStandard::ChannelBlendMode blendMode), (override));
    MOCK_METHOD(int32_t, SetVolumeWithRamp, (float volume, int32_t duration), (override));
    MOCK_METHOD(int32_t, SetSpeed, (float speed), (override));
    MOCK_METHOD(int32_t, SetPitch, (float pitch), ());
    MOCK_METHOD(float, GetSpeed, (), (override));
    MOCK_METHOD(bool, IsFastRenderer, (), (override));
    MOCK_METHOD(void, SetSilentModeAndMixWithOthers, (bool on), (override));
    MOCK_METHOD(bool, GetSilentModeAndMixWithOthers, (), (override));
    MOCK_METHOD(void, EnableVoiceModemCommunicationStartStream, (bool enable), (override));
    MOCK_METHOD(bool, IsNoStreamRenderer, (), (const, override));
    MOCK_METHOD(int32_t, GetAudioTimestampInfo,
        (AudioStandard::Timestamp &timestamp, AudioStandard::Timestamp::Timestampbase base), (const, override));
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(void, SetFastStatusChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererFastStatusChangeCallback>& callback),
        (override));
    MOCK_METHOD(void, SetAudioHapticsSyncId, (int32_t audioHapticsSyncId), (override));
    MOCK_METHOD(void, ResetFirstFrameState, (), (override));
    MOCK_METHOD(int32_t, StartImpl, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, DrainImpl, (), (const, override));
    MOCK_METHOD(int32_t, FlushImpl, (), (const, override));
    MOCK_METHOD(int32_t, PauseImpl, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, StopImpl, (), (override));
    MOCK_METHOD(int32_t, ReleaseImpl, (), (override));
    MOCK_METHOD(int32_t, StartWithError, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, DrainWithError, (), (const, override));
    MOCK_METHOD(int32_t, FlushWithError, (), (const, override));
    MOCK_METHOD(int32_t, PauseWithError, (AudioStandard::StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, StopWithError, (), (override));
    MOCK_METHOD(int32_t, ReleaseWithError, (), (override));
};
} // namespace Media
} // namespace OHOS
#endif // SOUNDPOOL_STREAM_UNITTEST_H
