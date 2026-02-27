
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
#ifndef MOCK_AUDIO_RENDERER_H
#define MOCK_AUDIO_RENDERER_H

#include <cstring>
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "audio_info.h"
#include "audio_renderer.h"
#include "audio_effect.h"
#include "audio_stream_info.h"
#include "audio_interrupt_info.h"

namespace OHOS {
namespace Media {
class MockAudioRenderer : public AudioStandard::AudioRenderer {
public:
    MockAudioRenderer() = default;
    virtual ~MockAudioRenderer() = default;

    MOCK_METHOD(void, SetAudioPrivacyType, (AudioStandard::AudioPrivacyType), (override));
    MOCK_METHOD(AudioStandard::AudioPrivacyType, GetAudioPrivacyType, (), (override));
    MOCK_METHOD(int32_t, SetParams, (const AudioStandard::AudioRendererParams), (override));
    MOCK_METHOD(int32_t, SetRendererCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererCallback> &), (override));
    MOCK_METHOD(int32_t, GetParams, (AudioStandard::AudioRendererParams &), (const, override));
    MOCK_METHOD(int32_t, GetRendererInfo, (AudioStandard::AudioRendererInfo &), (const, override));
    MOCK_METHOD(int32_t, GetStreamInfo, (AudioStandard::AudioStreamInfo &), (const, override));
    MOCK_METHOD(bool, Start, (AudioStandard::StateChangeCmdType), (override));
    MOCK_METHOD(int32_t, Write, (uint8_t *, size_t), (override));
    MOCK_METHOD(int32_t, Write, (uint8_t *, size_t, uint8_t *, size_t), (override));
    MOCK_METHOD(AudioStandard::RendererState, GetStatus, (), (const, override));
    MOCK_METHOD(bool, GetAudioTime,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (const, override));
    MOCK_METHOD(bool, GetAudioPosition,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (override));
    MOCK_METHOD(int32_t, GetLatency, (uint64_t &), (const, override));
    MOCK_METHOD(bool, Drain, (), (const, override));
    MOCK_METHOD(bool, Flush, (), (const, override));
    MOCK_METHOD(bool, PauseTransitent, (AudioStandard::StateChangeCmdType), (override));
    MOCK_METHOD(bool, Pause, (AudioStandard::StateChangeCmdType), (override));
    MOCK_METHOD(bool, Stop, (), (override));
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(int32_t, GetBufferSize, (size_t &), (const, override));
    MOCK_METHOD(int32_t, GetAudioStreamId, (uint32_t &), (const, override));
    MOCK_METHOD(int32_t, GetFrameCount, (uint32_t &), (const, override));
    MOCK_METHOD(int32_t, SetAudioRendererDesc, (AudioStandard::AudioRendererDesc), (override));
    MOCK_METHOD(int32_t, SetStreamType, (AudioStandard::AudioStreamType), (override));
    MOCK_METHOD(int32_t, SetVolume, (float), (const, override));
    MOCK_METHOD(float, GetVolume, (), (const, override));
    MOCK_METHOD(int32_t, SetLoopTimes, (int64_t bufferLoopTimes), (override));
    MOCK_METHOD(int32_t, SetRenderRate, (AudioStandard::AudioRendererRate), (const, override));
    MOCK_METHOD(AudioStandard::AudioRendererRate, GetRenderRate, (), (const, override));
    MOCK_METHOD(int32_t, SetRendererSamplingRate, (uint32_t), (const, override));
    MOCK_METHOD(uint32_t, GetRendererSamplingRate, (), (const, override));
    MOCK_METHOD(int32_t, SetRendererPositionCallback,
        (int64_t, const std::shared_ptr<AudioStandard::RendererPositionCallback> &), (override));
    MOCK_METHOD(void, UnsetRendererPositionCallback, (), (override));
    MOCK_METHOD(int32_t, SetRendererPeriodPositionCallback,
        (int64_t, const std::shared_ptr<AudioStandard::RendererPeriodPositionCallback> &), (override));
    MOCK_METHOD(void, UnsetRendererPeriodPositionCallback, (), (override));
    MOCK_METHOD(int32_t, SetBufferDuration, (uint64_t), (const, override));
    MOCK_METHOD(int32_t, SetRenderMode, (AudioStandard::AudioRenderMode), (override));
    MOCK_METHOD(AudioStandard::AudioRenderMode, GetRenderMode, (), (const, override));
    MOCK_METHOD(int32_t, SetRendererWriteCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererWriteCallback> &), (override));
    MOCK_METHOD(int32_t, SetRendererFirstFrameWritingCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererFirstFrameWritingCallback> &), (override));
    MOCK_METHOD(int32_t, GetBufferDesc, (AudioStandard::BufferDesc &), (override));
    MOCK_METHOD(int32_t, Enqueue, (const AudioStandard::BufferDesc &), (override));
    MOCK_METHOD(int32_t, Clear, (), (const, override));
    MOCK_METHOD(int32_t, GetBufQueueState, (AudioStandard::BufferQueueState &), (const, override));
    MOCK_METHOD(void, SetInterruptMode, (AudioStandard::InterruptMode), (override));
    MOCK_METHOD(int32_t, SetParallelPlayFlag, (bool), (override));
    MOCK_METHOD(int32_t, SetLowPowerVolume, (float), (const, override));
    MOCK_METHOD(float, GetLowPowerVolume, (), (const, override));
    MOCK_METHOD(int32_t, SetOffloadAllowed, (bool), (override));
    MOCK_METHOD(int32_t, SetOffloadMode, (int32_t, bool), (const, override));
    MOCK_METHOD(int32_t, UnsetOffloadMode, (), (const, override));
    MOCK_METHOD(float, GetSingleStreamVolume, (), (const, override));
    MOCK_METHOD(float, GetMinStreamVolume, (), (const, override));
    MOCK_METHOD(float, GetMaxStreamVolume, (), (const, override));
    MOCK_METHOD(uint32_t, GetUnderflowCount, (), (const, override));
    MOCK_METHOD(int32_t, GetCurrentOutputDevices, (AudioStandard::AudioDeviceDescriptor &), (const, override));
    MOCK_METHOD(AudioStandard::AudioEffectMode, GetAudioEffectMode, (), (const, override));
    MOCK_METHOD(int64_t, GetFramesWritten, (), (const, override));
    MOCK_METHOD(int32_t, SetAudioEffectMode, (AudioStandard::AudioEffectMode), (const, override));
    MOCK_METHOD(void, SetAudioRendererErrorCallback,
        (std::shared_ptr<AudioStandard::AudioRendererErrorCallback>), (override));
    MOCK_METHOD(int32_t, RegisterOutputDeviceChangeWithInfoCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &), (override));
    MOCK_METHOD(int32_t, UnregisterOutputDeviceChangeWithInfoCallback, (), (override));
    MOCK_METHOD(int32_t, UnregisterOutputDeviceChangeWithInfoCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererOutputDeviceChangeCallback> &), (override));
    MOCK_METHOD(int32_t, RegisterAudioPolicyServerDiedCb,
        (const int32_t, const std::shared_ptr<AudioStandard::AudioRendererPolicyServiceDiedCallback> &), (override));
    MOCK_METHOD(int32_t, UnregisterAudioPolicyServerDiedCb, (const int32_t), (override));
    MOCK_METHOD(int32_t, SetChannelBlendMode, (AudioStandard::ChannelBlendMode), (override));
    MOCK_METHOD(int32_t, SetVolumeWithRamp, (float, int32_t), (override));
    MOCK_METHOD(void, SetPreferredFrameSize, (int32_t), (override));
    MOCK_METHOD(int32_t, SetSpeed, (float), (override));
    MOCK_METHOD(float, GetSpeed, (), (override));
    MOCK_METHOD(bool, IsFastRenderer, (), (override));
    MOCK_METHOD(void, SetSilentModeAndMixWithOthers, (bool), (override));
    MOCK_METHOD(bool, GetSilentModeAndMixWithOthers, (), (override));
    MOCK_METHOD(void, EnableVoiceModemCommunicationStartStream, (bool), (override));
    MOCK_METHOD(bool, IsNoStreamRenderer, (), (const, override));
    MOCK_METHOD(int32_t, SetDefaultOutputDevice, (AudioStandard::DeviceType), (override));
    MOCK_METHOD(bool, Mute, (AudioStandard::StateChangeCmdType), (const, override));
    MOCK_METHOD(bool, Unmute, (AudioStandard::StateChangeCmdType), (const, override));
    MOCK_METHOD(int32_t, GetAudioTimestampInfo,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (const, override));
    MOCK_METHOD(void, SetFastStatusChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioRendererFastStatusChangeCallback> &), (override));
    MOCK_METHOD(int32_t, StartImpl, (StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, DrainImpl, (), (const, override));
    MOCK_METHOD(int32_t, FlushImpl, (), (const, override));
    MOCK_METHOD(int32_t, PauseImpl, (StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, StopImpl, (), (override));
    MOCK_METHOD(int32_t, ReleaseImpl, (), (override));
    MOCK_METHOD(int32_t, StartWithError, (StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, DrainWithError, (), (const, override));
    MOCK_METHOD(int32_t, FlushWithError, (), (const, override));
    MOCK_METHOD(int32_t, PauseWithError, (StateChangeCmdType cmdType), (override));
    MOCK_METHOD(int32_t, StopWithError, (), (override));
    MOCK_METHOD(int32_t, ReleaseWithError, (), (override));
};
} // namespace Media
} // namespace OHOS
#endif // MOCK_AUDIO_RENDERER_H
