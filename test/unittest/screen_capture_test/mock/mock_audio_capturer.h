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

#ifndef MOCK_AUDIO_CAPTURER_H
#define MOCK_AUDIO_CAPTURER_H

#include <gmock/gmock.h>
#include <memory>
#include "audio_capturer.h"

using testing::Return;
using testing::_;
using testing::DoAll;
using testing::SetArgReferee;

namespace OHOS {
namespace Media {

class MockAudioCapturer : public AudioStandard::AudioCapturer {
public:
    MockAudioCapturer() = default;
    ~MockAudioCapturer() override = default;

    MOCK_METHOD(bool, Start, (), (override));
    MOCK_METHOD(bool, Stop, (), (override, const));
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(int32_t, Read, (uint8_t &, size_t, bool), (override));
    MOCK_METHOD(int32_t, GetBufferSize, (size_t &), (override, const));
    MOCK_METHOD(bool, GetTimeStampInfo,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (override, const));
    MOCK_METHOD(bool, GetAudioTime,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (override, const));
    MOCK_METHOD(int32_t, SetCapturerCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerCallback> &), (override));
    MOCK_METHOD(int32_t, UpdatePlaybackCaptureConfig,
        (const AudioStandard::AudioPlaybackCaptureConfig &), (override));
    MOCK_METHOD(int32_t, SetAudioSourceConcurrency,
        (const std::vector<AudioStandard::SourceType> &), (override));
    MOCK_METHOD(AudioStandard::CapturerState, GetStatus, (), (override, const));
    MOCK_METHOD(bool, Pause, (), (override, const));
    MOCK_METHOD(bool, Flush, (), (override, const));
    MOCK_METHOD(void, SetAudioCapturerErrorCallback,
        (std::shared_ptr<AudioStandard::AudioCapturerErrorCallback>), (override));
    MOCK_METHOD(void, SetFastStatusChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerFastStatusChangeCallback> &), (override));
    MOCK_METHOD(void, SetPlaybackCaptureStartStateCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerOnPlaybackCaptureStartCallback> &), (override));
    MOCK_METHOD(int32_t, SetParams, (AudioStandard::AudioCapturerParams), (override));
    MOCK_METHOD(int32_t, GetParams, (AudioStandard::AudioCapturerParams &), (override, const));
    MOCK_METHOD(int32_t, GetCapturerInfo, (AudioStandard::AudioCapturerInfo &), (override, const));
    MOCK_METHOD(int32_t, GetStreamInfo, (AudioStandard::AudioStreamInfo &), (override, const));
    MOCK_METHOD(int32_t, GetAudioStreamId, (uint32_t &), (override, const));
    MOCK_METHOD(int32_t, GetFrameCount, (uint32_t &), (override, const));
    MOCK_METHOD(int32_t, SetCapturerPositionCallback,
        (int64_t, const std::shared_ptr<AudioStandard::CapturerPositionCallback> &), (override));
    MOCK_METHOD(void, UnsetCapturerPositionCallback, (), (override));
    MOCK_METHOD(int32_t, SetCapturerPeriodPositionCallback,
        (int64_t, const std::shared_ptr<AudioStandard::CapturerPeriodPositionCallback> &), (override));
    MOCK_METHOD(void, UnsetCapturerPeriodPositionCallback, (), (override));
    MOCK_METHOD(int32_t, RegisterAudioPolicyServerDiedCb,
        (int32_t, const std::shared_ptr<AudioStandard::AudioCapturerPolicyServiceDiedCallback> &), (override));
    MOCK_METHOD(int32_t, SetBufferDuration, (uint64_t), (override, const));
    MOCK_METHOD(int32_t, SetCaptureMode, (AudioStandard::AudioCaptureMode), (override));
    MOCK_METHOD(AudioStandard::AudioCaptureMode, GetCaptureMode, (), (override, const));
    MOCK_METHOD(int32_t, SetCapturerReadCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerReadCallback> &), (override));
    MOCK_METHOD(int32_t, GetBufferDesc, (AudioStandard::BufferDesc &), (override));
    MOCK_METHOD(int32_t, Enqueue, (const AudioStandard::BufferDesc &), (override));
    MOCK_METHOD(int32_t, Clear, (), (override, const));
    MOCK_METHOD(int32_t, GetBufQueueState, (AudioStandard::BufferQueueState &), (override, const));
    MOCK_METHOD(void, SetValid, (bool), (override));
    MOCK_METHOD(int64_t, GetFramesRead, (), (override, const));
    MOCK_METHOD(int32_t, SetAudioCapturerDeviceChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerDeviceChangeCallback> &), (override));
    MOCK_METHOD(int32_t, RemoveAudioCapturerDeviceChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerDeviceChangeCallback> &), (override));
    MOCK_METHOD(int32_t, SetAudioCapturerInfoChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerInfoChangeCallback> &), (override));
    MOCK_METHOD(int32_t, RemoveAudioCapturerInfoChangeCallback,
        (const std::shared_ptr<AudioStandard::AudioCapturerInfoChangeCallback> &), (override));
    MOCK_METHOD(int32_t, RegisterAudioCapturerEventListener, (), (override));
    MOCK_METHOD(int32_t, UnregisterAudioCapturerEventListener, (), (override));
    MOCK_METHOD(int32_t, GetCurrentInputDevices, (AudioStandard::AudioDeviceDescriptor &), (override, const));
    MOCK_METHOD(int32_t, GetCurrentCapturerChangeInfo, (AudioStandard::AudioCapturerChangeInfo &), (override, const));
    MOCK_METHOD(std::vector<sptr<AudioStandard::MicrophoneDescriptor>>, GetCurrentMicrophones, (), (override, const));
    MOCK_METHOD(int32_t, GetAudioTimestampInfo,
        (AudioStandard::Timestamp &, AudioStandard::Timestamp::Timestampbase), (override, const));
    MOCK_METHOD(uint32_t, GetOverflowCount, (), (override, const));
    MOCK_METHOD(int32_t, SetInputDevice, (AudioStandard::DeviceType), (override, const));
    MOCK_METHOD(int32_t, SetInterruptStrategy, (AudioStandard::InterruptStrategy), (override));
};

} // namespace Media
} // namespace OHOS
#endif // MOCK_AUDIO_CAPTURER_H