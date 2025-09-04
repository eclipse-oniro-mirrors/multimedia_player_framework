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

#ifndef AUDIO_RENDERER_H
#define AUDIO_RENDERER_H

#include <iostream>
#include <vector>
#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <cstring>
#include <mutex>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "audio_info.h"
#include "instance_mgr.h"

namespace OHOS {
namespace AudioStandard {
constexpr int32_t AUDIO_FLAG_PCM_OFFLOAD = 5;
static void* g_audioRendererInstance;

struct InterruptEvent {
    int64_t forceType = 0;
    int64_t hintType = 0;
};

enum InterruptMode {
    SHARE_MODE = 0,
    INDEPENDENT_MODE = 1
};

enum RendererState {
    RENDERER_INVALID = -1,
    RENDERER_NEW,
    RENDERER_PREPARED,
    RENDERER_RUNNING,
    RENDERER_STOPPED,
    RENDERER_RELEASED,
    RENDERER_PAUSED
};

enum AudioRenderMode {
    RENDER_MODE_NORMAL,
    RENDER_MODE_CALLBACK
};

enum StateChangeCmdType {
    DUMMY1 = 0,
};

struct AudioDeviceDescriptor {
    int64_t dummy = 0;
};

enum AudioStreamDeviceChangeReason {
    DUMMY2 = 0,
};

struct AudioRendererOptions {
    AudioStreamInfo streamInfo;
    AudioRendererInfo rendererInfo;
};

const std::vector<AudioEncodingType> AUDIO_SUPPORTED_ENCODING_TYPES {
    ENCODING_PCM,
    ENCODING_AUDIOVIVID,
    ENCODING_EAC3
};

class AudioRendererCallback {
public:
    virtual ~AudioRendererCallback() = default;
    virtual void OnInterrupt(const InterruptEvent &interruptEvent) = 0;
    virtual void OnStateChange(const RendererState state, const StateChangeCmdType cmdType) = 0;
};

class AudioRendererErrorCallback {
public:
    virtual ~AudioRendererErrorCallback() = default;
    virtual void OnError(const AudioStandard::AudioErrors errorCode) = 0;
};

class AudioRendererWriteCallback {
public:
    virtual ~AudioRendererWriteCallback() = default;
    virtual void OnWriteData(size_t length) = 0;
};

class AudioRendererFirstFrameWritingCallback {
public:
    virtual ~AudioRendererFirstFrameWritingCallback() = default;
    virtual void OnFirstFrameWriting(uint64_t latency) = 0;
};

class AudioRendererOutputDeviceChangeCallback {
public:
    virtual ~AudioRendererOutputDeviceChangeCallback() = default;
    virtual void OnOutputDeviceChange(const AudioDeviceDescriptor &deviceInfo,
        const AudioStreamDeviceChangeReason reason) = 0;
};

class AudioRendererPolicyServiceDiedCallback {
public:
    virtual ~AudioRendererPolicyServiceDiedCallback() = default;
    virtual void OnAudioPolicyServiceDied() = 0;
};

/**
 * @brief Provides functions for applications to implement audio rendering.
 * @since 8
 */
class AudioRenderer {
public:
    static std::unique_ptr<AudioRenderer> Create(const AudioRendererOptions &rendererOptions)
    {
        (void)rendererOptions;
        void* instance = Media::InstanceMgr::Get().GetInstance();
        std::cout << "instance: " << instance << std::endl;
        if (instance == nullptr) {
            std::cout << "instance is nullptr" << std::endl;
        }
        AudioRenderer* render =  static_cast<AudioRenderer*>(instance);
        std::unique_ptr<AudioRenderer> uniquePtr(render);
        return uniquePtr;
    }

    static std::vector<AudioEncodingType> GetSupportedEncodingTypes()
    {
        return AUDIO_SUPPORTED_ENCODING_TYPES;
    }
    MOCK_METHOD(int32_t, SetOffloadAllowed, (bool isAllowed));
    MOCK_METHOD(void, SetInterruptMode, (InterruptMode mode));
    MOCK_METHOD(RendererState, GetStatus, ());
    MOCK_METHOD(bool, Release, ());
    MOCK_METHOD(int32_t, SetRenderMode, (AudioRenderMode renderMode));
    MOCK_METHOD(int32_t, SetRendererWriteCallback, ((const std::shared_ptr<AudioRendererWriteCallback>)& callback));
    MOCK_METHOD(int32_t, SetBufferDuration, (uint64_t bufferDuration));
    MOCK_METHOD(int32_t, SetRendererCallback, ((const std::shared_ptr<AudioRendererCallback>) &callback));
    MOCK_METHOD(int32_t, RegisterOutputDeviceChangeWithInfoCallback, (
        (const std::shared_ptr<AudioRendererOutputDeviceChangeCallback>) &callback));
    MOCK_METHOD(int32_t, SetRendererFirstFrameWritingCallback, (
        (const std::shared_ptr<AudioRendererFirstFrameWritingCallback>) &callback));
    MOCK_METHOD(int32_t, RegisterAudioPolicyServerDiedCb, (int32_t clientPid,
        (const std::shared_ptr<AudioRendererPolicyServiceDiedCallback>) &callback));
    MOCK_METHOD(bool, Start, ());
    MOCK_METHOD(bool, Pause, ());
    MOCK_METHOD(bool, Flush, ());
    MOCK_METHOD(bool, Stop, ());
    MOCK_METHOD(int32_t, SetSpeed, (float speed));
    MOCK_METHOD(int32_t, SetVolume, (float volume));
    MOCK_METHOD(int32_t, SetLoudnessGain, (float loudnessGain));
    MOCK_METHOD(int32_t, GetAudioTimestampInfo, (Timestamp &timestamp, Timestamp::Timestampbase base));
    MOCK_METHOD(int32_t, GetBufferDesc, (BufferDesc &bufDesc));
    MOCK_METHOD(int32_t, Enqueue, (BufferDesc &bufDesc));
    MOCK_METHOD(bool, Drain, ());
};
}  // namespace AudioStandard
}  // namespace OHOS
#endif  // AUDIO_RENDERER_H
