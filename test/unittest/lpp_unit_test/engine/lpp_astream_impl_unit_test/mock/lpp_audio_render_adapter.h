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

#include "audio_renderer.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;

class LppAudioRenderAdapter : public std::enable_shared_from_this<LppAudioRenderAdapter> {
public:
    LppAudioRenderAdapter(const std::string &streamerId) {}
    ~LppAudioRenderAdapter() = default;

    MOCK_METHOD(int32_t, Init, ());
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, Start, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, SetParameter, (const Format &param));
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Resume, ());

    MOCK_METHOD(int32_t, Deinit, ());
    MOCK_METHOD(int32_t, SetSpeed, (float speed));
    MOCK_METHOD(int32_t, SetVolume, (const float volume));
    MOCK_METHOD(int32_t, GetCurrentPosition, (int64_t &currentPosition));

    MOCK_METHOD(void, OnWriteData, (size_t length));
    MOCK_METHOD(void, OnBufferAvailable, ());
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<EventReceiver> eventReceiver));

    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetBufferQueueProducer, ());

    MOCK_METHOD(void, OnInterrupt, (const OHOS::AudioStandard::InterruptEvent &interruptEvent));
    MOCK_METHOD(void, OnStateChange, (const OHOS::AudioStandard::RendererState &state,
        const OHOS::AudioStandard::StateChangeCmdType &cmdType));
    MOCK_METHOD(void, OnOutputDeviceChange, (const AudioStandard::AudioDeviceDescriptor &deviceInfo,
        const AudioStandard::AudioStreamDeviceChangeReason &reason));
    MOCK_METHOD(void, OnAudioPolicyServiceDied, ());
    MOCK_METHOD(void, OnFirstFrameWriting, (uint64_t latency));
};
}  // namespace Media
}  // namespace OHOS
#endif