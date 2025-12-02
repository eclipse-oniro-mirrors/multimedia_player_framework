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

#ifndef AUDIO_HAPTIC_MANAGER_TAIHE_H
#define AUDIO_HAPTIC_MANAGER_TAIHE_H

#include "ohos.multimedia.audioHaptic.audioHaptic.proj.hpp"
#include "ohos.multimedia.audioHaptic.audioHaptic.impl.hpp"
#include "taihe/runtime.hpp"

#include "audio_haptic_manager.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::audioHaptic::audioHaptic;

struct AudioHapticManagerTaiheContext;

class AudioHapticManagerImpl {
public:
    AudioHapticManagerImpl();
    AudioHapticManagerImpl(std::shared_ptr<OHOS::Media::AudioHapticManager> audioHapticMgrClient);
    ~AudioHapticManagerImpl();

    int32_t RegisterSourceSync(string_view audioUri, string_view hapticUri);
    void UnregisterSourceSync(int32_t id);
    void SetAudioLatencyMode(int32_t id, AudioLatencyMode latencyMode);
    void SetStreamUsage(int32_t id, uintptr_t usage);
    int32_t RegisterSourceFromFdSync(AudioHapticFileDescriptor const& audioFd,
        AudioHapticFileDescriptor const& hapticFd);
    AudioHapticPlayer CreatePlayerSync(int32_t id, optional_view<AudioHapticPlayerOptions> options);

private:
    bool IsLegalAudioLatencyMode(int32_t latencyMode);
    bool IsLegalAudioStreamUsage(int32_t streamUsage);
    static int32_t GetAudioHapticFileDescriptorValue(AudioHapticFileDescriptor const & audioFd,
        OHOS::Media::AudioHapticFileDescriptor& audioHapticFd);
    void CreatePlayerExecute(std::unique_ptr<AudioHapticManagerTaiheContext> &taiheContext);
    AudioHapticPlayer CreatePlayerComplete(std::unique_ptr<AudioHapticManagerTaiheContext> &taiheContext);

    std::shared_ptr<OHOS::Media::AudioHapticManager> audioHapticMgrClient_ = nullptr;
};

struct AudioHapticManagerTaiheContext {
    bool status;
    std::string audioUri;
    std::string hapticUri;
    std::shared_ptr<OHOS::Media::AudioHapticPlayer> audioHapticPlayer;
    int32_t sourceID;
    OHOS::Media::AudioHapticPlayerOptions playerOptions {false, false};
    std::string errMessage;
    int32_t errCode;
};
} // namespace ANI::Media

#endif // AUDIO_HAPTIC_MANAGER_TAIHE_H