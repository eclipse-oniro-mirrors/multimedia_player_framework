/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef AUDIO_HAPTIC_MANAGER_H
#define AUDIO_HAPTIC_MANAGER_H

#include <string>

#include "audio_info.h"

#include "audio_haptic_player.h"

namespace OHOS {
namespace Media {
enum AudioLatencyMode {
    AUDIO_LATENCY_MODE_NORMAL = 0,
    AUDIO_LATENCY_MODE_FAST = 1
};

struct AudioHapticPlayerOptions {
    bool muteAudio;
    bool muteHaptics;
};

class AudioHapticManager {
public:
    virtual ~AudioHapticManager() = default;

    virtual int32_t RegisterSource(const std::string &audioUri, const std::string &hapticUri) = 0;

    virtual int32_t UnregisterSource(const int32_t &sourceID) = 0;

    virtual int32_t SetAudioLatencyMode(const int32_t &sourceID, const AudioLatencyMode &latencyMode) = 0;

    virtual int32_t SetStreamUsage(const int32_t &sourceID, const AudioStandard::StreamUsage &streamUsage) = 0;

    virtual std::shared_ptr<AudioHapticPlayer> CreatePlayer(const int32_t &sourceID,
        const AudioHapticPlayerOptions &audioHapticPlayerOptions) = 0;
};

class __attribute__((visibility("default"))) AudioHapticManagerFactory {
public:
    static std::unique_ptr<AudioHapticManager> CreateAudioHapticManager();

private:
    AudioHapticManagerFactory() = default;
    ~AudioHapticManagerFactory() = default;
};
} // Media
} // OHOS
#endif // AUDIO_HAPTIC_MANAGER_H