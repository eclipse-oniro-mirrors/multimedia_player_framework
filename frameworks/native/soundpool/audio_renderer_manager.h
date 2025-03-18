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
#ifndef AUDIO_RENDERER_MANAGER_H
#define AUDIO_RENDERER_MANAGER_H

#include <unistd.h>
#include <list>
#include <utility>
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "audio_renderer.h"
#include "soundpool_xcollie.h"

namespace OHOS {
namespace Media {

class AudioRendererManager {
public:
    AudioRendererManager(const AudioRendererManager&) = delete;
    AudioRendererManager& operator = (const AudioRendererManager&) = delete;
    ~AudioRendererManager();

    static AudioRendererManager& GetInstance();
    int32_t GetGlobeId();
    std::unique_ptr<AudioStandard::AudioRenderer> GetAudioRendererInstance(int32_t globeId);
    void SetAudioRendererInstance(int32_t globeId, std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer);

private:
    AudioRendererManager() {}
    std::mutex renderMgrMutex_;
    int32_t globeIdNext_ = 0;
    std::list<std::pair<int32_t, std::unique_ptr<AudioStandard::AudioRenderer>>> audioRendererVector_;
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_RENDERER_MANAGER_H
