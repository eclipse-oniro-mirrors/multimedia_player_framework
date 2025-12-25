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

#include <list>
#include <unistd.h>
#include <utility>

#include "audio_renderer.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "parallel_stream_manager.h"
#include "soundpool_xcollie.h"
#include "stream_id_manager.h"

namespace OHOS {
namespace Media {

class AudioRendererManager {
public:
    AudioRendererManager(const AudioRendererManager&) = delete;
    AudioRendererManager& operator = (const AudioRendererManager&) = delete;
    ~AudioRendererManager();

    static AudioRendererManager& GetInstance();
    int32_t GetGlobalId();
    std::unique_ptr<AudioStandard::AudioRenderer> GetAudioRendererInstance(int32_t globalId);
    void SetAudioRendererInstance(int32_t globalId, std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer);
    void RemoveOldAudioRenderer();
    void SetParallelManager(std::weak_ptr<ParallelStreamManager> parallelManager);
    void SetStreamIDManager(std::weak_ptr<IStreamIDManager> streamIDManager);
    void DelAudioRenderer(int32_t globalId);

private:
    AudioRendererManager() {}
    void DeleteManager(int32_t globalId);
    std::mutex renderMgrMutex_;
    int32_t globalIdNext_ = 0;
    std::list<std::pair<int32_t, std::unique_ptr<AudioStandard::AudioRenderer>>> audioRendererVector_;
    std::list<std::weak_ptr<ParallelStreamManager>> parallelManagerList_;
    std::list<std::weak_ptr<IStreamIDManager>> streamIDManagerList_;
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_RENDERER_MANAGER_H
