/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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

#ifndef AUDIO_BACKGROUND_ADAPTER
#define AUDIO_BACKGROUND_ADAPTER

#include <mutex>
#include <list>
#include <map>
#include "audio_system_manager.h"
#include "i_player_service.h"

namespace OHOS {
namespace Media {
class AudioBackgroundAdapter
    : public AudioStandard::AudioBackgroundMuteCallback,
      public std::enable_shared_from_this<AudioBackgroundAdapter>  {
public:
    static AudioBackgroundAdapter &Instance();
    void AddListener(std::weak_ptr<IPlayerService> player, int32_t uid);
    void OnAudioRestart();
    AudioBackgroundAdapter();
    ~AudioBackgroundAdapter();

private:
    void Init();
    void OnBackgroundMute(const int32_t uid) override;

    static std::shared_ptr<AudioBackgroundAdapter> instance_;
    static std::once_flag onceFlag_;
    std::atomic<bool> init_ = false;
    std::map<int32_t, std::list<std::weak_ptr<IPlayerService>>> playerMap_;
    std::mutex mutex_;
    std::mutex initMutex_;
};
}
}
#endif // AUDIO_BACKGROUND_ADAPTER