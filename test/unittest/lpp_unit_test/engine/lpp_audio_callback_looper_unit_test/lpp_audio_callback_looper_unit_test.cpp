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

#ifndef LPP_ENGINE_MANAGER_H
#define LPP_ENGINE_MANAGER_H

#include "i_lpp_video_streamer.h"
#include "i_lpp_audio_streamer.h"

namespace OHOS {
namespace Media {
class ILppEngineManager {
public:
    static ILppEngineManager &GetInstance();

    // ILppEngineManager(const ILppEngineManager &) = delete;
    // ILppEngineManager &operator=(const ILppEngineManager &) = delete;

    void AddLppVideoInstance(const std::string &key, std::shared_ptr<ILppVideoStreamerEngine> instance);
    void AddLppAudioInstance(const std::string &key, std::shared_ptr<ILppAudioStreamerEngine> instance);

    std::shared_ptr<ILppVideoStreamerEngine> GetLppVideoInstance(const std::string &key);
    std::shared_ptr<ILppAudioStreamerEngine> GetLppAudioInstance(const std::string &key);

    void RemoveLppVideoInstance(const std::string &key);
    void RemoveLppAudioInstance(const std::string &key);

private:
    void* instance_;
};
}  // namespace Media
}  // namespace OHOS

#endif  // LPP_ENGINE_MANAGER_H
