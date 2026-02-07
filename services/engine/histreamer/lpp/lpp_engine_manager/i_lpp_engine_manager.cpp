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

#include "../lpp_engine_manager/i_lpp_engine_manager.h"
#include "common/log.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "ILppEngineManager"};
}

ILppEngineManager &ILppEngineManager::GetInstance()
{
    static ILppEngineManager instance;
    return instance;
}

ILppEngineManager::ILppEngineManager()
{}

ILppEngineManager::~ILppEngineManager()
{
    lppVideoStreamerMap_.clear();
    lppAudioStreamerMap_.clear();
}

void ILppEngineManager::AddLppVideoInstance(const std::string &key, std::shared_ptr<ILppVideoStreamerEngine> instance)
{
    MEDIA_LOG_I("0x%{public}06" PRIXPTR " AddLppVideoInstancee", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(videoMapMutex_);
    lppVideoStreamerMap_[key] = instance;
}

void ILppEngineManager::AddLppAudioInstance(const std::string &key, std::shared_ptr<ILppAudioStreamerEngine> instance)
{
    MEDIA_LOG_I("0x%{public}06" PRIXPTR " AddLppAudioInstance", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(audioMapMutex_);
    lppAudioStreamerMap_[key] = instance;
}

std::shared_ptr<ILppVideoStreamerEngine> ILppEngineManager::GetLppVideoInstance(const std::string &key)
{
    MEDIA_LOG_I("0x%{public}06" PRIXPTR " GetLppVideoInstance", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(videoMapMutex_);
    auto it = lppVideoStreamerMap_.find(key);
    if (it != lppVideoStreamerMap_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

std::shared_ptr<ILppAudioStreamerEngine> ILppEngineManager::GetLppAudioInstance(const std::string &key)
{
    MEDIA_LOG_I("0x%{public}06" PRIXPTR " GetLppAudioInstance", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(audioMapMutex_);
    auto it = lppAudioStreamerMap_.find(key);
    if (it != lppAudioStreamerMap_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

void ILppEngineManager::RemoveLppVideoInstance(const std::string &key)
{
    std::lock_guard<std::mutex> lock(videoMapMutex_);
    lppVideoStreamerMap_.erase(key);
}
void ILppEngineManager::RemoveLppAudioInstance(const std::string &key)
{
    std::lock_guard<std::mutex> lock(audioMapMutex_);
    lppAudioStreamerMap_.erase(key);
}
}  // namespace Media
}  // namespace OHOS