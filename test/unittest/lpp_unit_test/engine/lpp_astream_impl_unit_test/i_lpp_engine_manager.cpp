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

#include <iostream>
#include "i_lpp_engine_manager.h"

namespace OHOS {
namespace Media {

ILppEngineManager& ILppEngineManager::GetInstance()
{
    static ILppEngineManager iLppEngineManager;
    return iLppEngineManager;
}

void ILppEngineManager::AddLppVideoInstance(const std::string &key, std::shared_ptr<ILppVideoStreamerEngine> instance)
{
    return;
}

void ILppEngineManager::AddLppAudioInstance(const std::string &key, std::shared_ptr<ILppAudioStreamerEngine> instance)
{
    return;
}

std::shared_ptr<ILppVideoStreamerEngine> ILppEngineManager::GetLppVideoInstance(const std::string &key)
{
    return nullptr;
}

std::shared_ptr<ILppAudioStreamerEngine> ILppEngineManager::GetLppAudioInstance(const std::string &key)
{
    return nullptr;
}

void ILppEngineManager::removeLppVideoInstance(const std::string &key)
{
    return;
}

void ILppEngineManager::removeLppAudioInstance(const std::string &key)
{
    return;
}
}  // namespace Media
}  // namespace OHOS
