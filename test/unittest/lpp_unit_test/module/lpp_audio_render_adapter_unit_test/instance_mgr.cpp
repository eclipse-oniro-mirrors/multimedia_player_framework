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
#include "instance_mgr.h"

namespace OHOS {
namespace Media {

InstanceMgr& InstanceMgr::Get()
{
    static InstanceMgr mgr;
    return mgr;
}
void* InstanceMgr::GetInstance()
{
    std::cout << "InstanceMgr::GetInstance" << this << std::endl;
    std::cout << "InstanceMgr::GetInstance" << instance_ << std::endl;
    return instance_;
}
void InstanceMgr::SetInstance(void* instance)
{
    std::cout << "InstanceMgr::SetInstance" << this << std::endl;
    instance_ = instance;
    std::cout << "InstanceMgr::SetInstance" << instance_ << std::endl;
}
}  // namespace Media
}  // namespace OHOS
