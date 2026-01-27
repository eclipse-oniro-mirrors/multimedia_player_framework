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

#ifndef NETWORK_CLIENT_AGENT_H
#define NETWORK_CLIENT_AGENT_H

#include <mutex>
#include "network/network_client.h"
#include "network/network_typs.h"

namespace OHOS {
namespace Media {
class NetworkClientAgent {
public:
    static bool Create();
    static void Destroy();
    static std::shared_ptr<Plugins::HttpPlugin::NetworkClient> NewInstance(Plugins::HttpPlugin::RxHeader headCallback,
        Plugins::HttpPlugin::RxBody bodyCallback, void *userParam);

    using CreateFunc = Plugins::HttpPlugin::NetworkClient *(*)(Plugins::HttpPlugin::RxHeader,
        Plugins::HttpPlugin::RxBody, void *);
    static CreateFunc createFunc_;
private:
    static void *handler_;
    static std::mutex loadMutex_;

    static void Unload();
};
} // namespace Media
} // namespace OHOS
#endif // NETWORK_CLIENT_AGENT_H