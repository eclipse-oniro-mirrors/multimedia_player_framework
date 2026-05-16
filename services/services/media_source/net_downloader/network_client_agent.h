/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef NET_DOWNLOADER_NETWORK_CLIENT_AGENT_H
#define NET_DOWNLOADER_NETWORK_CLIENT_AGENT_H

#include <memory>
#include <mutex>
#include <string>

#include "network/network_client.h"
#include "network/network_typs.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class NetworkClientAgent {
public:
    static bool Create();
    static void Destroy();
    static std::shared_ptr<Plugins::HttpPlugin::NetworkClient> NewInstance(
        Plugins::HttpPlugin::RxHeader headCallback,
        Plugins::HttpPlugin::RxBody bodyCallback,
        void *userParam);

private:
    static void *handler_;
    static Plugins::HttpPlugin::NetworkClient* (*createFunc_)(Plugins::HttpPlugin::RxHeader,
        Plugins::HttpPlugin::RxBody, void *);
    static std::mutex loadMutex_;

    static void DestroyInner();
    static void Unload();
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // NET_DOWNLOADER_NETWORK_CLIENT_AGENT_H