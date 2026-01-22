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

#include "network_client_agent.h"
#include <dlfcn.h>
#include <mutex>
#include "common/log.h"
#include "network/network_client.h"
#include "network/network_typs.h"

namespace {
using namespace OHOS::Media::Plugins::HttpPlugin;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetworkClientAgent" };
#if (defined(__aarch64__) || defined(__x86_64__))
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib64/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#else
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#endif
}

namespace OHOS {
namespace Media {
void *NetworkClientAgent::handler_ = nullptr;
NetworkClientAgent::CreateFunc NetworkClientAgent::createFunc_ = nullptr;
std::mutex NetworkClientAgent::loadMutex_;

bool NetworkClientAgent::Create()
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    FALSE_RETURN_V_NOLOG(handler_ == nullptr || createFunc_ == nullptr, true);
    Unload();
    handler_ = ::dlopen(HTTP_SOURCE_SO_PATH.c_str(), RTLD_NOW | RTLD_LOCAL);
    FALSE_RETURN_V_MSG_E(handler_ != nullptr, false, "dlopen failed due to %{public}s", ::dlerror());
    CreateFunc createFunc = (CreateFunc)(::dlsym(handler_, "CreateNetworkClient"));
    FALSE_RETURN_V_MSG_E(createFunc != nullptr, false, "create func is nullptr");
    createFunc_ = createFunc;
    MEDIA_LOG_I("Create end");
    return true;
}

void NetworkClientAgent::Destroy()
{
    MEDIA_LOG_I("Destroy");
    std::lock_guard<std::mutex> lock(loadMutex_);
    createFunc_ = nullptr;
    Unload();
}

void NetworkClientAgent::Unload()
{
    FALSE_RETURN_NOLOG(handler_ != nullptr);
    (void)dlclose(handler_);
    handler_ = nullptr;
}

std::shared_ptr<NetworkClient> NetworkClientAgent::NewInstance(RxHeader headCallback,
    RxBody bodyCallback, void *userParam)
{
    FALSE_RETURN_V_MSG_E(createFunc_ != nullptr, nullptr, "create func is nullptr");
    auto *clientPtr = createFunc_(headCallback, bodyCallback, userParam);
    FALSE_RETURN_V_MSG_E(clientPtr != nullptr, nullptr, "clientPtr is nullptr");
    return std::shared_ptr<NetworkClient>(clientPtr);
}
} // namespace Media
} // namespace OHOS