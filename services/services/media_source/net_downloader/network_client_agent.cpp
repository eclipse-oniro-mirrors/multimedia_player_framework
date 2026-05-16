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

#include <dlfcn.h>

#include "network_client_agent.h"

#include "common/log.h"

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderNetworkClientAgent"};
#if (defined(__aarch64__) || defined(__x86_64__))
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib64/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#else
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#endif
}

void *NetworkClientAgent::handler_ = nullptr;
Plugins::HttpPlugin::NetworkClient* (*NetworkClientAgent::createFunc_)(Plugins::HttpPlugin::RxHeader,
    Plugins::HttpPlugin::RxBody, void *) = nullptr;
std::mutex NetworkClientAgent::loadMutex_;

bool NetworkClientAgent::Create()
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (handler_ != nullptr && createFunc_ != nullptr) {
        return true;
    }
    DestroyInner();
    handler_ = ::dlopen(HTTP_SOURCE_SO_PATH.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handler_ == nullptr) {
        MEDIA_LOGE("dlopen failed due to %{public}s", ::dlerror());
        return false;
    }
    using CreateFuncType = Plugins::HttpPlugin::NetworkClient* (*)(Plugins::HttpPlugin::RxHeader,
        Plugins::HttpPlugin::RxBody, void *);
    CreateFuncType createFunc = (CreateFuncType)(::dlsym(handler_, "CreateNetworkClient"));
    if (createFunc == nullptr) {
        MEDIA_LOGE("create func is nullptr");
        Unload();
        return false;
    }
    createFunc_ = createFunc;
    MEDIA_LOGI("NetworkClientAgent::Create success");
    return true;
}

void NetworkClientAgent::Destroy()
{
    MEDIA_LOGI("NetworkClientAgent::Destroy");
    std::lock_guard<std::mutex> lock(loadMutex_);
    DestroyInner();
}

void NetworkClientAgent::DestroyInner()
{
    createFunc_ = nullptr;
    if (handler_ != nullptr) {
        (void)dlclose(handler_);
        handler_ = nullptr;
    }
}

std::shared_ptr<Plugins::HttpPlugin::NetworkClient> NetworkClientAgent::NewInstance(
    Plugins::HttpPlugin::RxHeader headCallback,
    Plugins::HttpPlugin::RxBody bodyCallback,
    void *userParam)
{
    if (createFunc_ == nullptr) {
        MEDIA_LOGE("create func is nullptr");
        return nullptr;
    }
    auto *clientPtr = createFunc_(headCallback, bodyCallback, userParam);
    if (clientPtr == nullptr) {
        MEDIA_LOGE("clientPtr is nullptr");
        return nullptr;
    }
    return std::shared_ptr<Plugins::HttpPlugin::NetworkClient>(clientPtr);
}

void NetworkClientAgent::Unload()
{
    if (handler_ != nullptr) {
        (void)dlclose(handler_);
        handler_ = nullptr;
    }
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS