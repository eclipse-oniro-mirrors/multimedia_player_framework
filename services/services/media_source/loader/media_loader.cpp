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

#include "media_loader.h"
#include "media_log.h"
#include "common/log.h"

namespace OHOS {
namespace Media {
namespace {
    using namespace Plugins::HttpPlugin;
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "MediaLoader"};
}

std::atomic<uint32_t> MediaLoader::instanceCount_ = 0;

MediaLoader::MediaLoader(std::string url) : url_(url)
{
    downloadTask_ = std::make_shared<Task>("OS_Custom_Dlr", "", TaskType::SINGLETON, TaskPriority::HIGH, false);
    readTask_ = std::make_shared<Task>("OS_Custom_Read", "", TaskType::SINGLETON, TaskPriority::HIGH, false);
    interruptedTask_ = std::make_shared<Task>(
        "OS_Custom_Interrupted", "", TaskType::SINGLETON, TaskPriority::HIGH, false);
    isSupportLocalCache_ = true;
    instanceCount_.fetch_add(1);
    MEDIA_LOG_I("MediaLoader construtor");
}

MediaLoader::~MediaLoader()
{
    MEDIA_LOG_I("~MediaLoader");
    instanceCount_.fetch_sub(1);
    FALSE_RETURN_MSG(instanceCount_.load() == 0, "Instance count is not zero.");
    StreamCacheManager::Create()->ReleaseMap();
}

int64_t MediaLoader::Open(std::shared_ptr<LoadingRequest>& request)
{
    MEDIA_LOG_I("MediaLoader Open");
    FALSE_RETURN_V_MSG_E(request != nullptr, -1, "request is nullptr");
    std::lock_guard<std::mutex> lock(mutex_);
    ++uuid_;
    requestMap_[uuid_] = std::make_shared<CustomLoaderCallback>(
        uuid_, request, downloadTask_, readTask_, interruptedTask_);
    requestMap_[uuid_]->SetUrl(url_);
    if (!isSupportLocalCache_) {
        requestMap_[uuid_]->RemoveCacheFile();
    }
    requestMap_[uuid_]->Open(request);
    return uuid_;
}

void MediaLoader::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto request = requestMap_.find(uuid);
    if (request == requestMap_.end()) {
        MEDIA_LOG_I("Read error, invalid id: " PUBLIC_LOG_D64, uuid);
        return;
    }
    if (!isSupportLocalCache_) {
        requestMap_[uuid]->RemoveCacheFile();
    }
    request->second->Read(uuid, requestedOffset, requestedLength);
}

void MediaLoader::Close(int64_t uuid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (uuid == -1) {
        isSupportLocalCache_ = false;
        return;
    }
    auto it = requestMap_.find(uuid);
    if (it != requestMap_.end()) {
        it->second->Close(uuid);
        requestMap_.erase(it);
    }
}
} // namespace Media
} // namespace OHOS