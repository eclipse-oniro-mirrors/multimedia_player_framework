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

#include "downloaded_cache_loader.h"
#include "media_log.h"
#include "common/log.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedCacheLoader"};
}

std::atomic<uint32_t> DownloadedCacheLoader::instanceCount_ = 0;

DownloadedCacheLoader::DownloadedCacheLoader(std::string url) : url_(url)
{
    readTask_ = std::make_shared<Task>("OS_Custom_Read", "", TaskType::SINGLETON, TaskPriority::HIGH, false);
    instanceCount_.fetch_add(1);
    MEDIA_LOG_I("DownloadedCacheLoader construtor");
}

DownloadedCacheLoader::~DownloadedCacheLoader()
{
    MEDIA_LOG_I("~DownloadedCacheLoader");
    instanceCount_.fetch_sub(1);
    FALSE_RETURN_MSG(instanceCount_.load() == 0, "Instance count is not zero.");
    DownloadedCacheManager::Create()->ReleaseMap();
}

int64_t DownloadedCacheLoader::Open(std::shared_ptr<LoadingRequest>& request)
{
    MEDIA_LOG_I("DownloadedCacheLoader Open");
    FALSE_RETURN_V_MSG_E(request != nullptr, -1, "request is nullptr");
    std::lock_guard<std::mutex> lock(mutex_);
    ++uuid_;
    requestMap_[uuid_] = std::make_shared<CacheReader>(uuid_, request, readTask_);
    requestMap_[uuid_]->SetUrl(url_);
    return requestMap_[uuid_]->Open(request);
}

void DownloadedCacheLoader::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto request = requestMap_.find(uuid);
    if (request == requestMap_.end()) {
        MEDIA_LOG_I("Read error, invalid id: " PUBLIC_LOG_D64, uuid);
        return;
    }
    request->second->Read(uuid, requestedOffset, requestedLength);
}

void DownloadedCacheLoader::Close(int64_t uuid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = requestMap_.find(uuid);
    if (it != requestMap_.end()) {
        it->second->Close(uuid);
        requestMap_.erase(it);
    }
}
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS