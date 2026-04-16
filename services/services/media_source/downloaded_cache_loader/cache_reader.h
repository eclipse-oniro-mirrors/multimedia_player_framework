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

#ifndef DOWNLOADED_CACHE_READER_H
#define DOWNLOADED_CACHE_READER_H

#include <memory>
#include <string>
#include <atomic>
#include <mutex>
#include <filesystem>

#include "cache_manager.h"
#include "file_cache_manager.h"
#include "loading_request.h"
#include "osal/task/task.h"
#include "osal/task/mutex.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class CacheReader : public LoaderCallback, public std::enable_shared_from_this<CacheReader> {
public:
    CacheReader(int64_t uuid, const std::shared_ptr<LoadingRequest>& request,
        const std::shared_ptr<Task>& readTask,
        std::shared_ptr<DownloadedCacheManager> cacheManager);

    ~CacheReader();

    int64_t Open(std::shared_ptr<LoadingRequest>& request) override;
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    void Close(int64_t uuid) override;

private:
    void RespondHeader(int64_t uuid);
    void HandleCacheRequest(int64_t uuid, int64_t requestedOffset, int64_t requestedLength);

    std::string url_;
    std::string urlDir_;
    int64_t uuid_;
    std::shared_ptr<LoadingRequest> request_;
    std::shared_ptr<Task> readTask_;
    std::shared_ptr<DownloadedCacheManager> cacheManager_;
    std::shared_ptr<DownloadedFileCacheManager> fileCacheManager_;

    CacheMetaData metadata_;
    std::atomic<bool> isClosed_ {false};
    std::mutex mutex_;
    std::atomic<bool> isHeaderResponded_ {false};
};
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
#endif // DOWNLOADED_CACHE_READER_H