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

#ifndef MEDIA_LOADER_H
#define MEDIA_LOADER_H

#include <string>
#include <memory>
#include <map>
#include "cache_reader.h"
#include "loading_request.h"
#include "osal/task/task.h"
#include "osal/task/mutex.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class DownloadedCacheLoader : public LoaderCallback, public std::enable_shared_from_this<DownloadedCacheLoader> {
public:
    explicit DownloadedCacheLoader(std::string url);
    ~DownloadedCacheLoader();
    int64_t Open(std::shared_ptr<LoadingRequest>& request) override;
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    void Close(int64_t uuid) override;

private:
    std::string url_;
    std::shared_ptr<Task> readTask_;
    std::map<int64_t, std::shared_ptr<CacheReader>> requestMap_;
    int64_t uuid_ = 0;
    std::mutex mutex_;
    static std::atomic<uint32_t> instanceCount_;
};

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // MEDIA_LOADER_H