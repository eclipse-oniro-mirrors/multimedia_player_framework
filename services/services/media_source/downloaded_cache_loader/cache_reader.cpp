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

#include <filesystem>
#include <functional>
#include <iomanip>
#include <sstream>

#include "cache_reader.h"
#include "common/log.h"
#include "media_log.h"

namespace fs = std::filesystem;

namespace OHOS {
namespace Media {
namespace DownloadedCache {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedCacheReader" };
constexpr int32_t LOADING_ERROR_SUCCESS = 0;
constexpr int32_t LOADING_ERROR_NOT_READY = 1;
}

CacheReader::CacheReader(int64_t uuid, const std::shared_ptr<LoadingRequest>& request,
    const std::shared_ptr<Task>& readTask,
    std::shared_ptr<DownloadedCacheManager> cacheManager)
    : uuid_(uuid), request_(request), readTask_(readTask),
      cacheManager_(cacheManager),
      fileCacheManager_(std::make_shared<DownloadedFileCacheManager>(cacheManager->GetCacheDir())),
      isClosed_(false), isHeaderResponded_(false) {
}

CacheReader::~CacheReader()
{
}

int64_t CacheReader::Open(std::shared_ptr<LoadingRequest>& request)
{
    FALSE_RETURN_V_MSG_E(request != nullptr, -1, "request is nullptr");
    std::lock_guard<std::mutex> lock(mutex_);
    request_ = request;
    url_ = request->GetUrl();

    auto urlStr = cacheManager_->GetMediaCache(url_);
    if (urlStr.empty()) {
        MEDIA_LOG_E("Cache not found for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid_, LOADING_ERROR_NOT_READY);
        return -1;
    }

    urlDir_ = urlStr;

    if (!cacheManager_->GetCacheMetaData(url_, metadata_)) {
        MEDIA_LOG_E("Failed to get cache metadata for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid_, LOADING_ERROR_NOT_READY);
        return -1;
    }

    return uuid_;
}

void CacheReader::RespondHeader(int64_t uuid)
{
    if (isHeaderResponded_.load()) {
        return;
    }
    isHeaderResponded_.store(true);

    if (isClosed_.load()) {
        return;
    }
    auto headers = cacheManager_->BuildHttpHeaders(url_);
    if (headers.empty()) {
        MEDIA_LOG_E("Failed to build HTTP headers for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid, LOADING_ERROR_NOT_READY);
        return;
    }

    request_->RespondHeader(uuid, headers, "");
}

void CacheReader::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MEDIA_LOG_I(PUBLIC_LOG_D64 " Read requestedOffset: " PUBLIC_LOG_D64" requestedLength: " PUBLIC_LOG_D64
        " randomAccess_ = " PUBLIC_LOG_D32, uuid, requestedOffset, requestedLength, metadata_.randomAccess);

    auto weakThis = weak_from_this();
    readTask_->SubmitJobOnce([weakThis, uuid, requestedOffset, requestedLength] {
        auto self = weakThis.lock();
        if (!self) {
            return;
        }
        self->HandleCacheRequest(uuid, requestedOffset, requestedLength);
    });
}

void CacheReader::HandleCacheRequest(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    if (isClosed_.load()) {
        return;
    }

    RespondHeader(uuid);

    if (requestedLength == 0) {
        MEDIA_LOG_W("RequestedLength is zero, finish it.");
        request_->FinishLoading(uuid, LOADING_ERROR_SUCCESS);
        return;
    }

    int64_t fileSize = fileCacheManager_->GetSize(urlDir_);
    if (fileSize < 0) {
        MEDIA_LOG_E("Failed to get cache file size: %{public}s", urlDir_.c_str());
        request_->FinishLoading(uuid, LOADING_ERROR_NOT_READY);
        return;
    }

    int64_t actualRequestedLength = (requestedLength <= 0) ? fileSize : requestedLength;
    if (requestedOffset >= fileSize) {
        MEDIA_LOG_E("Requested offset exceeds file size");
        request_->FinishLoading(uuid, LOADING_ERROR_NOT_READY);
        return;
    }

    int64_t actualReadLength = std::min(actualRequestedLength, fileSize - requestedOffset);

    MEDIA_LOG_I("Read from file offset: " PUBLIC_LOG_D64 ", length: " PUBLIC_LOG_D64,
        requestedOffset, actualReadLength);

    auto buffer = std::make_shared<AVSharedMemoryBase>(
        static_cast<int32_t>(actualReadLength), AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    buffer->Init();

    if (fileCacheManager_->Read(urlDir_, buffer->GetBase(), requestedOffset, actualReadLength) != 0) {
        MEDIA_LOG_E("Failed to read cache file: %{public}s", urlDir_.c_str());
        request_->FinishLoading(uuid, LOADING_ERROR_NOT_READY);
        return;
    }

    MEDIA_LOG_I("RespondData offset: " PUBLIC_LOG_D64 ", readLen: " PUBLIC_LOG_D64,
        requestedOffset, actualReadLength);

    auto ret = request_->RespondData(uuid, requestedOffset, buffer);
    if (ret < 0) {
        MEDIA_LOG_E("RespondData failed");
        request_->FinishLoading(uuid, LOADING_ERROR_NOT_READY);
        return;
    }

    if (requestedLength == -1 || actualReadLength != requestedLength) {
        MEDIA_LOG_I("RespondData whole file complete, offset: " PUBLIC_LOG_D64 ", request: " PUBLIC_LOG_D64
            ", readLen: " PUBLIC_LOG_D64, requestedOffset, requestedLength, actualReadLength);
        request_->FinishLoading(uuid, LOADING_ERROR_SUCCESS);
    }
}

void CacheReader::Close(int64_t uuid)
{
    (void)uuid;
    std::lock_guard<std::mutex> lock(mutex_);
    isClosed_.store(true);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
