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
#include <climits>

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
      fileCacheManager_(cacheManager ? std::make_shared<DownloadedFileCacheManager>(
          cacheManager->GetCacheDir()) : nullptr),
      isClosed_(false), isHeaderResponded_(false) {
    if (cacheManager_ == nullptr) {
        MEDIA_LOG_E("CacheReader: cacheManager is nullptr");
    }
}

CacheReader::~CacheReader()
{
}

int64_t CacheReader::Open(std::shared_ptr<LoadingRequest>& request)
{
    FALSE_RETURN_V_MSG_E(request != nullptr, -1, "request is nullptr");
    std::shared_ptr<LoadingRequest> reqToFinish;
    int32_t finishErrorCode = 0;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        request_ = request;
        url_ = request->GetUrl();

        auto urlStr = cacheManager_->GetMediaCache(url_);
        if (urlStr.empty()) {
            MEDIA_LOG_E("Cache not found for url: %{public}s", url_.c_str());
            reqToFinish = request_;
            finishErrorCode = LOADING_ERROR_NOT_READY;
        } else {
            urlDir_ = urlStr;

            if (!cacheManager_->GetCacheMetaData(url_, metadata_)) {
                MEDIA_LOG_E("Failed to get cache metadata for url: %{public}s", url_.c_str());
                reqToFinish = request_;
                finishErrorCode = LOADING_ERROR_NOT_READY;
            }
        }
    }

    if (reqToFinish != nullptr) {
        reqToFinish->FinishLoading(uuid_, finishErrorCode);
        return -1;
    }

    return uuid_;
}

void CacheReader::RespondHeader(int64_t uuid)
{
    if (isHeaderResponded_.exchange(true)) {
        return;
    }

    if (isClosed_.load()) {
        return;
    }
    if (request_ == nullptr) {
        MEDIA_LOG_E("RespondHeader: request_ is nullptr");
        headerFailed_.store(true);
        return;
    }
    int64_t fileSize = fileCacheManager_ ? fileCacheManager_->GetSize(urlDir_) : -1;
    if (fileSize < 0) {
        MEDIA_LOG_E("RespondHeader: invalid file size=%{public}" PRId64, fileSize);
        headerFailed_.store(true);
        return;
    }
    auto headers = cacheManager_->BuildHttpHeaders(url_, fileSize);
    if (headers.empty()) {
        MEDIA_LOG_E("Failed to build HTTP headers for url: %{public}s", url_.c_str());
        headerFailed_.store(true);
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

bool CacheReader::ReadCacheFile(int64_t requestedOffset, int64_t requestedLength,
    std::shared_ptr<AVSharedMemoryBase> &buffer, int64_t &actualReadLength)
{
    int64_t fileSize = fileCacheManager_ ? fileCacheManager_->GetSize(urlDir_) : -1;
    if (fileSize < 0) {
        MEDIA_LOG_E("Failed to get cache file size: %{public}s", urlDir_.c_str());
        return false;
    }
    int64_t actualRequestedLength = (requestedLength <= 0) ? fileSize : requestedLength;
    if (requestedOffset >= fileSize) {
        MEDIA_LOG_E("Requested offset exceeds file size");
        return false;
    }
    actualReadLength = std::min(actualRequestedLength, fileSize - requestedOffset);
    constexpr int64_t MAX_READ_LENGTH = static_cast<int64_t>(INT32_MAX);
    if (actualReadLength > MAX_READ_LENGTH) {
        actualReadLength = MAX_READ_LENGTH;
    }

    MEDIA_LOG_I("Read from file offset: " PUBLIC_LOG_D64 ", length: " PUBLIC_LOG_D64,
        requestedOffset, actualReadLength);

    int32_t bufSize = static_cast<int32_t>(actualReadLength);
    buffer = std::make_shared<AVSharedMemoryBase>(bufSize, AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    if (buffer->Init() != 0 || buffer->GetBase() == nullptr) {
        MEDIA_LOG_E("Failed to init shared memory buffer");
        return false;
    }
    if (fileCacheManager_->Read(urlDir_, buffer->GetBase(), requestedOffset, actualReadLength) != 0) {
        MEDIA_LOG_E("Failed to read cache file: %{public}s", urlDir_.c_str());
        return false;
    }
    return true;
}

void CacheReader::RespondCacheData(int64_t uuid, int64_t requestedOffset, int64_t requestedLength,
    int64_t actualReadLength, const std::shared_ptr<AVSharedMemoryBase> &buffer,
    std::shared_ptr<LoadingRequest> &reqToFinish, int32_t &finishErrorCode, bool &shouldFinish)
{
    if (request_ == nullptr) {
        MEDIA_LOG_E("HandleCacheRequest: request_ is nullptr");
        shouldFinish = true;
        return;
    }
    MEDIA_LOG_I("RespondData offset: " PUBLIC_LOG_D64 ", readLen: " PUBLIC_LOG_D64,
        requestedOffset, actualReadLength);
    auto ret = request_->RespondData(uuid, requestedOffset, buffer);
    if (ret < 0) {
        MEDIA_LOG_E("RespondData failed");
        reqToFinish = request_;
        finishErrorCode = LOADING_ERROR_NOT_READY;
        shouldFinish = true;
    } else if (requestedLength == -1 || actualReadLength != requestedLength) {
        MEDIA_LOG_I("RespondData whole file complete, offset: " PUBLIC_LOG_D64
            ", request: " PUBLIC_LOG_D64 ", readLen: " PUBLIC_LOG_D64,
            requestedOffset, requestedLength, actualReadLength);
        reqToFinish = request_;
        finishErrorCode = LOADING_ERROR_SUCCESS;
        shouldFinish = true;
    }
}

void CacheReader::HandleCacheRequest(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    std::shared_ptr<LoadingRequest> reqToFinish;
    int32_t finishErrorCode = 0;
    bool shouldFinish = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isClosed_.load()) {
            return;
        }
        RespondHeader(uuid);

        if (headerFailed_.load()) {
            reqToFinish = request_;
            finishErrorCode = LOADING_ERROR_NOT_READY;
            shouldFinish = true;
        } else if (requestedLength == 0) {
            MEDIA_LOG_W("RequestedLength is zero, finish it.");
            reqToFinish = request_;
            finishErrorCode = LOADING_ERROR_SUCCESS;
            shouldFinish = true;
        } else {
            std::shared_ptr<AVSharedMemoryBase> buffer;
            int64_t actualReadLength = 0;
            if (!ReadCacheFile(requestedOffset, requestedLength, buffer, actualReadLength)) {
                reqToFinish = request_;
                finishErrorCode = LOADING_ERROR_NOT_READY;
                shouldFinish = true;
            } else {
                RespondCacheData(uuid, requestedOffset, requestedLength, actualReadLength,
                    buffer, reqToFinish, finishErrorCode, shouldFinish);
            }
        }
    }

    if (shouldFinish && reqToFinish != nullptr) {
        reqToFinish->FinishLoading(uuid, finishErrorCode);
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
