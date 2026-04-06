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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "CacheReader" };
constexpr int64_t SHARD_SIZE = 4 * 1024 * 1024;
constexpr int32_t CACHE_NOT_FOUND_ERROR = 404;
}

CacheReader::CacheReader(int64_t uuid, const std::shared_ptr<LoadingRequest>& request,
    const std::shared_ptr<Task>& readTask)
    : uuid_(uuid), request_(request), readTask_(readTask),
      cacheManager_(DownloadedCacheManager::Create()),
      fileCacheManager_(DownloadedFileCacheManager::Create()),
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

    auto urlStr = cacheManager_->GetMediaCache(url_);
    if (urlStr.empty()) {
        MEDIA_LOG_E("Cache not found for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid_, CACHE_NOT_FOUND_ERROR);
        return -1;
    }

    urlDir_ = urlStr;

    if (!cacheManager_->GetCacheMetaData(url_, metadata_)) {
        MEDIA_LOG_E("Failed to get cache metadata for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid_, CACHE_NOT_FOUND_ERROR);
        return -1;
    }

    return uuid_;
}

void CacheReader::SetUrl(std::string url)
{
    url_ = url;
}

void CacheReader::RespondHeader(int64_t uuid)
{
    if (isHeaderResponded_) {
        return;
    }
    
    auto headers = cacheManager_->BuildHttpHeaders(url_);
    if (headers.empty()) {
        MEDIA_LOG_E("Failed to build HTTP headers for url: %{public}s", url_.c_str());
        request_->FinishLoading(uuid, CACHE_NOT_FOUND_ERROR);
        return;
    }
    
    request_->RespondHeader(uuid, headers, "");
    isHeaderResponded_ = true;
}

void CacheReader::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MEDIA_LOG_I(PUBLIC_LOG_D64 " Read requestedOffset: " PUBLIC_LOG_D64" requestedLength: " PUBLIC_LOG_D64
        " randomAccess_ = " PUBLIC_LOG_D32, uuid, requestedOffset, requestedLength, metadata_.randomAccess);

    RespondHeader(uuid);

    if (requestedLength == 0) {
        MEDIA_LOG_W("RequestedLength is zero, finish it.");
        request_->FinishLoading(uuid, 0);
        return;
    }

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

    int startIndex = static_cast<int>(requestedOffset / SHARD_SIZE);
    int requestLength = (requestedLength <= 0) ? static_cast<int>(metadata_.size) : static_cast<int>(requestedLength);
    int64_t end = requestedOffset + requestLength;
    int endIndex = static_cast<int>((end - 1) / SHARD_SIZE);
    
    MEDIA_LOG_I("Start read start: " PUBLIC_LOG_D32 ", end: " PUBLIC_LOG_D32 ", offset: " PUBLIC_LOG_D64
        ", len = " PUBLIC_LOG_D64, startIndex, endIndex, requestedOffset, end);
    
    requestedOffset_ = requestedOffset;
    requestedLength_ = requestLength;
    
    for (int i = startIndex; i <= endIndex; ++i) {
        if (!ProcessShard(uuid, i, startIndex, endIndex)) {
            break;
        }
    }

    if (requestedLength == -1) {
        request_->FinishLoading(uuid, 0);
    }
}

bool CacheReader::ProcessShard(int64_t uuid, int index, int startIndex, int endIndex)
{
    if (isClosed_.load()) {
        return false;
    }

    path_ = std::to_string(std::hash<std::string>()(url_)) + "_" + std::to_string(index);
    std::string dataPath = urlDir_ + "/" + path_ + ".data";
    
    int len = (index == static_cast<int>((metadata_.size - 1) / SHARD_SIZE)) ? 
              static_cast<int>(metadata_.size % SHARD_SIZE) : static_cast<int>(SHARD_SIZE);
    if (len == 0) {
        len = static_cast<int>(SHARD_SIZE);
    }
    
    if (!fileCacheManager_->IsValid(dataPath, len)) {
        MEDIA_LOG_E("Cache shard invalid: %{public}s, expected size: %{public}d", dataPath.c_str(), len);
        request_->FinishLoading(uuid, CACHE_NOT_FOUND_ERROR);
        return false;
    }
    
    if (curOffset_ != requestedOffset_) {
        MEDIA_LOG_I("drop requestedOffset: " PUBLIC_LOG_D64, requestedOffset_);
        return false;
    }
    
    int64_t fileSize = fileCacheManager_->GetSize(dataPath);
    if (fileSize < 0) {
        MEDIA_LOG_E("Failed to get cache file size: %{public}s", dataPath.c_str());
        request_->FinishLoading(uuid, CACHE_NOT_FOUND_ERROR);
        return false;
    }
    
    int64_t endOffset = requestedOffset_ + requestedLength_ - 1;
    int fileBeg = (index == startIndex) ? static_cast<int>(requestedOffset_ % SHARD_SIZE) : 0;
    int fileEnd = (index == endIndex) ? static_cast<int>(endOffset % SHARD_SIZE) : static_cast<int>(SHARD_SIZE - 1);
    if (fileEnd >= static_cast<int>(fileSize)) {
        fileEnd = static_cast<int>(fileSize - 1);
    }
    int fileReadLen = (fileEnd >= fileBeg) ? (fileEnd - fileBeg + 1) : 0;
    
    if (fileReadLen <= 0) {
        return true;
    }
    
    auto buffer = std::make_shared<AVSharedMemoryBase>(
        static_cast<int32_t>(fileReadLen), AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    buffer->Init();

    if (fileCacheManager_->Read(dataPath, buffer->GetBase(), fileBeg, fileReadLen) != 0) {
        MEDIA_LOG_E("Failed to read cache file: %{public}s", dataPath.c_str());
        request_->FinishLoading(uuid, CACHE_NOT_FOUND_ERROR);
        return false;
    }
    
    int64_t offset = index * SHARD_SIZE + fileBeg;
    MEDIA_LOG_I("RespondData offset: " PUBLIC_LOG_D64" fileReadLen: " PUBLIC_LOG_D32,
        offset, fileReadLen);

    auto ret = request_->RespondData(uuid, offset, buffer);
    return ret >= 0;
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