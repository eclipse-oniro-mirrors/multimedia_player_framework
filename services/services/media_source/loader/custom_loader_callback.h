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

#ifndef CUSTOM_LOADER_CALLBACK_H
#define CUSTOM_LOADER_CALLBACK_H

#include <memory>
#include <string>
#include <atomic>
#include <mutex>

#include "loading_request.h"
#include "osal/task/task.h"
#include "osal/task/mutex.h"
#include "cache_manager.h"
#include "file_cache_manager.h"
#include "http_header_parser.h"
#include "request_handler.h"

namespace OHOS {
namespace Media {
class CustomLoaderCallback : public LoaderCallback, public std::enable_shared_from_this<CustomLoaderCallback> {
public:
    CustomLoaderCallback(int64_t uuid, const std::shared_ptr<LoadingRequest>& request,
        const std::shared_ptr<Task>& task, const std::shared_ptr<Task>& readTask,
        const std::shared_ptr<Task>& interruptedTask);
    
    ~CustomLoaderCallback();

    int64_t Open(std::shared_ptr<LoadingRequest>& request) override;
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    void Close(int64_t uuid) override;
    void RemoveCacheFile();
    void SetUrl(std::string url);
    void HandleNonRandomAccessLogic(int64_t uuid, int64_t requestedOffset,
        int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis);
    void SubmitNonRandomReadJob(int64_t uuid, int64_t requestedOffset,
        int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis);
    void HandleRequestDataCore(const std::shared_ptr<CustomLoaderCallback>& self,
        int64_t uuid, int64_t requestedOffset, int64_t requestedLength);
    void HandleNonCacheRequest(const std::shared_ptr<CustomLoaderCallback>& self,
        int64_t uuid, int64_t requestedOffset, int64_t requestedLength);
    void HandleCacheRequest(const std::shared_ptr<CustomLoaderCallback>& self,
        int64_t uuid, int64_t requestedOffset, int64_t requestedLength);
    bool ProcessShard(const std::shared_ptr<CustomLoaderCallback>& self, int64_t uuid,
        int index, int startIndex, int endIndex);
    static size_t RxHeaderData(void* buffer, size_t size, size_t nitems, void* userParam);
    static size_t RxBodyData(void* buffer, size_t size, size_t nitems, void* userParam);
    static size_t RxBodyDataUnsupportRangeAndCache(void* buffer, size_t size, size_t nitems, void* userParam);
    static void AppendToBuffer(CustomLoaderCallback* downloader, const uint8_t* buffer, int64_t dataLen);

private:
    void CreateUrlDir();
    void RequestData(const std::shared_ptr<LoadingRequest>& request, int64_t start, int64_t length);
    void DownloadUnsupportRangeAndCache(int64_t uuid,
        int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis);
    void InitializeClient();
    void StartDownloadTask(const std::weak_ptr<CustomLoaderCallback>& weakThis);
    void ReadDataTask(const std::weak_ptr<CustomLoaderCallback>& weakThis,
        int64_t uuid, int64_t requestedLength);
    void HandleInitialization(int64_t& len, bool& noSizeAndRequest, const std::shared_ptr<CustomLoaderCallback>& self);
    void HandleCacheMiss(int64_t start, int64_t& len, bool noSizeAndRequest,
        const std::shared_ptr<CustomLoaderCallback>& self);
    void HandleDownloadFromStart(int64_t& len, bool noSizeAndRequest,
        const std::shared_ptr<CustomLoaderCallback>& self, const std::weak_ptr<CustomLoaderCallback>& weakThis);
    void RespondDataChunk(int64_t start, int64_t& read, int64_t& len, bool noSizeAndRequest,
        const std::shared_ptr<CustomLoaderCallback>& self);
    void Redownload(const std::weak_ptr<CustomLoaderCallback>& weakThis);

    std::string url_;
    std::string urlDir_;
    int64_t uuid_;
    std::shared_ptr<LoadingRequest> request_;
    std::shared_ptr<Task> task_;
    std::shared_ptr<Task> readTask_;
    std::shared_ptr<Task> interruptedTask_;
    std::shared_ptr<StreamCacheManager> cacheManager_;
    std::shared_ptr<FileCacheManager> fileCacheManager_;
    std::shared_ptr<HttpHeaderParser> headerParser_;
    std::shared_ptr<RequestHandler> requestHandler_;
    std::map<std::string, std::string> headerMap_;
    std::string path_;
    std::string type_;
    int64_t size_ = -1;
    bool randomAccess_ = false;
    std::atomic<bool> isFirstCallback_;
    std::atomic<bool> isHeaderResponded_;
    std::atomic<bool> isSupportLocalCache_;
    std::atomic<bool> isClosed_;
    int64_t currentLen_ {0};
    uint8_t* currentBuffer_;
    int64_t currentOffset_ {0};
    int64_t curOffset_ {0};
    std::mutex mutex_;
    uint8_t* buffer_;
    int64_t dataSize = 0;
    volatile int64_t cacheOffset_ = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condDownload_ = PTHREAD_COND_INITIALIZER;
    pthread_cond_t condReturn_ = PTHREAD_COND_INITIALIZER;
    bool firstRequest_ = true;
    bool isDownload_ = false;
    bool isInterruptedNewDownLoad_ = false;
    bool isInterruptNeeded_ = false;
    int64_t requestedOffset_;
    int64_t requestedLength_;
};
} // namespace Media
} // namespace OHOS
#endif // CUSTOM_LOADER_CALLBACK_H