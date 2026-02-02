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

#include "custom_loader_callback.h"
#include <filesystem>
#include <functional>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>   // 必须包含，定义 S_IRUSR, S_IWUSR 等权限位
#include <fcntl.h>      // 已有，但确保在 sys/stat.h 后
#include "media_log.h"
#include "common/log.h"
#include "network_client_agent.h"

namespace fs = std::filesystem;

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "CustomLoaderCallback" };
    constexpr int64_t SHARD_SIZE = 4 * 1024 * 1024;
    constexpr int64_t WAIT_TIME_US = 10000;
    constexpr int64_t INTERNET_WAIT_TIME = 100;
    constexpr int64_t TAB_INDEX = 2;
}

CustomLoaderCallback::CustomLoaderCallback(int64_t uuid,
    const std::shared_ptr<LoadingRequest>& request, const std::shared_ptr<Task>& task,
    const std::shared_ptr<Task>& readTask, const std::shared_ptr<Task>& interruptedTask)
    : uuid_(uuid), request_(request), task_(task), readTask_(readTask), interruptedTask_(interruptedTask),
      cacheManager_(StreamCacheManager::Create()),
      fileCacheManager_(FileCacheManager::Create()),
      headerParser_(std::make_shared<HttpHeaderParser>()),
      requestHandler_(std::make_shared<RequestHandler>(nullptr)),
      isFirstCallback_(false),
      isHeaderResponded_(false),
      isSupportLocalCache_(true),
      isClosed_(false) {
    requestHandler_->SetCacheManager(cacheManager_);
    requestHandler_->SetFileCacheManager(fileCacheManager_);
    requestHandler_->SetHeaderParser(headerParser_);
    buffer_ = static_cast<uint8_t *>(malloc(SHARD_SIZE));
    FALSE_RETURN_MSG(buffer_ != nullptr, "buffer_ is nullptr");
    NetworkClientAgent::Create();
}

CustomLoaderCallback::~CustomLoaderCallback()
{
    if (requestHandler_->GetClient()) {
        requestHandler_->GetClient()->Deinit();
        requestHandler_->GetClient()->Close(false);
        requestHandler_->SetClient(nullptr);
    }
}

int64_t CustomLoaderCallback::Open(std::shared_ptr<LoadingRequest>& request)
{
    FALSE_RETURN_V_MSG_E(request != nullptr, -1, "request is nullptr");
    std::lock_guard<std::mutex> lock(mutex_);
    request_ = request;
 
    auto urlStr = cacheManager_->GetMediaCache(url_);
    if (urlStr.empty()) {
        MEDIA_LOG_I("url not exist");
        isFirstCallback_.store(true);
        RequestData(request, 0, 0);
        headerMap_ = requestHandler_->GetHeaders();
        CreateUrlDir();
        return uuid_;
    }
 
    urlDir_ = urlStr;
    std::string headerPath = urlDir_ + "/" + std::to_string(std::hash<std::string>()(request->GetUrl())) + ".header";
    if (!fs::exists(headerPath)) {
        MEDIA_LOG_I("header file not exist");
        isHeaderResponded_.store(false);
        isFirstCallback_.store(true);
        RequestData(request, 0, 0);
        headerMap_ = requestHandler_->GetHeaders();
        CreateUrlDir();
        return uuid_;
    }
 
    std::ifstream file(headerPath);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    HttpHeaderParser::ParseHttpHeader(headerMap_, content);
    CreateUrlDir();
    return uuid_;
}

void CustomLoaderCallback::CreateUrlDir()
{
    if (requestHandler_->IsRequestError()) {
        MEDIA_LOG_E("Request error, no need to create url dir.");
        return;
    }
    
    auto contentLength = headerMap_.find("content-length");
    if (contentLength != headerMap_.end()) {
        size_ = std::stoll(contentLength->second);
    }

    auto type = headerMap_.find("content-type");
    if (type != headerMap_.end()) {
        type_ = type->second;
    }

    auto rangeValue = headerMap_.find("content-range");
    auto acceptRanges = headerMap_.find("accept-ranges");
    randomAccess_ = (rangeValue != headerMap_.end() || acceptRanges != headerMap_.end());

    if (cacheManager_ && cacheManager_->GetMediaCache(url_).empty()) {
        cacheManager_->CreateMediaCache(url_, type_, randomAccess_, size_);
    }

    urlDir_ = cacheManager_->GetMediaCache(url_);
    std::string headerPath = urlDir_ + "/" + std::to_string(std::hash<std::string>()(request_->GetUrl())) + ".header";
    if (!fs::exists(headerPath)) {
        // 写入 header 文件
        int fd = open(headerPath.c_str(), O_WRONLY | O_CREAT, 0644);
        if (fd != -1) {
            for (const auto& [key, value] : headerMap_) {
                std::string line = key + ": " + value + "\r\n";
                write(fd, line.c_str(), line.size());
            }
            write(fd, "\r\n", TAB_INDEX);
            close(fd);
        }
    }
    requestHandler_->SetUrlDir(urlDir_);
    MEDIA_LOG_I("RxBodyData first come randomAccess_ %{public}d", randomAccess_);
}

void CustomLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MEDIA_LOG_I(PUBLIC_LOG_D64 " Read requestedOffset: " PUBLIC_LOG_D64" requestedLength: " PUBLIC_LOG_D64
        " randomAccess_ = " PUBLIC_LOG_D32, uuid, requestedOffset, requestedLength, randomAccess_);
    if (!requestHandler_->GetClient()) {
        MEDIA_LOG_I("Read requestHandler_->GetClient() is null");
        auto client = NetworkClientAgent::NewInstance(&RxHeaderData, &RxBodyData, this);
        FALSE_RETURN_MSG(client != nullptr, "client is null");
        client->Init();
        requestHandler_->SetClient(client);
    }

    auto weakThis = weak_from_this();
    if (!randomAccess_) {
        HandleNonRandomAccessLogic(uuid, requestedOffset, requestedLength, weakThis);
        return;
    }

    // 随机访问逻辑
    curOffset_ = requestedOffset;
    readTask_->SubmitJobOnce([weakThis, uuid, requestedOffset, requestedLength] {
        auto self = weakThis.lock();
        if (!self) {
            return;
        }
        self->HandleRequestDataCore(self, uuid, requestedOffset, requestedLength);
    });
}

void CustomLoaderCallback::HandleNonRandomAccessLogic(int64_t uuid, int64_t requestedOffset,
    int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    if (!isSupportLocalCache_) {
        requestedOffset_ = requestedOffset;
        DownloadUnsupportRangeAndCache(uuid, requestedLength, weakThis);
        return;
    }

    request_->RespondHeader(uuid, headerMap_, "");
    MEDIA_LOG_I("not support random");
    path_ = std::to_string(std::hash<std::string>()(request_->GetUrl())) + "_" + std::to_string(0);
    requestHandler_->SetPath(path_);

    task_->SubmitJobOnce([weakThis, requestedOffset, requestedLength] {
        auto self = weakThis.lock();
        if (!self) {
            return;
        }

        std::string dataPath = self->urlDir_ + "/" + self->path_ + ".data";
        if (self->size_ != -1 && self->fileCacheManager_->GetSize(dataPath) != self->size_) {
            self->fileCacheManager_->Clear(dataPath);
        }

        if (!fs::exists(dataPath)) {
            self->RequestData(self->request_, requestedOffset, requestedLength);
        }
    });

    SubmitNonRandomReadJob(uuid, requestedOffset, requestedLength, weakThis);
}

void CustomLoaderCallback::SubmitNonRandomReadJob(int64_t uuid, int64_t requestedOffset,
    int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    std::function<void()> job = [weakThis, uuid, requestedOffset, requestedLength] {
        auto self = weakThis.lock();
        if (!self) {
            return;
        }

        std::string dataPath = self->urlDir_ + "/" + self->path_ + ".data";
        while (!fs::exists(dataPath)) {
            usleep(WAIT_TIME_US);
        }

        int64_t fileSize = self->fileCacheManager_->GetSize(dataPath);
        int64_t readLength = (requestedLength == -1) ? fileSize : requestedLength;

        while (fileSize < requestedOffset + readLength) {
            usleep(WAIT_TIME_US);
            fileSize = self->fileCacheManager_->GetSize(dataPath);
        }

        auto buffer = std::make_shared<AVSharedMemoryBase>(static_cast<int32_t>(readLength),
            AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
        buffer->Init();

        if (self->fileCacheManager_->Read(dataPath, buffer->GetBase(), requestedOffset, readLength) != 0) {
            self->request_->FinishLoading(uuid, 1);
            return;
        }

        MEDIA_LOG_I("Read requestedOffset: " PUBLIC_LOG_D64" readLength: " PUBLIC_LOG_D64,
            requestedOffset, readLength);

        self->request_->RespondData(uuid, requestedOffset, buffer);
        if (requestedLength == -1) {
            self->request_->FinishLoading(uuid, 0);
        }
    };

    std::lock_guard<std::mutex> lock(mutex_);

    if (size_ == -1) {
        task_->SubmitJobOnce(job);
    } else {
        readTask_->SubmitJobOnce(job);
    }
}

void CustomLoaderCallback::HandleRequestDataCore(const std::shared_ptr<CustomLoaderCallback>& self,
    int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MEDIA_LOG_I("RequestData requestedOffset: " PUBLIC_LOG_D64", len = " PUBLIC_LOG_D64, requestedOffset,
        requestedLength);
    if (!self) {
        return;
    }

    if (!self->isHeaderResponded_.load()) {
        self->isHeaderResponded_.store(true);
        self->request_->RespondHeader(uuid, self->headerMap_, "");
    }
    if (requestedLength == 0) {
        MEDIA_LOG_W("RequestedLength is zero, finish it.");
        self->request_->FinishLoading(uuid, 0);
        return;
    }

    if (!self->isSupportLocalCache_) {
        self->HandleNonCacheRequest(self, uuid, requestedOffset, requestedLength);
        return;
    }

    self->HandleCacheRequest(self, uuid, requestedOffset, requestedLength);
}

void CustomLoaderCallback::HandleNonCacheRequest(const std::shared_ptr<CustomLoaderCallback>& self,
    int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    if (!self) {
        return;
    }

    std::lock_guard<std::mutex> lock(self->mutex_);
    self->path_ = "1";
    self->currentLen_ = (requestedLength <= 0) ? (self->size_ - requestedOffset) : requestedLength;
    self->currentBuffer_ = static_cast<uint8_t*>(malloc(self->currentLen_));
    if (self->currentBuffer_ == nullptr) {
        MEDIA_LOG_I("malloc is failed");
        return;
    }

    self->RequestData(self->request_, requestedOffset, self->currentLen_);
    if (self->isClosed_.load()) {
        std::free(self->currentBuffer_);
        self->currentBuffer_ = nullptr;
        self->currentOffset_ = 0;
        return;
    }

    auto buffer = std::make_shared<AVSharedMemoryBase>(
        static_cast<int32_t>(self->currentLen_),
        AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    buffer->Init();

    int32_t len = buffer->Write(self->currentBuffer_, self->currentLen_, 0);
    MEDIA_LOG_I("Write requestedOffset: " PUBLIC_LOG_D64
        ", fileReadLen: " PUBLIC_LOG_D64 ", len = " PUBLIC_LOG_D32,
        requestedOffset, self->currentLen_, len);

    self->request_->RespondData(uuid, requestedOffset, buffer);
    if (requestedLength == -1) {
        self->request_->FinishLoading(uuid, 0);
    }

    // 清除内存变量buffer
    memset_s(self->currentBuffer_, self->currentLen_, 0, self->currentLen_);
    std::free(self->currentBuffer_);
    self->currentOffset_ = 0;
    self->currentBuffer_ = nullptr;
}

void CustomLoaderCallback::HandleCacheRequest(const std::shared_ptr<CustomLoaderCallback>& self,
    int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    if (!self) {
        return;
    }

    int startIndex = requestedOffset / SHARD_SIZE;
    int requestLength = (requestedLength <= 0) ? self->size_ : requestedLength;
    int end = requestedOffset + requestLength;
    int endIndex = (end - 1) / SHARD_SIZE;
    MEDIA_LOG_I("Start requestData startIndex %{public}d endIndex %{public}d offset: " PUBLIC_LOG_D64
        ", len = " PUBLIC_LOG_D32, startIndex, endIndex, requestedOffset, end);
    requestedOffset_ = requestedOffset;
    requestedLength_ = requestLength;
    for (int i = startIndex; i <= endIndex; ++i) {
        if (!self->ProcessShard(self, uuid, i, startIndex, endIndex)) {
            break;
        }
    }

    if (requestedLength == -1) {
        self->request_->FinishLoading(uuid, 0);
    }
}

bool CustomLoaderCallback::ProcessShard(const std::shared_ptr<CustomLoaderCallback>& self, int64_t uuid,
    int index, int startIndex, int endIndex)
{
    if (!self) {
        return false;
    }

    self->path_ = std::to_string(std::hash<std::string>()(self->request_->GetUrl())) + "_" + std::to_string(index);
    self->requestHandler_->SetPath(self->path_);
    std::string dataPath = self->urlDir_ + "/" + self->path_ + ".data";
    int len = (index == (self->size_ - 1) / SHARD_SIZE) ? (self->size_ % SHARD_SIZE) : SHARD_SIZE;
    if (!self->fileCacheManager_->IsValid(dataPath, len)) {
        self->RequestData(self->request_, index * SHARD_SIZE, len);
    }
    if (self->curOffset_ != self->requestedOffset_) {
        MEDIA_LOG_I("drop requestedOffset: " PUBLIC_LOG_D64, self->requestedOffset_);
        return false;
    }
    if (self->isClosed_.load()) {
        return false;
    }
    int64_t fileSize = self->fileCacheManager_->GetSize(dataPath);
    if (fileSize < 0) {
        return false;
    }
    int endOffset = self->requestedOffset_ + self->requestedLength_ - 1;
    int fileBeg = (index == startIndex) ? (self->requestedOffset_ % SHARD_SIZE) : 0;
    int fileEnd = (index == endIndex) ? (endOffset % SHARD_SIZE) : (SHARD_SIZE - 1);
    if (fileEnd >= fileSize) {
        fileEnd = fileSize;
    }
    int fileReadLen = (fileEnd >= fileBeg) ? (fileEnd - fileBeg + 1) : 0;
    if (fileReadLen <= 0) {
        return true;
    }
    auto buffer = std::make_shared<AVSharedMemoryBase>(
        static_cast<int32_t>(fileReadLen), AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    buffer->Init();

    if (self->fileCacheManager_->Read(dataPath, buffer->GetBase(), fileBeg, fileReadLen) != 0) {
        self->request_->FinishLoading(uuid, 1);
        return false;
    }
    int64_t offset = index * SHARD_SIZE + fileBeg;
    MEDIA_LOG_I("RespondData offset: " PUBLIC_LOG_D64" fileReadLen: " PUBLIC_LOG_D32,
        offset, fileReadLen);

    auto ret = self->request_->RespondData(uuid, offset, buffer);
    return ret >= 0;
}

void CustomLoaderCallback::Close(int64_t uuid)
{
    (void)uuid;
    std::lock_guard<std::mutex> lock(mutex_);
    isClosed_.store(true);
    auto client = requestHandler_->GetClient();
    isInterruptNeeded_ = true;
    pthread_cond_signal(&condReturn_);
    if (client) {
        dataSize = 0;
        pthread_cond_signal(&condDownload_);
        client->Close(false);
        client->Deinit();
        requestHandler_->SetClient(nullptr);
    }
}

void CustomLoaderCallback::SetUrl(std::string url)
{
    url_ = url;
}

void CustomLoaderCallback::RequestData(const std::shared_ptr<LoadingRequest>& request, int64_t start, int64_t length)
{
    if (!requestHandler_->GetClient()) {
        MEDIA_LOG_I("RequestData requestHandler GetClient is null");
        auto client = NetworkClientAgent::NewInstance(&RxHeaderData, &RxBodyData, this);
        FALSE_RETURN_MSG(client != nullptr, "client is null");
        client->Init();
        requestHandler_->SetClient(client);
    }
    requestHandler_->SetUuid(uuid_);
    requestHandler_->Request(start, length, request->GetUrl(), request->GetHeader(), request);
}

size_t CustomLoaderCallback::RxHeaderData(void* buffer, size_t size, size_t nitems, void* userParam)
{
    FALSE_RETURN_V_MSG_E(buffer != nullptr, 0, "buffer is nullptr");
    FALSE_RETURN_V_MSG_E(userParam != nullptr, 0, "userParam is nullptr");
    auto mediaDownloader = static_cast<CustomLoaderCallback*>(userParam);
    mediaDownloader->requestHandler_->OnHeaderReceived(buffer, size, nitems);
    return size * nitems;
}

size_t CustomLoaderCallback::RxBodyData(void* buffer, size_t size, size_t nitems, void* userParam)
{
    FALSE_RETURN_V_MSG_E(buffer != nullptr, 0, "buffer is nullptr");
    FALSE_RETURN_V_MSG_E(userParam != nullptr, 0, "userParam is nullptr");
    auto mediaDownloader = static_cast<CustomLoaderCallback*>(userParam);
    size_t dataLen = size * nitems;
    if (mediaDownloader->isFirstCallback_) {
        MEDIA_LOG_I("receive first callback");
        mediaDownloader->task_->SubmitJobOnce(
            [mediaDownloader] {
                FALSE_RETURN_MSG(mediaDownloader->requestHandler_->GetClient() != nullptr, "client is nullptr!");
                mediaDownloader->requestHandler_->GetClient()->Close(false);
                mediaDownloader->requestHandler_->GetClient()->Deinit();
                mediaDownloader->requestHandler_->SetClient(nullptr);
            }, INTERNET_WAIT_TIME, false);
        mediaDownloader->isFirstCallback_ = false;
        return dataLen;
    }
 
    if (mediaDownloader->path_.empty()) {
        MEDIA_LOG_I("mediaDownloader path is empty");
        return dataLen;
    }
 
    if (!mediaDownloader->isSupportLocalCache_) {
        AppendToBuffer(mediaDownloader,  static_cast<const uint8_t*>(buffer), static_cast<int64_t>(dataLen));
        return dataLen;
    }
    
    mediaDownloader->requestHandler_->OnBodyReceived(buffer, size, nitems);
    return dataLen;
}

void CustomLoaderCallback::AppendToBuffer(CustomLoaderCallback* downloader, const uint8_t* buffer, int64_t dataLen)
{
    if (!downloader || !buffer || dataLen == 0) {
        MEDIA_LOG_E("invalid arguments");
        return;
    }

    if (downloader->currentOffset_ + dataLen > downloader->currentLen_) {
        MEDIA_LOG_I("currentoffset: " PUBLIC_LOG_D64 "; dataLen: " PUBLIC_LOG_D64 "; currentLen: " PUBLIC_LOG_D64,
            downloader->currentOffset_, dataLen, downloader->currentLen_);
        return;
    }

    if (memcpy_s(downloader->currentBuffer_ + downloader->currentOffset_,
        downloader->currentLen_ - downloader->currentOffset_, buffer, dataLen) != EOK) {
        MEDIA_LOG_E("memcpy failed");
        return;
    }
    downloader->currentOffset_ += dataLen;
}

void CustomLoaderCallback::RemoveCacheFile()
{
    MEDIA_LOG_I("RemoveCacheFile in");
    isSupportLocalCache_ = false;
}

void CustomLoaderCallback::DownloadUnsupportRangeAndCache(int64_t uuid,
    int64_t requestedLength, const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    // 1. 初始化客户端（仅第一次）
    if (!requestHandler_->GetClient() || firstRequest_) {
        InitializeClient();
    }

    // 2. 响应头部
    request_->RespondHeader(uuid, headerMap_, "");

    // 3. 启动下载任务（仅一次）
    if (!isDownload_) {
        StartDownloadTask(weakThis);
    }

    // 4. 启动读取任务（核心逻辑）
    ReadDataTask(weakThis, uuid, requestedLength);
}

void CustomLoaderCallback::InitializeClient()
{
    MEDIA_LOG_I("first request set RxBodyDataUnsupportRangeAndCache");
    auto client = NetworkClientAgent::NewInstance(&RxHeaderData, &RxBodyDataUnsupportRangeAndCache, this);
        FALSE_RETURN_MSG(client != nullptr, "client is null");
    client->Init();
    requestHandler_->SetClient(client);
    firstRequest_ = false;
}

void CustomLoaderCallback::StartDownloadTask(const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    task_->SubmitJobOnce([weakThis] {
        auto self = weakThis.lock();
        if (!self) {
            MEDIA_LOG_I("self is nullptr");
            return;
        }

        self->isDownload_ = true;
        self->RequestData(self->request_, 0, -1);
        self->isDownload_ = false;

        if (!self->isInterruptedNewDownLoad_) {
            MEDIA_LOG_I("download end");
            if (self->size_ == -1) {
                self->size_ = self->cacheOffset_ + self->dataSize;
            }
            self->dataSize = SHARD_SIZE;
            pthread_cond_signal(&self->condReturn_);
        }
    });
}

void CustomLoaderCallback::ReadDataTask(const std::weak_ptr<CustomLoaderCallback>& weakThis,
    int64_t uuid, int64_t requestedLength)
{
    readTask_->SubmitJobOnce([weakThis, uuid, requestedLength] {
        auto self = weakThis.lock();
        if (!self) {
            MEDIA_LOG_I("self is nullptr");
            return;
        }

        pthread_mutex_lock(&self->mutex);
        if (self->dataSize != SHARD_SIZE) {
            MEDIA_LOG_I("dataSize is under 4MB, wait download");
            pthread_cond_wait(&self->condReturn_, &self->mutex);
            MEDIA_LOG_I("wait download end");
        }

        int64_t start = self->requestedOffset_;
        int64_t len = requestedLength;
        bool noSizeAndRequest = false;

        self->HandleInitialization(len, noSizeAndRequest, self);

        int64_t read = 0;
        while (read < len) {
            if (self->isInterruptNeeded_) {
                MEDIA_LOG_I("Interrupt");
                break;
            }

            MEDIA_LOG_I("return data has read: " PUBLIC_LOG_D64 "; requestedLength: "
                PUBLIC_LOG_D64, read, len);

            if (start > self->cacheOffset_ + SHARD_SIZE) {
                self->HandleCacheMiss(start, len, noSizeAndRequest, self);
                continue;
            }

            if (start < self->cacheOffset_) {
                self->HandleDownloadFromStart(len, noSizeAndRequest, self, weakThis);
                continue;
            }

            self->RespondDataChunk(start, read, len, noSizeAndRequest, self);
        }

        if (requestedLength == -1) {
            self->request_->FinishLoading(uuid, 0);
        }

        pthread_mutex_unlock(&self->mutex);
    });
}

void CustomLoaderCallback::HandleInitialization(int64_t& len, bool& noSizeAndRequest,
    const std::shared_ptr<CustomLoaderCallback>& self)
{
    if (len == -1) {
        len = self->size_;
    }
    if (len == -1) {
        MEDIA_LOG_I("requestedLength: -1, len: -1");
        len = INT64_MAX;
        noSizeAndRequest = true;
    }
}

void CustomLoaderCallback::HandleCacheMiss(int64_t start, int64_t& len,
    bool noSizeAndRequest, const std::shared_ptr<CustomLoaderCallback>& self)
{
    MEDIA_LOG_I("need redownload cachedata, start: " PUBLIC_LOG_D64
        "; cacheOffset: " PUBLIC_LOG_D64, start, self->cacheOffset_);

    self->cacheOffset_ += SHARD_SIZE;
    self->dataSize = 0;
    memset_s(self->buffer_, SHARD_SIZE, 0, SHARD_SIZE);
    pthread_cond_signal(&self->condDownload_);
    pthread_cond_wait(&self->condReturn_, &self->mutex);

    if (noSizeAndRequest && self->size_ != -1) {
        len = self->size_;
    }
}

void CustomLoaderCallback::HandleDownloadFromStart(int64_t& len, bool noSizeAndRequest,
    const std::shared_ptr<CustomLoaderCallback>& self, const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    MEDIA_LOG_I("need download from start");
    self->isInterruptedNewDownLoad_ = true;
    self->dataSize = 0;
    pthread_cond_signal(&self->condDownload_);
    self->Redownload(weakThis);

    pthread_cond_wait(&self->condReturn_, &self->mutex);

    if (noSizeAndRequest && self->size_ != -1) {
        len = self->size_;
    }
}

void CustomLoaderCallback::RespondDataChunk(int64_t start, int64_t& read, int64_t& len,
    bool noSizeAndRequest, const std::shared_ptr<CustomLoaderCallback>& self)
{
    int64_t bufferStart = start % SHARD_SIZE;
    int32_t readLen = start + SHARD_SIZE - bufferStart > self->requestedOffset_ + len ?
        (self->requestedOffset_ + len) % SHARD_SIZE - bufferStart : SHARD_SIZE - bufferStart;
    auto buffer = std::make_shared<AVSharedMemoryBase>(readLen, AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    buffer->Init();
    memcpy_s(buffer->GetBase(), readLen, self->buffer_ + bufferStart, readLen);
    MEDIA_LOG_I("respondData start: " PUBLIC_LOG_D64 "; readLen: " PUBLIC_LOG_D32, start, readLen);
    self->request_->RespondData(uuid_, start, buffer);
    start += readLen;
    read += readLen;
    if (bufferStart + readLen == SHARD_SIZE) {
        self->cacheOffset_ += SHARD_SIZE;
        self->dataSize = 0;
        memset_s(self->buffer_, SHARD_SIZE, 0, SHARD_SIZE);
        MEDIA_LOG_I("data return thread wait, notify download thread");
        pthread_cond_signal(&self->condDownload_);
        pthread_cond_wait(&self->condReturn_, &self->mutex);
    }
    if (noSizeAndRequest && self->size_ != -1) {
        len = self->size_;
    }
}

size_t CustomLoaderCallback::RxBodyDataUnsupportRangeAndCache(void* buffer, size_t size, size_t nitems, void* userParam)
{
    FALSE_RETURN_V_MSG_E(buffer != nullptr, 0, "buffer is nullptr");
    FALSE_RETURN_V_MSG_E(userParam != nullptr, 0, "userParam is nullptr");
    auto downloader = static_cast<CustomLoaderCallback*>(userParam);
    pthread_mutex_lock(&downloader->mutex);
    size_t dataLen = size * nitems;
    uint8_t* tempBuffer = static_cast<uint8_t*>(buffer);
    if (dataLen + static_cast<size_t>(downloader->dataSize) > SHARD_SIZE) {
        MEDIA_LOG_I("download data need write with slice");
        size_t writeLen = 0;
        size_t needWriteLen = dataLen;
        while (needWriteLen > 0) {
            size_t len = needWriteLen + static_cast<size_t>(downloader->dataSize) > SHARD_SIZE ?
                static_cast<size_t>(SHARD_SIZE - downloader->dataSize) : needWriteLen;
            memcpy_s(downloader->buffer_ + downloader->dataSize, len, tempBuffer + writeLen, len);
            downloader->dataSize += static_cast<int64_t>(len);
            writeLen += len;
            needWriteLen -= len;
            if (downloader->dataSize == SHARD_SIZE) {
                MEDIA_LOG_I("download thread wait, notify data return thread:");
                pthread_cond_signal(&downloader->condReturn_);
                pthread_cond_wait(&downloader->condDownload_, &downloader->mutex);
            }
        }
    } else {
        memcpy_s(downloader->buffer_ + downloader->dataSize, SHARD_SIZE - downloader->dataSize, tempBuffer, dataLen);
        downloader->dataSize += static_cast<int64_t>(dataLen);
        if (downloader->dataSize == SHARD_SIZE) {
            MEDIA_LOG_I("download thread wait, notify data return thread:");
            pthread_cond_signal(&downloader->condReturn_);
            pthread_cond_wait(&downloader->condDownload_, &downloader->mutex);
        }
    }
    pthread_mutex_unlock(&downloader->mutex);
    return dataLen;
}

void CustomLoaderCallback::Redownload(const std::weak_ptr<CustomLoaderCallback>& weakThis)
{
    interruptedTask_->SubmitJobOnce([weakThis] {
        auto self = weakThis.lock();
        if (!self) {
            MEDIA_LOG_I("self is nullptr");
            return;
        }
        FALSE_RETURN_MSG(self->requestHandler_->GetClient() != nullptr, "client is nullptr");
        self->requestHandler_->GetClient()->Close(false);
        self->requestHandler_->GetClient()->Deinit();
        self->requestHandler_->SetClient(nullptr);
        self->isInterruptedNewDownLoad_ = true;
    });
    task_->SubmitJobOnce([weakThis] {
        auto self = weakThis.lock();
        if (!self) {
            MEDIA_LOG_I("self is nullptr");
            return;
        }
        self->isInterruptedNewDownLoad_ = false;
        self->isDownload_ = true;
        self->dataSize = 0;
        self->cacheOffset_ = 0;
        memset_s(self->buffer_, SHARD_SIZE, 0, SHARD_SIZE);
        auto client = NetworkClientAgent::NewInstance(&RxHeaderData, &RxBodyData, self.get());
        FALSE_RETURN_MSG(client != nullptr, "client is null");
        client->Init();
        self->requestHandler_->SetClient(client);
        MEDIA_LOG_I("read requestedOffset: 0, requestedLength: -1");
        self->RequestData(self->request_, 0, -1);
        self->isDownload_ = false;
        if (!self->isInterruptedNewDownLoad_) {
            MEDIA_LOG_I("download end");
            self->dataSize = SHARD_SIZE;
            pthread_cond_signal(&self->condReturn_);
        }
    });
}
} // namespace Media
} // namespace OHOS