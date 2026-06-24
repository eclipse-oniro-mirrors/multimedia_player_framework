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

#include <algorithm>
#include <cstring>
#include <chrono>
#include <thread>
#include <charconv>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "download_network_client.h"
#include "network_client_agent.h"
#include "status.h"

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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderNetworkClient"};
constexpr int32_t HTTP_OK = 200;
constexpr int32_t HTTP_PARTIAL_CONTENT = 206;
constexpr int32_t HTTP_RANGE_NOT_SATISFIABLE = 416;
constexpr int32_t HTTP_DISCONNECT = 56;
constexpr int32_t HTTP_CAN_NOT_CONNECT = 7;
}

NetworkClient::NetworkClient(const std::string &url, const std::map<std::string, std::string> &header,
                              int32_t timeoutMs, int32_t retryCount)
    : url_(url),
      header_(header),
      timeoutMs_(timeoutMs),
      connected_(false),
      totalSize_(-1)
{
    (void)retryCount;
    MEDIA_LOGI("NetworkClient created, url=%{private}s", url.c_str());
    for (const auto &[k, v]: header_) {
        MEDIA_LOGI("NetworkClient header: %{private}s, %{private}s", k.c_str(), v.c_str());
    }
    ctx_ = std::make_shared<DownloadContext>();
    ctx_->parent = this;
}

NetworkClient::~NetworkClient()
{
    MEDIA_LOGI("NetworkClient destroyed");
}

int32_t NetworkClient::SetOutputPath(const std::string &path, int64_t existingSize)
{
    if (ctx_ == nullptr) {
        return DOWNLOAD_ERROR_INTERNAL;
    }

    ctx_->outputPath = path;

    if (ctx_->outputFd >= 0) {
        close(ctx_->outputFd);
        ctx_->outputFd = -1;
    }

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    if (existingSize > 0) {
        MEDIA_LOGI("SetOutputPath: resuming from %{public}" PRId64, existingSize);
        ctx_->outputFd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, mode);
    } else {
        ctx_->outputFd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    }

    if (ctx_->outputFd < 0) {
        MEDIA_LOGE("SetOutputPath failed: open failed, errno=%{public}d", errno);
        return DOWNLOAD_ERROR_FILE_IO;
    }

    MEDIA_LOGI("SetOutputPath success: %{public}s, existingSize=%{public}" PRId64, path.c_str(), existingSize);
    return DOWNLOAD_RET_OK;
}

bool NetworkClient::IsValidUrl(const std::string &url)
{
    if (url.empty()) {
        return false;
    }

    if (url.find("http://") != 0 && url.find("https://") != 0) {
        return false;
    }

    return true;
}

size_t NetworkClient::RxHeaderCallback(void* buffer, size_t size, size_t nitems, void* userParam)
{
    if (buffer == nullptr || userParam == nullptr) {
        return size * nitems;
    }

    auto* ctx = static_cast<DownloadContext*>(userParam);
    auto* client = ctx->parent;
    size_t dataLen = size * nitems;
    std::string headerStr(static_cast<const char*>(buffer), dataLen);

    MEDIA_LOGD("RxHeaderCallback: header length=%{public}zu", dataLen);

    std::lock_guard<std::mutex> lock(ctx->mutex);
    size_t pos = 0;
    size_t newlinePos = 0;
    while ((newlinePos = headerStr.find('\n', pos)) != std::string::npos) {
        std::string line = headerStr.substr(pos, newlinePos - pos);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            pos = newlinePos + 1;
            continue;
        }
        std::string key = line.substr(0, colonPos);
        std::string value = line.substr(colonPos + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        ctx->responseHeaders[key] = value;

        if (key == "Content-Length" || key == "content-length") {
            int64_t contentLength = 0;
            auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), contentLength);
            if (ec == std::errc{} && ptr == value.data() + value.size()) {
                ctx->totalSize.store(contentLength);
                client->totalSize_.store(contentLength);
                MEDIA_LOGI("Content-Length: %{public}" PRId64, contentLength);
            } else {
                MEDIA_LOGW("Failed to parse Content-Length");
            }
        }
        pos = newlinePos + 1;
    }

    ctx->isHeaderReceived.store(true);
    ctx->cv.notify_one();

    return size * nitems;
}

size_t NetworkClient::RxBodyCallback(void* buffer, size_t size, size_t nitems, void* userParam)
{
    if (buffer == nullptr || userParam == nullptr) {
        return size * nitems;
    }

    auto* ctx = static_cast<DownloadContext*>(userParam);
    auto* client = ctx->parent;
    size_t dataLen = size * nitems;

    MEDIA_LOGI("RxBodyCallback: IsConnected=%{public}d, IsPaused=%{public}d, dataLen=%{public}zu",
        client->IsConnected(), client->IsPaused(), dataLen);

    if (!client->IsConnected()) {
        MEDIA_LOGW("RxBodyCallback: not connected, skip data");
        return 0;
    }

    if (client->IsPaused()) {
        MEDIA_LOGI("RxBodyCallback: paused, return 0 to disconnect");
        return 0;
    }

    if (client->startPos_ > 0 && ctx->downloadedSize.load() == 0) {
        auto rangeIt = ctx->responseHeaders.find("Content-Range");
        if (rangeIt == ctx->responseHeaders.end()) {
            MEDIA_LOGW("RxBodyCallback: server does not support range resume, truncating file");
            if (ftruncate(ctx->outputFd, 0) != 0) {
                MEDIA_LOGE("RxBodyCallback: failed to truncate file");
                return 0;
            }
            lseek(ctx->outputFd, 0, SEEK_SET);
            client->startPos_ = 0;
        }
    }

    MEDIA_LOGD("RxBodyCallback: data length=%{public}zu", dataLen);

    if (ctx->outputFd >= 0) {
        ssize_t writeLen = write(ctx->outputFd, buffer, dataLen);
        if (writeLen < 0 || static_cast<size_t>(writeLen) != dataLen) {
            MEDIA_LOGE("RxBodyCallback: write failed, errno=%{public}d", errno);
            DownloadErrorType errorType = (errno == ENOSPC) ?
                DOWNLOAD_ERROR_DISK_SPACE : DOWNLOAD_ERROR_FILE_IO;
            if (client->errorCallback_) {
                client->errorCallback_(errorType, errno);
            }
            return 0;
        }
        ctx->downloadedSize.fetch_add(dataLen);
        if (client->progressCallback_) {
            client->progressCallback_(ctx->downloadedSize.load() + client->startPos_,
                client->totalSize_.load() + client->startPos_);
        }
    }

    return dataLen;
}

int32_t NetworkClient::Download(int64_t startPos)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!IsValidUrl(url_)) {
        MEDIA_LOGE("Download failed: invalid URL");
        return DOWNLOAD_ERROR_INVALID_URL;
    }

    return DoDownload(startPos);
}

void NetworkClient::InitDownloadContext(int64_t startPos)
{
    MEDIA_LOGI("InitDownloadContext start, startPos=%{public}" PRId64, startPos);

    connected_.store(false);
    totalSize_.store(-1);
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        paused_.store(false);
    }

    ctx_->requestSuccess.store(false);
    ctx_->requestCompleted.store(false);
    ctx_->totalSize.store(-1);
    ctx_->downloadedSize.store(0);
    ctx_->responseHeaders.clear();

    startPos_ = startPos;
}

std::shared_ptr<Plugins::HttpPlugin::NetworkClient> NetworkClient::CreateAndInitClient()
{
    if (!NetworkClientAgent::Create()) {
        MEDIA_LOGE("CreateAndInitClient failed: NetworkClientAgent::Create failed");
        return nullptr;
    }

    auto clientImpl = NetworkClientAgent::NewInstance(RxHeaderCallback, RxBodyCallback, ctx_.get(), timeoutMs_);
    if (clientImpl == nullptr) {
        MEDIA_LOGE("CreateAndInitClient failed: NewInstance failed");
        return nullptr;
    }

    auto status = clientImpl->Init();
    if (status != Status::OK) {
        MEDIA_LOGE("CreateAndInitClient failed: Init failed, status=%{public}d", static_cast<int>(status));
        clientImpl->Deinit();
        clientImpl->Close(false);
        return nullptr;
    }

    return clientImpl;
}

Plugins::HttpPlugin::RequestInfo NetworkClient::BuildRequestInfo(int64_t startPos)
{
    Plugins::HttpPlugin::RequestInfo sourceInfo = {url_, header_, 0};

    if (startPos > 0) {
        std::string rangeHeader = "bytes=" + std::to_string(startPos) + "-";
        sourceInfo.httpHeader["Range"] = rangeHeader;
        MEDIA_LOGI("BuildRequestInfo: Range request: %{public}s", rangeHeader.c_str());
    }

    return sourceInfo;
}

int32_t NetworkClient::DoDownload(int64_t startPos)
{
    MEDIA_LOGI("DoDownload start, url=%{public}s, startPos=%{public}" PRId64, url_.c_str(), startPos);

    InitDownloadContext(startPos);

    auto clientImpl = CreateAndInitClient();
    if (clientImpl == nullptr) {
        CloseOutputFd();
        return DOWNLOAD_ERROR_NETWORK;
    }

    connected_.store(true);

    auto sourceInfo = BuildRequestInfo(startPos);
    auto handleResponseCb = [this](const int32_t clientCode, const int32_t serverCode,
        const std::string &ca, const Status ret) {
        HandleResponse(clientCode, serverCode, ca, ret);
    };

    auto status = clientImpl->RequestData(startPos, -1, sourceInfo, handleResponseCb);
    clientImpl->Deinit();
    clientImpl->Close(false);
    CloseOutputFd();
    connected_.store(false);
    if (status != Status::OK) {
        MEDIA_LOGE("DoDownload failed: RequestData failed, status=%{public}d", static_cast<int>(status));
        return DOWNLOAD_ERROR_NETWORK;
    }

    MEDIA_LOGI("DoDownload success");
    return DOWNLOAD_RET_OK;
}

void NetworkClient::CloseOutputFd()
{
    if (ctx_ != nullptr && ctx_->outputFd >= 0) {
        close(ctx_->outputFd);
        ctx_->outputFd = -1;
    }
}

void NetworkClient::HandleResponse(const int32_t clientCode, const int32_t serverCode, const std::string &ca,
    const Status ret)
{
    (void)ca;
    MEDIA_LOGI("Response callback: clientCode=%{public}d, serverCode=%{public}d, status=%{public}d",
        clientCode, serverCode, static_cast<int>(ret));

    std::lock_guard<std::mutex> lock(ctx_->mutex);
    ctx_->requestCompleted.store(true);

    if (ret == Status::OK) {
        if (clientCode == 0 || clientCode == HTTP_OK || clientCode == HTTP_PARTIAL_CONTENT) {
            ProcessHttpSuccess(clientCode);
        } else if (clientCode == HTTP_RANGE_NOT_SATISFIABLE && startPos_ > 0) {
            ProcessHttp416RangeNotSatisfiable();
        } else {
            ProcessHttpError(clientCode);
        }
    } else if (clientCode == HTTP_DISCONNECT || clientCode == HTTP_CAN_NOT_CONNECT) {
        ProcessHttpError(clientCode);
    } else {
        ProcessStatusError(ret);
    }

    ctx_->cv.notify_one();
}

void NetworkClient::ProcessHttpSuccess(int32_t clientCode)
{
    (void)clientCode;
    ctx_->requestSuccess.store(true);
    MEDIA_LOGI("Response callback: downloadedSize=%{public}" PRId64, ctx_->downloadedSize.load());
}

void NetworkClient::ProcessHttp416RangeNotSatisfiable()
{
    MEDIA_LOGI("Response callback: 416 Range Not Satisfiable, checking file completeness");
    auto rangeIt = ctx_->responseHeaders.find("Content-Range");
    if (rangeIt == ctx_->responseHeaders.end()) {
        MEDIA_LOGW("416 response: no Content-Range header");
        ctx_->requestSuccess.store(false);
        if (errorCallback_) {
            errorCallback_(DOWNLOAD_ERROR_NETWORK, HTTP_RANGE_NOT_SATISFIABLE);
        }
        return;
    }

    std::string rangeValue = rangeIt->second;
    size_t slashPos = rangeValue.find('/');
    if (slashPos == std::string::npos) {
        MEDIA_LOGW("416 response: Content-Range format invalid");
        ctx_->requestSuccess.store(false);
        if (errorCallback_) {
            errorCallback_(DOWNLOAD_ERROR_NETWORK, HTTP_RANGE_NOT_SATISFIABLE);
        }
        return;
    }

    std::string totalSizeStr = rangeValue.substr(slashPos + 1);
    int64_t serverTotalSize = 0;
    auto [ptr, ec] = std::from_chars(totalSizeStr.data(), totalSizeStr.data() + totalSizeStr.size(), serverTotalSize);
    if (ec == std::errc{} && serverTotalSize > 0) {
        MEDIA_LOGI("Content-Range: %{public}s, server total size: %{public}" PRId64,
            rangeValue.c_str(), serverTotalSize);
        if (serverTotalSize == startPos_) {
            MEDIA_LOGI("416 response: local file size matches server, download complete");
            ctx_->requestSuccess.store(true);
            ctx_->totalSize.store(serverTotalSize);
        } else {
            MEDIA_LOGE("416 response: size mismatch, local: %{public}" PRId64 ", server: %{public}" PRId64,
                startPos_, serverTotalSize);
            ctx_->requestSuccess.store(false);
            if (errorCallback_) {
                errorCallback_(DOWNLOAD_ERROR_NETWORK, HTTP_RANGE_NOT_SATISFIABLE);
            }
        }
    } else {
        MEDIA_LOGW("416 response: failed to parse Content-Range total size");
        ctx_->requestSuccess.store(false);
        if (errorCallback_) {
            errorCallback_(DOWNLOAD_ERROR_NETWORK, HTTP_RANGE_NOT_SATISFIABLE);
        }
    }
}

void NetworkClient::ProcessHttpError(int32_t clientCode)
{
    ctx_->requestSuccess.store(false);
    MEDIA_LOGE("Request failed with HTTP code: %{public}d", clientCode);
    if (errorCallback_) {
        errorCallback_(DOWNLOAD_ERROR_NETWORK, clientCode);
    }
}

void NetworkClient::ProcessStatusError(const Status ret)
{
    ctx_->requestSuccess.store(false);
    MEDIA_LOGE("Request failed with status: %{public}d", static_cast<int>(ret));
    if (errorCallback_) {
        errorCallback_(DOWNLOAD_ERROR_NETWORK, static_cast<int32_t>(ret));
    }
}

int64_t NetworkClient::GetTotalSize()
{
    return totalSize_.load();
}

bool NetworkClient::IsConnected()
{
    return connected_.load();
}

int64_t NetworkClient::GetDownloadedSize()
{
    if (ctx_ != nullptr) {
        return ctx_->downloadedSize.load();
    }
    return 0;
}

int NetworkClient::GetOutputFd() const
{
    if (ctx_ != nullptr) {
        return ctx_->outputFd;
    }
    return -1;
}

void NetworkClient::PauseDownload()
{
    MEDIA_LOGI("PauseDownload called");
    std::lock_guard<std::mutex> lock(pauseMutex_);
    paused_.store(true);
}

bool NetworkClient::IsPaused()
{
    std::lock_guard<std::mutex> lock(pauseMutex_);
    return paused_.load();
}

// cancel only allow rxbodycb, rxbodycb will return 0 to tell cancel
void NetworkClient::Cancel()
{
    MEDIA_LOGI("Cancel called");
    std::lock_guard<std::mutex> lock(pauseMutex_);
    paused_.store(true); // set true to notify rxbodycb
}

void NetworkClient::SetProgressCallback(ProgressCallback cb)
{
    progressCallback_ = std::move(cb);
}

void NetworkClient::SetErrorCallback(ErrorCallback cb)
{
    errorCallback_ = std::move(cb);
}

bool NetworkClient::IsRequestCompleted() const
{
    if (ctx_ != nullptr) {
        return ctx_->requestCompleted.load();
    }
    return false;
}

bool NetworkClient::IsRequestSuccess() const
{
    if (ctx_ != nullptr) {
        return ctx_->requestSuccess.load();
    }
    return false;
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
