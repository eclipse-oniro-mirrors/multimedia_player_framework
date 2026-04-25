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
    Disconnect();
    MEDIA_LOGI("NetworkClient destroyed");
}

int32_t NetworkClient::SetOutputPath(const std::string &path)
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
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) == 0 && statbuf.st_size > 0) {
        MEDIA_LOGI("SetOutputPath: existing file found (size=" PUBLIC_LOG_D64 "), removing for resume",
            (int64_t)statbuf.st_size);
        (void)unlink(path.c_str());
    }

    ctx_->outputFd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (ctx_->outputFd < 0) {
        MEDIA_LOGE("SetOutputPath failed: open failed, errno=%{public}d", errno);
        return DOWNLOAD_ERROR_FILE_IO;
    }

    MEDIA_LOGI("SetOutputPath success: %{public}s", path.c_str());
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
        MEDIA_LOGI("RxBodyCallback: paused, waiting for resume");
        std::unique_lock<std::mutex> lock(client->pauseMutex_);
        client->pauseCv_.wait(lock, [client] { return !client->IsPaused(); });
        MEDIA_LOGI("RxBodyCallback: resumed, continue");
    }

    if (!client->IsConnected()) {
        MEDIA_LOGW("RxBodyCallback: disconnected while waiting, skip data");
        return 0;
    }

    MEDIA_LOGD("RxBodyCallback: data length=%{public}zu", dataLen);

    if (client->dataCallback_) {
        bool ok = client->dataCallback_(static_cast<const char*>(buffer), dataLen, client->totalSize_.load());
        if (!ok) {
            MEDIA_LOGE("RxBodyCallback: data write failed, return 0 to abort download");
            return 0;
        }
    }

    return dataLen;
}

int32_t NetworkClient::Connect(int64_t startPos)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!IsValidUrl(url_)) {
        MEDIA_LOGE("Connect failed: invalid URL");
        return DOWNLOAD_ERROR_INVALID_URL;
    }

    return DoConnect(startPos);
}

int32_t NetworkClient::DoConnect(int64_t startPos)
{
    MEDIA_LOGI("DoConnect start, url=%{public}s, startPos=%{public}" PRId64, url_.c_str(), startPos);

    connected_.store(false);
    totalSize_.store(-1);
    paused_.store(false);

    ctx_->isRunning.store(false);
    ctx_->requestSuccess.store(false);
    ctx_->requestCompleted.store(false);
    ctx_->totalSize.store(-1);
    ctx_->downloadedSize.store(0);
    ctx_->responseHeaders.clear();

    if (!NetworkClientAgent::Create()) {
        MEDIA_LOGE("DoConnect failed: NetworkClientAgent::Create failed");
        return DOWNLOAD_ERROR_NETWORK;
    }

    ctx_->client = NetworkClientAgent::NewInstance(RxHeaderCallback, RxBodyCallback, ctx_.get());
    if (ctx_->client == nullptr) {
        MEDIA_LOGE("DoConnect failed: client is nullptr");
        return DOWNLOAD_ERROR_NETWORK;
    }

    auto status = ctx_->client->Init();
    if (status != Status::OK) {
        MEDIA_LOGE("DoConnect failed: Init failed, status=%{public}d", static_cast<int>(status));
        ctx_->client->Deinit();
        ctx_->client->Close(false);
        ctx_->client = nullptr;
        return DOWNLOAD_ERROR_NETWORK;
    }

    Plugins::HttpPlugin::RequestInfo sourceInfo = {url_, header_, timeoutMs_};

    auto handleResponseCb = [this](const int32_t clientCode, const int32_t serverCode,
        const std::string &ca, const Status ret) {
        HandleResponse(clientCode, serverCode, ca, ret);
    };

    ctx_->isRunning.store(true);
    connected_.store(true);
    status = ctx_->client->RequestData(startPos, -1, sourceInfo, handleResponseCb);
    if (status != Status::OK) {
        connected_.store(false);
        MEDIA_LOGE("DoConnect failed: RequestData failed, status=%{public}d", static_cast<int>(status));
        ctx_->client->Deinit();
        ctx_->client->Close(false);
        ctx_->client = nullptr;
        return DOWNLOAD_ERROR_NETWORK;
    }

    MEDIA_LOGI("DoConnect success, download started");
    return DOWNLOAD_RET_OK;
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
            ctx_->requestSuccess.store(true);
            connected_.store(true);
            MEDIA_LOGI("Response callback: set connected_=true, downloadedSize=%{public}" PRId64,
                ctx_->downloadedSize.load());
        } else {
            ctx_->requestSuccess.store(false);
            MEDIA_LOGE("Request failed with HTTP code: %{public}d", clientCode);
        }
    } else {
        ctx_->requestSuccess.store(false);
        MEDIA_LOGE("Request failed with status: %{public}d", static_cast<int>(ret));
    }

    ctx_->cv.notify_one();
}

void NetworkClient::Disconnect()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!connected_.load()) {
        return;
    }

    MEDIA_LOGI("Disconnect start");

    if (ctx_ != nullptr) {
        ctx_->isRunning.store(false);
        if (ctx_->client != nullptr) {
            ctx_->client->Close(false);
            ctx_->client->Deinit();
            ctx_->client = nullptr;
        }
        if (ctx_->outputFd >= 0) {
            close(ctx_->outputFd);
            ctx_->outputFd = -1;
        }
    }

    connected_.store(false);

    MEDIA_LOGI("Disconnect done");
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

void NetworkClient::ResumeDownload()
{
    MEDIA_LOGI("ResumeDownload called");
    {
        std::lock_guard<std::mutex> lock(pauseMutex_);
        paused_.store(false);
    }
    pauseCv_.notify_all();
}

bool NetworkClient::IsPaused() const
{
    return paused_.load();
}

// cancel only allow rxbodycb, rxbodycb will return 0 to tell cancel
void NetworkClient::Cancel()
{
    MEDIA_LOGI("Cancel called");
    std::lock_guard<std::mutex> lock(pauseMutex_);
    paused_.store(false); // set false to notify pause cv, then allow rxbodycb
    pauseCv_.notify_all(); // notify callback thread(sleeping)
}

void NetworkClient::SetDataCallback(DataCallback cb)
{
    dataCallback_ = std::move(cb);
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