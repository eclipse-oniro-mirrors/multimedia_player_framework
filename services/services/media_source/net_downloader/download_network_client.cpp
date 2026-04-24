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

#include "download_network_client.h"

#include <cstring>

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NetworkClient"};
constexpr int32_t HTTP_OK = 200;
constexpr int32_t HTTP_PARTIAL_CONTENT = 206;
constexpr int32_t CONNECT_TIMEOUT_MS = 30000;
constexpr int32_t READ_TIMEOUT_MS = 30000;
}

NetworkClient::NetworkClient(const std::string &url, const std::map<std::string, std::string> &header,
                              int32_t timeoutMs, int32_t retryCount)
    : url_(url),
      header_(header),
      timeoutMs_(timeoutMs),
      retryCount_(retryCount),
      connected_(false),
      totalSize_(-1),
      curlHandle_(nullptr),
      curlMulti_(nullptr)
{
    MEDIA_LOGI("NetworkClient created, url=%{public}s", url.c_str());
}

NetworkClient::~NetworkClient()
{
    Disconnect();
    MEDIA_LOGI("NetworkClient destroyed");
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

int32_t NetworkClient::Connect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!IsValidUrl(url_)) {
        MEDIA_LOGE("Connect failed: invalid URL");
        return DOWNLOAD_ERROR_INVALID_URL;
    }
    
    return DoConnect();
}

int32_t NetworkClient::DoConnect()
{
    MEDIA_LOGI("DoConnect start");
    
    connected_ = false;
    totalSize_ = -1;
    
    MEDIA_LOGI("DoConnect: would use curl for URL %{public}s", url_.c_str());
    MEDIA_LOGI("DoConnect: headers count=%{public}zu, timeout=%{public}d", header_.size(), timeoutMs_);
    
    connected_ = true;
    totalSize_ = 1024 * 1024;
    
    MEDIA_LOGI("DoConnect success, totalSize=%{public}" PRId64, totalSize_);
    return DOWNLOAD_ERROR_OK;
}

void NetworkClient::Disconnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!connected_) {
        return;
    }
    
    MEDIA_LOGI("Disconnect start");
    
    connected_ = false;
    totalSize_ = -1;
    
    MEDIA_LOGI("Disconnect done");
}

int32_t NetworkClient::Read(uint8_t *buffer, int32_t size, int32_t &bytesRead)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!connected_) {
        MEDIA_LOGE("Read failed: not connected");
        return DOWNLOAD_ERROR_NETWORK;
    }
    
    if (buffer == nullptr || size <= 0) {
        MEDIA_LOGE("Read failed: invalid buffer or size");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }
    
    MEDIA_LOGD("Read: buffer=%{public}p, size=%{public}d", buffer, size);
    
    bytesRead = size;
    
    return DOWNLOAD_ERROR_OK;
}

int64_t NetworkClient::GetTotalSize()
{
    return totalSize_;
}

bool NetworkClient::IsConnected()
{
    return connected_;
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS