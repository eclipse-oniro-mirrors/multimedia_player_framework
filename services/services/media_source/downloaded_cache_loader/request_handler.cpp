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

#include <cstring>
#include "request_handler.h"
#include "common/log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedRequestHandler" };
    constexpr int64_t TIMEOUT_MS = 5000;
}

DownloadedRequestHandler::DownloadedRequestHandler(std::shared_ptr<Plugins::HttpPlugin::NetworkClient> client): client_(client) {}

void DownloadedRequestHandler::Request(int64_t start, int64_t length, const std::string& url,
    const std::map<std::string, std::string>& headers, std::shared_ptr<LoadingRequest> request)
{
    request_ = request;

    Plugins::HttpPlugin::RequestInfo sourceInfo;
    sourceInfo.url = url;
    sourceInfo.httpHeader = headers;
    sourceInfo.timeoutMs = TIMEOUT_MS;

    auto weakThis = weak_from_this();
    auto handleResponseCb = [weakThis](int32_t clientCode, int32_t serverCode, const std::string &ca, Status ret) {
        MEDIA_LOG_W("HandleResponseCb clientCode: %{public}d serverCode %{public}d", clientCode, serverCode);
        auto self = weakThis.lock();
        if (!self) {
            return;
        }

        (void)ca;
        self->clientCode_ = clientCode;
        if (ret != Status::OK) {
            self->request_->FinishLoading(self->uuid_, 5);
            self->SetClosed(true);
            self->isRequestError_.store(true);
        }
    };
    MEDIA_LOG_I("DownloadedRequestHandler::Request start");
    isRequestError_.store(false);
    client_->RequestData(start, length, sourceInfo, handleResponseCb);
}

void DownloadedRequestHandler::OnHeaderReceived(void* buffer, size_t size, size_t nitems)
{
    FALSE_RETURN_MSG(buffer != nullptr, "Buffer is nullptr");
    size_t dataLen = size * nitems;
    FALSE_RETURN_MSG(dataLen > 0, "DataLen invalid");
    DownloadedHttpHeaderParser::ParseHttpHeader(headerMap_, std::string(static_cast<const char*>(buffer), dataLen));
}

void DownloadedRequestHandler::OnBodyReceived(void* buffer, size_t size, size_t nitems)
{
    std::string dataPath = urlDir_ + "/" + path_ + ".data";
    size_t dataLen = size * nitems;
    if (DownloadedFileCacheManager_->Write(dataPath, buffer, dataLen) != 0) {
        MEDIA_LOG_W("WriteCacheData error");
        return;
    }
    if (cacheManager_) {
        cacheManager_->FlushWriteLength("", dataLen);
    }
}

void DownloadedRequestHandler::SetIsFirstCallback(bool isFirst)
{
    isFirstCallback_.store(isFirst);
}

void DownloadedRequestHandler::SetPath(const std::string& path)
{
    path_ = path;
}

void DownloadedRequestHandler::SetUrlDir(const std::string& urlDir)
{
    urlDir_ = urlDir;
}

void DownloadedRequestHandler::SetCacheManager(std::shared_ptr<DownloadedCacheManager> cacheManager)
{
    cacheManager_ = cacheManager;
}

void DownloadedRequestHandler::SetDownloadedFileCacheManager(std::shared_ptr<DownloadedFileCacheManager> DownloadedFileCacheManager)
{
    DownloadedFileCacheManager_ = DownloadedFileCacheManager;
}

void DownloadedRequestHandler::SetHeaderParser(std::shared_ptr<DownloadedHttpHeaderParser> parser)
{
    headerParser_ = parser;
}

void DownloadedRequestHandler::SetUuid(int64_t uuid)
{
    uuid_ = uuid;
}

std::map<std::string, std::string> DownloadedRequestHandler::GetHeaders() const
{
    return headerMap_;
}

bool DownloadedRequestHandler::IsHeaderResponded() const
{
    return isHeaderResponded_.load();
}

void DownloadedRequestHandler::SetHeaderResponded(bool responded)
{
    isHeaderResponded_.store(responded);
}

bool DownloadedRequestHandler::IsClosed() const
{
    return isClosed_.load();
}

void DownloadedRequestHandler::SetClosed(bool closed)
{
    isClosed_.store(closed);
}
void DownloadedRequestHandler::SetClient(const std::shared_ptr<Plugins::HttpPlugin::NetworkClient>& client)
{
    client_ = client;
}

std::shared_ptr<Plugins::HttpPlugin::NetworkClient> DownloadedRequestHandler::GetClient()
{
    return client_;
}

int32_t DownloadedRequestHandler::GetClientCode()
{
    return clientCode_;
}

std::string DownloadedRequestHandler::GetPath()
{
    return path_;
}

bool DownloadedRequestHandler::IsRequestError()
{
    return isRequestError_.load();
}
} // namespace Media
} // namespace OHOS