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

#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <memory>
#include <string>
#include <functional>
#include <atomic>

#include "loading_request.h"
#include "network/network_client.h"
#include "network/network_typs.h"
#include "cache_manager.h"
#include "file_cache_manager.h"
#include "http_header_parser.h"
#include "request_handler.h"

namespace OHOS {
namespace Media {
class RequestHandler : public std::enable_shared_from_this<RequestHandler> {
public:
    explicit RequestHandler(std::shared_ptr<Plugins::HttpPlugin::NetworkClient> client);
    void Request(int64_t start, int64_t length, const std::string& url,
        const std::map<std::string, std::string>& headers,
        std::shared_ptr<LoadingRequest> request);

    void OnHeaderReceived(void* buffer, size_t size, size_t nitems);
    void OnBodyReceived(void* buffer, size_t size, size_t nitems);

    void SetIsFirstCallback(bool isFirst);
    void SetPath(const std::string& path);
    void SetUrlDir(const std::string& urlDir);
    void SetCacheManager(std::shared_ptr<StreamCacheManager> cacheManager);
    void SetFileCacheManager(std::shared_ptr<FileCacheManager> fileCacheManager);
    void SetHeaderParser(std::shared_ptr<HttpHeaderParser> parser);

    std::map<std::string, std::string> GetHeaders() const;
    bool IsHeaderResponded() const;
    void SetHeaderResponded(bool responded);
    bool IsClosed() const;
    void SetClosed(bool closed);
    void SetUuid(int64_t uuid);
    void SetClient(const std::shared_ptr<Plugins::HttpPlugin::NetworkClient>& client);
    std::shared_ptr<Plugins::HttpPlugin::NetworkClient> GetClient();
    int32_t GetClientCode();
    std::string GetPath();
    bool IsRequestError();

private:
    std::shared_ptr<Plugins::HttpPlugin::NetworkClient> client_;
    std::map<std::string, std::string> headerMap_;
    std::string path_;
    std::string urlDir_;
    std::shared_ptr<StreamCacheManager> cacheManager_;
    std::shared_ptr<FileCacheManager> fileCacheManager_;
    std::shared_ptr<HttpHeaderParser> headerParser_;

    std::atomic<bool> isFirstCallback_{false};
    std::atomic<bool> isHeaderResponded_{false};
    std::atomic<bool> isClosed_{false};
    std::shared_ptr<LoadingRequest> request_;
    int64_t uuid_;
    int32_t clientCode_ {-1};
    std::atomic<bool> isRequestError_{false};
};
} // namespace Media
} // namespace OHOS
#endif // REQUEST_HANDLER_H