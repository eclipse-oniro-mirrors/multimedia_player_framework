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

#ifndef DOWNLOAD_NETWORK_CLIENT_H
#define DOWNLOAD_NETWORK_CLIENT_H

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "downloader.h"
#include "nocopyable.h"
#include "network/network_client.h"
#include "network/network_typs.h"
#include "status.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class DownloadTaskCallback;

class NetworkClient : public NoCopyable {
public:
    NetworkClient(const std::string &url, const std::map<std::string, std::string> &header,
        int32_t timeoutMs, int32_t retryCount);
    ~NetworkClient();

    int32_t SetOutputPath(const std::string &path, int64_t existingSize = 0);
    int32_t Download(int64_t startPos = 0);
    int64_t GetTotalSize();
    bool IsConnected();
    int64_t GetDownloadedSize();
    int GetOutputFd() const;

    void PauseDownload();
    bool IsPaused();

    void Cancel();

    using ProgressCallback = std::function<void(int64_t downloadedSize, int64_t totalSize)>;
    void SetProgressCallback(ProgressCallback cb);

    using ErrorCallback = std::function<void(DownloadErrorType errorType, int32_t errorCode)>;
    void SetErrorCallback(ErrorCallback cb);

    bool IsRequestCompleted() const;
    bool IsRequestSuccess() const;

private:
    static size_t RxHeaderCallback(void* buffer, size_t size, size_t nitems, void* userParam);
    static size_t RxBodyCallback(void* buffer, size_t size, size_t nitems, void* userParam);

    int32_t DoDownload(int64_t startPos = 0);
    bool IsValidUrl(const std::string &url);
    void HandleResponse(const int32_t clientCode, const int32_t serverCode, const std::string &ca, const Status ret);
    void ProcessHttpSuccess(int32_t clientCode);
    void ProcessHttp416RangeNotSatisfiable();
    void ProcessHttpError(int32_t clientCode);
    void ProcessStatusError(const Status ret);
    void InitDownloadContext(int64_t startPos);
    std::shared_ptr<Plugins::HttpPlugin::NetworkClient> CreateAndInitClient();
    Plugins::HttpPlugin::RequestInfo BuildRequestInfo(int64_t startPos);
    void CloseOutputFd();

    std::string url_;
    std::map<std::string, std::string> header_;
    int32_t timeoutMs_;
    std::atomic<bool> connected_;
    std::atomic<int64_t> totalSize_;

    std::mutex mutex_;

    std::mutex pauseMutex_;
    std::atomic<bool> paused_{false};

    ProgressCallback progressCallback_;
    ErrorCallback errorCallback_;

    struct DownloadContext {
        NetworkClient* parent;
        std::atomic<bool> requestSuccess{false};
        std::atomic<bool> requestCompleted{false};
        std::atomic<int64_t> totalSize{-1};
        std::atomic<int64_t> downloadedSize{0};
        std::atomic<bool> isHeaderReceived{false};
        std::string outputPath;
        int outputFd{-1};
        std::map<std::string, std::string> responseHeaders;
        std::mutex mutex;
        std::condition_variable cv;
    };
    std::shared_ptr<DownloadContext> ctx_;
    int64_t startPos_{0};
    std::optional<uint32_t> connectTimeoutMs_ {std::nullopt};
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOAD_NETWORK_CLIENT_H