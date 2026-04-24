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

#ifndef DOWNLOAD_NETWORK_CLIENT_H
#define DOWNLOAD_NETWORK_CLIENT_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "downloader.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class NetworkClient : public NoCopyable {
public:
    NetworkClient(const std::string &url, const std::map<std::string, std::string> &header,
                  int32_t timeoutMs, int32_t retryCount);
    ~NetworkClient();

    int32_t Connect();
    void Disconnect();
    int32_t Read(uint8_t *buffer, int32_t size, int32_t &bytesRead);
    int64_t GetTotalSize();
    bool IsConnected();

private:
    int32_t DoConnect();
    bool IsValidUrl(const std::string &url);

    std::string url_;
    std::map<std::string, std::string> header_;
    int32_t timeoutMs_;
    int32_t retryCount_;
    bool connected_;
    int64_t totalSize_;
    std::mutex mutex_;
    void *curlHandle_;
    void *curlMulti_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOAD_NETWORK_CLIENT_H