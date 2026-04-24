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

#ifndef DOWNLOADER_IMPL_H
#define DOWNLOADER_IMPL_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "downloader.h"
#include "download_task.h"
#include "message_queue.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class DownloaderImpl : public Downloader, public NoCopyable {
public:
    DownloaderImpl();
    ~DownloaderImpl();

    uint64_t GetDownloaderId() override;
    uint64_t GetCurrentTaskId() override;

    int32_t SetUrl(const std::string &url) override;
    int32_t SetOutputPath(const std::string &path) override;
    int32_t SetHeader(const std::map<std::string, std::string> &header) override;
    int32_t SetConfig(const DownloadConfig &config) override;
    int32_t SetDownloadCallback(const std::shared_ptr<DownloadCallback> &callback) override;

    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Cancel() override;
    int32_t Release() override;

    DownloadState GetState() override;
    int32_t GetProgress(DownloadProgress &progress) override;

private:
    int32_t ValidateUrl(const std::string &url);
    int32_t ValidateOutputPath(const std::string &path);
    bool CanRelease() const;
    bool IsTerminalState() const;
    void NotifyStateChanged(DownloadState state);
    void NotifyCompleted(int64_t downloadedSize);
    void NotifyFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg);
    void NotifyProgress(const DownloadProgress &progress);
    void OnTaskStateChanged(DownloadState state);
    void OnTaskCompleted(int64_t downloadedSize);
    void OnTaskFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg);
    void OnTaskProgress(const DownloadProgress &progress);

    uint64_t downloaderId_;
    uint64_t taskId_;
    std::string url_;
    std::string outputPath_;
    std::map<std::string, std::string> header_;
    DownloadConfig config_;
    std::weak_ptr<DownloadCallback> callback_;
    std::atomic<DownloadState> state_;
    DownloadProgress progress_;
    std::shared_ptr<DownloadTask> task_;
    std::unique_ptr<MessageQueue> messageQueue_;
    std::mutex mutex_;
    bool urlSet_;
    bool pathSet_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADER_IMPL_H