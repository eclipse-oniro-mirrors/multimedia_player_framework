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

#ifndef DOWNLOADER_IMPL_H
#define DOWNLOADER_IMPL_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <array>
#include <string>
#include <thread>
#include <queue>

#include "downloader.h"
#include "download_task.h"
#include "message_queue.h"
#include "nocopyable.h"
#include "network_utils.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

struct QueuedTaskInfo {
    std::string url;
    std::string outputPath;
    std::map<std::string, std::string> header;
    DownloadConfig config;
};

class DownloaderImpl : public Downloader, public DownloadTaskCallback, public NoCopyable,
    public std::enable_shared_from_this<DownloaderImpl> {
public:
    DownloaderImpl();
    ~DownloaderImpl() override;

    uint64_t GetDownloaderId() override;
    uint64_t GetCurrentTaskId() override;

    int32_t SetUrl(const std::string &url) override;
    int32_t SetOutputPath(const std::string &path) override;
    int32_t SetHeader(const std::map<std::string, std::string> &header) override;
    int32_t SetConfig(const DownloadConfig &config) override;
    int32_t AddFileTask(const std::string &url, const std::string &path, const DownloadConfig &config) override;
    int32_t SetDownloadCallback(const std::shared_ptr<DownloadCallback> &callback) override;

    int32_t Start() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Cancel() override;
    int32_t Release() override;

    DownloadState GetState() override;
    int32_t GetProgress(DownloadProgress &progress) override;
    std::string GetCurrentFilePath() const override;

private:
    int32_t InnerStart();
    void StartMessageQueue();
    void StartSchedulerQueue();     // 任务调度队列
    int32_t ValidateUrl(const std::string &url);
    int32_t ValidateOutputPath(const std::string &path);
    bool CanRelease() const;
    bool IsTerminalState() const;
    void NotifyStateChanged(DownloadState state);
    void NotifyCompleted(int64_t downloadedSize);
    void NotifyFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg);
    void NotifyProgress(const DownloadProgress &progress);

    void OnStateChanged(DownloadState state) override;      // task回调线程
    void OnCompleted(int64_t downloadedSize) override;
    void OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg) override;
    void OnProgress(const DownloadProgress &progress) override;
    int32_t ProcessNextTaskInQueue();
    void HandleTaskCompleted();       // 回调到AVDownloaderManager，通过消息队列线程
    void HandleTaskFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg);
    void HandleTaskCanceled();      // 处理上层的取消操作
    void HandleTaskNetChanged();

    bool IsNetworkAllowDownload(MediaSourceUtils::NetConnType newType);       // 检查当前网络允许下载

    uint64_t downloaderId_;
    uint64_t taskId_;
    std::string url_;
    std::string outputPath_;
    std::map<std::string, std::string> header_;
    DownloadConfig config_;
    std::weak_ptr<DownloadCallback> callback_;
    std::atomic<DownloadState> state_;
    std::mutex progressMutex_;
    DownloadProgress progress_;
    std::shared_ptr<DownloadTask> task_;
    std::unique_ptr<MessageQueue> messageQueue_;
    std::unique_ptr<MessageQueue> schedulerQueue_;      // 任务调度队列
    std::thread schedulerThread_;       // 任务调度线程

    mutable std::mutex mutex_;
    std::mutex queueMutex_;     // 队列锁
    std::queue<QueuedTaskInfo> taskQueue_;  // 任务队列
    bool urlSet_;
    bool pathSet_;
    bool messageQueueStarted_;      // 消息队列状态位
    std::shared_ptr<DownloadTask> pendingTaskToRelease_;        // 待释放任务
    std::atomic<bool> schedulerRunning_;  // 任务调度线程状态
    int32_t totalTaskCount_;
    int32_t completedTaskCount_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADER_IMPL_H