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

#ifndef DOWNLOAD_TASK_H
#define DOWNLOAD_TASK_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "downloader.h"
#include "download_network_client.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class DownloadTaskCallback {
public:
    virtual ~DownloadTaskCallback() = default;
    virtual void OnStateChanged(DownloadState state) = 0;
    virtual void OnCompleted(int64_t downloadedSize) = 0;
    virtual void OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg) = 0;
    virtual void OnProgress(const DownloadProgress &progress) = 0;
};

struct DownloadTaskInfo {
    uint64_t taskId {};
    std::string url;
    std::string outputPath;
    std::map<std::string, std::string> header;
};

class DownloadTask : public NoCopyable {
public:
    DownloadTask(const DownloadTaskInfo &info, const DownloadConfig &config,
        const std::weak_ptr<DownloadTaskCallback> &callback);
    ~DownloadTask();

    int32_t Start();
    int32_t Pause();
    int32_t Resume();
    int32_t Cancel();
    DownloadState GetState();
    DownloadProgress GetProgress();

private:
    void Run();
    bool EnterRunningState();
    void StartProgressThread(std::thread& progressThread, std::atomic<bool>& progressRunning,
        std::mutex& progressMutex, std::condition_variable& progressCv);
    void StopProgressThread(std::thread& progressThread, std::atomic<bool>& progressRunning,
        std::condition_variable& progressCv);
    void CheckDownloadResult(bool success);
    bool HandleDownloadCompleted(bool success);
    bool HandleDownloadPaused();
    bool HandleDownloadCanceled();
    void HandleDownloadFailed();
    void NotifyFinish();
    void InitClient();
    void ExecuteDownload();
    void ReleaseClient();
    void HandleError(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg);
    int64_t CalculateSpeed();
    void UpdateProgress();
    static int64_t GetFileSize(const std::string &path);

    void RunProgressThread(std::atomic<bool>& progressRunning,
        std::mutex& progressMutex, std::condition_variable& progressCv);
    std::shared_ptr<NetworkClient> GetClient()
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        return networkClient_;
    }

    void SetClient(std::shared_ptr<NetworkClient> client)
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        networkClient_ = client;
    }

    uint64_t taskId_;
    std::string url_;
    std::string outputPath_;
    std::map<std::string, std::string> header_;
    DownloadConfig config_;
    std::atomic<DownloadState> state_;
    std::mutex stateMutex_;
    std::atomic<int64_t> downloadedSize_;
    std::chrono::steady_clock::time_point lastSpeedUpdateTime_ {};
    std::chrono::steady_clock::time_point lastProgressTime_ {};
    int64_t lastDownloadedSize_ {0};
    std::atomic<int64_t> totalSize_;
    std::atomic<int64_t> downloadSpeed_;
    std::thread workerThread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable finishCv_;
    std::weak_ptr<DownloadTaskCallback> callback_;
    std::mutex clientMutex_;
    std::shared_ptr<NetworkClient> networkClient_;

    std::atomic<DownloadErrorType> lastErrorType_{DOWNLOAD_ERROR_NONE};
    std::atomic<int32_t> lastErrorCode_{0};
    std::atomic<int64_t> resumePos_{0};
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOAD_TASK_H