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

#include "download_task.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cerrno>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderDownloadTask"};
constexpr int32_t SPEED_CALCULATION_INTERVAL_MS = 1000;
constexpr int64_t PERCENT_MAX = 100;
constexpr int64_t CANCEL_TIMEOUT_SECONDS = 3;
}

DownloadTask::DownloadTask(const DownloadTaskInfo &info, const DownloadConfig &config,
    const std::weak_ptr<DownloadTaskCallback> &callback)
    : taskId_(info.taskId),
      url_(info.url),
      outputPath_(info.outputPath),
      header_(info.header),
      config_(config),
      state_(DOWNLOAD_PREPARING),
      downloadedSize_(0),
      totalSize_(-1),
      downloadSpeed_(0),
      running_(false),
      paused_(false),
      canceled_(false),
      downloadTerminated_(false),
      callback_(callback)
{
    MEDIA_LOGI("DownloadTask created, taskId=%{public}" PRIu64, taskId_);
}

DownloadTask::~DownloadTask()
{
    MEDIA_LOGI("DownloadTask destroyed, taskId=%{public}" PRIu64, taskId_);
    Cancel();
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
}

int32_t DownloadTask::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (running_.load()) {
        MEDIA_LOGE("Start failed: already running");
        return DOWNLOAD_ERROR_ALREADY_RUNNING;
    }

    running_.store(true);
    paused_.store(false);
    canceled_.store(false);
    downloadTerminated_.store(false);
    downloadedSize_.store(0);
    totalSize_.store(-1);
    downloadSpeed_.store(0);
    state_.store(DOWNLOAD_PREPARING);

    workerThread_ = std::thread(&DownloadTask::Run, this);

    MEDIA_LOGI("Start success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloadTask::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!running_.load() || paused_.load()) {
        MEDIA_LOGE("Pause failed: not running or already paused");
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    paused_.store(true);
    state_.store(DOWNLOAD_PAUSED);

    auto client = GetClient();
    if (client != nullptr) {
        client->PauseDownload();
    }

    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_PAUSED);
    }

    MEDIA_LOGI("Pause success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloadTask::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!paused_.load()) {
        MEDIA_LOGE("Resume failed: not paused");
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    paused_.store(false);
    canceled_.store(false);
    state_.store(DOWNLOAD_RUNNING);

    auto client = GetClient();
    if (client != nullptr) {
        client->ResumeDownload();
    }

    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_RUNNING);
    }

    MEDIA_LOGI("Resume success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloadTask::Cancel()
{
    std::unique_lock<std::mutex> lock(mutex_);

    canceled_.store(true);
    paused_.store(false);
    downloadTerminated_.store(true);

    // notify client cb thread
    auto client = GetClient();
    if (client != nullptr) {
        client->Cancel();
    }

    bool finished = finishCv_.wait_for(lock, std::chrono::seconds(CANCEL_TIMEOUT_SECONDS), [this] {
        return !running_.load();
    });
    if (!finished) {
        MEDIA_LOGW("Cancel: timeout waiting for Run()");
    }

    MEDIA_LOGI("Cancel success");
    return DOWNLOAD_RET_OK;
}

DownloadState DownloadTask::GetState()
{
    return state_.load();
}

DownloadProgress DownloadTask::GetProgress()
{
    DownloadProgress progress;
    progress.downloadedSize = downloadedSize_.load();
    progress.totalSize = totalSize_.load();
    progress.downloadSpeed = downloadSpeed_.load();

    if (progress.totalSize > 0) {
        int64_t percent = progress.downloadedSize * PERCENT_MAX / progress.totalSize;
        progress.progressPercent = static_cast<int32_t>(std::min(PERCENT_MAX, percent));
    } else {
        progress.progressPercent = 0;
    }

    return progress;
}

void DownloadTask::Run()
{
    MEDIA_LOGI("DownloadTask thread started, taskId=%{public}" PRIu64, taskId_);

    state_.store(DOWNLOAD_RUNNING);
    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_RUNNING);
    }

    StartProgressThread();

    DoPrepare();

    StopProgressThread();

    auto client = GetClient();
    if (client != nullptr && client->IsRequestSuccess()) {
        state_.store(DOWNLOAD_COMPLETED);
        running_.store(false);
        downloadTerminated_.store(true);
        if (cb) {
            DownloadProgress progress = GetProgress();
            progress.downloadSpeed = CalculateSpeed();
            cb->OnProgress(progress);
            cb->OnStateChanged(DOWNLOAD_COMPLETED);
            cb->OnCompleted(downloadedSize_.load());
        }
    } else {
        if (canceled_.load()) {
            MEDIA_LOGI("Download canceled by user");
            state_.store(DOWNLOAD_CANCELED);
            running_.store(false);
            downloadTerminated_.store(true);
            if (cb) {
                cb->OnStateChanged(DOWNLOAD_CANCELED);
            }
        } else if (lastErrorType_.load() == DOWNLOAD_ERROR_DISK_SPACE) {
            HandleError(lastErrorType_.load(), lastErrorCode_.load(), "Disk space insufficient during download");
        } else if (lastErrorType_.load() == DOWNLOAD_ERROR_FILE_IO) {
            HandleError(lastErrorType_.load(), lastErrorCode_.load(), "File write error during download");
        } else {
            HandleError(DOWNLOAD_ERROR_NETWORK, -1, "Request failed");
        }
    }

    DoCleanup();

    running_.store(false);
    finishCv_.notify_all();

    MEDIA_LOGI("DownloadTask thread ended, taskId=%{public}" PRIu64, taskId_);
}

int64_t DownloadTask::GetFileSize(const std::string &path)
{
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) == 0) {
        return statbuf.st_size;
    }
    return 0;
}

void DownloadTask::DoPrepare()
{
    MEDIA_LOGI("DoPrepare start");

    auto preClient = GetClient();
    if (preClient != nullptr) {
        preClient->Disconnect();
        SetClient(nullptr);
    }

    int64_t existingSize = GetFileSize(outputPath_);
    MEDIA_LOGI("DoPrepare: existing file size=%{public}" PRId64, existingSize);

    SetClient(std::make_unique<NetworkClient>(url_, header_, config_.timeoutMs, config_.retryCount));

    auto client = GetClient();
    int32_t setPathRet = client->SetOutputPath(outputPath_);
    if (setPathRet != DOWNLOAD_RET_OK) {
        HandleError(DOWNLOAD_ERROR_FILE_IO, setPathRet, "Failed to set output path");
        return;
    }

    client->SetDataCallback([this](const char* data, size_t len, int64_t totalSize) {
        if (canceled_.load()) {
            MEDIA_LOGI("DataCallback: canceled, return false to abort");
            return false;
        }
        return OnDataReceived(data, len, totalSize);
    });

    outputFd_ = client->GetOutputFd();

    lastSpeedUpdateTime_ = std::chrono::steady_clock::now();
    lastDownloadedSize_ = 0;
    lastProgressTime_ = std::chrono::steady_clock::now();

    int32_t connectRet = client->Connect(existingSize);
    if (connectRet != DOWNLOAD_RET_OK) {
        if (lastErrorType_.load() == DOWNLOAD_ERROR_DISK_SPACE) {
            HandleError(lastErrorType_.load(), lastErrorCode_.load(), "Disk space insufficient during download");
        } else if (lastErrorType_.load() == DOWNLOAD_ERROR_FILE_IO) {
            HandleError(lastErrorType_.load(), lastErrorCode_.load(), "File write error during download");
        } else {
            HandleError(DOWNLOAD_ERROR_NETWORK, connectRet, "Failed to connect to server");
        }
        return;
    }

    totalSize_.store(client->GetTotalSize());
    MEDIA_LOGI("DoPrepare success, totalSize=%{public}" PRId64, totalSize_.load());
}

void DownloadTask::DoCleanup()
{
    MEDIA_LOGI("DoCleanup start");

    auto client = GetClient();
    if (client != nullptr) {
        client->Disconnect();
        SetClient(nullptr);
    }

    MEDIA_LOGI("DoCleanup done");
}

void DownloadTask::HandleError(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("Download error: type=%{public}d, code=%{public}d, msg=%{public}s",
               errorType, errorCode, errorMsg.c_str());

    state_.store(DOWNLOAD_FAILED);
    running_.store(false);
    downloadTerminated_.store(true);

    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_FAILED);
        cb->OnFailed(errorType, errorCode, errorMsg);
    }

    DoCleanup();
}

int64_t DownloadTask::CalculateSpeed()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSpeedUpdateTime_);

    if (elapsed.count() >= SPEED_CALCULATION_INTERVAL_MS) {
        int64_t currentDownloaded = downloadedSize_.load();
        int64_t downloadedDelta = currentDownloaded - lastDownloadedSize_;

        int64_t speed = downloadedDelta * 1000 / elapsed.count();
        downloadSpeed_.store(speed);

        lastDownloadedSize_ = currentDownloaded;
        lastSpeedUpdateTime_ = now;

        return speed;
    }

    return downloadSpeed_.load();
}

void DownloadTask::UpdateProgress()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgressTime_);

    MEDIA_LOGI("update progress check, duration: %{public}" PRId64 ", interval: %{public}d",
        (int64_t)elapsed.count(), config_.progressCallbackIntervalMs);
    if (elapsed.count() >= config_.progressCallbackIntervalMs) {
        auto cb = callback_.lock();
        if (cb) {
            DownloadProgress progress = GetProgress();
            progress.downloadSpeed = CalculateSpeed();
            cb->OnProgress(progress);
        }
        lastProgressTime_ = now;
    }

    CalculateSpeed();
}

bool DownloadTask::OnDataReceived(const char* data, size_t len, int64_t totalSize)
{
    if (state_.load() != DOWNLOAD_RUNNING) {
        return true;
    }

    if (totalSize > 0 && totalSize_.load() <= 0) {
        totalSize_.store(totalSize);
    }

    if (outputFd_ >= 0) {
        ssize_t writeLen = write(outputFd_, data, len);
        if (writeLen == len) {
            downloadedSize_.fetch_add(writeLen);
            return true;
        }
        MEDIA_LOGE("OnDataReceived: write failed, errno=%{public}d", errno);
        if (errno == ENOSPC) {
            lastErrorType_.store(DOWNLOAD_ERROR_DISK_SPACE);
        } else {
            lastErrorType_.store(DOWNLOAD_ERROR_FILE_IO);
        }
        lastErrorCode_.store(errno);
        return false;
    }
    return true;
}

void DownloadTask::StartProgressThread()
{
    progressThreadRunning_.store(true);
    progressThread_ = std::thread(&DownloadTask::ProgressReporterThread, this);
}

void DownloadTask::StopProgressThread()
{
    progressThreadRunning_.store(false);
    if (progressThread_.joinable()) {
        progressThread_.join();
    }
}

void DownloadTask::ProgressReporterThread()
{
    bool hasReportedTotalSize = false;

    while (progressThreadRunning_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.progressCallbackIntervalMs));

        if (!progressThreadRunning_.load()) {
            break;
        }

        if (state_.load() != DOWNLOAD_RUNNING) {
            continue;
        }

        int64_t total = totalSize_.load();

        bool canReport = (total > 0) || hasReportedTotalSize;

        if (canReport) {
            auto cb = callback_.lock();
            if (cb) {
                auto progress = GetProgress();
                progress.downloadSpeed = CalculateSpeed();
                MEDIA_LOGI("OnProgress %{public}d%% (%{public}" PRId64 "/%{public}" PRId64 ") speed=%{public}" PRId64,
                    progress.progressPercent, progress.downloadedSize, progress.totalSize, progress.downloadSpeed);
                cb->OnProgress(progress);
            }
        }

        hasReportedTotalSize = true;
    }
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS