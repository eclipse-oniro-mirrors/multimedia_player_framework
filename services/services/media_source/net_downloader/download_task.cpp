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
constexpr int64_t CANCEL_TIMEOUT_SECONDS = 1;
constexpr int64_t PAUSE_TIMEOUT_SECONDS = 1;
}

DownloadTask::DownloadTask(const DownloadTaskInfo &info, const DownloadConfig &config,
    const std::weak_ptr<DownloadTaskCallback> &callback)
    : taskId_(info.taskId),
      url_(info.url),
      outputPath_(info.outputPath),
      header_(info.header),
      config_(config),
      state_(DOWNLOAD_IDLE),
      downloadedSize_(0),
      totalSize_(-1),
      downloadSpeed_(0),
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
    std::lock_guard<std::mutex> lock(stateMutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("Start failed: not idle, currentState=%{public}s", DownloadStateLog(currentState));
        return DOWNLOAD_ERROR_ALREADY_RUNNING;
    }

    downloadedSize_.store(0);
    totalSize_.store(-1);
    downloadSpeed_.store(0);
    lastErrorType_.store(DOWNLOAD_ERROR_NONE);
    lastErrorCode_.store(0);
    resumePos_.store(0);

    state_.store(DOWNLOAD_PREPARING);

    workerThread_ = std::thread(&DownloadTask::Run, this);

    MEDIA_LOGI("Start success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloadTask::Pause()
{
    std::unique_lock<std::mutex> stateLock(stateMutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_RUNNING) {
        MEDIA_LOGE("Pause failed: not running, currentState=%{public}s", DownloadStateLog(currentState));
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    state_.store(DOWNLOAD_PAUSING);

    auto client = GetClient();
    if (client != nullptr) {
        client->PauseDownload();
    }

    bool finished = finishCv_.wait_for(stateLock, std::chrono::seconds(PAUSE_TIMEOUT_SECONDS), [this] {
        DownloadState s = state_.load();
        return s == DOWNLOAD_PAUSED || s == DOWNLOAD_COMPLETED ||
               s == DOWNLOAD_CANCELED || s == DOWNLOAD_FAILED;
    });

    if (!finished) {
        MEDIA_LOGW("Pause: timeout waiting for state transition");
    }

    DownloadState s = state_.load();
    MEDIA_LOGI("Pause done: currentState=%{public}s", DownloadStateLog(s));
    return s == DOWNLOAD_PAUSED ? DOWNLOAD_RET_OK : DOWNLOAD_ERROR_INVALID_OPERATION;
}

int32_t DownloadTask::Resume()
{
    std::lock_guard<std::mutex> lock(stateMutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_PAUSED && currentState != DOWNLOAD_FAILED) {
        MEDIA_LOGE("Resume failed: not paused, currentState=%{public}s", DownloadStateLog(currentState));
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    state_.store(DOWNLOAD_RESUMING);

    if (workerThread_.joinable()) {
        workerThread_.detach();
    }
    workerThread_ = std::thread(&DownloadTask::Run, this);

    MEDIA_LOGI("Resume success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloadTask::Cancel()
{
    std::unique_lock<std::mutex> stateLock(stateMutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_RUNNING && currentState != DOWNLOAD_PAUSED && currentState != DOWNLOAD_RESUMING &&
        currentState != DOWNLOAD_PREPARING) {
        MEDIA_LOGE("Cancel failed: invalid state, currentState=%{public}s", DownloadStateLog(currentState));
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    state_.store(DOWNLOAD_CANCELING);
    if (currentState != DOWNLOAD_RUNNING) {
        MEDIA_LOGI("Cancel done: pre state=%{public}s", DownloadStateLog(currentState));
        return DOWNLOAD_RET_OK;
    }

    auto client = GetClient();
    if (client != nullptr) {
        client->Cancel();
    }

    bool finished = finishCv_.wait_for(stateLock, std::chrono::seconds(CANCEL_TIMEOUT_SECONDS), [this] {
        DownloadState s = state_.load();
        return s == DOWNLOAD_CANCELED || s == DOWNLOAD_COMPLETED || s == DOWNLOAD_FAILED;
    });

    if (!finished) {
        MEDIA_LOGW("Cancel: timeout waiting for state transition");
    }

    DownloadState s = state_.load();
    MEDIA_LOGI("Cancel done: currentState=%{public}s", DownloadStateLog(s));
    return s == DOWNLOAD_CANCELED ? DOWNLOAD_RET_OK : DOWNLOAD_ERROR_INVALID_OPERATION;
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
        int64_t percent = progress.downloadedSize * 100 / progress.totalSize;
        progress.progressPercent = static_cast<int32_t>(std::min(PERCENT_MAX, percent));
    } else {
        progress.progressPercent = 0;
    }

    return progress;
}

bool DownloadTask::EnterRunningState()
{
    auto cb = callback_.lock();
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (state_.load() != DOWNLOAD_PREPARING && state_.load() != DOWNLOAD_RESUMING) {
        MEDIA_LOGW("Run: invalid entry state %{public}d", state_.load());
        return false;
    }
    state_.store(DOWNLOAD_RUNNING);
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_RUNNING);
    }
    return true;
}

void DownloadTask::StartProgressThread(std::thread& progressThread, std::atomic<bool>& progressRunning,
    std::mutex& progressMutex, std::condition_variable& progressCv)
{
    progressRunning.store(true);
    progressThread = std::thread(&DownloadTask::RunProgressThread, this, std::ref(progressRunning),
        std::ref(progressMutex), std::ref(progressCv));
}

void DownloadTask::StopProgressThread(std::thread& progressThread, std::atomic<bool>& progressRunning,
    std::condition_variable& progressCv)
{
    progressRunning.store(false);
    progressCv.notify_one();
    if (progressThread.joinable()) {
        progressThread.join();
    }
}

void DownloadTask::CheckDownloadResult(bool success)
{
    if (HandleDownloadCompleted(success)) {
        return;
    }
    if (HandleDownloadPaused()) {
        return;
    }
    if (HandleDownloadCanceled()) {
        return;
    }
    HandleDownloadFailed();
}

bool DownloadTask::HandleDownloadCompleted(bool success)
{
    if (!success) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_.store(DOWNLOAD_COMPLETED);
    }
    MEDIA_LOGI("Download completed");
    auto cb = callback_.lock();
    if (cb) {
        DownloadProgress progress = GetProgress();
        progress.downloadSpeed = CalculateSpeed();
        cb->OnProgress(progress);
        cb->OnStateChanged(DOWNLOAD_COMPLETED);
        cb->OnCompleted(downloadedSize_.load());
    }
    return true;
}

bool DownloadTask::HandleDownloadPaused()
{
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_.load() != DOWNLOAD_PAUSING) {
            return false;
        }
        MEDIA_LOGI("Run: detected PAUSING after DoPrepare");
        resumePos_.store(downloadedSize_.load());
        state_.store(DOWNLOAD_PAUSED);
    }
    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_PAUSED);
    }
    return true;
}

bool DownloadTask::HandleDownloadCanceled()
{
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_.load() != DOWNLOAD_CANCELING) {
            return false;
        }
        MEDIA_LOGI("Run: detected CANCELING after DoPrepare");
        state_.store(DOWNLOAD_CANCELED);
    }
    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_CANCELED);
    }
    return true;
}

void DownloadTask::HandleDownloadFailed()
{
    MEDIA_LOGI("Download failed, errorType=%{public}d", lastErrorType_.load());
    HandleError(lastErrorType_.load(), lastErrorCode_.load(), "Download failed");
}

void DownloadTask::NotifyFinish()
{
    finishCv_.notify_all();
    MEDIA_LOGI("DownloadTask thread ended, taskId=%{public}" PRIu64, taskId_);
}

void DownloadTask::InitClient()
{
    auto preClient = GetClient();
    if (preClient != nullptr) {
        SetClient(nullptr);
    }
    SetClient(std::make_unique<NetworkClient>(url_, header_, config_.timeoutMs, config_.retryCount));
}

void DownloadTask::ExecuteDownload()
{
    MEDIA_LOGI("ExecuteDownload start");

    int64_t startPos = 0;
    if (resumePos_.load() > 0) {
        startPos = resumePos_.load();
        MEDIA_LOGI("DoPrepare: resuming from %{public}" PRId64, startPos);
    } else {
        startPos = GetFileSize(outputPath_);
        MEDIA_LOGI("DoPrepare: starting fresh, file size=%{public}" PRId64, startPos);
    }

    auto client = GetClient();
    int32_t setPathRet = client->SetOutputPath(outputPath_, startPos);
    if (setPathRet != DOWNLOAD_RET_OK) {
        lastErrorType_.store(DOWNLOAD_ERROR_FILE_IO);
        lastErrorCode_.store(setPathRet);
        return;
    }

    client->SetProgressCallback([this](int64_t downloadedSize, int64_t totalSize) {
        downloadedSize_.store(downloadedSize);
        if (totalSize > 0) {
            totalSize_.store(totalSize);
        }
    });

    client->SetErrorCallback([this](DownloadErrorType errorType, int32_t errorCode) {
        MEDIA_LOGE("download error, type: %{public}d, code: %{puiblic}d", static_cast<int32_t>(errorType), errorCode);
        lastErrorType_.store(errorType);
        lastErrorCode_.store(errorCode);
    });

    lastSpeedUpdateTime_ = std::chrono::steady_clock::now();
    lastDownloadedSize_ = 0;
    lastProgressTime_ = std::chrono::steady_clock::now();

    int32_t connectRet = client->Download(startPos);

    if (connectRet != DOWNLOAD_RET_OK) {
        if (lastErrorType_.load() == DOWNLOAD_ERROR_NONE) {
            lastErrorType_.store(DOWNLOAD_ERROR_NETWORK);
            lastErrorCode_.store(connectRet);
        }
        return;
    }

    MEDIA_LOGI("DoPrepare success");
}

void DownloadTask::Run()
{
    MEDIA_LOGI("DownloadTask thread started, taskId=%{public}" PRIu64, taskId_);
    if (!EnterRunningState()) {
        return;
    }

    std::atomic<bool> progressRunning{false};
    std::thread progressThread;
    std::mutex progressMutex;
    std::condition_variable progressCv;
    StartProgressThread(progressThread, progressRunning, progressMutex, progressCv);

    InitClient();
    ExecuteDownload();

    StopProgressThread(progressThread, progressRunning, progressCv);

    auto client = GetClient();
    bool success = (client != nullptr && client->IsRequestSuccess());
    CheckDownloadResult(success);

    ReleaseClient();
    NotifyFinish();
}

int64_t DownloadTask::GetFileSize(const std::string &path)
{
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) == 0) {
        return statbuf.st_size;
    }
    return 0;
}

void DownloadTask::ReleaseClient()
{
    MEDIA_LOGI("ReleaseClient start");

    auto client = GetClient();
    if (client != nullptr) {
        SetClient(nullptr);
    }

    MEDIA_LOGI("ReleaseClient done");
}

void DownloadTask::HandleError(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("Download error: type=%{public}d, code=%{public}d, msg=%{public}s",
               errorType, errorCode, errorMsg.c_str());

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_.store(DOWNLOAD_FAILED);
        resumePos_.store(downloadedSize_.load());
    }

    auto cb = callback_.lock();
    if (cb) {
        cb->OnStateChanged(DOWNLOAD_FAILED);
        cb->OnFailed(errorType, errorCode, errorMsg);
    }
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

void DownloadTask::RunProgressThread(std::atomic<bool>& progressRunning,
    std::mutex& progressMutex, std::condition_variable& progressCv)
{
    bool hasReportedTotalSize = false;
    std::unique_lock<std::mutex> lock(progressMutex);

    while (progressRunning.load()) {
        progressCv.wait_for(lock, std::chrono::milliseconds(config_.progressCallbackIntervalMs),
            [&progressRunning] { return !progressRunning.load(); });

        if (!progressRunning.load()) {
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
