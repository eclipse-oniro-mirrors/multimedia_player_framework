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

#include "download_task.h"

#include <algorithm>
#include <chrono>

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DownloadTask"};
constexpr int32_t PROGRESS_UPDATE_INTERVAL_MS = 100;
constexpr int32_t SPEED_CALCULATION_INTERVAL_MS = 1000;
constexpr int32_t MAX_RETRY_DELAY_MS = 30000;
constexpr int32_t INITIAL_RETRY_DELAY_MS = 1000;
}

DownloadTask::DownloadTask(uint64_t taskId, const std::string &url, const std::string &outputPath,
                            const std::map<std::string, std::string> &header, const DownloadConfig &config,
                            DownloadTaskCallback *callback)
    : taskId_(taskId),
      url_(url),
      outputPath_(outputPath),
      header_(header),
      config_(config),
      state_(DOWNLOAD_PREPARING),
      downloadedSize_(0),
      totalSize_(-1),
      downloadSpeed_(0),
      running_(false),
      paused_(false),
      canceled_(false),
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
    downloadedSize_.store(0);
    totalSize_.store(-1);
    downloadSpeed_.store(0);
    state_.store(DOWNLOAD_PREPARING);
    
    workerThread_ = std::thread(&DownloadTask::Run, this);
    
    MEDIA_LOGI("Start success");
    return DOWNLOAD_ERROR_OK;
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
    
    if (callback_ != nullptr) {
        callback_->OnStateChanged(DOWNLOAD_PAUSED);
    }
    
    MEDIA_LOGI("Pause success");
    return DOWNLOAD_ERROR_OK;
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
    downloadedSize_.store(0);
    state_.store(DOWNLOAD_PREPARING);
    
    cv_.notify_one();
    
    MEDIA_LOGI("Resume success");
    return DOWNLOAD_ERROR_OK;
}

int32_t DownloadTask::Cancel()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    canceled_.store(true);
    running_.store(false);
    paused_.store(false);
    
    cv_.notify_all();
    
    DoCleanup();
    
    MEDIA_LOGI("Cancel success");
    return DOWNLOAD_ERROR_OK;
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
        progress.progressPercent = static_cast<int32_t>(
            std::min(100, static_cast<int32_t>(progress.downloadedSize * 100 / progress.totalSize)));
    } else {
        progress.progressPercent = 0;
    }
    
    return progress;
}

void DownloadTask::Run()
{
    MEDIA_LOGI("DownloadTask thread started, taskId=%{public}" PRIu64, taskId_);
    
    while (running_.load() && !canceled_.load()) {
        if (paused_.load()) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !paused_.load() || canceled_.load() || !running_.load(); });
            if (canceled_.load() || !running_.load()) {
                break;
            }
        }
        
        DoPrepare();
        
        if (canceled_.load()) {
            break;
        }
        
        if (state_.load() == DOWNLOAD_PREPARING) {
            state_.store(DOWNLOAD_RUNNING);
            if (callback_ != nullptr) {
                callback_->OnStateChanged(DOWNLOAD_RUNNING);
            }
        }
        
        DoDownload();
        
        break;
    }
    
    DoCleanup();
    
    MEDIA_LOGI("DownloadTask thread ended, taskId=%{public}" PRIu64, taskId_);
}

void DownloadTask::DoPrepare()
{
    MEDIA_LOGI("DoPrepare start");
    
    if (networkClient_ != nullptr) {
        networkClient_->Disconnect();
    }
    networkClient_ = std::make_unique<NetworkClient>(url_, header_, config_.timeoutMs, config_.retryCount);
    
    if (!DoRetry([this]() { return networkClient_->Connect(); }, DOWNLOAD_ERROR_NETWORK)) {
        HandleError(DOWNLOAD_ERROR_NETWORK, DOWNLOAD_ERROR_OK, "Failed to connect to server");
        return;
    }
    
    totalSize_.store(networkClient_->GetTotalSize());
    
    if (fileWriter_ != nullptr) {
        fileWriter_->Close();
    }
    fileWriter_ = std::make_unique<FileWriter>(outputPath_);
    
    int32_t openRet = fileWriter_->Open();
    if (openRet != DOWNLOAD_ERROR_OK) {
        HandleError(DOWNLOAD_ERROR_FILE_IO, openRet, "Failed to open output file");
        return;
    }
    
    if (totalSize_.load() > 0) {
        int32_t truncateRet = fileWriter_->Truncate();
        if (truncateRet != DOWNLOAD_ERROR_OK) {
            MEDIA_LOGW("Truncate file failed, may not support");
        }
    }
    
    MEDIA_LOGI("DoPrepare success, totalSize=%{public}" PRId64, totalSize_.load());
}

void DownloadTask::DoDownload()
{
    MEDIA_LOGI("DoDownload start");
    
    std::vector<uint8_t> buffer(config_.bufferSize);
    
    lastProgressTime_ = std::chrono::steady_clock::now();
    lastSpeedUpdateTime_ = std::chrono::steady_clock::now();
    lastDownloadedSize_ = 0;
    
    while (running_.load() && !canceled_.load() && !paused_.load()) {
        int32_t bytesRead = 0;
        int32_t readRet = networkClient_->Read(buffer.data(), config_.bufferSize, bytesRead);
        
        if (readRet != DOWNLOAD_ERROR_OK) {
            if (!DoRetry([this, &buffer, &bytesRead]() {
                return networkClient_->Read(buffer.data(), config_.bufferSize, bytesRead);
            }, DOWNLOAD_ERROR_NETWORK)) {
                HandleError(DOWNLOAD_ERROR_NETWORK, readRet, "Failed to read data from server");
                return;
            }
        }
        
        if (bytesRead <= 0) {
            break;
        }
        
        int32_t writeRet = fileWriter_->Write(buffer.data(), bytesRead);
        if (writeRet != DOWNLOAD_ERROR_OK) {
            HandleError(DOWNLOAD_ERROR_FILE_IO, writeRet, "Failed to write data to file");
            return;
        }
        
        downloadedSize_.fetch_add(bytesRead);
        
        UpdateProgress();
    }
    
    if (!canceled_.load() && running_.load()) {
        state_.store(DOWNLOAD_COMPLETED);
        if (callback_ != nullptr) {
            callback_->OnStateChanged(DOWNLOAD_COMPLETED);
            callback_->OnCompleted(downloadedSize_.load());
        }
        MEDIA_LOGI("DoDownload completed, downloadedSize=%{public}" PRId64, downloadedSize_.load());
    }
}

void DownloadTask::DoCleanup()
{
    MEDIA_LOGI("DoCleanup start");
    
    if (fileWriter_ != nullptr) {
        fileWriter_->Close();
        fileWriter_ = nullptr;
    }
    
    if (networkClient_ != nullptr) {
        networkClient_->Disconnect();
        networkClient_ = nullptr;
    }
    
    MEDIA_LOGI("DoCleanup done");
}

void DownloadTask::HandleError(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("Download error: type=%{public}d, code=%{public}d, msg=%{public}s",
               errorType, errorCode, errorMsg.c_str());
    
    state_.store(DOWNLOAD_FAILED);
    running_.store(false);
    
    if (callback_ != nullptr) {
        callback_->OnStateChanged(DOWNLOAD_FAILED);
        callback_->OnFailed(errorType, errorCode, errorMsg);
    }
    
    DoCleanup();
}

bool DownloadTask::DoRetry(std::function<int32_t()> operation, DownloadErrorType errorType)
{
    for (int32_t i = 0; i < config_.retryCount; ++i) {
        if (!running_.load() || canceled_.load()) {
            return false;
        }
        
        SleepWithExponentialBackoff(i);
        
        int32_t ret = operation();
        if (ret == DOWNLOAD_ERROR_OK) {
            MEDIA_LOGI("Retry succeeded at attempt %{public}d", i + 1);
            return true;
        }
        
        MEDIA_LOGW("Retry attempt %{public}d failed, ret=%{public}d", i + 1, ret);
    }
    
    return false;
}

void DownloadTask::SleepWithExponentialBackoff(int32_t retryIndex)
{
    int32_t delayMs = INITIAL_RETRY_DELAY_MS * (1 << retryIndex);
    delayMs = std::min(delayMs, MAX_RETRY_DELAY_MS);
    
    MEDIA_LOGI("Sleep for %{public}dms before retry %{public}d", delayMs, retryIndex + 1);
    
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, std::chrono::milliseconds(delayMs),
                 [this] { return canceled_.load() || !running_.load(); });
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
    
    if (elapsed.count() >= config_.progressCallbackIntervalMs) {
        if (totalSize_.load() > 0 && callback_ != nullptr) {
            DownloadProgress progress = GetProgress();
            progress.downloadSpeed = CalculateSpeed();
            callback_->OnProgress(progress);
        }
        lastProgressTime_ = now;
    }
    
    CalculateSpeed();
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS