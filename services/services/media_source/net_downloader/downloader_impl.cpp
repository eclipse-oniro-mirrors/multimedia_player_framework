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

#include "downloader_impl.h"

#include <chrono>
#include <mutex>
#include <random>

#include "network_monitor.h"

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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderDownloaderImpl"};
constexpr int32_t MIN_URL_LENGTH = 10;
std::atomic<uint64_t> g_downloaderIdCounter{1};
std::atomic<uint64_t> g_taskIdCounter{1};
constexpr int64_t PERCENT_MAX = 100;

std::string GetErrorMessage(int32_t errorCode)
{
    switch (errorCode) {
        case DOWNLOAD_ERROR_INVALID_OPERATION:
            return "Invalid operation";
        case DOWNLOAD_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case DOWNLOAD_ERROR_NOT_SET_URL:
            return "URL not set";
        case DOWNLOAD_ERROR_NOT_SET_PATH:
            return "Output path not set";
        case DOWNLOAD_ERROR_ALREADY_RUNNING:
            return "Already running";
        case DOWNLOAD_ERROR_CREATE_FAILED:
            return "Create failed";
        default:
            return "Unknown error";
    }
}
}

DownloaderImpl::DownloaderImpl()
    : downloaderId_(g_downloaderIdCounter.fetch_add(1)),
      taskId_(INVALID_TASK_ID),
      state_(DOWNLOAD_IDLE),
      urlSet_(false),
      pathSet_(false)
{
    MEDIA_LOGI("DownloaderImpl created, id=%{public}" PRIu64, downloaderId_);
    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress_.downloadedSize = 0;
        progress_.totalSize = -1;
        progress_.progressPercent = 0;
        progress_.downloadSpeed = 0;
    }

    messageQueue_ = std::make_unique<MessageQueue>();
}

DownloaderImpl::~DownloaderImpl()
{
    MEDIA_LOGI("DownloaderImpl destroyed, id=%{public}" PRIu64, downloaderId_);
    if (task_ != nullptr) {
        task_->Cancel();
        task_ = nullptr;
    }
    if (messageQueue_ != nullptr) {
        messageQueue_->Stop();
        messageQueue_ = nullptr;
    }
}

uint64_t DownloaderImpl::GetDownloaderId()
{
    return downloaderId_;
}

uint64_t DownloaderImpl::GetCurrentTaskId()
{
    DownloadState currentState = state_.load();
    if (currentState == DOWNLOAD_IDLE) {
        return INVALID_TASK_ID;
    }
    return taskId_;
}

int32_t DownloaderImpl::ValidateUrl(const std::string &url)
{
    if (url.empty() || url.length() < MIN_URL_LENGTH) {
        MEDIA_LOGE("Invalid URL: empty or too short");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }

    if (url.find("http://") != 0 && url.find("https://") != 0) {
        MEDIA_LOGE("Invalid URL: must start with http:// or https://");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }

    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::ValidateOutputPath(const std::string &path)
{
    if (path.empty()) {
        MEDIA_LOGE("Invalid output path: empty");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }

    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::SetUrl(const std::string &url)
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("SetUrl failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    int32_t ret = ValidateUrl(url);
    if (ret != DOWNLOAD_RET_OK) {
        return ret;
    }

    url_ = url;
    urlSet_ = true;
    MEDIA_LOGI("SetUrl success: %{public}s", url.c_str());
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::SetOutputPath(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("SetOutputPath failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    int32_t ret = ValidateOutputPath(path);
    if (ret != DOWNLOAD_RET_OK) {
        return ret;
    }

    outputPath_ = path;
    pathSet_ = true;
    MEDIA_LOGI("SetOutputPath success: %{public}s", path.c_str());
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::SetHeader(const std::map<std::string, std::string> &header)
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("SetHeader failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    header_ = header;
    MEDIA_LOGI("SetHeader success, count=%{public}zu", header.size());
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::SetConfig(const DownloadConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("SetConfig failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    config_ = config;
    MEDIA_LOGI("SetConfig success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::SetDownloadCallback(const std::shared_ptr<DownloadCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
    MEDIA_LOGI("SetDownloadCallback success");
    return DOWNLOAD_RET_OK;
}

bool DownloaderImpl::CanRelease() const
{
    DownloadState currentState = state_.load();
    return currentState == DOWNLOAD_IDLE ||
           currentState == DOWNLOAD_COMPLETED ||
           currentState == DOWNLOAD_FAILED ||
           currentState == DOWNLOAD_CANCELED;
}

bool DownloaderImpl::IsTerminalState() const
{
    DownloadState currentState = state_.load();
    return currentState == DOWNLOAD_COMPLETED ||
           currentState == DOWNLOAD_FAILED ||
           currentState == DOWNLOAD_CANCELED;
}

int32_t DownloaderImpl::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_IDLE) {
        MEDIA_LOGE("Start failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (!urlSet_) {
        MEDIA_LOGE("Start failed: URL not set");
        return DOWNLOAD_ERROR_NOT_SET_URL;
    }

    if (!pathSet_) {
        MEDIA_LOGE("Start failed: output path not set");
        return DOWNLOAD_ERROR_NOT_SET_PATH;
    }

    NetworkMonitor &networkMonitor = NetworkMonitor::GetInstance();
    NetworkType networkType = networkMonitor.GetCurrentNetworkType();
    if (config_.allowWifi && networkType == NETWORK_WIFI) {
        MEDIA_LOGI("Start allowed: WiFi network");
    } else if (config_.allowMobileData && networkType == NETWORK_MOBILE_DATA) {
        MEDIA_LOGI("Start allowed: Mobile data network");
    } else if (networkType == NETWORK_NONE || networkType == NETWORK_UNKNOWN) {
        MEDIA_LOGE("Start failed: no network available");
        return DOWNLOAD_ERROR_NETWORK;
    } else {
        MEDIA_LOGE("Start failed: network type %{public}d not allowed", networkType);
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }

    return InnerStart();
}

int32_t DownloaderImpl::InnerStart()
{
    taskId_ = g_taskIdCounter.fetch_add(1);
    state_.store(DOWNLOAD_PREPARING);

    NotifyStateChanged(DOWNLOAD_PREPARING);

    auto weakThis = std::weak_ptr<DownloaderImpl>(shared_from_this());
    messageQueue_->Start([weakThis](const Message &msg) {
        auto strongThis = weakThis.lock();
        if (!strongThis) {
            return;
        }
        auto cb = strongThis->callback_.lock();
        if (cb == nullptr) {
            return;
        }
        switch (msg.type) {
            case MSG_STATE_CHANGED:
                cb->OnStateChanged(msg.state);
                break;
            case MSG_COMPLETED:
                cb->OnCompleted(msg.downloadedSize);
                break;
            case MSG_FAILED:
                cb->OnFailed(msg.errorType, msg.errorCode, msg.errorMsg);
                break;
            case MSG_PROGRESS:
                cb->OnProgress(msg.progress);
                break;
        }
    });

    DownloadTaskInfo info = {taskId_, url_, outputPath_, header_};
    task_ = std::make_shared<DownloadTask>(info, config_, shared_from_this());

    int32_t ret = task_->Start();
    if (ret != DOWNLOAD_RET_OK) {
        state_.store(DOWNLOAD_FAILED);
        NotifyStateChanged(DOWNLOAD_FAILED);
        NotifyFailed(DOWNLOAD_ERROR_INTERNAL, ret, GetErrorMessage(ret));
        task_ = nullptr;
        return ret;
    }

    MEDIA_LOGI("Start success, taskId=%{public}" PRIu64, taskId_);
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_RUNNING) {
        MEDIA_LOGE("Pause failed: state=%{public}d, expected RUNNING", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (task_ == nullptr) {
        MEDIA_LOGE("Pause failed: task is null");
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    int32_t ret = task_->Pause();
    if (ret != DOWNLOAD_RET_OK) {
        return ret;
    }

    state_.store(DOWNLOAD_PAUSED);
    NotifyStateChanged(DOWNLOAD_PAUSED);

    MEDIA_LOGI("Pause success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_PAUSED) {
        MEDIA_LOGE("Resume failed: state=%{public}d, expected PAUSED", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (task_ == nullptr) {
        MEDIA_LOGE("Resume failed: task is null");
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    state_.store(DOWNLOAD_PREPARING);
    NotifyStateChanged(DOWNLOAD_PREPARING);

    int32_t ret = task_->Resume();
    if (ret != DOWNLOAD_RET_OK) {
        state_.store(DOWNLOAD_FAILED);
        NotifyStateChanged(DOWNLOAD_FAILED);
        NotifyFailed(DOWNLOAD_ERROR_INTERNAL, ret, GetErrorMessage(ret));
        return ret;
    }

    MEDIA_LOGI("Resume success, taskId=%{public}" PRIu64, taskId_);
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Cancel()
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_PREPARING &&
        currentState != DOWNLOAD_RUNNING &&
        currentState != DOWNLOAD_PAUSED) {
        MEDIA_LOGE("Cancel failed: state=%{public}d", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (task_ == nullptr) {
        MEDIA_LOGE("Cancel failed: task is null");
        state_.store(DOWNLOAD_CANCELED);
        NotifyStateChanged(DOWNLOAD_CANCELED);
        return DOWNLOAD_RET_OK;
    }

    (void)task_->Cancel();
    task_ = nullptr;

    state_.store(DOWNLOAD_CANCELED);
    NotifyStateChanged(DOWNLOAD_CANCELED);

    MEDIA_LOGI("Cancel success");
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!CanRelease()) {
        MEDIA_LOGE("Release failed: state=%{public}d, cannot release in this state", state_.load());
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (task_ != nullptr) {
        task_->Cancel();
        task_ = nullptr;
    }

    if (messageQueue_ != nullptr) {
        messageQueue_->Stop();
    }

    url_.clear();
    outputPath_.clear();
    header_.clear();
    urlSet_ = false;
    pathSet_ = false;
    taskId_ = INVALID_TASK_ID;
    state_.store(DOWNLOAD_IDLE);

    MEDIA_LOGI("Release success");
    return DOWNLOAD_RET_OK;
}

DownloadState DownloaderImpl::GetState()
{
    return state_.load();
}

int32_t DownloaderImpl::GetProgress(DownloadProgress &progress)
{
    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_RUNNING &&
        currentState != DOWNLOAD_PAUSED &&
        currentState != DOWNLOAD_COMPLETED) {
        MEDIA_LOGE("GetProgress failed: state=%{public}d", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress = progress_;
    }

    return DOWNLOAD_RET_OK;
}

void DownloaderImpl::NotifyStateChanged(DownloadState state)
{
    Message msg;
    msg.type = MSG_STATE_CHANGED;
    msg.state = state;

    if (messageQueue_ != nullptr) {
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::NotifyCompleted(int64_t downloadedSize)
{
    Message msg;
    msg.type = MSG_COMPLETED;
    msg.downloadedSize = downloadedSize;

    if (messageQueue_ != nullptr) {
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::NotifyFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    Message msg;
    msg.type = MSG_FAILED;
    msg.errorType = errorType;
    msg.errorCode = errorCode;
    msg.errorMsg = errorMsg;

    if (messageQueue_ != nullptr) {
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::NotifyProgress(const DownloadProgress &progress)
{
    Message msg;
    msg.type = MSG_PROGRESS;
    msg.progress = progress;

    if (messageQueue_ != nullptr) {
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::OnStateChanged(DownloadState state)
{
    state_.store(state);
    NotifyStateChanged(state);
}

void DownloaderImpl::OnCompleted(int64_t downloadedSize)
{
    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress_.downloadedSize = downloadedSize;
        if (progress_.totalSize > 0) {
            progress_.progressPercent = static_cast<int32_t>(downloadedSize * PERCENT_MAX / progress_.totalSize);
        }
    }
    NotifyCompleted(downloadedSize);
}

void DownloaderImpl::OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    NotifyFailed(errorType, errorCode, errorMsg);
}

void DownloaderImpl::OnProgress(const DownloadProgress &progress)
{
    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress_ = progress;
    }
    NotifyProgress(progress);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS