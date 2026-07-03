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
constexpr std::array<int32_t, 5> HTTP_NETWORK_ERROR_CODES = {6, 7, 35, 55, 56};
constexpr auto IsNetworkErrorCode = [](int32_t code) {
    for (auto it : HTTP_NETWORK_ERROR_CODES) {
        if (it == code) return true;
    }
    return false;
};
std::atomic<uint64_t> g_downloaderIdCounter{1};
std::atomic<uint64_t> g_taskIdCounter{1};

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
      pathSet_(false),
      messageQueueStarted_(false),
      schedulerRunning_(false),
      totalTaskCount_(0),
      completedTaskCount_(0)
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
    schedulerQueue_ = std::make_unique<MessageQueue>();     // 任务调度队列
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
    if (schedulerRunning_.load()) {
        schedulerRunning_.store(false);
        if (schedulerThread_.joinable()) {
            schedulerThread_.join();
        }
    }
    if (schedulerQueue_ != nullptr) {
        schedulerQueue_->Stop();
        schedulerQueue_ = nullptr;
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

// 用于添加单个任务，加入任务队列
int32_t DownloaderImpl::AddFileTask(const std::string &url, const std::string &path, const DownloadConfig &config)
{
    int32_t ret = ValidateUrl(url);
    if (ret != DOWNLOAD_RET_OK) {
        MEDIA_LOGE("AddFileTask failed: invalid url");
        return ret;
    }

    ret = ValidateOutputPath(path);
    if (ret != DOWNLOAD_RET_OK) {
        MEDIA_LOGE("AddFileTask failed: invalid path");
        return ret;
    }

    QueuedTaskInfo taskInfo;
    taskInfo.url = url;
    taskInfo.outputPath = path;
    taskInfo.config = config;

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        taskQueue_.push(taskInfo);
        totalTaskCount_++;
        MEDIA_LOGD("AddFileTask: url=%{public}s, path=%{public}s, queueSize=%{public}zu, totalTaskCount=%{public}d",
            url.c_str(), path.c_str(), taskQueue_.size(), totalTaskCount_);
    }
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
    if (currentState == DOWNLOAD_IDLE) {
        return true;
    }
    if (currentState == DOWNLOAD_COMPLETED ||
        currentState == DOWNLOAD_FAILED ||
        currentState == DOWNLOAD_CANCELED) {
        return true;
    }
    if (currentState == DOWNLOAD_PAUSED) {
        return true;
    }
    return false;
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
    if (currentState != DOWNLOAD_IDLE && currentState != DOWNLOAD_COMPLETED) {
        MEDIA_LOGE("Start failed: state=%{public}d, expected IDLE", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    // 获取当前网络类型
    auto networkType = MediaSourceUtils::NetworkUtils::GetInstance().GetCurrentNetworkType();
    if (!IsNetworkAllowDownload(networkType)) {    // 当前网络不允许下载
        MEDIA_LOGE("Start failed: network not available");
        return DOWNLOAD_ERROR_NETWORK;
    }

    StartMessageQueue();
    StartSchedulerQueue();
    return ProcessNextTaskInQueue();        // 进行任务调度
}

int32_t DownloaderImpl::InnerStart()
{
    taskId_ = g_taskIdCounter.fetch_add(1);

    DownloadTaskInfo info = {taskId_, url_, outputPath_, header_};
    task_ = std::make_shared<DownloadTask>(info, config_, shared_from_this());

    int32_t ret = task_->Start();
    state_.store(DOWNLOAD_RUNNING);
    if (ret != DOWNLOAD_RET_OK) {
        state_.store(DOWNLOAD_FAILED);
        NotifyFailed(DOWNLOAD_ERROR_INTERNAL, ret, GetErrorMessage(ret));
        task_ = nullptr;
        return ret;
    }

    MEDIA_LOGI("Start success, taskId=%{public}" PRIu64, taskId_);
    return DOWNLOAD_RET_OK;
}

void DownloaderImpl::StartMessageQueue()
{
    MEDIA_LOGI("StartMessageQueue");
    if (messageQueueStarted_) {
        return;
    }
    messageQueueStarted_ = true;
    auto weakThis = std::weak_ptr<DownloaderImpl>(shared_from_this());
    messageQueue_->Start([weakThis](const Message &msg) {
        MEDIA_LOGI("Handle message, type=%{public}d", msg.type);
        auto strongThis = weakThis.lock();
        if (!strongThis) {
            MEDIA_LOGI("StartMessageQueue, strongThis null");
            return;
        }
        auto cb = strongThis->callback_.lock();
        if (cb == nullptr) {
            MEDIA_LOGI("StartMessageQueue, callback_ null");
            return;
        }
        MEDIA_LOGI("Message report, type=%{public}d", msg.type);
        switch (msg.type) {
            case MSG_STATE_CHANGED:
                cb->OnStateChanged(strongThis->downloaderId_, msg.state);
                break;
            case MSG_COMPLETED:     // 队列中的COMPLETED消息，通知上层
                cb->OnCompleted(strongThis->downloaderId_, msg.downloadedSize);
                break;
            case MSG_FAILED:
                cb->OnFailed(strongThis->downloaderId_, msg.errorType, msg.errorCode, msg.errorMsg);
                break;
            case MSG_PROGRESS:
                cb->OnProgress(strongThis->downloaderId_, msg.progress);
                break;
            default:
                break;
        }
    });
    MEDIA_LOGI("StartMessageQueue end");
}

void DownloaderImpl::StartSchedulerQueue()
{
    if (schedulerRunning_.load()) {
        return;
    }
    schedulerRunning_.store(true);
    auto weakThis = std::weak_ptr<DownloaderImpl>(shared_from_this());
    schedulerQueue_->Start([weakThis](const Message &msg) {
        auto strongThis = weakThis.lock();
        if (!strongThis) {
            return;
        }
        switch (msg.type) {
            case MSG_TASK_COMPLETED:     // 文件Completed，继续调度
                strongThis->HandleTaskCompleted();
                break;
            case MSG_TASK_FAILED:
                strongThis->HandleTaskFailed(msg.errorType, msg.errorCode, msg.errorMsg);
                break;
            case MSG_TASK_NET_CHANGE:       // 网络切换问题
                strongThis->HandleTaskNetChanged();
                break;
            case MSG_TASK_CANCELED:
                strongThis->HandleTaskCanceled();
                break;
            default:
                break;
        }
    });
}

int32_t DownloaderImpl::ProcessNextTaskInQueue()
{
    std::lock_guard<std::mutex> lockQueue(queueMutex_);
    if (taskQueue_.empty()) {
        MEDIA_LOGI("ProcessNextTaskInQueue: queue is empty");
        return DOWNLOAD_RET_OK;
    }

    QueuedTaskInfo taskInfo = taskQueue_.front();
    taskQueue_.pop();

    url_ = taskInfo.url;
    outputPath_ = taskInfo.outputPath;
    header_ = taskInfo.header;
    config_ = taskInfo.config;
    urlSet_ = true;
    pathSet_ = true;

    MEDIA_LOGI("ProcessNextTaskInQueue: starting task, remaining=%{public}zu", taskQueue_.size());

    state_.store(DOWNLOAD_PREPARING);

    auto networkType = MediaSourceUtils::NetworkUtils::GetInstance().GetCurrentNetworkType();
    if (!IsNetworkAllowDownload(networkType)) {    // 当前网络不允许下载
        MEDIA_LOGE("ProcessNextTaskInQueue failed: network not available");
        return DOWNLOAD_ERROR_NETWORK;
    }

    return InnerStart();
}

int32_t DownloaderImpl::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);

    DownloadState currentState = state_.load();
    if (currentState != DOWNLOAD_RUNNING) {
        MEDIA_LOGE("Pause failed: state=%{public}d, expected RUNNING", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    if (task_ != nullptr) {
        int32_t ret = task_->Pause();
        if (ret != DOWNLOAD_RET_OK) {
            return ret;
        }
    }

    state_.store(DOWNLOAD_PAUSED);
    schedulerRunning_.store(false);
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

    if (task_ != nullptr) {     // 当前有task
        int32_t ret = task_->Resume();  // 恢复
        if (ret != DOWNLOAD_RET_OK) {   // 恢复失败
            state_.store(DOWNLOAD_FAILED);
            NotifyFailed(DOWNLOAD_ERROR_INTERNAL, ret, GetErrorMessage(ret));
            return ret;
        }
        state_.store(DOWNLOAD_RUNNING);     // 恢复成功
        schedulerRunning_.store(true);
        NotifyStateChanged(DOWNLOAD_RUNNING);
    } else {        // 当前无task
        schedulerRunning_.store(true);
        bool hasNextTask = false;
        {
            std::lock_guard<std::mutex> lockQueue(queueMutex_);
            hasNextTask = !taskQueue_.empty();
        }
        if (hasNextTask) {
            state_.store(DOWNLOAD_PREPARING);
            ProcessNextTaskInQueue();
        } else {    // 无task了
            state_.store(DOWNLOAD_COMPLETED);
            NotifyCompleted(progress_.downloadedSize);
        }
    }

    MEDIA_LOGI("Resume success, taskId=%{public}" PRIu64, taskId_);
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Cancel()
{
    MEDIA_LOGI("DownloaderImpl::Cancel enter");

    {
        std::lock_guard<std::mutex> lock(mutex_);
        DownloadState currentState = state_.load();
        if (currentState != DOWNLOAD_PREPARING &&
            currentState != DOWNLOAD_RUNNING &&
            currentState != DOWNLOAD_PAUSED) {
            MEDIA_LOGE("Cancel failed: state=%{public}d", currentState);
            return DOWNLOAD_ERROR_INVALID_OPERATION;
        }

        if (task_ != nullptr) {
            (void)task_->Cancel();
            pendingTaskToRelease_ = task_;
            task_ = nullptr;
        }

        state_.store(DOWNLOAD_CANCELED);
    }

    {
        std::lock_guard<std::mutex> lockQueue(queueMutex_);
        while (!taskQueue_.empty()) {
            taskQueue_.pop();
        }
    }

    if (schedulerQueue_ != nullptr) {
        Message msg;
        msg.type = MSG_TASK_CANCELED;
        schedulerQueue_->PostMessage(msg);
    }

    MEDIA_LOGI("DownloaderImpl::Cancel done");
    return DOWNLOAD_RET_OK;
}

int32_t DownloaderImpl::Release()
{
    MEDIA_LOGI("DownloaderImpl::Release enter");
    if (messageQueue_ != nullptr) {
        messageQueue_->Stop();
        messageQueue_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (task_ != nullptr) {
            task_->Cancel();
            pendingTaskToRelease_ = task_;
            task_ = nullptr;
        }
    }

    std::shared_ptr<DownloadTask> taskToRelease;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskToRelease = pendingTaskToRelease_;
        pendingTaskToRelease_ = nullptr;
    }
    taskToRelease = nullptr;

    if (schedulerRunning_.load()) {
        schedulerRunning_.store(false);
        if (schedulerThread_.joinable()) {
            schedulerThread_.join();
        }
    }
    if (schedulerQueue_ != nullptr) {
        schedulerQueue_->Stop();
        schedulerQueue_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> lockQueue(queueMutex_);
        while (!taskQueue_.empty()) {
            taskQueue_.pop();
        }
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
        currentState != DOWNLOAD_COMPLETED &&
        currentState != DOWNLOAD_PREPARING) {
        MEDIA_LOGE("GetProgress failed: state=%{public}d", currentState);
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }

    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress = progress_;
    }

    return DOWNLOAD_RET_OK;
}

std::string DownloaderImpl::GetCurrentFilePath() const      // 获取当前下载的fileTask路径
{
    std::lock_guard<std::mutex> lock(mutex_);
    return outputPath_;
}

void DownloaderImpl::NotifyStateChanged(DownloadState state)
{
    Message msg;
    msg.type = MSG_STATE_CHANGED;
    msg.state = state;

    if (messageQueue_ != nullptr) {
        MEDIA_LOGI("NotifyStateChanged: called: %{public}d", msg.type);
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::NotifyCompleted(int64_t downloadedSize)
{
    Message msg;
    msg.type = MSG_COMPLETED;       // complete消息入队
    msg.downloadedSize = downloadedSize;

    if (messageQueue_ != nullptr) {
        MEDIA_LOGI("NotifyCompleted: called: %{public}d", msg.type);
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
        MEDIA_LOGI("NotifyFailed: called: %{public}d", msg.type);
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::NotifyProgress(const DownloadProgress &progress)
{
    Message msg;
    msg.type = MSG_PROGRESS;
    msg.progress = progress;

    if (messageQueue_ != nullptr) {
        MEDIA_LOGI("NotifyProgress: called: %{public}d", msg.type);
        messageQueue_->PostMessage(msg);
    }
}

void DownloaderImpl::OnStateChanged(DownloadState state)
{
    state_.store(state);
    if (state == DOWNLOAD_RUNNING || state == DOWNLOAD_PAUSED || state == DOWNLOAD_CANCELED) {
        NotifyStateChanged(state);
    }
}

void DownloaderImpl::OnCompleted(int64_t downloadedSize)
{
    MEDIA_LOGI("OnCompleted: called");
    DownloadProgress currentProgress = task_->GetProgress();

    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress_.downloadedSize += downloadedSize;
        progress_.totalSize += currentProgress.totalSize;
    }

    MEDIA_LOGI("OnCompleted: start new task");

    { // 单个文件下载完成后自动调度后续下载
        std::lock_guard<std::mutex> lock(mutex_);
        pendingTaskToRelease_ = task_;
        task_ = nullptr;
        MEDIA_LOGI("OnCompleted: find new task");
    }

    if (schedulerQueue_ != nullptr) {
        Message msg;
        msg.type = MSG_TASK_COMPLETED; // 单个文件完成，继续调度入队
        schedulerQueue_->PostMessage(msg);
    }
    MEDIA_LOGI("DownloaderImpl::OnCompleted done");
}

void DownloaderImpl::OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGI("DownloaderImpl::OnFailed enter");
    if (IsNetworkErrorCode(errorCode)) {    // 网络切换
        Message msg;
        msg.type = MSG_TASK_NET_CHANGE;
        msg.errorType = errorType;
        msg.errorCode = errorCode;
        msg.errorMsg = errorMsg;
        schedulerQueue_->PostMessage(msg);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pendingTaskToRelease_ = task_;
        task_ = nullptr;
    }

    if (schedulerQueue_ != nullptr) {
        Message msg;
        msg.type = MSG_TASK_FAILED;
        msg.errorType = errorType;
        msg.errorCode = errorCode;
        msg.errorMsg = errorMsg;
        schedulerQueue_->PostMessage(msg);
    }

    MEDIA_LOGI("DownloaderImpl::OnFailed done");
}

void DownloaderImpl::OnProgress(const DownloadProgress &progress)
{
    DownloadProgress tempProgress;
    {
        std::lock_guard<std::mutex> lock(progressMutex_);
        progress_.downloadSpeed = progress.downloadSpeed;
        if (totalTaskCount_ > 0) {
            progress_.progressPercent = (completedTaskCount_ * 100 + progress.progressPercent) / totalTaskCount_;
        } else {        // 单个文件，直接取回调上来的信息
            progress_ = progress;
        }
        tempProgress.totalSize = progress_.totalSize;
        tempProgress.downloadSpeed = progress_.downloadSpeed;
        tempProgress.progressPercent = progress_.progressPercent;
        tempProgress.downloadedSize = progress_.downloadedSize + progress.downloadedSize;
    }
    NotifyProgress(tempProgress);
}

void DownloaderImpl::HandleTaskCompleted()
{
    MEDIA_LOGI("HandleTaskCompleted enter: %{public}" PRIu64, downloaderId_);

    completedTaskCount_++;
    pendingTaskToRelease_ = nullptr;

    bool hasNextTask = false;
    {
        std::lock_guard<std::mutex> lockQueue(queueMutex_);
        hasNextTask = !taskQueue_.empty();
    }

    if (hasNextTask) {
        state_.store(DOWNLOAD_PREPARING);
        MEDIA_LOGI("HandleTaskCompleted: starting next task");
        ProcessNextTaskInQueue();
    } else {
        state_.store(DOWNLOAD_COMPLETED);
        NotifyCompleted(progress_.downloadedSize);
        MEDIA_LOGI("HandleTaskCompleted: all tasks finished");
    }

    MEDIA_LOGI("HandleTaskCompleted done");
}

void DownloaderImpl::HandleTaskFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGI("HandleTaskFailed enter");
    pendingTaskToRelease_ = nullptr;

    {
        std::lock_guard<std::mutex> lockQueue(queueMutex_);
        while (!taskQueue_.empty()) {
            taskQueue_.pop();
        }
    }

    state_.store(DOWNLOAD_FAILED);
    NotifyFailed(errorType, errorCode, errorMsg);
    MEDIA_LOGI("HandleTaskFailed done");
}

void DownloaderImpl::HandleTaskCanceled()
{
    MEDIA_LOGI("HandleTaskCanceled enter");
    pendingTaskToRelease_ = nullptr;

    NotifyStateChanged(DOWNLOAD_CANCELED);
    MEDIA_LOGI("HandleTaskCanceled done");
}

void DownloaderImpl::HandleTaskNetChanged()     // 网络切换，暂停
{
    MEDIA_LOGI("HandleTaskNetChanged: enter");
    state_.store(DOWNLOAD_PAUSED);
    auto networkType = MediaSourceUtils::NetworkUtils::GetInstance().GetCurrentNetworkType();
    if (!IsNetworkAllowDownload(networkType)) {    // 当前网络不允许下载
        MEDIA_LOGE("HandleTaskNetChanged: network not available");
        schedulerRunning_.store(false);
        NotifyStateChanged(DOWNLOAD_PAUSED);
    } else {
        Resume();
    }
}

// 检查网络配置是否允许下载
bool DownloaderImpl::IsNetworkAllowDownload(MediaSourceUtils::NetConnType newType)
{
    MEDIA_LOGI("IsNetworkAllowDownload: network type: %{public}d", newType);
    if (newType == MediaSourceUtils::NetConnType::NET_CONN_NONE
        || newType == MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN) {
        MEDIA_LOGE("no network available");
        return false;
    }

    if (config_.allowWifi && newType == MediaSourceUtils::NetConnType::NET_CONN_WIFI) {
        MEDIA_LOGI("Start allowed: WiFi network");
        return true;
    }
    if (config_.allowMobileData && newType == MediaSourceUtils::NetConnType::NET_CONN_CELLULAR) {
        MEDIA_LOGI("Start allowed: Mobile data network");
        return true;
    }

    MEDIA_LOGE("IsNetworkAllowDownload: network type %{public}d not allowed", newType);
    return false;
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS