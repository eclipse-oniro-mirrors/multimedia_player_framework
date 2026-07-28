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

#include "avdownloader_taihe.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_taihe_utils.h"
#include "media_source.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVDownloaderTaihe"};
}

namespace ANI::Media {

// ===== AVDownloaderManagerImpl implementation =====

AVDownloaderManagerImpl::AVDownloaderManagerImpl()
{
    downloaderManager_ = OHOS::Media::AVDownloaderManagerFactory::Create();
    if (downloaderManager_ == nullptr) {
        MEDIA_LOGE("failed to CreateAVDownloaderManager");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateAVDownloaderManager");
        return;
    }

    downloaderCb_ = std::make_shared<AVDownloaderCallback>();
    if (downloaderCb_ == nullptr) {
        MEDIA_LOGE("failed to CreateAVDownloaderCallback");
        // Release the manager since early return prevents further initialization
        downloaderManager_->Release();
        downloaderManager_ = nullptr;
        MediaTaiheUtils::ThrowExceptionError("failed to CreateAVDownloaderCallback");
        return;
    }

    downloaderManager_->SetManagerCallback(downloaderCb_);
    MEDIA_LOGI("AVDownloaderManagerImpl Constructor success");
}

void AVDownloaderManagerImpl::AllowsCellularAccess(bool value)
{
    MEDIA_LOGI("AllowsCellularAccess In, value: %{public}d", value);
    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        allowCellularAccess_ = value;
        manager = downloaderManager_;
    }
    if (manager) {
        manager->SetAllowCellularAccess(value);
    }
}

void AVDownloaderManagerImpl::SetRequestTimeout(int32_t expired)
{
    MEDIA_LOGI("SetRequestTimeout In, expired: %{public}d", expired);
    if (expired < 0) {
        set_business_error(ERR_PARAM_OUT_OF_RANGE, "Invalid parameter: timeout must be non-negative");
        return;
    }
    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        requestTimeoutMs_ = expired;
        manager = downloaderManager_;
    }
    if (manager) {
        manager->SetRequestTimeout(expired);
    }
}

string AVDownloaderManagerImpl::AddAVDownloadTask(ohos::multimedia::media::weak::MediaSource source)
{
    MEDIA_LOGI("AddAVDownloadTask In");

    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        manager = downloaderManager_;
    }
    if (manager == nullptr) {
        set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return string("");
    }

    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceImpl::GetMediaSource(source);
    if (srcTmp == nullptr) {
        set_business_error(ERR_OPERATION_NOT_PERMIT, "Invalid parameter: media source is null");
        return string("");
    }

    auto pluginSource = std::make_shared<OHOS::Media::Plugins::MediaSource>(srcTmp->url, srcTmp->header);
    std::string taskId = manager->AddDownloadTask(pluginSource);
    if (taskId.empty()) {
        set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: failed to add download task");
        return string("");
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskIdToUrl_[taskId] = srcTmp->url;
    }
    MEDIA_LOGI("AddAVDownloadTask Out, taskId: %{public}s", taskId.c_str());
    return MediaTaiheUtils::ToTaiheString(taskId);
}

std::shared_ptr<OHOS::Media::AVDownloaderManager> AVDownloaderManagerImpl::GetManagerLocked()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return downloaderManager_;
}

bool AVDownloaderManagerImpl::TaskIdExistsLocked(const std::string &taskIdStr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return taskIdToUrl_.find(taskIdStr) != taskIdToUrl_.end();
}

void AVDownloaderManagerImpl::RemoveTaskStateLocked(const std::string &taskIdStr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    taskIdToUrl_.erase(taskIdStr);
    taskIdToCacheDir_.erase(taskIdStr);
    taskIdToStatus_.erase(taskIdStr);
    taskIdToProgress_.erase(taskIdStr);
}

void AVDownloaderManagerImpl::ClearAllTaskStateLocked()
{
    std::lock_guard<std::mutex> lock(mutex_);
    taskIdToUrl_.clear();
    taskIdToCacheDir_.clear();
    taskIdToStatus_.clear();
    taskIdToProgress_.clear();
}

void AVDownloaderManagerImpl::ApplyToAllTasks(const char *actionName,
    const std::shared_ptr<OHOS::Media::AVDownloaderManager> &manager,
    std::function<int32_t(const std::shared_ptr<OHOS::Media::AVDownloaderManager>&, const std::string &)> action)
{
    bool hasError = false;
    for (const auto &id : manager->GetDownloadTasks()) {
        if (action(manager, id) != 0) {
            MEDIA_LOGE("%{public}s failed for task: %{public}s", actionName, id.c_str());
            hasError = true;
        }
    }
    if (hasError) {
        set_business_error(ERR_OPERATION_NOT_PERMIT,
            std::string("Operation not allowed: some tasks failed to ") + actionName);
    }
}

void AVDownloaderManagerImpl::RemoveDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("RemoveDownloadTask In");

    if (taskId.has_value()) {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        std::string taskIdStr(taskId.value());
        if (!TaskIdExistsLocked(taskIdStr)) {
            set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        if (manager->RemoveDownloadTask(taskIdStr) != 0) {
            set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: remove task failed");
            return;
        }
        RemoveTaskStateLocked(taskIdStr);
    } else {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        ApplyToAllTasks("remove", manager,
            [](const std::shared_ptr<OHOS::Media::AVDownloaderManager> &mgr, const std::string &id) {
                return mgr->RemoveDownloadTask(id);
            });
        ClearAllTaskStateLocked();
    }
}

void AVDownloaderManagerImpl::PauseDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("PauseDownloadTask In");

    if (taskId.has_value()) {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        std::string taskIdStr(taskId.value());
        if (!TaskIdExistsLocked(taskIdStr)) {
            set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        if (manager->PauseDownloadTask(taskIdStr) != 0) {
            set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: pause failed");
        }
    } else {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        ApplyToAllTasks("pause", manager,
            [](const std::shared_ptr<OHOS::Media::AVDownloaderManager> &mgr, const std::string &id) {
                return mgr->PauseDownloadTask(id);
            });
    }
}

void AVDownloaderManagerImpl::ResumeDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("ResumeDownloadTask In");

    if (taskId.has_value()) {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        std::string taskIdStr(taskId.value());
        if (!TaskIdExistsLocked(taskIdStr)) {
            set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        if (manager->ResumeDownloadTask(taskIdStr) != 0) {
            set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: resume failed");
        }
    } else {
        auto manager = GetManagerLocked();
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return;
        }
        ApplyToAllTasks("resume", manager,
            [](const std::shared_ptr<OHOS::Media::AVDownloaderManager> &mgr, const std::string &id) {
                return mgr->ResumeDownloadTask(id);
            });
    }
}

array<string> AVDownloaderManagerImpl::GetDownloadTasks()
{
    MEDIA_LOGI("GetDownloadTasks In");

    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        manager = downloaderManager_;
    }
    if (manager == nullptr) {
        set_business_error(ERR_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        std::vector<string> empty;
        return array<string>(copy_data_t{}, empty.data(), empty.size());
    }

    std::vector<std::string> taskIds = manager->GetDownloadTasks();
    std::vector<string> result;
    result.reserve(taskIds.size());
    for (const auto &id : taskIds) {
        result.push_back(MediaTaiheUtils::ToTaiheString(id));
    }
    return array<string>(copy_data_t{}, result.data(), result.size());
}

string AVDownloaderManagerImpl::GetTaskCacheDirectory(string_view taskId)
{
    MEDIA_LOGI("GetTaskCacheDirectory In, taskId: %{public}s", std::string(taskId).c_str());

    std::string taskIdStr(taskId);
    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        manager = downloaderManager_;
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return string("");
        }
        if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
            set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
            return string("");
        }
    }

    std::string cacheDir = manager->GetTaskCacheDirectory(taskIdStr);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cacheDir.empty()) {
            auto it = taskIdToCacheDir_.find(taskIdStr);
            if (it != taskIdToCacheDir_.end()) {
                cacheDir = it->second;
            }
        } else {
            taskIdToCacheDir_[taskIdStr] = cacheDir;
        }
    }
    return MediaTaiheUtils::ToTaiheString(cacheDir);
}

string AVDownloaderManagerImpl::GetTaskStatus(string_view taskId)
{
    MEDIA_LOGI("GetTaskStatus In, taskId: %{public}s", std::string(taskId).c_str());

    auto manager = GetManagerLocked();
    if (manager == nullptr) {
        set_business_error(ERR_OPERATION_NOT_PERMIT,
            "Operation not allowed: downloader manager not available");
        return MediaTaiheUtils::ToTaiheString(std::string("error"));
    }
    std::string taskIdStr(taskId);
    if (!TaskIdExistsLocked(taskIdStr)) {
        set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
        return MediaTaiheUtils::ToTaiheString(std::string("error"));
    }

    OHOS::Media::AVDownloadTaskState state = manager->GetTaskStatus(taskIdStr);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskIdToStatus_[taskIdStr] = static_cast<int32_t>(state);
    }
    return MediaTaiheUtils::ToTaiheString(AVDownloadTaskStateToString(state));
}

double AVDownloaderManagerImpl::GetTaskProgress(string_view taskId)
{
    MEDIA_LOGI("GetTaskProgress In, taskId: %{public}s", std::string(taskId).c_str());

    std::string taskIdStr(taskId);
    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        manager = downloaderManager_;
        if (manager == nullptr) {
            set_business_error(ERR_OPERATION_NOT_PERMIT,
                "Operation not allowed: downloader manager not available");
            return -1.0;
        }
        if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
            set_business_error(ERR_PARAM_OUT_OF_RANGE, "Task ID not found");
            return -1.0;
        }
    }

    double progress = manager->GetTaskProgress(taskIdStr);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskIdToProgress_[taskIdStr] = progress;
    }
    return progress;
}

// ===== Event On/Off methods =====

void AVDownloaderManagerImpl::OnStatusChange(callback_view<void(string_view, string_view)> callback)
{
    MEDIA_LOGI("OnStatusChange In");

    ani_env *env = get_env();
    if (env == nullptr) {
        MEDIA_LOGE("OnStatusChange: get_env() returned nullptr");
        return;
    }
    std::shared_ptr<taihe::callback<void(string_view, string_view)>>
        taiheCallback = std::make_shared<taihe::callback<void(string_view, string_view)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVDownloaderEvent::EVENT_STATUS_CHANGE, autoRef);
    MEDIA_LOGI("OnStatusChange End");
}

void AVDownloaderManagerImpl::OnProgressChange(callback_view<void(string_view, double)> callback)
{
    MEDIA_LOGI("OnProgressChange In");

    ani_env *env = get_env();
    if (env == nullptr) {
        MEDIA_LOGE("OnProgressChange: get_env() returned nullptr");
        return;
    }
    std::shared_ptr<taihe::callback<void(string_view, double)>> taiheCallback =
        std::make_shared<taihe::callback<void(string_view, double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SaveCallbackReference(AVDownloaderEvent::EVENT_PROGRESS_CHANGE, autoRef);
    MEDIA_LOGI("OnProgressChange End");
}

void AVDownloaderManagerImpl::OffStatusChange(
    optional_view<callback<void(string_view, string_view)>> callback)
{
    MEDIA_LOGI("OffStatusChange In");
    ClearCallbackReference(AVDownloaderEvent::EVENT_STATUS_CHANGE);
    MEDIA_LOGI("OffStatusChange End");
}

void AVDownloaderManagerImpl::OffProgressChange(
    optional_view<callback<void(string_view, double)>> callback)
{
    MEDIA_LOGI("OffProgressChange In");
    ClearCallbackReference(AVDownloaderEvent::EVENT_PROGRESS_CHANGE);
    MEDIA_LOGI("OffProgressChange End");
}

// ===== Release methods =====

void AVDownloaderManagerImpl::Release()
{
    MEDIA_LOGI("ReleaseSync In");

    std::shared_ptr<OHOS::Media::AVDownloaderManager> manager;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (downloaderManager_ == nullptr) {
            return; // already released
        }
        manager = downloaderManager_;
        // Clear all local state under lock regardless of Release result
        downloaderManager_ = nullptr;
        downloaderCb_ = nullptr;
        taskIdToUrl_.clear();
        taskIdToCacheDir_.clear();
        taskIdToStatus_.clear();
        taskIdToProgress_.clear();
        refMap_.clear();
    }
    // Release the manager outside the lock to avoid holding lock during IPC
    int32_t ret = manager->Release();
    if (ret != 0) {
        MEDIA_LOGE("Release failed with ret=%{public}d", ret);
    }

    MEDIA_LOGI("ReleaseSync Out");
}

// ===== Callback reference management =====

void AVDownloaderManagerImpl::SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::shared_ptr<AVDownloaderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        refMap_[callbackName] = ref;
        cb = downloaderCb_;
    }
    if (cb) {
        cb->SaveCallbackReference(callbackName, ref);
    }
}

void AVDownloaderManagerImpl::ClearCallbackReference(const std::string &callbackName)
{
    std::shared_ptr<AVDownloaderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = downloaderCb_;
        refMap_.erase(callbackName);
    }
    if (cb) {
        cb->ClearCallbackReference(callbackName);
    }
}

// ===== Factory function =====

optional<ohos::multimedia::media::AVDownloaderManager> CreateAVDownloaderManagerSync()
{
    auto res = make_holder<AVDownloaderManagerImpl, ohos::multimedia::media::AVDownloaderManager>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVDownloaderManager failed!");
        taihe::reset_error();
        return optional<ohos::multimedia::media::AVDownloaderManager>(std::nullopt);
    }
    return optional<ohos::multimedia::media::AVDownloaderManager>(std::in_place, res);
}

} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVDownloaderManagerSync(ANI::Media::CreateAVDownloaderManagerSync);
TH_EXPORT_CPP_API_CreateAVDownloaderManagerWithAsyncCallback(ANI::Media::CreateAVDownloaderManagerSync);
TH_EXPORT_CPP_API_CreateAVDownloaderManagerRetPromise(ANI::Media::CreateAVDownloaderManagerSync);