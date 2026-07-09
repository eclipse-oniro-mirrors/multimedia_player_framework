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
        MediaTaiheUtils::ThrowExceptionError("failed to CreateAVDownloaderCallback");
        return;
    }

    auto selfRef = std::shared_ptr<AVDownloaderManagerImpl>(this, [](AVDownloaderManagerImpl *) {});
    downloaderManager_->SetManagerCallback(downloaderCb_);
    MEDIA_LOGI("AVDownloaderManagerImpl Constructor success");
}

void AVDownloaderManagerImpl::AllowsCellularAccess(bool value)
{
    MEDIA_LOGI("AllowsCellularAccess In, value: %{public}d", value);
    allowCellularAccess_ = value;
    if (downloaderManager_ != nullptr) {
        downloaderManager_->SetAllowCellularAccess(value);
    }
}

void AVDownloaderManagerImpl::SetRequestTimeout(int32_t expired)
{
    MEDIA_LOGI("SetRequestTimeout In, expired: %{public}d", expired);
    requestTimeoutMs_ = expired;
    if (downloaderManager_ != nullptr) {
        downloaderManager_->SetRequestTimeout(expired);
    }
}

string AVDownloaderManagerImpl::AddAVDownloadTask(ohos::multimedia::media::weak::MediaSource source)
{
    MEDIA_LOGI("AddAVDownloadTask In");

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return string("");
    }

    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceImpl::GetMediaSource(source);
    if (srcTmp == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Invalid parameter: media source is null");
        return string("");
    }

    auto pluginSource = std::make_shared<OHOS::Media::Plugins::MediaSource>(srcTmp->url, srcTmp->header);
    std::string taskId = downloaderManager_->AddDownloadTask(pluginSource);
    if (taskId.empty()) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: failed to add download task");
        return string("");
    }

    taskIdToUrl_[taskId] = srcTmp->url;
    MEDIA_LOGI("AddAVDownloadTask Out, taskId: %{public}s", taskId.c_str());
    return MediaTaiheUtils::ToTaiheString(taskId);
}

void AVDownloaderManagerImpl::RemoveDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("RemoveDownloadTask In");

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return;
    }

    if (taskId.has_value()) {
        std::string taskIdStr(taskId.value());
        if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
            set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        downloaderManager_->RemoveDownloadTask(taskIdStr);
        taskIdToUrl_.erase(taskIdStr);
        taskIdToCacheDir_.erase(taskIdStr);
        taskIdToStatus_.erase(taskIdStr);
        taskIdToProgress_.erase(taskIdStr);
    } else {
        // Remove all tasks
        std::vector<std::string> taskIds = downloaderManager_->GetDownloadTasks();
        for (const auto &id : taskIds) {
            downloaderManager_->RemoveDownloadTask(id);
        }
        taskIdToUrl_.clear();
        taskIdToCacheDir_.clear();
        taskIdToStatus_.clear();
        taskIdToProgress_.clear();
    }
}

void AVDownloaderManagerImpl::PauseDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("PauseDownloadTask In");

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return;
    }

    if (taskId.has_value()) {
        std::string taskIdStr(taskId.value());
        if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
            set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        int32_t ret = downloaderManager_->PauseDownloadTask(taskIdStr);
        if (ret != 0) {
            set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: pause failed");
        }
    } else {
        // Pause all tasks
        std::vector<std::string> taskIds = downloaderManager_->GetDownloadTasks();
        for (const auto &id : taskIds) {
            downloaderManager_->PauseDownloadTask(id);
        }
    }
}

void AVDownloaderManagerImpl::ResumeDownloadTask(optional_view<string> taskId)
{
    MEDIA_LOGI("ResumeDownloadTask In");

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return;
    }

    if (taskId.has_value()) {
        std::string taskIdStr(taskId.value());
        if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
            set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
            return;
        }
        int32_t ret = downloaderManager_->ResumeDownloadTask(taskIdStr);
        if (ret != 0) {
            set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: resume failed");
        }
    } else {
        // Resume all tasks
        std::vector<std::string> taskIds = downloaderManager_->GetDownloadTasks();
        for (const auto &id : taskIds) {
            downloaderManager_->ResumeDownloadTask(id);
        }
    }
}

array<string> AVDownloaderManagerImpl::GetDownloadTasks()
{
    MEDIA_LOGI("GetDownloadTasks In");

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        std::vector<string> empty;
        return array<string>(copy_data_t{}, empty.data(), empty.size());
    }

    std::vector<std::string> taskIds = downloaderManager_->GetDownloadTasks();
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

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return string("");
    }

    std::string taskIdStr(taskId);
    if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
        set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
        return string("");
    }

    std::string cacheDir = downloaderManager_->GetTaskCacheDirectory(taskIdStr);
    if (cacheDir.empty()) {
        auto it = taskIdToCacheDir_.find(taskIdStr);
        if (it != taskIdToCacheDir_.end()) {
            cacheDir = it->second;
        }
    } else {
        taskIdToCacheDir_[taskIdStr] = cacheDir;
    }
    return MediaTaiheUtils::ToTaiheString(cacheDir);
}

string AVDownloaderManagerImpl::GetTaskStatus(string_view taskId)
{
    MEDIA_LOGI("GetTaskStatus In, taskId: %{public}s", std::string(taskId).c_str());

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return MediaTaiheUtils::ToTaiheString(std::string("error"));
    }

    std::string taskIdStr(taskId);
    if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
        set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
        return MediaTaiheUtils::ToTaiheString(std::string("error"));
    }

    OHOS::Media::AVDownloadTaskState state = downloaderManager_->GetTaskStatus(taskIdStr);
    taskIdToStatus_[taskIdStr] = static_cast<int32_t>(state);

    std::string stateStr;
    switch (state) {
        case OHOS::Media::AVDownloadTaskState::INIT:
            stateStr = "init";
            break;
        case OHOS::Media::AVDownloadTaskState::QUEUED:
            stateStr = "queued";
            break;
        case OHOS::Media::AVDownloadTaskState::RUNNING:
            stateStr = "running";
            break;
        case OHOS::Media::AVDownloadTaskState::COMPLETED:
            stateStr = "completed";
            break;
        case OHOS::Media::AVDownloadTaskState::PAUSED:
            stateStr = "paused";
            break;
        case OHOS::Media::AVDownloadTaskState::REMOVING:
            stateStr = "removing";
            break;
        case OHOS::Media::AVDownloadTaskState::ERROR:
        default:
            stateStr = "error";
            break;
    }
    return MediaTaiheUtils::ToTaiheString(stateStr);
}

double AVDownloaderManagerImpl::GetTaskProgress(string_view taskId)
{
    MEDIA_LOGI("GetTaskProgress In, taskId: %{public}s", std::string(taskId).c_str());

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return -1.0;
    }

    std::string taskIdStr(taskId);
    if (taskIdToUrl_.find(taskIdStr) == taskIdToUrl_.end()) {
        set_business_error(ERR_AVD_PARAM_OUT_OF_RANGE, "Task ID not found");
        return -1.0;
    }

    double progress = downloaderManager_->GetTaskProgress(taskIdStr);
    taskIdToProgress_[taskIdStr] = progress;
    return progress;
}

// ===== Event On/Off methods =====

void AVDownloaderManagerImpl::OnStatusChange(callback_view<void(string_view, string_view)> callback)
{
    MEDIA_LOGI("OnStatusChange In");

    ani_env *env = get_env();
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

    if (downloaderManager_ == nullptr) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Operation not allowed: downloader manager not available");
        return;
    }

    int32_t ret = downloaderManager_->Release();
    if (ret != 0) {
        set_business_error(ERR_AVD_OPERATION_NOT_PERMIT, "Release failed");
        return;
    }

    // Clear local state
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskIdToUrl_.clear();
        taskIdToCacheDir_.clear();
        taskIdToStatus_.clear();
        taskIdToProgress_.clear();
        refMap_.clear();
        downloaderManager_ = nullptr;
        downloaderCb_ = nullptr;
    }

    MEDIA_LOGI("ReleaseSync Out");
}

// ===== Callback reference management =====

void AVDownloaderManagerImpl::SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[callbackName] = ref;
    if (downloaderCb_ != nullptr) {
        downloaderCb_->SaveCallbackReference(callbackName, ref);
    }
}

void AVDownloaderManagerImpl::ClearCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (downloaderCb_ != nullptr) {
        downloaderCb_->ClearCallbackReference(callbackName);
    }
    refMap_.erase(callbackName);
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
