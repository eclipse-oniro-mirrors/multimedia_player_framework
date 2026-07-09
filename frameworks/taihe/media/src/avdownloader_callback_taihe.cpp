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

#include "avdownloader_callback_taihe.h"
#include "media_log.h"
#include "media_taihe_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVDownloaderCallback"};

std::string AVDownloadTaskStateToString(OHOS::Media::AVDownloadTaskState state)
{
    switch (state) {
        case OHOS::Media::AVDownloadTaskState::INIT:
            return "init";
        case OHOS::Media::AVDownloadTaskState::QUEUED:
            return "queued";
        case OHOS::Media::AVDownloadTaskState::RUNNING:
            return "running";
        case OHOS::Media::AVDownloadTaskState::COMPLETED:
            return "completed";
        case OHOS::Media::AVDownloadTaskState::PAUSED:
            return "paused";
        case OHOS::Media::AVDownloadTaskState::REMOVING:
            return "removing";
        case OHOS::Media::AVDownloadTaskState::ERROR:
        default:
            return "error";
    }
}
}

namespace ANI {
namespace Media {

void AVDownloaderCallback::OnStatusChange(const std::string &taskId, OHOS::Media::AVDownloadTaskState state)
{
    MEDIA_LOGI("OnStatusChange taskId: %{public}s, state: %{public}d", taskId.c_str(), static_cast<int32_t>(state));
    SendStatusChangeCallback(taskId, state);
}

void AVDownloaderCallback::OnProgressChange(const std::string &taskId, double progress)
{
    MEDIA_LOGI("OnProgressChange taskId: %{public}s, progress: %{public}f", taskId.c_str(), progress);
    SendProgressChangeCallback(taskId, progress);
}

void AVDownloaderCallback::SendStatusChangeCallback(const std::string &taskId, OHOS::Media::AVDownloadTaskState state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVDownloaderEvent::EVENT_STATUS_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find statusChange callback!");
        return;
    }

    AVDownloaderTaiheCallback *cb = new(std::nothrow) AVDownloaderTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVDownloaderEvent::EVENT_STATUS_CHANGE);
    cb->callbackName = AVDownloaderEvent::EVENT_STATUS_CHANGE;
    cb->taskId = taskId;
    cb->stateStr = AVDownloadTaskStateToString(state);

    auto task = [this, cb]() {
        this->OnTaiheStatusChangeCallback(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnStatusChange",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void AVDownloaderCallback::SendProgressChangeCallback(const std::string &taskId, double progress)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVDownloaderEvent::EVENT_PROGRESS_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find progressChange callback!");
        return;
    }

    AVDownloaderTaiheCallback *cb = new(std::nothrow) AVDownloaderTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVDownloaderEvent::EVENT_PROGRESS_CHANGE);
    cb->callbackName = AVDownloaderEvent::EVENT_PROGRESS_CHANGE;
    cb->taskId = taskId;
    cb->progress = progress;

    auto task = [this, cb]() {
        this->OnTaiheProgressChangeCallback(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnProgressChange",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void AVDownloaderCallback::OnTaiheStatusChangeCallback(AVDownloaderTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheStatusChangeCallback is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");

        std::shared_ptr<taihe::callback<void(string_view, string_view)>>
            cacheCallback = std::reinterpret_pointer_cast<
                taihe::callback<void(string_view, string_view)>>(func);

        (*cacheCallback)(taiheCb->taskId, taiheCb->stateStr);
    } while (0);
    delete taiheCb;
}

void AVDownloaderCallback::OnTaiheProgressChangeCallback(AVDownloaderTaiheCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheProgressChangeCallback is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");

        std::shared_ptr<taihe::callback<void(string_view, double)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view, double)>>(func);
        (*cacheCallback)(taiheCb->taskId, taiheCb->progress);
    } while (0);
    delete taiheCb;
}

void AVDownloaderCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void AVDownloaderCallback::ClearCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Clear callback type: %{public}s", name.c_str());
}

} // namespace Media
} // namespace ANI
