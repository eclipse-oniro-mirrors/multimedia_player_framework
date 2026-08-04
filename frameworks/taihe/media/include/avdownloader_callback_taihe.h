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

#ifndef AVDOWNLOADER_CALLBACK_TAIHE_H
#define AVDOWNLOADER_CALLBACK_TAIHE_H

#include <map>
#include <mutex>
#include <string>
#include "av_downloader_manager.h"
#include "common_taihe.h"
#include "event_handler.h"
#include "media_errors.h"

namespace ANI {
namespace Media {

inline std::string AVDownloadTaskStateToString(OHOS::Media::AVDownloadTaskState state)
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

namespace AVDownloaderEvent {
    const std::string EVENT_STATUS_CHANGE = "statusChange";
    const std::string EVENT_PROGRESS_CHANGE = "progressChange";
}

class AVDownloaderCallback : public OHOS::Media::AVDownloaderManagerCallback,
                             public std::enable_shared_from_this<AVDownloaderCallback> {
public:
    AVDownloaderCallback() = default;
    ~AVDownloaderCallback() override;

    void OnStatusChange(const std::string &taskId, OHOS::Media::AVDownloadTaskState state) override;
    void OnProgressChange(const std::string &taskId, double progress) override;

    void SendStatusChangeCallback(const std::string &taskId, OHOS::Media::AVDownloadTaskState state);
    void SendProgressChangeCallback(const std::string &taskId, double progress);

    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void ClearCallbackReference(const std::string &name);

private:
    struct AVDownloaderTaiheCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        std::string taskId = "";
        std::string stateStr = "";
        double progress = 0.0;
    };
    void OnTaiheStatusChangeCallback(AVDownloaderTaiheCallback *taiheCb) const;
    void OnTaiheProgressChangeCallback(AVDownloaderTaiheCallback *taiheCb) const;
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
};

} // namespace Media
} // namespace ANI
#endif // AVDOWNLOADER_CALLBACK_TAIHE_H
