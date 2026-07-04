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

#ifndef AVDOWNLOADER_MANAGER_H
#define AVDOWNLOADER_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include "media_source.h"

namespace OHOS {
namespace Media {

enum class AVDownloadTaskState : int32_t {
    INIT = 0,
    QUEUED,
    RUNNING,
    COMPLETED,
    PAUSED,
    REMOVING,
    ERROR
};

class AVDownloaderManager;
class AVDownloaderManagerCallback {
public:
    virtual ~AVDownloaderManagerCallback() = default;
    virtual void OnStatusChange(const std::string &taskId, AVDownloadTaskState state) = 0;
    virtual void OnProgressChange(const std::string &taskId, double progress) = 0;
};

class __attribute__((visibility("default"))) AVDownloaderManager {
public:
    virtual ~AVDownloaderManager() = default;

    virtual int32_t SetAllowCellularAccess(bool allow) = 0;
    virtual int32_t SetRequestTimeout(int32_t timeoutMs) = 0;
    virtual std::string AddDownloadTask(std::shared_ptr<Plugins::MediaSource> source) = 0;
    virtual int32_t RemoveDownloadTask(const std::string &taskId) = 0;
    virtual int32_t PauseDownloadTask(const std::string &taskId) = 0;
    virtual int32_t ResumeDownloadTask(const std::string &taskId) = 0;
    virtual std::vector<std::string> GetDownloadTasks() = 0;
    virtual std::string GetTaskCacheDirectory(const std::string &taskId) = 0;
    virtual AVDownloadTaskState GetTaskStatus(const std::string &taskId) = 0;
    virtual double GetTaskProgress(const std::string &taskId) = 0;
    virtual int32_t SetManagerCallback(const std::weak_ptr<AVDownloaderManagerCallback> &callback) = 0;
    virtual int32_t Release() = 0;

protected:
    AVDownloaderManager() = default;
};

class __attribute__((visibility("default"))) AVDownloaderManagerFactory {
public:
    static std::shared_ptr<AVDownloaderManager> Create();

private:
    AVDownloaderManagerFactory() = default;
    ~AVDownloaderManagerFactory() = default;
};

} // namespace Media
} // namespace OHOS
#endif // AVDOWNLOADER_MANAGER_H
