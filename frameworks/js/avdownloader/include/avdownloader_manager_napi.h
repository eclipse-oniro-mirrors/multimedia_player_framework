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

#ifndef AVDOWNLOADER_MANAGER_NAPI_H
#define AVDOWNLOADER_MANAGER_NAPI_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "av_downloader_manager.h"

namespace OHOS {
namespace Media {

class AVDownloaderManagerNapi : public AVDownloaderManagerCallback {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateAVDownloaderManager(napi_env env, napi_callback_info info);

    // DownloaderImpl called
    void OnStatusChange(const std::string &taskId, AVDownloadTaskState state) override;
    void OnProgressChange(const std::string &taskId, double progress) override;

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    static napi_value AllowsCellularAccess(napi_env env, napi_callback_info info);
    static napi_value SetRequestTimeout(napi_env env, napi_callback_info info);
    static napi_value AddAVDownloadTask(napi_env env, napi_callback_info info);
    static napi_value RemoveDownloadTask(napi_env env, napi_callback_info info);
    static napi_value PauseDownloadTask(napi_env env, napi_callback_info info);
    static napi_value ResumeDownloadTask(napi_env env, napi_callback_info info);
    static napi_value GetDownloadTasks(napi_env env, napi_callback_info info);
    static napi_value GetTaskCacheDirectory(napi_env env, napi_callback_info info);
    static napi_value GetTaskStatus(napi_env env, napi_callback_info info);
    static napi_value GetTaskProgress(napi_env env, napi_callback_info info);
    static napi_value OnStatusChange(napi_env env, napi_callback_info info);
    static napi_value OnProgressChange(napi_env env, napi_callback_info info);
    static napi_value OffStatusChange(napi_env env, napi_callback_info info);
    static napi_value OffProgressChange(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    AVDownloaderManagerNapi();
    ~AVDownloaderManagerNapi();

    std::string GenerateTaskId();
    std::string GetTaskCacheDir(const std::string &taskId);
    void TriggerStatusCallback(const std::string &taskId, AVDownloadTaskState state);
    void TriggerProgressCallback(const std::string &taskId, double progress);

    std::shared_ptr<AVDownloaderManager> downloaderManager_;
    std::shared_ptr<AVDownloaderManagerNapi> selfRef_;
    napi_env env_ = nullptr;
    bool allowCellularAccess_ = false;
    int32_t requestTimeoutMs_ = 30000;
    std::map<std::string, std::string> taskIdToUrl_;
    std::map<std::string, std::string> taskIdToCacheDir_;
    std::map<std::string, int32_t> taskIdToStatus_;
    std::map<std::string, double> taskIdToProgress_;
    napi_ref statusChangeCallback_ = nullptr;
    napi_ref progressChangeCallback_ = nullptr;

    static thread_local napi_ref constructor_;
};

} // namespace Media
} // namespace OHOS
#endif // AVDOWNLOADER_MANAGER_NAPI_H