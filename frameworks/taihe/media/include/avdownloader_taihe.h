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
#ifndef AVDOWNLOADER_TAIHE_H
#define AVDOWNLOADER_TAIHE_H

#include <mutex>
#include "av_downloader_manager.h"
#include "avdownloader_callback_taihe.h"
#include "common_taihe.h"
#include "media_ani_common.h"
#include "media_source_taihe.h"
#include "media_taihe_utils.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;

constexpr int32_t ERR_AVD_PARAM_OUT_OF_RANGE = 5400108;
constexpr int32_t ERR_AVD_OPERATION_NOT_PERMIT = 5400102;

class AVDownloaderManagerImpl {
public:
    AVDownloaderManagerImpl();

    void AllowsCellularAccess(bool value);
    void SetRequestTimeout(int32_t expired);
    string AddAVDownloadTask(ohos::multimedia::media::weak::MediaSource source);
    void RemoveDownloadTask(optional_view<string> taskId);
    void PauseDownloadTask(optional_view<string> taskId);
    void ResumeDownloadTask(optional_view<string> taskId);
    array<string> GetDownloadTasks();
    string GetTaskCacheDirectory(string_view taskId);
    string GetTaskStatus(string_view taskId);
    double GetTaskProgress(string_view taskId);

    void OnStatusChange(callback_view<void(string_view, string_view)> callback);
    void OnProgressChange(callback_view<void(string_view, double)> callback);
    void OffStatusChange(optional_view<callback<void(string_view, string_view)>> callback);
    void OffProgressChange(optional_view<callback<void(string_view, double)>> callback);

    void Release();

    void SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void ClearCallbackReference(const std::string &callbackName);

private:
    std::shared_ptr<OHOS::Media::AVDownloaderManager> downloaderManager_ = nullptr;
    std::shared_ptr<AVDownloaderCallback> downloaderCb_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    std::mutex mutex_;
    bool allowCellularAccess_ = false;
    int32_t requestTimeoutMs_ = 30000;
    std::map<std::string, std::string> taskIdToUrl_;
    std::map<std::string, std::string> taskIdToCacheDir_;
    std::map<std::string, int32_t> taskIdToStatus_;
    std::map<std::string, double> taskIdToProgress_;
};

} // namespace ANI::Media
#endif // AVDOWNLOADER_TAIHE_H
