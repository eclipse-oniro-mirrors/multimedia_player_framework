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
#ifndef MEDIA_SOURCE_LOADER_CALLBACK_TAIHE_H
#define MEDIA_SOURCE_LOADER_CALLBACK_TAIHE_H

#include <mutex>
#include "event_handler.h"
#include "media_source.h"
#include "media_ani_common.h"
#include "loading_request.h"
#include "nocopyable.h"

namespace ANI {
namespace Media {
namespace FunctionName {
const std::string SOURCE_OPEN = "open";
const std::string SOURCE_READ = "read";
const std::string SOURCE_CLOSE = "close";
}
struct MediaDataSourceLoaderTaiheCallback {
    ~MediaDataSourceLoaderTaiheCallback();
    void WaitResult();
    std::weak_ptr<AutoRef> autoRef_;
    std::string callbackName_ = "unknown";
    std::shared_ptr<OHOS::Media::LoadingRequest> request_;
    int64_t uuid_ = 0; // The default value is 0, indicating retry upon failure.
    int64_t requestedOffset_ = -1;
    int64_t requestedLength_ = -1;
    std::mutex mutexCond_;
    std::condition_variable cond_;
    bool setResult_ = false;
    bool isExit_ = false;
};

class MediaSourceLoaderCallback : public OHOS::Media::LoaderCallback, public OHOS::NoCopyable {
public:
    explicit MediaSourceLoaderCallback();
    virtual ~MediaSourceLoaderCallback();

    int64_t Open(std::shared_ptr<OHOS::Media::LoadingRequest> &request) override;
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    void Close(int64_t uuid) override;
    void SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref);
    void ClearCallbackReference();
    void WaitResult();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

private:
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    std::shared_ptr<MediaDataSourceLoaderTaiheCallback> taiheCb_ = nullptr;
};
} // namespace Media
} // namespace ANI
#endif // MEDIA_SOURCE_LOADER_CALLBACK_TAIHE_H