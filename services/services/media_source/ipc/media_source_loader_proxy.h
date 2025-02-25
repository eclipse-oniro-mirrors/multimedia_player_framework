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

#ifndef MEDIA_SOURCE_LOADER_PROXY_H
#define MEDIA_SOURCE_LOADER_PROXY_H

#include "i_standard_media_source_loader.h"
#include "media_death_recipient.h"
#include "nocopyable.h"
#include "media_source_loading_request_stub.h"

namespace OHOS {
namespace Media {
using namespace OHOS::Media::Plugins;
class MediaSourceLoaderCallback : public IMediaSourceLoader, public NoCopyable {
public:
    explicit MediaSourceLoaderCallback(const sptr<IStandardMediaSourceLoader> &ipcProxy);
    virtual ~MediaSourceLoaderCallback();

    int32_t Init(std::shared_ptr<IMediaSourceLoadingRequest> &request) override;
    int64_t Open(const std::string &url, const std::map<std::string, std::string> &header) override;
    int32_t Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    int32_t Close(int64_t uuid) override;
private:
    sptr<IStandardMediaSourceLoader> callbackProxy_ = nullptr;
};

class MediaSourceLoaderProxy : public IRemoteProxy<IStandardMediaSourceLoader>, public NoCopyable {
public:
    explicit MediaSourceLoaderProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaSourceLoaderProxy();

    int32_t Init(std::shared_ptr<IMediaSourceLoadingRequest> &request) override;
    int64_t Open(const std::string &url, const std::map<std::string, std::string> &header) override;
    int32_t Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    int32_t Close(int64_t uuid) override;
private:
    static inline BrokerDelegator<MediaSourceLoaderProxy> delegator_;
    sptr<MediaSourceLoadingRequestStub> loadingRequestStub_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SOURCE_LOADER_PROXY_H