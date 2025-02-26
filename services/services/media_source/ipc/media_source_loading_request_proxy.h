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

#ifndef MEDIA_SOURCE_LOADING_REQUEST_PROXY_H
#define MEDIA_SOURCE_LOADING_REQUEST_PROXY_H

#include "i_standard_media_source_loading_request.h"
#include "media_death_recipient.h"
#include "media_source_loading_request_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
using namespace OHOS::Media::Plugins;

class MediaSourceLoadingRequestCallback : public IMediaSourceLoadingRequest, public NoCopyable {
public:
    explicit MediaSourceLoadingRequestCallback(const sptr<IStandardMediaSourceLoadingRequest> &ipcProxy);
    virtual ~MediaSourceLoadingRequestCallback();

    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) override;
    int32_t FinishLoading(int64_t uuid, LoadingRequestError requestedError) override;
    void Release() override;
private:
    sptr<IStandardMediaSourceLoadingRequest> callbackProxy_ = nullptr;
};

class MediaSourceLoadingRequestProxy : public IRemoteProxy<IStandardMediaSourceLoadingRequest>, public NoCopyable {
public:
    explicit MediaSourceLoadingRequestProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaSourceLoadingRequestProxy();

    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) override;
    int32_t FinishLoading(int64_t uuid, LoadingRequestError requestedError) override;
private:
    int32_t SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    static inline BrokerDelegator<MediaSourceLoadingRequestProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SOURCE_LOADING_REQUEST_PROXY_H