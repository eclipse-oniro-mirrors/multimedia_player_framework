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

#ifndef MEDIA_SOURCE_LOADER_STUB_H
#define MEDIA_SOURCE_LOADER_STUB_H

#include "i_standard_media_source_loader.h"
#include "loading_request_impl.h"
#include "media_death_recipient.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
class MediaSourceLoaderStub : public IRemoteStub<IStandardMediaSourceLoader>, public NoCopyable {
public:
    explicit MediaSourceLoaderStub(const std::shared_ptr<LoaderCallback> &mediaSourceLoader);
    virtual ~MediaSourceLoaderStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t Init(std::shared_ptr<IMediaSourceLoadingRequest> &request) override;
    int64_t Open(const std::string &url, const std::map<std::string, std::string> &header) override;
    int32_t Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    int32_t Close(int64_t uuid) override;

private:
    std::shared_ptr<LoaderCallback> mediaSourceLoader_ = nullptr;
    std::shared_ptr<IMediaSourceLoadingRequest> requestCallback_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SOURCE_LOADER_STUB_H