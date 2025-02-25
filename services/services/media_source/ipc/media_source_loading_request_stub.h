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

#ifndef MEDIA_SOURCE_LOADING_REQUEST_STUB_H
#define MEDIA_SOURCE_LOADING_REQUEST_STUB_H

#include "i_standard_media_source_loading_request.h"
#include "media_death_recipient.h"
#include "nocopyable.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {
using MediaSourceLoadingRequestStubFunc = std::function<int32_t (MessageParcel &, MessageParcel &)>;
class MediaSourceLoadingRequestStub : public IRemoteStub<IStandardMediaSourceLoadingRequest>, public NoCopyable {
public:
    explicit MediaSourceLoadingRequestStub(std::shared_ptr<IMediaSourceLoadingRequest> &loadingRequest);
    virtual ~MediaSourceLoadingRequestStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirctUrl) override;
    int32_t FinishLoading(int64_t uuid, LoadingRequestError requestedError) override;

private:
    int32_t RespondData(MessageParcel &data, MessageParcel &reply);
    int32_t RespondHeader(MessageParcel &data, MessageParcel &reply);
    int32_t FinishLoading(MessageParcel &data, MessageParcel &reply);
    void DumpData(uint8_t* buffer, const size_t& bytesSingle);
    void SetDumpBySysParam();

    TaskQueue taskQue_;
    std::mutex mutex_;
    std::map<uint32_t, std::pair<std::string, MediaSourceLoadingRequestStubFunc>> loadingRequestFuncs_;
    std::shared_ptr<IMediaSourceLoadingRequest> loadingRequest_ = nullptr;

    bool enableEntireDump_ {false};
    FILE* entireDumpFile_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SOURCE_LOADING_REQUEST_STUB_H