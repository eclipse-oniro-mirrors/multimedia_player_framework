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

#ifndef LOADING_REQUEST_IMPL_H
#define LOADING_REQUEST_IMPL_H

#include "loading_request.h"
#include "media_source.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
using namespace OHOS::Media::Plugins;
class LoadingRequestImpl : public LoadingRequest, public NoCopyable {
public:
    explicit LoadingRequestImpl(const std::shared_ptr<IMediaSourceLoadingRequest> &loadingRequest,
        std::string url, std::map<std::string, std::string> header);
    ~LoadingRequestImpl();
    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) override;
    int32_t FinishLoading(int64_t uuid, int32_t requestedError) override;
    uint64_t GetUniqueId() override;
    std::string GetUrl() override;
    std::map<std::string, std::string> GetHeader() override;
    
private:
    std::shared_ptr<IMediaSourceLoadingRequest> loadingRequestCallback_ = nullptr;
    uint64_t uniqueId_ = 0;
    std::string url_ {};
    std::map<std::string, std::string> header_ {};
};
} // namespace Media
} // namespace OHOS
#endif // LOADING_REQUEST_IMPL_H