/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LOADING_REQUEST_MOCK_H
#define LOADING_REQUEST_MOCK_H

#include "loading_request.h"
#include <string>

namespace OHOS {
namespace Media {
class LoadingRequestMock : public LoadingRequest {
public:
    LoadingRequestMock(std::string url, std::map<std::string, std::string> header)
        : url_(url), header_(header) {}
    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) override
    {
        return AV_ERR_OK;
    }
    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) override
    {
        respondHeaderCalled = true;
        return AV_ERR_OK;
    }
    int32_t FinishLoading(int64_t uuid, int32_t requestedError) override
    {
        finishLoadingCalled = true;
        return AV_ERR_OK;
    }
    uint64_t GetUniqueId() override
    {
        return 1;
    }
    std::string GetUrl() override
    {
        return url_;
    }
    std::map<std::string, std::string> GetHeader() override
    {
        return header_;
    }
private:
    std::string url_;
    std::map<std::string, std::string> header_;
    bool respondHeaderCalled = false;
    bool finishLoadingCalled = false;
};
} // Media
} // OHOS
#endif // LOADING_REQUEST_MOCK_H
