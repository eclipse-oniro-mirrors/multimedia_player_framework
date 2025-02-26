/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef LOADING_REQUEST_H
#define LOADING_REQUEST_H
#include <map>
#include "buffer/avsharedmemorybase.h"

namespace OHOS {
namespace Media {
class LoadingRequest {
public:
    virtual ~LoadingRequest() = default;

    virtual int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) = 0;
    virtual int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) = 0;
    virtual int32_t FinishLoading(int64_t uuid, int32_t requestedError) = 0;
    virtual uint64_t GetUniqueId() = 0;
    virtual std::string GetUrl() = 0;
    virtual std::map<std::string, std::string> GetHeader() = 0;
};

class LoaderCallback {
public:
    virtual ~LoaderCallback() = default;
    virtual int64_t Open(std::shared_ptr<LoadingRequest> &request) = 0;
    virtual void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) = 0;
    virtual void Close(int64_t uuid) = 0;
};
} // namespace Media
} // namespace OHOS
#endif // LOADING_REQUEST_H
