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

#ifndef I_STANDARD_MEDIA_SOURCE_LOADING_REQUEST_H
#define I_STANDARD_MEDIA_SOURCE_LOADING_REQUEST_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "media_source.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
using namespace OHOS::Media::Plugins;
class IStandardMediaSourceLoadingRequest : public IRemoteBroker {
public:
    virtual ~IStandardMediaSourceLoadingRequest() = default;
    virtual int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem) = 0;
    virtual int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirctUrl) = 0;
    virtual int32_t FinishLoading(int64_t uuid, LoadingRequestError requestedError) = 0;

    enum LoadingRequestMsg {
        RESPOND_DATA = 0,
        RESPOND_HEADER,
        FINISH_LOADING,
        MAX_IPC_ID,                   // all IPC codes should be added before MAX_IPC_ID
    }; 

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardMediaSourceLoadingRequest");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_MEDIA_SOURCE_LOADING_REQUEST_H