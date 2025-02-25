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

#ifndef I_STANDARD_MEDIA_SOURCE_LOADER_H
#define I_STANDARD_MEDIA_SOURCE_LOADER_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "media_source.h"
#include "loading_request.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
using namespace OHOS::Media::Plugins;
class IStandardMediaSourceLoader : public IRemoteBroker {
public:
    virtual ~IStandardMediaSourceLoader() = default;
    virtual int32_t Init(std::shared_ptr<IMediaSourceLoadingRequest> &request) = 0;
    virtual int64_t Open(const std::string &url, const std::map<std::string, std::string> &header) = 0;
    virtual int32_t Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) = 0;
    virtual int32_t Close(int64_t uuid) = 0;

    enum SourceLoaderMsg {
        INIT = 0,
        OPEN,
        READ,
        CLOSE,
        MAX_IPC_ID,                   // all IPC codes should be added before MAX_IPC_ID
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardMediaSourceLoader");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_MEDIA_SOURCE_LOADER_H