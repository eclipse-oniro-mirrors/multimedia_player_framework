/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef I_STANDARD_PCM_OUTPUT_CALLBACK_H
#define I_STANDARD_PCM_OUTPUT_CALLBACK_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "avbuffer.h"

namespace OHOS {
namespace Media {
class IStandardPCMOutputCallback : public IRemoteBroker {
public:
    virtual ~IStandardPCMOutputCallback() = default;
    virtual void OnPCMOutput(const std::shared_ptr<AVBuffer> &buffer) = 0;

    enum PCMOutputCallbackMsg {
        ON_PCM_OUTPUT = 0,
        MAX_IPC_ID,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardPCMOutputCallback");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_PCM_OUTPUT_CALLBACK_H
