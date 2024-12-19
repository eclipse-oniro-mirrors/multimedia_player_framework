/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef I_STANDARD_MEDIA_REPLY_H
#define I_STANDARD_MEDIA_REPLY_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Media {
class IStandardMediaReply : public IRemoteBroker {
public:
    virtual ~IStandardMediaReply() = default;
    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardMediaReply");

    /**
     * IPC code ID for IStandardMediaReply
     */
    enum MediaReplyMsg : uint32_t {
        ON_SEND_SUB_SYSTEM_ABILITY_ASYNC = 0,
    };

    /**
     * Send Player/Recorder/AVCodec/Codeclist/Split/AVmetadata Service Ability
     *
     * @return Returns {@link MSERR_OK} if call successfully; returns
     */
    virtual int32_t SendSubSystemAbilityAync(sptr<IRemoteObject> &subSystemAbility) = 0;
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_MEDIA_REPLY_H
