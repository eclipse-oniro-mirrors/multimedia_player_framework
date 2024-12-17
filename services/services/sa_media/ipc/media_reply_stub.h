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

#ifndef MEDIA_REPLY_STUB_H
#define MEDIA_REPLY_STUB_H

#include "i_standard_media_reply.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
class MediaReplyStub : public IRemoteStub<IStandardMediaReply>, public NoCopyable {
public:
    MediaReplyStub();
    virtual ~MediaReplyStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    virtual int32_t SendSubSystemAbilityAync(sptr<IRemoteObject> &subSystemAbility) override;

    sptr<IRemoteObject> WaitForAsyncSubSystemAbility(uint32_t timeoutMs);

private:
    std::mutex asyncRemoteObjRecvMtx__;
    std::condition_variable asyncRemoteObjRecvCv_;
    bool cvWaitExitFlag_ = false;
    sptr<IRemoteObject> subSystemAbility_ {nullptr};
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_REPLY_STUB_H
