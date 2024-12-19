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

#include "media_reply_stub.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaReplyStub"};
}

namespace OHOS {
namespace Media {
MediaReplyStub::MediaReplyStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaReplyStub::~MediaReplyStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int MediaReplyStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,  MessageOption &option)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Stub: OnRemoteRequest of code: %{public}u is received",
        FAKE_POINTER(this), code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (MediaReplyStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }
    
    if (code == MediaReplyMsg::ON_SEND_SUB_SYSTEM_ABILITY_ASYNC) {
        sptr<IRemoteObject> object = data.ReadRemoteObject();
        return SendSubSystemAbilityAync(object);
    }
    MEDIA_LOGW("no MediaReplyMsg %{public}" PRIu32 "supporting, applying default process", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t MediaReplyStub::SendSubSystemAbilityAync(sptr<IRemoteObject> &subSystemAbility)
{
    std::unique_lock<std::mutex> lck(asyncRemoteObjRecvMtx_);
    subSystemAbility_ = subSystemAbility;
    cvWaitExitFlag_ = true;
    asyncRemoteObjRecvCv_.notify_all();
    return MSERR_OK;
}

sptr<IRemoteObject> MediaReplyStub::WaitForAsyncSubSystemAbility(uint32_t timeoutMs)
{
    std::unique_lock<std::mutex> lck(asyncRemoteObjRecvMtx_);
    if (subSystemAbility_ != nullptr) {
        return subSystemAbility_;
    }
    asyncRemoteObjRecvCv_.wait_for(lck, std::chrono::milliseconds(timeoutMs), [this]() {
        return cvWaitExitFlag_;
    });

    if (subSystemAbility_ == nullptr) {
        MEDIA_LOGW(" timeout %{public}" PRIu32 " Ms for get subSystemAbility_", timeoutMs);
    }
    return subSystemAbility_;
}
} // namespace Media
} // namespace OHOS
