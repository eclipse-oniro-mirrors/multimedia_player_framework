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

#include "media_reply_proxy.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaReplyProxy"};
}

namespace OHOS {
namespace Media {
MediaReplyProxy::MediaReplyProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardMediaReply>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}
MediaReplyProxy::~MediaReplyProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t MediaReplyProxy::SendSubSystemAbilityAync(sptr<IRemoteObject> &subSystemAbility)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };

    bool token = data.WriteInterfaceToken(MediaReplyProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteRemoteObject(subSystemAbility);
    int error = Remote()->SendRequest(ON_SEND_SUB_SYSTEM_ABILITY_ASYNC, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SendSubSystemAbilityAync failed, error: %{public}d", error);

    return MSERR_OK;
}

} // namespace Media
} // namespace OHOS
