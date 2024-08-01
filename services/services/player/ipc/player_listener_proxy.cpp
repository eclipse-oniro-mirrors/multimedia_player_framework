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

#include "player_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "player_xcollie.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerListenerProxy"};
}

namespace OHOS {
namespace Media {
PlayerListenerProxy::PlayerListenerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardPlayerListener>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

PlayerListenerProxy::~PlayerListenerProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void PlayerListenerProxy::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(PlayerListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(errorCode);
    data.WriteString(errorMsg);
    int error = SendRequest(PlayerListenerMsg::ON_ERROR_MSG, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on error failed, error: %{public}d", error);
}

void PlayerListenerProxy::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    if (type == INFO_TYPE_ERROR_MSG) {
        int32_t errorCode = -1;
        std::string errorMsg;
        infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_ERROR_TYPE), errorCode);
        infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_ERROR_MSG), errorMsg);
        return OnError(errorCode, errorMsg);
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(PlayerListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(type);
    data.WriteInt32(extra);
    MediaParcel::Marshalling(data, infoBody);
    int error = SendRequest(PlayerListenerMsg::ON_INFO, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "0x%{public}06" PRIXPTR " on info failed, error: %{public}d",
        FAKE_POINTER(this), error);
}

PlayerListenerCallback::PlayerListenerCallback(const sptr<IStandardPlayerListener> &listener) : listener_(listener)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

PlayerListenerCallback::~PlayerListenerCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void PlayerListenerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("player callback onError, errorCode: %{public}d, errorMsg: %{public}s", errorCode, errorMsg.c_str());
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnError(errorCode, errorMsg);
}

void PlayerListenerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnInfo(type, extra, infoBody);
}

int32_t PlayerListenerProxy::SendRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    int32_t error = MSERR_OK;
    error = Remote()->SendRequest(code, data, reply, option);
    return error;
}
} // namespace Media
} // namespace OHOS
