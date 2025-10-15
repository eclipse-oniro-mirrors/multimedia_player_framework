/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "ui_extension_ability_connection.h"
#include "ability_connect_callback_interface.h"
#include "ability_manager_client.h"
#include "media_log.h"
#include "media_utils.h"

constexpr int32_t SIGNAL_NUM = 3;
constexpr int32_t CLOSE_CONNECTION = 3;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "UIExtensionAbilityConnection"};
}

namespace OHOS {
namespace Media {

void UIExtensionAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    CHECK_AND_RETURN_LOG(status_ == ConnectStatus::UNKNOWN, "status is not UNKNOWN");
    status_ = ConnectStatus::STARTING;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    remoteObject_ = remoteObject;
    data.WriteInt32(SIGNAL_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(GetScreenCaptureSystemParam()
        ["const.multimedia.screencapture.screenrecorderbundlename"]));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(GetScreenCaptureSystemParam()
        ["const.multimedia.screencapture.screenrecorderabilityname"]));
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(commandStr_));
    MEDIA_LOGI("UIExtensionAbilityConnection::OnAbilityConnectDone start");
    remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    if (status_ == ConnectStatus::STARTING) {
        status_ = ConnectStatus::STARTED;
    } else if (status_ == ConnectStatus::CLOSING) {
        status_ = ConnectStatus::STARTED;
        CloseDialog();
    }
    MEDIA_LOGI("UIExtensionAbilityConnection::OnAbilityConnectDone end");
}

void UIExtensionAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    MEDIA_LOGI("UIExtensionAbilityConnection::OnAbilityDisconnectDone start");
}

bool UIExtensionAbilityConnection::CloseDialog()
{
    if (status_ != ConnectStatus::STARTED) {
        status_ = ConnectStatus::CLOSING;
        MEDIA_LOGI("UIExtensionAbilityConnection::CloseDialog status is not STARTED");
        return true;
    }
    status_ = ConnectStatus::CLOSING;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (remoteObject_ != nullptr) {
        MEDIA_LOGI("UIExtensionAbilityConnection::CloseDialog send close request.");
        int32_t ret = remoteObject_->SendRequest(CLOSE_CONNECTION, data, reply, option);
        status_ = ConnectStatus::CLOSED;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, false,
            "UIExtensionAbilityConnection::CloseDialog SendRequest failed.");
        return reply.ReadInt32() == 0;
    }
    return true;
}
} // namespace Media
} // namespace OHOS