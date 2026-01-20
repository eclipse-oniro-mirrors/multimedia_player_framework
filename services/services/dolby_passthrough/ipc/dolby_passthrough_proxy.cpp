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

#include "dolby_passthrough_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DolbyPassthroughProxy"};
}

namespace OHOS {
namespace Media {

DolbyPassthroughCallback::DolbyPassthroughCallback(const sptr<IStandardDolbyPassthrough> &ipcProxy)
    : callbackProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

DolbyPassthroughCallback::~DolbyPassthroughCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}


bool DolbyPassthroughCallback::IsAudioPass(const char* mime)
{
    MEDIA_LOGD("IsAudioPass in");
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, false, "callbackProxy_ is nullptr");
    return callbackProxy_->IsAudioPass(mime);
}

std::vector<std::string> DolbyPassthroughCallback::GetList()
{
    MEDIA_LOGD("GetDolbyList in");
    std::vector<std::string> nulllist = {};
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, nulllist, "callbackProxy_ is nullptr");
    return callbackProxy_->GetList();
}


DolbyPassthroughProxy::DolbyPassthroughProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardDolbyPassthrough>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

DolbyPassthroughProxy::~DolbyPassthroughProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool DolbyPassthroughProxy::IsAudioPass(const char* mime)
{
    MEDIA_LOGD("IsAudioPass in");
    CHECK_AND_RETURN_RET_LOG(mime != nullptr, false, "mime is nullptr");
    MediaTrace trace("DolbyPassthrough::IsAudioPass");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    bool token = data.WriteInterfaceToken(DolbyPassthroughProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

    data.WriteString(std::string(mime));
    int error = Remote()->SendRequest(static_cast<uint32_t>(ListenerMsg::IS_AUDIO_PASS), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, false, "IsAudioPass failed, error: %{public}d", error);
    return reply.ReadBool();
}

std::vector<std::string> DolbyPassthroughProxy::GetList()
{
    MEDIA_LOGD("GetDolbyList in");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    std::vector<std::string> nulllist = {};
    bool token = data.WriteInterfaceToken(DolbyPassthroughProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nulllist, "Failed to write descriptor!");

    int error = Remote()->SendRequest(static_cast<uint32_t>(ListenerMsg::GET_LIST), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nulllist, "GetDolbyList failed, error: %{public}d", error);

    std::vector<std::string> dolbylist;
    (void)reply.ReadStringVector(&dolbylist);
    return dolbylist;
}
} // namespace Media
} // namespace OHOS