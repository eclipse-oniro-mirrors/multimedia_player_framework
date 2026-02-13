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

#include "media_service_proxy.h"
#include "media_reply_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "player_xcollie.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaServiceProxy"};
constexpr int64_t MAX_PIDS_COUNT = 65536;
}

namespace OHOS {
namespace Media {
MediaServiceProxy::MediaServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardMediaService>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaServiceProxy::~MediaServiceProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void MediaServiceProxy::ReleaseClientListener()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::RELEASE_CLIENT_LISTENER, data, reply, option);
    if (error != MSERR_OK) {
        MEDIA_LOGE("Send request failed, error: %{public}d", error);
    }
}

std::vector<pid_t> MediaServiceProxy::GetPlayerPids()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    std::vector<pid_t> res;

    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, res, "Failed to write descriptor!");
    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::GET_PLAYER_PIDS, data, reply, option);
    if (error != MSERR_OK) {
        MEDIA_LOGE("Send request failed, error: %{public}d", error);
        return res;
    }
    int64_t vecSize = reply.ReadInt64();
    CHECK_AND_RETURN_RET_LOG(vecSize >= 0 && vecSize <= MAX_PIDS_COUNT, res, "Fail to read vecSize");
    for (int64_t i = 0; i < vecSize; i++) {
        res.emplace_back(static_cast<pid_t>(reply.ReadInt64()));
    }
    return res;
}

int32_t MediaServiceProxy::GetLppCapacity(LppAvCapabilityInfo &lppAvCapability)
{
    MEDIA_LOGI("MediaServiceProxy::GetLppCapacity");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t error = -1;
    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, error, "Failed to write descriptor!");
    error = Remote()->SendRequest(MediaServiceMsg::GET_LPP_CAPABILITY, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, error, "Failed to SendRequest");
    int32_t ret = reply.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Fail to MediaServiceProxy::GetLppCapacity");
    lppAvCapability = LppAvCapabilityInfo::Unmarshalling(reply);
    MEDIA_LOGI("MediaServiceProxy::GetLppCapacity %{public}zu %{public}zu",
        lppAvCapability.videoCap_.size(), lppAvCapability.audioCap_.size());
    return ret;
}

sptr<IRemoteObject> MediaServiceProxy::GetSubSystemAbility(IStandardMediaService::MediaSystemAbility subSystemId,
    const sptr<IRemoteObject> &listener)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_AND_RETURN_RET_LOG(listener != nullptr, nullptr, "listener is nullptr!");
    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    (void)data.WriteInt32(static_cast<int32_t>(subSystemId));
    (void)data.WriteRemoteObject(listener);
    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::GET_SUBSYSTEM, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "Create player proxy failed, error: %{public}d", error);
    return reply.ReadRemoteObject();
}

sptr<IRemoteObject> MediaServiceProxy::GetSubSystemAbilityWithTimeOut(
    IStandardMediaService::MediaSystemAbility subSystemId, const sptr<IRemoteObject> &listener, uint32_t timeoutMs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };

    CHECK_AND_RETURN_RET_LOG(listener != nullptr, nullptr, "listener is nullptr!");
    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    (void)data.WriteInt32(static_cast<int32_t>(subSystemId));
    (void)data.WriteRemoteObject(listener);

    sptr<MediaReplyStub> mediaReplyStub = new(std::nothrow) MediaReplyStub();
    CHECK_AND_RETURN_RET_LOG(mediaReplyStub != nullptr, nullptr, "failed to create MediaReplyStub.");

    (void) data.WriteUint32(timeoutMs);
    sptr<IRemoteObject> object = mediaReplyStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "mediaReplyStub object is nullptr.");
    (void)data.WriteRemoteObject(object);

    int32_t error = Remote()->SendRequest(MediaServiceMsg::GET_SUBSYSTEM_ASYNC, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "SendRequest failed, error: %{public}d", error);
    
    return mediaReplyStub->WaitForAsyncSubSystemAbility(timeoutMs);
}

bool MediaServiceProxy::CanKillMediaService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
 
    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::CAN_KILL_MEDIA_SERVICE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, false,
        "CanKillMediaService failed, error: %{public}d", error);
    
    return reply.ReadBool();
}

int32_t MediaServiceProxy::FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "WriteInterfaceToken failed");

    CHECK_AND_RETURN_RET_LOG(data.WriteBool(isProxy), MSERR_INVALID_OPERATION, "Failed to write bool");

    int32_t size = static_cast<int32_t>(pidList.size());
    CHECK_AND_RETURN_RET_LOG(size > 0, MSERR_INVALID_VAL, "size is invalid");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(size), MSERR_INVALID_OPERATION, "Failed to write int32");

    for (auto pid : pidList) {
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(pid), MSERR_INVALID_OPERATION, "Failed to write int32");
    }

    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::FREEZE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SendRequest failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t MediaServiceProxy::ResetAllProxy()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(MediaServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "WriteInterfaceToken failed");

    int32_t error = -1;
    error = Remote()->SendRequest(MediaServiceMsg::RESET_ALL_PROXY, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SendRequest failed, error: %{public}d", error);
    return reply.ReadInt32();
}
} // namespace Media
} // namespace OHOS
