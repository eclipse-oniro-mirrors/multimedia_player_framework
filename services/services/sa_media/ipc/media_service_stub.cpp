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

#include "media_service_stub.h"
#include "i_standard_media_reply.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_server_manager.h"
#include "player_xcollie.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaServiceStub"};
const std::string TASK_NAME = "OHOS::Media::MediaServiceStub::GetSystemAbility";
const int32_t TIME_OUT_SECOND = 30; // time out is 30 senconds
}

namespace OHOS {
namespace Media {
MediaServiceStub::MediaServiceStub()
{
    deathRecipientMap_.clear();
    mediaListenerMap_.clear();
    Init();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaServiceStub::~MediaServiceStub()
{
}

void MediaServiceStub::Init()
{
    mediaFuncs_[GET_SUBSYSTEM] =
        [this](MessageParcel &data, MessageParcel &reply) { return GetSystemAbility(data, reply); };
    mediaFuncs_[GET_SUBSYSTEM_ASYNC] =
        [this](MessageParcel &data, MessageParcel &reply) { return GetSystemAbilityAync(data, reply); };
}

int32_t MediaServiceStub::DestroyStubForPid(pid_t pid)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sptr<MediaDeathRecipient> deathRecipient = nullptr;
        sptr<IStandardMediaListener> mediaListener = nullptr;

        auto itDeath = deathRecipientMap_.find(pid);
        if (itDeath != deathRecipientMap_.end()) {
            deathRecipient = itDeath->second;

            if (deathRecipient != nullptr) {
                deathRecipient->SetNotifyCb(nullptr);
            }

            (void)deathRecipientMap_.erase(itDeath);
        }

        auto itListener = mediaListenerMap_.find(pid);
        if (itListener != mediaListenerMap_.end()) {
            mediaListener = itListener->second;

            if (mediaListener != nullptr && mediaListener->AsObject() != nullptr && deathRecipient != nullptr) {
                (void)mediaListener->AsObject()->RemoveDeathRecipient(deathRecipient);
            }

            (void)mediaListenerMap_.erase(itListener);
        }
    }

    MediaServerManager::GetInstance().DestroyStubObjectForPid(pid);
    return MSERR_OK;
}

int MediaServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Stub: OnRemoteRequest of code: %{public}u is received",
        FAKE_POINTER(this), code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (MediaServiceStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }
    auto itFunc = mediaFuncs_.find(code);
    if (itFunc != mediaFuncs_.end()) {
        int32_t ret = itFunc->second(data, reply);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("Calling memberFunc is failed.");
        }
        return MSERR_OK;
    }
    MEDIA_LOGW("mediaFuncs_: no member func supporting, applying default process");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void MediaServiceStub::ClientDied(pid_t pid)
{
    MEDIA_LOGE("client pid is dead, pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);
}

int32_t MediaServiceStub::SetDeathListener(const sptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set listener object is nullptr");

    sptr<IStandardMediaListener> mediaListener = iface_cast<IStandardMediaListener>(object);
    CHECK_AND_RETURN_RET_LOG(mediaListener != nullptr, MSERR_NO_MEMORY,
        "failed to convert IStandardMediaListener");

    pid_t pid = IPCSkeleton::GetCallingPid();
    sptr<MediaDeathRecipient> deathRecipient = new(std::nothrow) MediaDeathRecipient(pid);
    CHECK_AND_RETURN_RET_LOG(deathRecipient != nullptr, MSERR_NO_MEMORY, "failed to new MediaDeathRecipient");

    deathRecipient->SetNotifyCb(std::bind(&MediaServiceStub::ClientDied, this, std::placeholders::_1));

    if (mediaListener->AsObject() != nullptr) {
        (void)mediaListener->AsObject()->AddDeathRecipient(deathRecipient);
    }

    sptr<MediaDeathRecipient> oldDeathRecipient =
        deathRecipientMap_.find(pid) != deathRecipientMap_.end() ? deathRecipientMap_[pid] : nullptr;
    sptr<IStandardMediaListener> oldMediaListener =
        mediaListenerMap_.find(pid) != mediaListenerMap_.end() ? mediaListenerMap_[pid] : nullptr;
    if (oldDeathRecipient != nullptr) {
        oldDeathRecipient->SetNotifyCb(nullptr);
    }
    if (oldMediaListener != nullptr && oldDeathRecipient != nullptr) {
        oldMediaListener->AsObject()->RemoveDeathRecipient(oldDeathRecipient);
    }

    MEDIA_LOGD("client pid pid:%{public}d", pid);
    mediaListenerMap_[pid] = mediaListener;
    deathRecipientMap_[pid] = deathRecipient;
    return MSERR_OK;
}

int32_t MediaServiceStub::GetSystemAbility(MessageParcel &data, MessageParcel &reply)
{
    int32_t mediaSystemAbility = data.ReadInt32();
    MediaSystemAbility id = static_cast<MediaSystemAbility>(mediaSystemAbility);
    sptr<IRemoteObject> listenerObj = data.ReadRemoteObject();
    LISTENER(reply.WriteRemoteObject(GetSubSystemAbility(id, listenerObj)),
        TASK_NAME + ":" + std::to_string(mediaSystemAbility), false, TIME_OUT_SECOND);
    return MSERR_OK;
}

int32_t MediaServiceStub::GetSystemAbilityAync(MessageParcel &data, MessageParcel &reply)
{
    int32_t mediaSystemAbility = data.ReadInt32();
    MediaSystemAbility id = static_cast<MediaSystemAbility>(mediaSystemAbility);
    sptr<IRemoteObject> listenerObj = data.ReadRemoteObject();

    uint32_t timeOutMs = data.ReadUint32();
    sptr<IStandardMediaReply> mediaReplyProxy = iface_cast<IStandardMediaReply>(data.ReadRemoteObject());
    CHECK_AND_RETURN_RET_LOG(mediaReplyProxy != nullptr, MSERR_UNKNOWN, "mediaReplyProxy remote object is nullptr");
    
    sptr<IRemoteObject> subSystemAbility = GetSubSystemAbilityWithTimeOut(id, listenerObj, timeOutMs);
    LISTENER(mediaReplyProxy->SendSubSystemAbilityAync(subSystemAbility),
        TASK_NAME + ":" + std::to_string(mediaSystemAbility), false, TIME_OUT_SECOND);
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS
