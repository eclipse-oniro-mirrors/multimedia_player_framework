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

#include "dolby_passthrough_stub.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DolbyPassthroughStub"};
}

namespace OHOS {
namespace Media {

DolbyPassthroughStub::DolbyPassthroughStub(IsAudioPassthrough callback, GetDolbyList getDolbyList)
    : callback_(callback), getDolbyList_(getDolbyList)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

DolbyPassthroughStub::~DolbyPassthroughStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int DolbyPassthroughStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MEDIA_LOGI("DolbyPassthroughStub::OnRemoteRequest");
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (DolbyPassthroughStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }

    switch (static_cast<ListenerMsg>(code)) {
        case ListenerMsg::IS_AUDIO_PASS: {
            std::string mime = data.ReadString();
            bool ret = IsAudioPass(mime.c_str());
            reply.WriteBool(ret);
            return MSERR_OK;
        }
        case ListenerMsg::GET_LIST: {
            std::vector<std::string> ret = GetList();
            reply.WriteStringVector(ret);
            return MSERR_OK;
        }
        default: {
            MEDIA_LOGE("default case, need check DolbyPassthroughStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

bool DolbyPassthroughStub::IsAudioPass(const char* mime)
{
    MEDIA_LOGD("IsAudioPass in mime =  %{public}s", mime);
    if (!callback_) {
        MEDIA_LOGE("callback_ is null, cannot check IsAudioPass");
        return false;
    }
    return callback_(mime);
}

std::vector<std::string> DolbyPassthroughStub::GetList()
{
    if (!getDolbyList_) {
        MEDIA_LOGE("getDolbyList_ is null, cannot get list");
        return {};
    }
    return getDolbyList_();
}
} // namespace Media
} // namespace OHOS