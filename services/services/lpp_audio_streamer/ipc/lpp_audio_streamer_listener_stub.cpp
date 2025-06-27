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

#include "lpp_audio_streamer_listener_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioStreamerListenerStub"};
}

namespace OHOS {
namespace Media {
LppAudioStreamerListenerStub::LppAudioStreamerListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppAudioStreamerListenerStub::~LppAudioStreamerListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int LppAudioStreamerListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    CHECK_AND_RETURN_RET_LOG(LppAudioStreamerListenerStub::GetDescriptor() == remoteDescriptor, MSERR_INVALID_OPERATION,
        "Invalid descriptor");

    switch (code) {
        case LppAudioStreamerListenerMsg::ON_ERROR: {
            int32_t errorCode = data.ReadInt32();
            std::string errorMsg = data.ReadString();
            OnError(errorCode, errorMsg);
            return MSERR_OK;
        }
        case LppAudioStreamerListenerMsg::ON_INFO: {
            int32_t type = data.ReadInt32();
            int32_t extra = data.ReadInt32();
            Format format;
            (void)MediaParcel::Unmarshalling(data, format);
            std::string info = format.Stringify();
            MEDIA_LOGD("0x%{public}06" PRIXPTR " listen on info type: %{public}d extra %{public}d, format %{public}s",
                       FAKE_POINTER(this), type, extra, info.c_str());
            OnInfo(static_cast<AudioStreamerOnInfoType>(type), extra, format);
            return MSERR_OK;
        }
        default: {
            MEDIA_LOGE("default case, need check LppAudioStreamerListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

void LppAudioStreamerListenerStub::OnError(int32_t errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnError(errorCode, errorMsg);
}

void LppAudioStreamerListenerStub::OnInfo(AudioStreamerOnInfoType type,
    int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnInfo(type, extra, infoBody);
}


void LppAudioStreamerListenerStub::SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback)
{
    callback_ = callback;
}

} // namespace Media
} // namespace OHOS