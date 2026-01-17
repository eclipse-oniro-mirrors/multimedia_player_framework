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

#include "lpp_video_streamer_listener_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoStreamerListenerStub"};
}

namespace OHOS {
namespace Media {
LppVideoStreamerListenerStub::LppVideoStreamerListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppVideoStreamerListenerStub::~LppVideoStreamerListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int LppVideoStreamerListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    CHECK_AND_RETURN_RET_LOG(LppVideoStreamerListenerStub::GetDescriptor() == remoteDescriptor, MSERR_INVALID_OPERATION,
        "Invalid descriptor");

    switch (code) {
        case LppVideoStreamerListenerMsg::ON_ERROR: {
            int32_t errorCode = data.ReadInt32();
            std::string errorMsg = data.ReadString();
            OnError(errorCode, errorMsg);
            return MSERR_OK;
        }
        case LppVideoStreamerListenerMsg::ON_INFO: {
            int32_t type = data.ReadInt32();
            int32_t extra = data.ReadInt32();
            Format format;
            (void)MediaParcel::Unmarshalling(data, format);
            std::string info = format.Stringify();
            MEDIA_LOGD("0x%{public}06" PRIXPTR " listen on info type: %{public}d extra %{public}d, format %{public}s",
                       FAKE_POINTER(this), type, extra, info.c_str());
            OnInfo(static_cast<VideoStreamerOnInfoType>(type), extra, format);
            return MSERR_OK;
        }
        default: {
            MEDIA_LOGE("default case, need check LppVideoStreamerListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

void LppVideoStreamerListenerStub::OnError(int32_t errorCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(vListenStubMutex_);
    if (callback_ != nullptr) {
        callback_->OnError(errorCode, errorMsg);
    }
}

void LppVideoStreamerListenerStub::OnInfo(VideoStreamerOnInfoType type,
    int32_t extra, const Format &infoBody)
{
    std::lock_guard<std::mutex> lock(vListenStubMutex_);
    CHECK_AND_RETURN_LOG(callback_!=nullptr, "callback_ is nullptr");
    callback_->OnInfo(type, extra, infoBody);
}


void LppVideoStreamerListenerStub::SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback)
{
    std::lock_guard<std::mutex> lock(vListenStubMutex_);
    callback_ = callback;
}

} // namespace Media
} // namespace OHOS