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

#include "lpp_audio_streamer_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "LppAudioStreamerListenerProxy"};
}

namespace OHOS {
namespace Media {
LppAudioStreamerListenerProxy::LppAudioStreamerListenerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardLppAudioStreamerListener>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppAudioStreamerListenerProxy::~LppAudioStreamerListenerProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void LppAudioStreamerListenerProxy::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(LppAudioStreamerListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(errorCode);
    data.WriteString(errorMsg);
    CHECK_AND_RETURN_LOG(Remote() != nullptr, "Remote() is nullptr!");
    int error = Remote()->SendRequest(LppAudioStreamerListenerMsg::ON_ERROR, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on error failed, error: %{public}d", error);
}

void LppAudioStreamerListenerProxy::OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(LppAudioStreamerListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(type);
    data.WriteInt32(extra);
    MediaParcel::Marshalling(data, infoBody);
    int error = Remote()->SendRequest(LppAudioStreamerListenerMsg::ON_INFO, data, reply, option);
    CHECK_AND_RETURN_LOG(
        error == MSERR_OK, "0x%{public}06" PRIXPTR " on info failed, error: %{public}d", FAKE_POINTER(this), error);
}

LppAudioStreamerListenerCallback ::LppAudioStreamerListenerCallback(
    const sptr<IStandardLppAudioStreamerListener> &listener)
    : listener_(listener)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppAudioStreamerListenerCallback::~LppAudioStreamerListenerCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void LppAudioStreamerListenerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnError(errorCode, errorMsg);
}

void LppAudioStreamerListenerCallback::OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnInfo(type, extra, infoBody);
}
}  // namespace Media
}  // namespace OHOS
