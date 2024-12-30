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

#include "recorder_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderListenerProxy"};
}

namespace OHOS {
namespace Media {
RecorderListenerProxy::RecorderListenerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardRecorderListener>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderListenerProxy::~RecorderListenerProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void RecorderListenerProxy::OnError(int32_t errorType, int32_t errorCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(RecorderListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(errorType);
    data.WriteInt32(errorCode);
    int error = Remote()->SendRequest(RecorderListenerMsg::ON_ERROR, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on error failed, error: %{public}d", error);
}

void RecorderListenerProxy::OnInfo(int32_t type, int32_t extra)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(RecorderListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(static_cast<int>(type));
    data.WriteInt32(static_cast<int>(extra));
    int error = Remote()->SendRequest(RecorderListenerMsg::ON_INFO, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on info failed, error: %{public}d", error);
}

void RecorderListenerProxy::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(RecorderListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    audioRecorderChangeInfo.Marshalling(data);
    int error = Remote()->SendRequest(RecorderListenerMsg::ON_AUDIO_CAPTURE_CHANGE, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on audio capture change failed, error: %{public}d", error);
}

void RecorderListenerProxy::OnPhotoAssertAvailable(const std::string &uri)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
 
    bool token = data.WriteInterfaceToken(RecorderListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
 
    data.WriteString(uri);
    int error = Remote()->SendRequest(RecorderListenerMsg::ON_PHOTO_ASSERT_AVAILABLE, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on audio capture change failed, error: %{public}d", error);
}

RecorderListenerCallback::RecorderListenerCallback(const sptr<IStandardRecorderListener> &listener)
    : listener_(listener)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderListenerCallback::~RecorderListenerCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void RecorderListenerCallback::OnError(RecorderErrorType errorType, int32_t errorCode)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnError(errorType, errorCode);
}

void RecorderListenerCallback::OnInfo(int32_t type, int32_t extra)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnInfo(type, extra);
}

void RecorderListenerCallback::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnAudioCaptureChange(audioRecorderChangeInfo);
}

void RecorderListenerCallback::OnPhotoAssertAvailable(const std::string &uri)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnPhotoAssertAvailable(uri);
}
} // namespace Media
} // namespace OHOS
