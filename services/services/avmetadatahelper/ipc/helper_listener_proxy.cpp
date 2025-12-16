/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "helper_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "HelperListenerProxy"};
}

namespace OHOS {
namespace Media {
#define LISTENER(statement, args...) { OHOS::Media::XcollieTimer xCollie(args); statement; }

HelperListenerProxy::HelperListenerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardHelperListener>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

HelperListenerProxy::~HelperListenerProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void HelperListenerProxy::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(HelperListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(errorCode);
    data.WriteString(errorMsg);
    int error = SendRequest(HelperListenerMsg::ON_ERROR_MSG, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on error failed, error: %{public}d", error);
}

void HelperListenerProxy::OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    bool token = data.WriteInterfaceToken(HelperListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    data.WriteInt32(type);
    data.WriteInt32(extra);
    MediaParcel::Marshalling(data, infoBody);
    int error = SendRequest(HelperListenerMsg::ON_INFO, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "on info failed, error: %{public}d", error);
}

void HelperListenerProxy::OnPixelComplete(HelperOnInfoType type,
    const std::shared_ptr<AVBuffer> &reAvbuffer_,
    const FrameInfo &info,
    const PixelMapParams &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(HelperListenerProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    (void)data.WriteInt32(type);
    (void)data.WriteInt32(info.err);
    (void)data.WriteInt64(info.requestedTimeUs);
    (void)data.WriteInt64(info.actualTimeUs);
    (void)data.WriteInt32(info.fetchResult);
    CHECK_AND_RETURN_LOG(reAvbuffer_ != nullptr, "Failed to write buffer!");
    reAvbuffer_->WriteToMessageParcel(data);
    (void)data.WriteInt32(param.dstWidth);
    (void)data.WriteInt32(param.dstHeight);
    (void)data.WriteInt32(static_cast<int32_t>(param.colorFormat));
    (void)data.WriteBool(param.isSupportFlip);
    (void)data.WriteBool(param.convertColorSpace);
    int error = SendRequest(HelperListenerMsg::ON_PIXEL_COMPLETE, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "OnPixelComplete failed, error: %{public}d", error);
}

HelperListenerCallback::HelperListenerCallback(const sptr<IStandardHelperListener> &listener) : listener_(listener)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

HelperListenerCallback::~HelperListenerCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void HelperListenerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("Helper callback onError, errorCode: %{public}d, errorMsg: %{public}s", errorCode, errorMsg.c_str());
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnError(errorCode, errorMsg);
}

void HelperListenerCallback::OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnInfo(type, extra, infoBody);
}

void HelperListenerCallback::OnPixelComplete(HelperOnInfoType type,
    const std::shared_ptr<AVBuffer> &reAvbuffer_,
    const FrameInfo &info,
    const PixelMapParams &param)
{
    CHECK_AND_RETURN(listener_ != nullptr);
    listener_->OnPixelComplete(type, reAvbuffer_, info, param);
}

int32_t HelperListenerProxy::SendRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    int32_t error = Remote()->SendRequest(code, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SendRequest failed, error: %{public}d", error);
    return error;
}
} // namespace Media
} // namespace OHOS
