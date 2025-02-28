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
#include "media_source_loading_request_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "avsharedmemory_ipc.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoadingRequestProxy"};
}

namespace OHOS {
namespace Media {
using namespace Plugins;
MediaSourceLoadingRequestCallback::MediaSourceLoadingRequestCallback(
    const sptr<IStandardMediaSourceLoadingRequest> &ipcProxy) : callbackProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Callback Instances create", FAKE_POINTER(this));
}

MediaSourceLoadingRequestCallback::~MediaSourceLoadingRequestCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Callback Instances destroy", FAKE_POINTER(this));
}

int32_t MediaSourceLoadingRequestCallback::RespondData(int64_t uuid, int64_t offset,
    const std::shared_ptr<AVSharedMemory> &mem)
{
    MEDIA_LOGI("RespondData in");
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MEDIA_SOURCE_ERROR_IO, "callbackProxy_ is nullptr");
    return callbackProxy_->RespondData(uuid, offset, mem);
}

int32_t MediaSourceLoadingRequestCallback::RespondHeader(int64_t uuid, std::map<std::string, std::string> header,
    std::string redirectUrl)
{
    MEDIA_LOGI("RespondHeader in");
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MSERR_INVALID_OPERATION, "callbackProxy_ is nullptr");
    return callbackProxy_->RespondHeader(uuid, header, redirectUrl);
}

int32_t MediaSourceLoadingRequestCallback::FinishLoading(int64_t uuid, LoadingRequestError requestedError)
{
    MEDIA_LOGI("FinishLoading in");
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MSERR_INVALID_OPERATION, "callbackProxy_ is nullptr");
    return callbackProxy_->FinishLoading(uuid, requestedError);
}

void MediaSourceLoadingRequestCallback::Release()
{
    MEDIA_LOGI("Release in");
    callbackProxy_ = nullptr;
}

MediaSourceLoadingRequestProxy::MediaSourceLoadingRequestProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardMediaSourceLoadingRequest>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaSourceLoadingRequestProxy::~MediaSourceLoadingRequestProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t MediaSourceLoadingRequestProxy::RespondData(int64_t uuid, int64_t offset,
    const std::shared_ptr<AVSharedMemory> &mem)
{
    MediaTrace trace("MediaSourceLoadingRequestProxy::RespondData, uuid: " +
        std::to_string(uuid) + " offset: " + std::to_string(offset));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    MEDIA_LOGI("RespondData in");
    bool token = data.WriteInterfaceToken(MediaSourceLoadingRequestProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MEDIA_SOURCE_ERROR_IO, "Failed to write descriptor!");
    data.WriteInt64(uuid);
    data.WriteInt64(offset);
    CHECK_AND_RETURN_RET_LOG(WriteAVSharedMemoryToParcel(mem, data) == MSERR_OK,
        MEDIA_SOURCE_ERROR_IO, "Failed to WriteAVSharedMemoryToParcel!");
    int error = Remote()->SendRequest(static_cast<uint32_t>(LoadingRequestMsg::RESPOND_DATA), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MEDIA_SOURCE_ERROR_IO, "RespondData failed, error: %{public}d", error);
    return reply.ReadInt32();
}

int32_t MediaSourceLoadingRequestProxy::RespondHeader(int64_t uuid, std::map<std::string, std::string> header,
    std::string redirectUrl)
{
    MediaTrace trace("MediaSourceLoadingRequestProxy::RespondHeader, uuid: " + std::to_string(uuid));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(MediaSourceLoadingRequestProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteInt64(uuid);
    data.WriteUint32(static_cast<uint32_t>(header.size()));
    for (auto [key, value] : header) {
        data.WriteString(key);
        data.WriteString(value);
    }
    data.WriteString(redirectUrl);
    int error = Remote()->SendRequest(static_cast<uint32_t>(LoadingRequestMsg::RESPOND_HEADER), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "RespondHeader fail, error: %{public}d", error);

    return MSERR_OK;
}

int32_t MediaSourceLoadingRequestProxy::FinishLoading(int64_t uuid, LoadingRequestError requestedError)
{
    MediaTrace trace("MediaSourceLoadingRequestProxy::FinishLoading, uuid: " + std::to_string(uuid));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(MediaSourceLoadingRequestProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteInt64(uuid);
    data.WriteInt32(static_cast<int32_t>(requestedError));
    int error = Remote()->SendRequest(static_cast<uint32_t>(LoadingRequestMsg::FINISH_LOADING), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "FinishLoading fail, error: %{public}d", error);

    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS