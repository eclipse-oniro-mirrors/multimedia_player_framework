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

#include "media_source_loader_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoaderProxy"};
}

namespace OHOS {
namespace Media {
MediaSourceLoaderCallback::MediaSourceLoaderCallback(const sptr<IStandardMediaSourceLoader> &ipcProxy)
    : callbackProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " cb Instances create", FAKE_POINTER(this));
}

MediaSourceLoaderCallback::~MediaSourceLoaderCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " cb Instances create", FAKE_POINTER(this));
}

int32_t MediaSourceLoaderCallback::Init(std::shared_ptr<IMediaSourceLoadingRequest> &request)
{
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MSERR_INVALID_VAL, "callbackProxy_ is nullptr");
    return callbackProxy_->Init(request);
}

int64_t MediaSourceLoaderCallback::Open(const std::string &url, const std::map<std::string, std::string> &header)
{
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MEDIA_SOURCE_ERROR_IO, "callbackProxy_ is nullptr");
    return callbackProxy_->Open(url, header);
}

int32_t MediaSourceLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MSERR_INVALID_VAL, "callbackProxy_ is nullptr");
    return callbackProxy_->Read(uuid, requestedOffset, requestedLength);
}

int32_t MediaSourceLoaderCallback::Close(int64_t uuid)
{
    CHECK_AND_RETURN_RET_LOG(callbackProxy_ != nullptr, MSERR_INVALID_VAL, "callbackProxy_ is nullptr");
    return callbackProxy_->Close(uuid);
}

MediaSourceLoaderProxy::MediaSourceLoaderProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardMediaSourceLoader>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaSourceLoaderProxy::~MediaSourceLoaderProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    if (loadingRequestStub_) {
        loadingRequestStub_ = nullptr;
    }
}

int32_t MediaSourceLoaderProxy::Init(std::shared_ptr<IMediaSourceLoadingRequest> &request)
{
    MediaTrace trace("MediaSourceLoaderProxy::Init");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    MEDIA_LOGI("<< Init");
    bool token = data.WriteInterfaceToken(MediaSourceLoaderProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    loadingRequestStub_ = new(std::nothrow) MediaSourceLoadingRequestStub(request);
    CHECK_AND_RETURN_RET_LOG(loadingRequestStub_ != nullptr, MSERR_NO_MEMORY,
        "failed to new MediaSourceLoadingRequestStub object");
    sptr<IRemoteObject> object = loadingRequestStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "object is nullptr");
    (void)data.WriteRemoteObject(object);

    int error = Remote()->SendRequest(static_cast<uint32_t>(SourceLoaderMsg::INIT), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION, "Init fail, error: %{public}d", error);

    return reply.ReadInt32();
}

int64_t MediaSourceLoaderProxy::Open(const std::string &url, const std::map<std::string, std::string> &header)
{
    MediaTrace trace("MediaSourceLoaderProxy::open");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    MEDIA_LOGI("<< open");
    bool token = data.WriteInterfaceToken(MediaSourceLoaderProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MEDIA_SOURCE_ERROR_IO, "Failed to write descriptor!");

    data.WriteString(url);
    if (!data.WriteUint32(header.size())) {
        MEDIA_LOGE("Write mapSize failed");
        return MSERR_INVALID_OPERATION;
    }
    for (auto [key, value] : header) { // need check
        data.WriteString(key);
        data.WriteString(value);
    }
    int error = Remote()->SendRequest(static_cast<uint32_t>(SourceLoaderMsg::OPEN), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MEDIA_SOURCE_ERROR_IO, "open fail, error: %{public}d", error);
    int64_t uuid = reply.ReadInt64();
    MEDIA_LOGI(">> open %{public}" PRId64, uuid);
    return uuid;
}

int32_t MediaSourceLoaderProxy::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MediaTrace trace("MediaSourceLoaderProxy::read, uuid: " + std::to_string(uuid) +
        " offset: " + std::to_string(requestedOffset) + " Length:" + std::to_string(requestedLength));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    MEDIA_LOGD("<< read,uuid %{public}" PRId64 ", offset %{public}" PRId64 ", len %{public}" PRId64,
        uuid, requestedOffset, requestedLength);
    bool token = data.WriteInterfaceToken(MediaSourceLoaderProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteInt64(uuid);
    data.WriteInt64(requestedOffset);
    data.WriteInt64(requestedLength);
    int error = Remote()->SendRequest(static_cast<uint32_t>(SourceLoaderMsg::READ), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION, "read fail, error: %{public}d", error);
    return MSERR_OK;
}

int32_t MediaSourceLoaderProxy::Close(int64_t uuid)
{
    MediaTrace trace("MediaSourceLoaderStub::close, uuid: " + std::to_string(uuid));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    MEDIA_LOGI("<< close,uuid %{public}" PRId64, uuid);
    bool token = data.WriteInterfaceToken(MediaSourceLoaderProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    data.WriteInt64(uuid);
    int error = Remote()->SendRequest(static_cast<uint32_t>(SourceLoaderMsg::CLOSE), data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION, "close fail, error: %{public}d", error);

    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS