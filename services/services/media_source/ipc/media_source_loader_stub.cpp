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

#include "media_source_loader_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_source_loading_request_proxy.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoaderStub"};
constexpr uint32_t MAX_MAP_SIZE = 100;
}

namespace OHOS {
namespace Media {
using namespace Plugins;
MediaSourceLoaderStub::MediaSourceLoaderStub(const std::shared_ptr<LoaderCallback> &mediaSourceLoader)
    : mediaSourceLoader_(mediaSourceLoader)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaSourceLoaderStub::~MediaSourceLoaderStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    if (requestCallback_) {
        requestCallback_->Release();
    }
}

int MediaSourceLoaderStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MediaTrace trace("MediaSourceLoaderStub::OnRemoteRequest");
    auto remoteDescriptor = data.ReadInterfaceToken();
    CHECK_AND_RETURN_RET_LOG(MediaSourceLoaderStub::GetDescriptor() == remoteDescriptor,
        MSERR_INVALID_OPERATION, "Invalid descriptor");

    switch (static_cast<SourceLoaderMsg>(code)) {
        case SourceLoaderMsg::INIT: {
            sptr<IRemoteObject> object = data.ReadRemoteObject();
            CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "object is nullptr");
            sptr<IStandardMediaSourceLoadingRequest> requestProxy =
                iface_cast<IStandardMediaSourceLoadingRequest>(object);
            CHECK_AND_RETURN_RET_LOG(requestProxy != nullptr, MSERR_NO_MEMORY, "failed to convert");
            requestCallback_ =  std::make_shared<MediaSourceLoadingRequestCallback>(requestProxy);
            CHECK_AND_RETURN_RET_LOG(requestCallback_ != nullptr, MSERR_NO_MEMORY, "failed to create requestCallback_");
            reply.WriteInt32(Init(requestCallback_));
            return MSERR_OK;
        }
        case SourceLoaderMsg::OPEN: {
            std::string url = data.ReadString();
            uint32_t mapSize = data.ReadUint32();
            CHECK_AND_RETURN_RET_LOG(mapSize >= 0 && mapSize <= MAX_MAP_SIZE,
                MSERR_INVALID_VAL, "Size is not in range");
            std::map<std::string, std::string> header;
            for (uint32_t i = 0; i < mapSize; i++) {
                auto kstr = data.ReadString();
                auto vstr = data.ReadString();
                header.emplace(kstr, vstr);
            }
            reply.WriteInt64(Open(url, header));
            return MSERR_OK;
        }
        case SourceLoaderMsg::READ: {
            int64_t uuid = data.ReadInt64();
            int64_t requestedOffset = data.ReadInt64();
            int64_t requestedLength = data.ReadInt64();
            Read(uuid, requestedOffset, requestedLength);
            return MSERR_OK;
        }
        case SourceLoaderMsg::CLOSE: {
            Close(data.ReadInt64());
            return MSERR_OK;
        }
        default: {
            MEDIA_LOGE("default case, need check MediaSourceLoaderStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t MediaSourceLoaderStub::Init(std::shared_ptr<IMediaSourceLoadingRequest> &request)
{
    MediaTrace trace("MediaSourceLoaderProxy::Init");
    (void) request;
    return MSERR_OK;
}

int64_t MediaSourceLoaderStub::Open(const std::string &url, const std::map<std::string, std::string> &header)
{
    MediaTrace trace("MediaSourceLoaderStub::open");
    MEDIA_LOGI("open enter");
    CHECK_AND_RETURN_RET_LOG(mediaSourceLoader_ != nullptr, MEDIA_SOURCE_ERROR_IO, "mediaSourceLoader_ is nullptr");
    std::shared_ptr<LoadingRequest> loadingRequestImpl
        = std::make_shared<LoadingRequestImpl>(requestCallback_, url, header);
    CHECK_AND_RETURN_RET_LOG(loadingRequestImpl != nullptr, MEDIA_SOURCE_ERROR_IO, "request is nullptr");
    return mediaSourceLoader_->Open(loadingRequestImpl);
}

int32_t MediaSourceLoaderStub::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MediaTrace trace("MediaSourceLoaderStub::read, uuid: " + std::to_string(uuid) +
        " offset: " + std::to_string(requestedOffset) + " Length:" + std::to_string(requestedLength));
    MEDIA_LOGD("read enter uuid: %{public}" PRId64 ", Offset:%{public}" PRId64 ", Length:%{public}" PRId64,
        uuid, requestedOffset, requestedLength);
    CHECK_AND_RETURN_RET_LOG(mediaSourceLoader_ != nullptr, MSERR_UNKNOWN, "mediaSourceLoader_ is nullptr");
    mediaSourceLoader_->Read(uuid, requestedOffset, requestedLength);
    return MSERR_OK;
}

int32_t MediaSourceLoaderStub::Close(int64_t uuid)
{
    MediaTrace trace("MediaSourceLoaderStub::close, uuid: " + std::to_string(uuid));
    MEDIA_LOGI("close enter uuid:%{public}" PRId64, uuid);
    CHECK_AND_RETURN_RET_LOG(mediaSourceLoader_ != nullptr, MSERR_UNKNOWN, "mediaSourceLoader_ is nullptr");
    mediaSourceLoader_->Close(uuid);
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS