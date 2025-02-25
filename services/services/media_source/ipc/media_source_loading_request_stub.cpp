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
#include <fstream>
#include "media_source_loading_request_stub.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "avsharedmemory_ipc.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoadingRequestStub"};
constexpr uint32_t MAX_MAP_SIZE = 100;
}

namespace OHOS {
namespace Media {
using namespace Plugins;
MediaSourceLoadingRequestStub::MediaSourceLoadingRequestStub(
    std::shared_ptr<IMediaSourceLoadingRequest> &loadingRequest)
    : taskQue_("LoadingRequest"), loadingRequest_(loadingRequest)
{
    (void)taskQue_.Start();
    SetDumpBySysParam();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    loadingRequestFuncs_[LoadingRequestMsg::RESPOND_DATA] = { "LoadingRequestStub::RespondData",
        [this](MessageParcel &data, MessageParcel &reply) { return RespondData(data, reply); } };
    loadingRequestFuncs_[LoadingRequestMsg::RESPOND_HEADER] = { "LoadingRequestStub::RespondHeader",
        [this](MessageParcel &data, MessageParcel &reply) { return RespondHeader(data, reply); } };
    loadingRequestFuncs_[LoadingRequestMsg::FINISH_LOADING] = { "LoadingRequestStub::FinishLoading",
        [this](MessageParcel &data, MessageParcel &reply) { return FinishLoading(data, reply); } };
}

MediaSourceLoadingRequestStub::~MediaSourceLoadingRequestStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int MediaSourceLoadingRequestStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MediaTrace trace("MediaSourceLoadingRequestStub::OnRemoteRequest");
    auto remoteDescriptor = data.ReadInterfaceToken();
    CHECK_AND_RETURN_RET_LOG(MediaSourceLoadingRequestStub::GetDescriptor() == remoteDescriptor,
        MSERR_INVALID_OPERATION, "Invalid descriptor");

    auto itFunc = loadingRequestFuncs_.find(code);
    if (itFunc != loadingRequestFuncs_.end()) {
        auto memberFunc = itFunc->second.second;
        auto funcName = itFunc->second.first;
        if (memberFunc != nullptr) {
            auto task = std::make_shared<TaskHandler<int>>([&] {
                return memberFunc(data, reply);
            });
            (void)taskQue_.EnqueueTask(task);
            auto result = task->GetResult();
            CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION,
                "failed to OnRemoteRequest code: %{public}u", code);
            return result.Value();
        }
    }
    MEDIA_LOGW("MediaSourceLoadingRequestStub: no member func supporting, applying default process");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t MediaSourceLoadingRequestStub::RespondData(int64_t uuid, int64_t offset,
    const std::shared_ptr<AVSharedMemory> &mem)
{
    MediaTrace trace("MediaSourceLoadingRequestStub::RespondData, uuid: " +
        std::to_string(uuid) + " offset: " + std::to_string(offset));
    MEDIA_LOGI("RespondData enter uuid:%{public}" PRId64, uuid);
    CHECK_AND_RETURN_RET_LOG(loadingRequest_ != nullptr, MEDIA_SOURCE_ERROR_IO, "loadingRequest_ is nullptr");
    return loadingRequest_->RespondData(uuid, offset, mem);
}

int32_t MediaSourceLoadingRequestStub::RespondHeader(int64_t uuid, std::map<std::string, std::string> header,
    std::string redirctUrl)
{
    MediaTrace trace("MediaSourceLoadingRequestStub::RespondHeader, uuid: " + std::to_string(uuid));
    MEDIA_LOGI("RespondHeader enter uuid:%{public}" PRId64, uuid);
    CHECK_AND_RETURN_RET_LOG(loadingRequest_ != nullptr, MSERR_UNKNOWN, "loadingRequest_ is nullptr");
    return loadingRequest_->RespondHeader(uuid, header, redirctUrl);
}

int32_t MediaSourceLoadingRequestStub::FinishLoading(int64_t uuid, LoadingRequestError requestedError)
{
    MediaTrace trace("MediaSourceLoadingRequestStub::FinishLoading, uuid: " + std::to_string(uuid));
    MEDIA_LOGI("FinishLoading enter uuid:%{public}" PRId64, uuid);
    CHECK_AND_RETURN_RET_LOG(loadingRequest_ != nullptr, MSERR_UNKNOWN, "loadingRequest_ is nullptr");
    return loadingRequest_->FinishLoading(uuid, requestedError);
}

int32_t MediaSourceLoadingRequestStub::RespondData(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_LOGI("RespondData in");
    int64_t uuid = data.ReadInt64();
    int64_t offset = data.ReadInt64();
    std::shared_ptr<AVSharedMemory> memory = ReadAVDataSrcMemoryFromParcel(data);
    CHECK_AND_RETURN_RET_LOG(memory != nullptr, MSERR_INVALID_VAL, "Read Memory failed");
    DumpData(memory->GetBase(), memory->GetSize());
    return reply.WriteInt32(RespondData(uuid, offset, memory));
}

void MediaSourceLoadingRequestStub::SetDumpBySysParam()
{
    std::string dumpAllEnable;
    enableEntireDump_ = false;
    int32_t dumpAllRes = OHOS::system::GetStringParameter("sys.media.sink.entiredump.enable", dumpAllEnable, "");
    if (dumpAllRes == 0 && !dumpAllEnable.empty() && dumpAllEnable == "true") {
        enableEntireDump_ = true;
    }
}

void MediaSourceLoadingRequestStub::DumpData(uint8_t* buffer, const size_t& bytesSingle)
{
    if (!enableEntireDump_) {
        return;
    }

    if (entireDumpFile_ == nullptr) {
        std::string path = "data/media/DumpData.mp4";
        entireDumpFile_ = fopen(path.c_str(), "wb+");
    }
    if (entireDumpFile_ == nullptr) {
        return;
    }
    (void)fwrite(buffer, bytesSingle, 1, entireDumpFile_);
    (void)fflush(entireDumpFile_);
}

int32_t MediaSourceLoadingRequestStub::RespondHeader(MessageParcel &data, MessageParcel &reply)
{
    int64_t uuid = data.ReadInt64();
    uint32_t mapSize = data.ReadUint32();
    CHECK_AND_RETURN_RET_LOG(mapSize >= 0 && mapSize <= MAX_MAP_SIZE, MSERR_INVALID_VAL, "Size is not in range");
    std::map<std::string, std::string> header;
    for (uint32_t i = 0; i < mapSize; i++) {
        auto kstr = data.ReadString();
        auto vstr = data.ReadString();
        header.emplace(kstr, vstr);
    }
    std::string redirctUrl = data.ReadString();
    RespondHeader(uuid, header, redirctUrl);
    return MSERR_OK;
}

int32_t MediaSourceLoadingRequestStub::FinishLoading(MessageParcel &data, MessageParcel &reply)
{
    int64_t uuid = data.ReadInt64();
    int32_t error = data.ReadInt32();
    if (error > static_cast<int32_t>(LoadingRequestError::LOADING_ERROR_AUTHORIZE_FAILED) ||
        error < static_cast<int32_t>(LoadingRequestError::LOADING_ERROR_SUCCESS)) {
        MEDIA_LOGI("error code");
        return MSERR_INVALID_VAL;
    }
    reply.WriteInt32(FinishLoading(uuid, static_cast<LoadingRequestError>(error)));
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS