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

#include "avmetadatahelper_service_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "avsharedmemory_ipc.h"
#include "surface_buffer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA,
                                               "AVMetadataHelperServiceProxy"};
}

namespace OHOS {
namespace Media {
AVMetadataHelperServiceProxy::AVMetadataHelperServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardAVMetadataHelperService>(impl)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVMetadataHelperServiceProxy::~AVMetadataHelperServiceProxy()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t AVMetadataHelperServiceProxy::DestroyStub()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int error = Remote()->SendRequest(DESTROY, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "DestroyStub failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t AVMetadataHelperServiceProxy::SetSource(const std::string &uri, int32_t usage)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteString(uri);
    (void)data.WriteInt32(usage);

    int error = Remote()->SendRequest(SET_URI_SOURCE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetSource failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t AVMetadataHelperServiceProxy::SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(offset);
    (void)data.WriteInt64(size);
    (void)data.WriteInt32(usage);

    int error = Remote()->SendRequest(SET_FD_SOURCE, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetSource failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t AVMetadataHelperServiceProxy::SetSource(const sptr<IRemoteObject> &object)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteRemoteObject(object);
    int32_t error = Remote()->SendRequest(SET_MEDIA_DATA_SRC_OBJ, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetSource failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t AVMetadataHelperServiceProxy::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteRemoteObject(object);
    int32_t error = Remote()->SendRequest(SET_LISTENER_OBJ, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetListenerObject failed, error: %{public}d", error);

    return reply.ReadInt32();
}

std::string AVMetadataHelperServiceProxy::ResolveMetadata(int32_t key)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, "", "Failed to write descriptor!");

    (void)data.WriteInt32(key);

    int error = Remote()->SendRequest(RESOLVE_METADATA, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, "",
        "ResolveMetadata failed, error: %{public}d", error);

    return reply.ReadString();
}

std::shared_ptr<Meta> AVMetadataHelperServiceProxy::GetAVMetadata()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<Meta> metadata = std::make_shared<Meta>();
    std::shared_ptr<Meta> customInfo = std::make_shared<Meta>();

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, metadata, "Failed to write descriptor!");

    int error = Remote()->SendRequest(GET_AVMETADATA, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, metadata,
        "GetAVMetadata failed, error: %{public}d", error);

    bool ret = true;
    std::string key = reply.ReadString();
    if (key.compare("customInfo") == 0) {
        ret = customInfo->FromParcel(reply);
    }
    CHECK_AND_RETURN_RET_LOG(ret == true, metadata, "customInfo FromParcel failed");

    key = reply.ReadString();
    if (key.compare("AVMetadata") == 0) {
        ret = metadata->FromParcel(reply);
    }
    CHECK_AND_RETURN_RET_LOG(ret == true, metadata, "metadata FromParcel failed");

    metadata->SetData("customInfo", customInfo);
    return metadata;
}

std::unordered_map<int32_t, std::string> AVMetadataHelperServiceProxy::ResolveMetadataMap()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::unordered_map<int32_t, std::string> metadata;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, metadata, "Failed to write descriptor!");

    int error = Remote()->SendRequest(RESOLVE_METADATA_MAP, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, metadata,
        "ResolveMetadataMap failed, error: %{public}d", error);

    std::vector<int32_t> key;
    (void)reply.ReadInt32Vector(&key);
    CHECK_AND_RETURN_RET_LOG(!key.empty(), metadata, "key is empty");

    std::vector<std::string> dataStr;
    (void)reply.ReadStringVector(&dataStr);
    CHECK_AND_RETURN_RET_LOG(!dataStr.empty(), metadata, "dataStr is empty");

    auto itKey = key.begin();
    auto itDataStr = dataStr.begin();
    for (; itKey != key.end() && itDataStr != dataStr.end(); ++itKey, ++itDataStr) {
        metadata[*itKey] = *itDataStr;
    }

    return metadata;
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperServiceProxy::FetchArtPicture()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    int error = Remote()->SendRequest(FETCH_ALBUM_COVER, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "FetchArtPicture failed, error: %{public}d", error);

    return ReadAVSharedMemoryFromParcel(reply);
}

std::shared_ptr<AVBuffer> AVMetadataHelperServiceProxy::FetchFrameYuv(int64_t timeUs, int32_t option,
                                                                      const OutputConfiguration &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    (void)data.WriteInt64(timeUs);
    (void)data.WriteInt32(option);
    (void)data.WriteInt32(param.dstWidth);
    (void)data.WriteInt32(param.dstHeight);
    (void)data.WriteInt32(static_cast<int32_t>(param.colorFormat));

    int error = Remote()->SendRequest(FETCH_FRAME_YUV, data, reply, opt);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr, "FetchFrameYuv failed, error: %{public}d", error);
    CHECK_AND_RETURN_RET(reply.ReadInt32() == MSERR_OK, nullptr);
    auto avBuffer = AVBuffer::CreateAVBuffer();
    CHECK_AND_RETURN_RET(avBuffer != nullptr, nullptr);
    auto ret = avBuffer->ReadFromMessageParcel(reply);
    return ret ? avBuffer : nullptr;
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperServiceProxy::FetchFrameAtTime(int64_t timeUs,
    int32_t option, const OutputConfiguration &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, nullptr, "Failed to write descriptor!");

    (void)data.WriteInt64(timeUs);
    (void)data.WriteInt32(option);
    (void)data.WriteInt32(param.dstWidth);
    (void)data.WriteInt32(param.dstHeight);
    (void)data.WriteInt32(static_cast<int32_t>(param.colorFormat));

    int error = Remote()->SendRequest(FETCH_FRAME_AT_TIME, data, reply, opt);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, nullptr,
        "FetchFrameAtTime failed, error: %{public}d", error);

    return ReadAVSharedMemoryFromParcel(reply);
}

void AVMetadataHelperServiceProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int error = Remote()->SendRequest(RELEASE, data, reply, option);
    CHECK_AND_RETURN_LOG(error == MSERR_OK, "Release failed, error: %{public}d", error);
}

int32_t AVMetadataHelperServiceProxy::SetHelperCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    int32_t error = Remote()->SendRequest(SET_CALLBACK, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetHelperCallback failed, error: %{public}d", error);

    return reply.ReadInt32();
}

int32_t AVMetadataHelperServiceProxy::GetTimeByFrameIndex(uint32_t index, int64_t &time)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteUint32(index);

    int32_t error = Remote()->SendRequest(GET_TIME_BY_FRAME_INDEX, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "GetTimeByFrameIndex failed, error: %{public}d", error);
    time = reply.ReadInt64();
    return MSERR_OK;
}

int32_t AVMetadataHelperServiceProxy::GetFrameIndexByTime(int64_t time, uint32_t &index)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataHelperServiceProxy::GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(token, MSERR_INVALID_OPERATION, "Failed to write descriptor!");

    (void)data.WriteInt64(time);

    int32_t error = Remote()->SendRequest(GET_FRAME_INDEX_BY_TIME, data, reply, option);
    CHECK_AND_RETURN_RET_LOG(error == MSERR_OK, MSERR_INVALID_OPERATION,
        "SetHelperCallback failed, error: %{public}d", error);
    index = reply.ReadUint32();
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS

