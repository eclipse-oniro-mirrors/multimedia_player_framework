/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avmetadata_service_proxy_local_fuzzer.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace OHOS {
namespace Media {
namespace {
    using Fuzzer = AVMetadataServiceProxyFuzzer;
    using AVMetaStubFunc = std::function<int32_t(Fuzzer*, uint8_t*, size_t, bool)>;
    std::map<uint32_t, AVMetaStubFunc> avmetaFuncs_ = {
        {Fuzzer::SET_URI_SOURCE, Fuzzer::SetUriSourceStatic},
        {Fuzzer::SET_FD_SOURCE, Fuzzer::SetFdSourceStatic},
        {Fuzzer::RESOLVE_METADATA, Fuzzer::ResolveMetadataStatic},
        {Fuzzer::RESOLVE_METADATA_MAP, Fuzzer::ResolveMetadataMapStatic},
        {Fuzzer::GET_AVMETADATA, Fuzzer::GetAVMetadataStatic},
        {Fuzzer::FETCH_ALBUM_COVER, Fuzzer::FetchArtPictureStatic},
        {Fuzzer::FETCH_FRAME_AT_TIME, Fuzzer::FetchFrameAtTimeStatic},
        {Fuzzer::RELEASE, Fuzzer::ReleaseStatic},
        {Fuzzer::DESTROY, Fuzzer::DestroyStubStatic}
    };
}
AVMetadataServiceProxyFuzzer::AVMetadataServiceProxyFuzzer(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardAVMetadataHelperService>(impl)
{
}

sptr<AVMetadataServiceProxyFuzzer> AVMetadataServiceProxyFuzzer::Create()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> obj = samgr->GetSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID);
    if (obj == nullptr) {
        std::cout << "media object is nullptr." << std::endl;
        return nullptr;
    }
    sptr<IStandardMediaService> proxy = iface_cast<IStandardMediaService>(obj);
    if (proxy == nullptr) {
        std::cout << "media proxy is nullptr." << std::endl;
        return nullptr;
    }
    sptr<IRemoteObject> listenerStub = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> avmetaObject = proxy->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_AVMETADATAHELPER, listenerStub);
    if (avmetaObject == nullptr) {
        std::cout << "avmetaObject is nullptr." << std::endl;
        return nullptr;
    }

    sptr<AVMetadataServiceProxyFuzzer> avmetaProxy = iface_cast<AVMetadataServiceProxyFuzzer>(avmetaObject);
    if (avmetaProxy == nullptr) {
        std::cout << "avmetaProxy is nullptr." << std::endl;
        return nullptr;
    }
    return avmetaProxy;
}

void AVMetadataServiceProxyFuzzer::SendRequest(uint32_t code, uint8_t *inputData, size_t size, bool isFuzz)
{
    auto itFunc = avmetaFuncs_.find(code);
    if (itFunc != avmetaFuncs_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            memberFunc(this, inputData, size, isFuzz);
        }
    }
}

int32_t AVMetadataServiceProxyFuzzer::SetUriSourceStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "SetUriSource:Failed to write descriptor!" << std::endl;
        return false;
    }
    std::string url(reinterpret_cast<const char *>(inputData), size);
    (void)data.WriteString(url);
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(SET_URI_SOURCE, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::SetFdSourceStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Failed to write descriptor!" << std::endl;
        return false;
    }

    int32_t fdValue;
    int64_t offset;
    int64_t lengthValue;
    int32_t usage;
    if (isFuzz) {
        fdValue = *reinterpret_cast<int32_t *>(inputData);
        lengthValue = *reinterpret_cast<int64_t *>(inputData);
        offset = *reinterpret_cast<uint32_t *>(inputData) % *reinterpret_cast<int64_t *>(inputData);
        usage = *reinterpret_cast<int32_t *>(inputData);
        (void)data.WriteFileDescriptor(fdValue);
        (void)data.WriteInt64(offset);
        (void)data.WriteInt64(lengthValue);
        (void)data.WriteInt32(usage);
        return ptr->SendRequest(SET_FD_SOURCE, data, reply, option);
    } else {
        const std::string filePath = "/data/test/media/H264_AAC.mp4";
        fdValue = open(filePath.c_str(), O_RDONLY);
        offset = 0;
        if (fdValue < 0) {
            std::cout << "Open file failed." << std::endl;
            (void)close(fdValue);
            return -1;
        }

        struct stat64 buf;
        if (fstat64(fdValue, &buf) != 0) {
            std::cout << "Get file state failed." << std::endl;
            (void)close(fdValue);
            return -1;
        }
        lengthValue = static_cast<int64_t>(buf.st_size);
        usage = AVMetadataUsage::AV_META_USAGE_PIXEL_MAP;
        (void)data.WriteFileDescriptor(fdValue);
        (void)data.WriteInt64(offset);
        (void)data.WriteInt64(lengthValue);
        (void)data.WriteInt32(usage);
        int32_t ret = ptr->SendRequest(SET_FD_SOURCE, data, reply, option);
        (void)close(fdValue);
        return ret;
    }
}

int32_t AVMetadataServiceProxyFuzzer::ResolveMetadataStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)isFuzz;
    (void)size;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "ResolveMetadata:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RESOLVE_METADATA, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::ResolveMetadataMapStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "ResolveMetadataMap:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RESOLVE_METADATA_MAP, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::GetAVMetadataStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "GetAVMetadata:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RESOLVE_METADATA_MAP, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::FetchArtPictureStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "FetchArtPicture:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(FETCH_ALBUM_COVER, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::FetchFrameAtTimeStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)isFuzz;
    (void)size;
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "FetchFrameAtTime:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt64(*reinterpret_cast<int64_t *>(inputData));
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(FETCH_FRAME_AT_TIME, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::ReleaseStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    (void)isFuzz;
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "Release:Failed to write descriptor!" << std::endl;
        return false;
    }
    (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    return ptr->SendRequest(RELEASE, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::DestroyStubStatic(AVMetadataServiceProxyFuzzer* ptr, uint8_t *inputData,
    size_t size, bool isFuzz)
{
    (void)size;
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;

    bool token = data.WriteInterfaceToken(AVMetadataServiceProxyFuzzer::GetDescriptor());
    if (!token) {
        std::cout << "DestroyStub:Failed to write descriptor!" << std::endl;
        return false;
    }
    if (isFuzz) {
        (void)data.WriteInt32(*reinterpret_cast<int32_t *>(inputData));
    }
    return ptr->SendRequest(DESTROY, data, reply, option);
}

int32_t AVMetadataServiceProxyFuzzer::SendRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return Remote()->SendRequest(code, data, reply, option);
}
}
}