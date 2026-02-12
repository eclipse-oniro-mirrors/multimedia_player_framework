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

#include "avmetadatastub_fuzzer.h"

#include <fcntl.h>

#include "stub_common.h"
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_avmetadatahelper_service.h"

namespace {
constexpr char VIDEO_PATH[] = "/data/test/H264_AAC.mp4";
constexpr int32_t SET_FD_SOURCE = 3;
}

namespace OHOS {
namespace Media {
void SetSourceLocalFd(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadataStub)
{
    int32_t fileDes = open(VIDEO_PATH, O_RDONLY);
    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadataStub->GetDescriptor());
    msg.WriteFileDescriptor(fileDes);
    msg.WriteInt64(0);
    msg.WriteInt64(0);
    msg.WriteInt32(0);
    avmetadataStub->OnRemoteRequest(AVMetadataServiceProxyFuzzer::SET_FD_SOURCE, msg, reply, option);
}

const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
bool FuzzAVMetadataStubLocal(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> avmetadata = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_AVMETADATAHELPER, listener);
    if (avmetadata == nullptr) {
        return false;
    }

    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadataStub =
        iface_cast<IRemoteStub<IStandardAVMetadataHelperService>>(avmetadata);
    if (avmetadataStub == nullptr) {
        return false;
    }

    SetSourceLocalFd(avmetadataStub);
    bool isWirteToken = size >0 && data[0] % 9 != 0;
    for (uint32_t code = SET_FD_SOURCE; code <= AVMetadataServiceProxyFuzzer::MAX_IPC_ID; code++) {
        MessageParcel msg;
        if (isWirteToken) {
            msg.WriteInterfaceToken(avmetadataStub->GetDescriptor());
        }
        size_t offset = code % size;
        size_t length = size - offset;
        msg.WriteBuffer(data + offset, length);
        msg.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        avmetadataStub->OnRemoteRequest(code, msg, reply, option);
    }

    return true;
}

bool FuzzAVMetadataStubLocal2(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> avmetadata = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_AVMETADATAHELPER, listener);
    if (avmetadata == nullptr) {
        return false;
    }
 
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadataStub =
        iface_cast<IRemoteStub<IStandardAVMetadataHelperService>>(avmetadata);
    if (avmetadataStub == nullptr) {
        return false;
    }
 
    SetSourceLocalFd(avmetadataStub);
    bool isWirteToken = size >0 && data[0] % 9 != 0;
    for (uint32_t code = 0; code <= AVMetadataServiceProxyFuzzer::MAX_IPC_ID; code++) {
        MessageParcel msg;
        if (isWirteToken) {
            msg.WriteInterfaceToken(avmetadataStub->GetDescriptor());
        }
        size_t offset = code % size;
        size_t length = size - offset;
        msg.WriteBuffer(data + offset, length);
        msg.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        avmetadataStub->OnRemoteRequest(code, msg, reply, option);
    }
 
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
    OHOS::Media::FuzzAVMetadataStubLocal(data, size);
    OHOS::Media::FuzzAVMetadataStubLocal2(data, size);
    return 0;
}