/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avmetadatahelperdatasrcconcurrent_fuzzer.h"

#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <filesystem>
#include "fuzzer/FuzzedDataProvider.h"
#include "media_log.h"
#include "stub_common.h"
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_avmetadatahelper_service.h"
#include "media_data_source_stub.h"

namespace {
constexpr char VIDEO_PATH[] = "/data/local/tmp/test.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
}  // namespace

namespace OHOS {
namespace Media {
class IMediaDataSourceImpl : public IMediaDataSource {
public:
    IMediaDataSourceImpl(int32_t fd, size_t size) : fd_(fd), size_(size) {}

    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override
    {
        if (mem == nullptr) {
            return 0;
        }
        if (pos + static_cast<int64_t>(length) >= static_cast<int64_t>(size_)) {
            return -1;
        }
        if (pos > 0) {
            lseek(fd_, pos, SEEK_SET);
        }
        return read(fd_, mem->GetBase(), length);
    }

    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override
    {
        if (mem == nullptr) {
            return 0;
        }
        if (static_cast<int64_t>(length) >= static_cast<int64_t>(size_)) {
            return -1;
        }
        return read(fd_, mem->GetBase(), length);
    }

    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1) override
    {
        return ReadAt(pos, length, mem);
    }

    int32_t GetSize(int64_t &size) override
    {
        return static_cast<int32_t>(size_);
    }

private:
    int32_t fd_{ 0 };
    size_t size_{ 0 };
};

sptr<IRemoteStub<IStandardAVMetadataHelperService>> CreateFuzzavmetadatahelper()
{
    std::shared_ptr<MediaServer> mediaServer = std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    if (mediaServer == nullptr) {
        return nullptr;
    }
    
    sptr<IRemoteObject> listener = new (std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> avmetadata =
        mediaServer->GetSubSystemAbility(IStandardMediaService::MediaSystemAbility::MEDIA_AVMETADATAHELPER, listener);
    return iface_cast<IRemoteStub<IStandardAVMetadataHelperService>>(avmetadata);
}

void FuzzavmetadatahelperSetSource(
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper, MediaDataSourceStub *&dataSrcStub)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    int32_t fileDes = open(VIDEO_PATH, O_RDONLY);
    if (fileDes < 0) {
        return;
    }
    struct stat64 st;
    fstat(fileDes, &st);
    const std::shared_ptr<IMediaDataSource> src = std::make_shared<IMediaDataSourceImpl>(fileDes, st.st_size);
    dataSrcStub = new (std::nothrow) MediaDataSourceStub(src);
    if (dataSrcStub == nullptr) {
        return;
    }
    sptr<IRemoteObject> object = dataSrcStub->AsObject();

    if (object == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    msg.WriteRemoteObject(object);
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::SET_MEDIA_DATA_SRC_OBJ, msg, reply, option);
}

void FuzzavmetadatahelperResolveMetadata(
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper, int32_t randomKey)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    msg.WriteInt64(randomKey);
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::RESOLVE_METADATA, msg, reply, option);
}

void FuzzavmetadatahelperResolveMetadataMap(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::RESOLVE_METADATA_MAP, msg, reply, option);
}

void FuzzavmetadatahelperFetchAlbumCover(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::FETCH_ALBUM_COVER, msg, reply, option);
}

void FuzzavmetadatahelperFetchFrame(
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper, int32_t randomTimeUs, int32_t randomInt32)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());

    msg.WriteInt64(randomTimeUs);
    msg.WriteInt32(randomInt32);
    msg.WriteInt32(randomInt32);
    msg.WriteInt32(randomInt32);
    msg.WriteInt32(randomInt32);
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::FETCH_FRAME_AT_TIME, msg, reply, option);
    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::FETCH_FRAME_YUV, msg, reply, option);
}

void FuzzavmetadatahelperGetAVMeta(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());

    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::GET_AVMETADATA, msg, reply, option);
}

void FuzzavmetadatahelperGetTimeByFrameIndex(
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper, int32_t data)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    uint32_t randomU32 = static_cast<uint32_t>(data);

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    msg.WriteUint32(randomU32);

    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::GET_TIME_BY_FRAME_INDEX, msg, reply, option);
}

void FuzzavmetadatahelperGetFrameIndexByTime(
    sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper, int32_t data)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    uint32_t randomU64 = static_cast<uint64_t>(data);

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());
    msg.WriteUint64(randomU64);

    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::GET_FRAME_INDEX_BY_TIME, msg, reply, option);
}

void FuzzavmetadatahelperRelease(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());

    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::RELEASE, msg, reply, option);
}

void FuzzavmetadatahelperDestroy(sptr<IRemoteStub<IStandardAVMetadataHelperService>> avmetadatahelper)
{
    if (avmetadatahelper == nullptr) {
        return;
    }

    MessageParcel msg;
    MessageParcel reply;
    MessageOption option;

    msg.WriteInterfaceToken(avmetadatahelper->GetDescriptor());

    avmetadatahelper->OnRemoteRequest(IStandardAVMetadataHelperService::DESTROY, msg, reply, option);
}

static sptr<IRemoteStub<OHOS::Media::IStandardAVMetadataHelperService>> avmetadatahelper = nullptr;
}  // namespace Media
}  // namespace OHOS




extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    OHOS::Media::avmetadatahelper = OHOS::Media::CreateFuzzavmetadatahelper();
    OHOS::Media::MediaDataSourceStub *dataSrcStub = nullptr;
    OHOS::Media::FuzzavmetadatahelperSetSource(OHOS::Media::avmetadatahelper, dataSrcStub);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    int fd = open(VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return 0;
    }
    int len = write(fd, data, size);
    if (len <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    FuzzedDataProvider fdp(data, size);
    
    static const int ipccodes[] = {1, 2, 3, 4, 5, 6, 7};
    int code = fdp.PickValueInArray(ipccodes);
        
    switch (code) {
        case 1: {
            OHOS::Media::FuzzavmetadatahelperResolveMetadata(OHOS::Media::avmetadatahelper, fdp.ConsumeIntegral<int32_t>());
            break;
        }
        case 2: {
            OHOS::Media::FuzzavmetadatahelperResolveMetadataMap(OHOS::Media::avmetadatahelper);
            break;
        }
        case 3: {
            OHOS::Media::FuzzavmetadatahelperFetchAlbumCover(OHOS::Media::avmetadatahelper);
            break;
        }
        case 4: {
            OHOS::Media::FuzzavmetadatahelperFetchFrame(
                OHOS::Media::avmetadatahelper, fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
            break;
        }
        case 5: {
            OHOS::Media::FuzzavmetadatahelperGetAVMeta(OHOS::Media::avmetadatahelper);
            break;
        }
        case 6: {
            OHOS::Media::FuzzavmetadatahelperGetTimeByFrameIndex(OHOS::Media::avmetadatahelper, fdp.ConsumeIntegral<int32_t>());
            break;
        }
        case 7: {
            OHOS::Media::FuzzavmetadatahelperGetFrameIndexByTime(OHOS::Media::avmetadatahelper, fdp.ConsumeIntegral<int32_t>());
            break;
        }
    }
    return 0;
}