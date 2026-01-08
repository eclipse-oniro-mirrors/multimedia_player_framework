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

#ifndef AVMETADATAHELPER_SERVICE_STUB_H
#define AVMETADATAHELPER_SERVICE_STUB_H

#include <map>
#include <gmock/gmock.h>
#include "i_standard_avmetadatahelper_service.h"
#include "media_death_recipient.h"
#include "avmetadatahelper_server.h"
#include "i_standard_helper_listener.h"
#include "helper_listener_proxy.h"

namespace OHOS {
namespace Media {
using AVMetadataHelperStubFunc = std::function<int32_t (MessageParcel &, MessageParcel &)>;
class AVMetadataHelperServiceStub : public IRemoteStub<IStandardAVMetadataHelperService>, public NoCopyable {
public:
    static sptr<AVMetadataHelperServiceStub> Create()
    {
        sptr<AVMetadataHelperServiceStub> avMetadataStub = new(std::nothrow) AVMetadataHelperServiceStub();
        return avMetadataStub;
    }
    virtual ~AVMetadataHelperServiceStub() = default;

    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::string &uri, int32_t usage), (override));
    MOCK_METHOD(int32_t, SetAVMetadataCaller, (AVMetadataCaller caller), (override));
    MOCK_METHOD(int32_t, SetUrlSource, (const std::string &uri,
        (const std::map<std::string, std::string> &header)), (override));
    MOCK_METHOD(int32_t, SetSource, (int32_t fd, int64_t offset, int64_t size, int32_t usage), (override));
    MOCK_METHOD(int32_t, SetSource, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(std::string, ResolveMetadata, (int32_t key), (override));
    MOCK_METHOD(int32_t, CancelAllFetchFrames, (), (override));
    MOCK_METHOD((std::unordered_map<int32_t, std::string>), ResolveMetadataMap, (), (override));
    MOCK_METHOD(std::shared_ptr<Meta>, GetAVMetadata, (), (override));
    MOCK_METHOD(std::shared_ptr<AVSharedMemory>, FetchArtPicture, (), (override));
    MOCK_METHOD(std::shared_ptr<AVSharedMemory>, FetchFrameAtTime, (int64_t timeUs, int32_t option,
        const OutputConfiguration &param), (override));
    MOCK_METHOD(std::shared_ptr<AVBuffer>, FetchFrameYuv, (int64_t timeUs,
        int32_t option, const OutputConfiguration &param), (override));
    MOCK_METHOD(int32_t, FetchFrameYuvs, (const std::vector<int64_t>& timeUs,
        int32_t option, const PixelMapParams &param), (override));
    MOCK_METHOD(void, Release, (), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, SetHelperCallback, (), (override));
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, GetTimeByFrameIndex, (uint32_t index, uint64_t &time), (override));
    MOCK_METHOD(int32_t, GetFrameIndexByTime, (uint64_t time, uint32_t &index), (override));
    MOCK_METHOD(int32_t, SetUriSourceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetAVMetadataCallerInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetUrlSourceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetFdSourceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetMediaDataSourceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ResolveMetadataInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ResolveMetadataMapInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetAVMetadataInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, FetchArtPictureInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, FetchFrameAtTimeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, FetchFrameYuvInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, FetchFrameYuvsInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ReleaseInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, DestroyStubInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetHelperCallbackInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetListenerObjectInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetTimeByFrameIndexInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetFrameIndexByTimeInner, (MessageParcel &data, MessageParcel &reply));
};
} // namespace Media
} // namespace OHOS
#endif // AVMETADATAHELPER_SERVICE_STUB_H
