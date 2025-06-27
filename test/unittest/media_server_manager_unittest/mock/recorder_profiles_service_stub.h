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

#ifndef RECORDERPROFILES_SERVICE_STUB_H
#define RECORDERPROFILES_SERVICE_STUB_H

#include <map>
#include <gmock/gmock.h>
#include "i_standard_recorder_profiles_service.h"
#include "media_death_recipient.h"
#include "recorder_profiles_server.h"
#include "nocopyable.h"
#include "media_parcel.h"
#include "recorder_profiles_parcel.h"

namespace OHOS {
namespace Media {
class RecorderProfilesServiceStub : public IRemoteStub<IStandardRecorderProfilesService>, public NoCopyable {
public:
    static sptr<RecorderProfilesServiceStub> Create()
    {
        sptr<RecorderProfilesServiceStub> profileStub = new(std::nothrow) RecorderProfilesServiceStub();
        return profileStub;
    }
    virtual ~RecorderProfilesServiceStub() = default;

    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(bool, IsAudioRecorderConfigSupported, (const RecorderProfilesData &profile), (override));
    MOCK_METHOD(bool, HasVideoRecorderProfile, (int32_t sourceId, int32_t qualityLevel), (override));
    MOCK_METHOD(std::vector<RecorderProfilesData>, GetAudioRecorderCapsInfo, (), (override));
    MOCK_METHOD(std::vector<RecorderProfilesData>, GetVideoRecorderCapsInfo, (), (override));
    MOCK_METHOD(RecorderProfilesData, GetVideoRecorderProfileInfo, (int32_t sourceId,
        int32_t qualityLevel), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, IsAudioRecorderConfigSupportedInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, HasVideoRecorderProfileInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetAudioRecorderCapsInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetVideoRecorderCapsInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetVideoRecorderProfileInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, DestroyStubInner, (MessageParcel &data, MessageParcel &reply));
};
}  // namespace Media
}  // namespace OHOS
#endif  // RECORDERPROFILES_SERVICE_STUB_H
