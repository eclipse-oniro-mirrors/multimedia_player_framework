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

#ifndef TRANSCODER_SERVICE_STUB_H
#define TRANSCODER_SERVICE_STUB_H

#include <map>
#include <set>
#include <gmock/gmock.h>
#include "i_standard_transcoder_service.h"
#include "i_standard_transcoder_listener.h"
#include "media_death_recipient.h"
#include "transcoder_server.h"
#include "nocopyable.h"
#include "monitor_server_object.h"

namespace OHOS {
namespace Media {
class TransCoderServiceStub : public IRemoteStub<IStandardTransCoderService>,
    public MonitorServerObject, public NoCopyable {
public:
    static sptr<TransCoderServiceStub> Create()
    {
        sptr<TransCoderServiceStub> transcoderStub = new(std::nothrow) TransCoderServiceStub();
        return transcoderStub;
    }
    virtual ~TransCoderServiceStub() = default;

    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetVideoEncoder, (VideoCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetVideoSize, (int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, SetVideoEncodingBitRate, (int32_t rate), (override));
    MOCK_METHOD(int32_t, SetColorSpace, (TranscoderColorSpace colorSpaceFormat), (override));
    MOCK_METHOD(int32_t, SetEnableBFrame, (bool enableBFrame), (override));
    MOCK_METHOD(int32_t, SetAudioEncoder, (AudioCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetAudioEncodingBitRate, (int32_t bitRate), (override));
    MOCK_METHOD(int32_t, SetOutputFormat, (OutputFormatType format), (override));
    MOCK_METHOD(int32_t, SetInputFile, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, SetOutputFile, (int32_t fd), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, Start, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Resume, (), (override));
    MOCK_METHOD(int32_t, Cancel, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, DumpInfo, (int32_t fd), ());
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, DoIpcAbnormality, (), (override));
    MOCK_METHOD(int32_t, DoIpcRecovery, (bool fromMonitor), (override));
    MOCK_METHOD(int32_t, SetListenerObjectInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoEncoderInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoSizeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoEncodingBitRateInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetColorSpaceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetAudioEncoderInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetAudioEncodingBitRateInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetOutputFormatInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetInputFileUrlInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetInputFileFdInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetOutputFileInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, PrepareInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, StartInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, PauseInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ResumeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, CancelInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ReleaseInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, DestroyStubInner, (MessageParcel &data, MessageParcel &reply));
};
} // namespace Media
} // namespace OHOS
#endif // TRANSCODER_SERVICE_STUB_H
