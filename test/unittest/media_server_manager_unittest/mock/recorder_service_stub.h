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

#ifndef RECORDER_SERVICE_STUB_H
#define RECORDER_SERVICE_STUB_H

#include <map>
#include <set>
#include <gmock/gmock.h>
#include "i_standard_recorder_service.h"
#include "i_standard_recorder_listener.h"
#include "media_death_recipient.h"
#include "recorder_server.h"
#include "nocopyable.h"
#include "monitor_server_object.h"

namespace OHOS {
namespace Media {
class RecorderServiceStub : public IRemoteStub<IStandardRecorderService>,
    public MonitorServerObject, public NoCopyable {
public:
    static sptr<RecorderServiceStub> Create()
    {
        sptr<RecorderServiceStub> recorderStub = new(std::nothrow) RecorderServiceStub();
        return recorderStub;
    }
    virtual ~RecorderServiceStub() = default;

    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetVideoSource, (VideoSourceType source, int32_t &sourceId), (override));
    MOCK_METHOD(int32_t, SetVideoEncoder, (int32_t sourceId, VideoCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetVideoSize, (int32_t sourceId, int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, SetVideoFrameRate, (int32_t sourceId, int32_t frameRate), (override));
    MOCK_METHOD(int32_t, SetVideoEncodingBitRate, (int32_t sourceId, int32_t rate), (override));
    MOCK_METHOD(int32_t, SetVideoIsHdr, (int32_t sourceId, bool isHdr), (override));
    MOCK_METHOD(int32_t, SetVideoEnableTemporalScale, (int32_t sourceId, bool enableTemporalScale), (override));
    MOCK_METHOD(int32_t, SetVideoEnableStableQualityMode, (int32_t sourceId,
        bool enableStableQualityMode), (override));
    MOCK_METHOD(int32_t, SetMetaConfigs, (int32_t sourceId), (override));
    MOCK_METHOD(int32_t, SetMetaSource, (MetaSourceType source, int32_t &sourceId), (override));
    MOCK_METHOD(int32_t, SetMetaMimeType, (int32_t sourceId, const std::string_view &type), (override));
    MOCK_METHOD(int32_t, SetMetaTimedKey, (int32_t sourceId, const std::string_view &timedKey), (override));
    MOCK_METHOD(int32_t, SetMetaSourceTrackMime, (int32_t sourceId, const std::string_view &srcTrackMime), (override));
    MOCK_METHOD(sptr<OHOS::Surface>, GetSurface, (int32_t sourceId), (override));
    MOCK_METHOD(sptr<OHOS::Surface>, GetMetaSurface, (int32_t sourceId), (override));
    MOCK_METHOD(int32_t, SetAudioSource, (AudioSourceType source, int32_t &sourceId), (override));
    MOCK_METHOD(int32_t, SetAudioEncoder, (int32_t sourceId, AudioCodecFormat encoder), (override));
    MOCK_METHOD(int32_t, SetAudioAacProfile, (int32_t sourceId, AacProfile aacProfile), (override));
    MOCK_METHOD(int32_t, SetAudioSampleRate, (int32_t sourceId, int32_t rate), (override));
    MOCK_METHOD(int32_t, SetAudioChannels, (int32_t sourceId, int32_t num), (override));
    MOCK_METHOD(int32_t, SetAudioEncodingBitRate, (int32_t sourceId, int32_t bitRate), (override));
    MOCK_METHOD(int32_t, SetVideoEnableBFrame, (int32_t sourceId, bool enableBFrame), (override));
    MOCK_METHOD(int32_t, SetDataSource, (DataSourceType dataType, int32_t &sourceId), (override));
    MOCK_METHOD(int32_t, SetUserCustomInfo, (Meta &userCustomInfo), (override));
    MOCK_METHOD(int32_t, SetGenre, (std::string &genre), (override));
    MOCK_METHOD(int32_t, SetMaxDuration, (int32_t duration), (override));
    MOCK_METHOD(int32_t, SetOutputFormat, (OutputFormatType format), (override));
    MOCK_METHOD(int32_t, SetOutputFile, (int32_t fd), (override));
    MOCK_METHOD(int32_t, SetFileGenerationMode, (FileGenerationMode mode), (override));
    MOCK_METHOD(int32_t, SetLocation, (float latitude, float longitude), (override));
    MOCK_METHOD(int32_t, SetOrientationHint, (int32_t rotation), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, Start, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Resume, (), (override));
    MOCK_METHOD(int32_t, Stop, (bool block), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, DumpInfo, (int32_t fd), ());
    MOCK_METHOD(int32_t, GetAVRecorderConfig, (ConfigMap &configMap), (override));
    MOCK_METHOD(int32_t, GetLocation, (Location &location), (override));
    MOCK_METHOD(int32_t, GetCurrentCapturerChangeInfo, (AudioRecorderChangeInfo &changeInfo), (override));
    MOCK_METHOD(int32_t, GetAvailableEncoder, (std::vector<EncoderCapabilityData> &encoderInfo), (override));
    MOCK_METHOD(int32_t, GetMaxAmplitude, (), (override));
    MOCK_METHOD(int32_t, IsWatermarkSupported, (bool &isWatermarkSupported), (override));
    MOCK_METHOD(int32_t, SetWatermark, (std::shared_ptr<AVBuffer> &waterMarkBuffer), (override));
    MOCK_METHOD(int32_t, SetUserMeta, (const std::shared_ptr<Meta> &userMeta), (override));
    MOCK_METHOD(int32_t, SetWillMuteWhenInterrupted, (bool muteWhenInterrupted), (override));
    MOCK_METHOD(int32_t, TransmitQos, (QOS::QosLevel level), (override));
    MOCK_METHOD(int32_t, DoIpcAbnormality, (), (override));
    MOCK_METHOD(int32_t, DoIpcRecovery, (bool fromMonitor), (override));
    MOCK_METHOD(int32_t, SetListenerObjectInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoSourceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoEncoderInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetVideoSizeInner, (MessageParcel &data, MessageParcel &reply));
};
} // namespace Media
} // namespace OHOS
#endif // RECORDER_SERVICE_STUB_H
