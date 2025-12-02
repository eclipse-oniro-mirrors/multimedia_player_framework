/*
Copyright (c) 2025 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "recorderservicestubfunctions_fuzzer.h"
#include <cmath>
#include <iostream>
#include "string_ex.h"
#include "directory_ex.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "stub_common.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
RecorderServiceStubFunctionsFuzzer::RecorderServiceStubFunctionsFuzzer()
{
}

RecorderServiceStubFunctionsFuzzer::~RecorderServiceStubFunctionsFuzzer()
{
}

const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
const int32_t SET_INTERRUPT_STRATEGY = 51;
const int32_t TRANSMIT_QOS = 52;

sptr<IRemoteStub<IStandardRecorderService>> RecorderServiceStubFunctionsFuzzer::GetRecorderStub()
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> recorder = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_RECORDER, listener);
    if (recorder == nullptr) {
        return nullptr;
    }
    sptr<IRemoteStub<IStandardRecorderService>> recorderStub =
        iface_cast<IRemoteStub<IStandardRecorderService>>(recorder);
    return recorderStub;
}

void RecorderServiceStubFunctionsFuzzer::RecorderOnRemoteRequest(
    const sptr<IRemoteStub<IStandardRecorderService>>recorderStub, uint8_t *data, size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(recorderStub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    recorderStub->OnRemoteRequest(SET_INTERRUPT_STRATEGY, msg, reply, option);
    recorderStub->OnRemoteRequest(TRANSMIT_QOS, msg, reply, option);
}

void RecorderServiceStubFunctionsFuzzer::SetRecorderConfig(
    const sptr<IRemoteStub<IStandardRecorderService>>recorderStub)
{
    int32_t sourceId = GetData<int32_t>();
    recorderStub->SetVideoSource(VideoSourceType::VIDEO_SOURCE_SURFACE_YUV, sourceId);

    sourceId = GetData<int32_t>();
    recorderStub->SetMetaConfigs(sourceId);
    sourceId = GetData<int32_t>();
    recorderStub->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, sourceId);
    sourceId = GetData<int32_t>();
    const std::string_view type;
    recorderStub->SetMetaMimeType(sourceId, type);
    sourceId = GetData<int32_t>();
    const std::string_view timedKey;
    recorderStub->SetMetaTimedKey(sourceId, timedKey);
    sourceId = GetData<int32_t>();
    const std::string_view srcTrackMime;
    recorderStub->SetMetaSourceTrackMime(sourceId, srcTrackMime);

    sourceId = GetData<int32_t>();
    double fps = GetData<double>();
    recorderStub->SetCaptureRate(sourceId, fps);

    sourceId = GetData<int32_t>();
    int32_t bitRate = GetData<int32_t>();
    recorderStub->SetAudioEncodingBitRate(sourceId, bitRate);

    std::string genre;
    recorderStub->SetGenre(genre);
    int32_t duration = GetData<int32_t>();
    recorderStub->SetMaxDuration(duration);
    int32_t fd = GetData<int32_t>();
    recorderStub->SetNextOutputFile(fd);
    int32_t fileSize = GetData<int32_t>();
    recorderStub->SetMaxFileSize(fileSize);
    int32_t aacProfile = GetData<int32_t>();
    const int32_t aacSize = 3;
    aacProfile = ((aacProfile % aacSize) + aacSize) % aacSize;
    AacProfile acProfile = static_cast<AacProfile>(aacProfile);
    recorderStub->SetAudioAacProfile(sourceId, acProfile);

    sourceId = GetData<int32_t>();
    recorderStub->SetVideoIsHdr(sourceId, true);
    sourceId = GetData<int32_t>();
    recorderStub->SetVideoEnableTemporalScale(sourceId, true);
    sourceId = GetData<int32_t>();
    recorderStub->SetVideoEnableStableQualityMode(sourceId, true);
    sourceId = GetData<int32_t>();
    recorderStub->SetVideoEnableBFrame(sourceId, true);

    std::shared_ptr<AVBuffer> waterMarkBuffer;
    recorderStub->SetWatermark(waterMarkBuffer);
}

void RecorderServiceStubFunctionsFuzzer::GetRecorderConfig(
    const sptr<IRemoteStub<IStandardRecorderService>> recorderStub)
{
    int32_t sourceId = GetData<int32_t>();
    recorderStub->GetSurface(sourceId);
    sourceId = GetData<int32_t>();
    recorderStub->GetMetaSurface(sourceId);

    ConfigMap configMap;
    recorderStub->GetAVRecorderConfig(configMap);

    AudioRecorderChangeInfo changeInfo;
    recorderStub->GetCurrentCapturerChangeInfo(changeInfo);

    std::vector<EncoderCapabilityData> encoderInfo;
    recorderStub->GetAvailableEncoder(encoderInfo);

    recorderStub->GetMaxAmplitude();
}

bool RecorderServiceStubFunctionsFuzzer::FuzzRecorderServiceStubFunctions(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    sptr<IRemoteStub<IStandardRecorderService>> recorderStub = GetRecorderStub();
    if (recorderStub == nullptr) {
        return false;
    }

    SetRecorderConfig(recorderStub);
    GetRecorderConfig(recorderStub);
    bool isSupported = false;
    recorderStub->IsWatermarkSupported(isSupported);
    recorderStub->SetWillMuteWhenInterrupted(true);
    recorderStub->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE);
    RecorderOnRemoteRequest(recorderStub, data, size);
    recorderStub->DestroyStub();
    return true;
}
}

bool FuzzTestRecorderServiceStubFunctions(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }
    if (size < sizeof(int32_t)) {
        return true;
    }

    RecorderServiceStubFunctionsFuzzer testRecorder;
    return testRecorder.FuzzRecorderServiceStubFunctions(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestRecorderServiceStubFunctions(data, size);
    return 0;
}