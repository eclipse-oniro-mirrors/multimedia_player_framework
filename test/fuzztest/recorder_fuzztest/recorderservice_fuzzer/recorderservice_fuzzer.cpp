/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cmath>
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "recorder.h"
#include "recorderservice_fuzzer.h"
#include "i_standard_recorder_service.h"
#include "i_recorder_service.h"
#include "test_template.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
RecorderServiceFuzzer::RecorderServiceFuzzer()
{
}

RecorderServiceFuzzer::~RecorderServiceFuzzer()
{
}

const uint32_t VIDEO_FRMAME_RATE = 60;
const uint32_t VIDEO_ENCODING_BIT_RATE = 48000;
const uint32_t VIDEO_FRAME_WIDTH = 10;
const uint32_t VIDEO_FRAME_HEIGHT = 5;
const uint32_t VIDEO_CHANNEL_NO = 2;

void InitFunctions(const std::shared_ptr<RecorderServer> recoderServer)
{
    int32_t sourceId = GetData<int32_t>();
    recoderServer->SetVideoSource(VideoSourceType::VIDEO_SOURCE_SURFACE_YUV, sourceId);
    recoderServer->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, sourceId);
    const std::shared_ptr<IAudioDataSource> audioSource;
    recoderServer->SetAudioDataSource(audioSource, sourceId);
    recoderServer->SetWillMuteWhenInterrupted(true);
    recoderServer->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4);
    int32_t rotation = GetData<int32_t>();
    recoderServer->SetOrientationHint(rotation);
}

void ConfigureFunctions(const std::shared_ptr<RecorderServer> recoderServer)
{
    int32_t sourceId = GetData<int32_t>();
    recoderServer->SetVideoEncoder(sourceId, VideoCodecFormat::MPEG4);
    recoderServer->SetVideoSize(sourceId, VIDEO_FRAME_WIDTH, VIDEO_FRAME_HEIGHT);
    recoderServer->SetVideoFrameRate(sourceId, VIDEO_FRMAME_RATE);
    recoderServer->SetVideoEncodingBitRate(sourceId, VIDEO_ENCODING_BIT_RATE);
    recoderServer->SetAudioEncodingBitRate(sourceId, VIDEO_ENCODING_BIT_RATE);
    recoderServer->SetVideoIsHdr(sourceId, true);
    recoderServer->SetVideoEnableTemporalScale(sourceId, true);
    recoderServer->SetVideoEnableStableQualityMode(sourceId, true);
    recoderServer->SetVideoEnableBFrame(sourceId, true);
    const std::string_view type;
    recoderServer->SetMetaMimeType(sourceId, type);
    const std::string_view timedKey;
    recoderServer->SetMetaTimedKey(sourceId, timedKey);
    const std::string_view srcTrackMime;
    recoderServer->SetMetaSourceTrackMime(sourceId, srcTrackMime);
    double fps = GetData<double>();
    recoderServer->SetCaptureRate(sourceId, fps);
    recoderServer->SetAudioEncoder(sourceId, AudioCodecFormat::AUDIO_MPEG);
    recoderServer->SetAudioSampleRate(sourceId, VIDEO_ENCODING_BIT_RATE);
    recoderServer->SetAudioChannels(sourceId, VIDEO_CHANNEL_NO);
    Meta userCustomInfo;
    recoderServer->SetUserCustomInfo(userCustomInfo);
    std::string genre;
    recoderServer->SetGenre(genre);
    int32_t duration = GetData<int32_t>();
    recoderServer->SetMaxDuration(duration);
    int32_t fd = GetData<int32_t>();
    recoderServer->SetOutputFile(fd);
    recoderServer->SetFileGenerationMode(FileGenerationMode::AUTO_CREATE_CAMERA_SCENE);
    recoderServer->SetNextOutputFile(fd);
    int64_t size = GetData<int32_t>();
    recoderServer->SetMaxFileSize(size);
    float latitude = GetData<int32_t>();
    float longitude = GetData<int32_t>();
    recoderServer->SetLocation(latitude, longitude);
    recoderServer->SetAudioAacProfile(sourceId, AacProfile::AAC_LC);
}

bool RecorderServiceFuzzer::FuzzRecorderService(uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2 * sizeof(int32_t)) {  // 2 input params
        return false;
    }
    std::shared_ptr<RecorderServer> recoderServer;
    std::shared_ptr<IRecorderService> tempServer = RecorderServer::Create();
    if (tempServer == nullptr) {
        return false;
    }
    recoderServer = std::static_pointer_cast<RecorderServer>(tempServer);
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    int32_t sourceId = GetData<int32_t>();
    InitFunctions(recoderServer);
    ConfigureFunctions(recoderServer);
    recoderServer->Prepare();
    recoderServer->SetMetaConfigs(sourceId);
    ConfigMap configMap;
    recoderServer->GetAVRecorderConfig(configMap);
    AudioRecorderChangeInfo changeInfo;
    recoderServer->GetCurrentCapturerChangeInfo(changeInfo);
    recoderServer->GetSurface(sourceId);
    recoderServer->GetMetaSurface(sourceId);
    std::shared_ptr<AVBuffer> waterMarkBuffer;
    recoderServer->SetWatermark(waterMarkBuffer);
    const std::shared_ptr<Meta> userMeta;
    recoderServer->SetUserMeta(userMeta);
    int64_t timestamp = GetData<int64_t>();
    uint32_t duration = GetData<uint32_t>();
    recoderServer->SetFileSplitDuration(FileSplitType::FILE_SPLIT_NORMAL, timestamp, duration);
    std::vector<EncoderCapabilityData> encoderInfo;
    recoderServer->GetAvailableEncoder(encoderInfo);
    recoderServer->GetMaxAmplitude();
    recoderServer->Start();
    recoderServer->Pause();
    recoderServer->Resume();
    recoderServer->Stop(true);
    recoderServer->Reset();
    bool isSupported = false;
    recoderServer->IsWatermarkSupported(isSupported);
    recoderServer->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE);
    return true;
}
} // namespace Media

bool FuzzTestRecorderService(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < 2 * sizeof(int32_t)) { // 2 input params
        return true;
    }
    RecorderServiceFuzzer testRecorder;
    return testRecorder.FuzzRecorderService(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestRecorderService(data, size);
    return 0;
}