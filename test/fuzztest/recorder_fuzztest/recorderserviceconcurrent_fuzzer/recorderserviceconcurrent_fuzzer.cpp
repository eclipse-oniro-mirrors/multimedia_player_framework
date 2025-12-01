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
#include "recorderserviceconcurrent_fuzzer.h"
#include "i_standard_recorder_service.h"
#include "i_recorder_service.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS;
using namespace Media;

std::shared_ptr<RecorderServer> recoderServer;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    std::shared_ptr<IRecorderService> tempServer = RecorderServer::Create();
    if (tempServer) {
        recoderServer = std::static_pointer_cast<RecorderServer>(tempServer);
        int32_t sourceId = 256;
        recoderServer->SetVideoSource(VideoSourceType::VIDEO_SOURCE_SURFACE_YUV, sourceId);
        recoderServer->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4);
    }
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (recoderServer == nullptr || data == nullptr) {
        return 0;
    }
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    static const int ipccodes[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16, 17, 18, 19, 20
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case 1: {
            int32_t rotation = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetOrientationHint(rotation);
            break;
        }
        case 2: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEncoder(sourceId, VideoCodecFormat::MPEG4);
            break;
        }
        case 3: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoSize(sourceId, 10, 5);
            break;
        }
        case 4: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoFrameRate(sourceId, 60);
            break;
        }
        case 5: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEncodingBitRate(sourceId, 48000);
            break;
        }
        case 6: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioEncodingBitRate(sourceId, 48000);
            break;
        }
        case 7: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoIsHdr(sourceId, true);
            break;
        }
        case 8: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableTemporalScale(sourceId, true);
            break;
        }
        case 9: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableStableQualityMode(sourceId, true);
            break;
        }
        case 10: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableBFrame(sourceId, true);
            break;
        }
        case 11: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            const std::string_view type;
            recoderServer->SetMetaMimeType(sourceId, type);
            break;
        }
        case 12: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            const std::string_view timedKey;
            recoderServer->SetMetaTimedKey(sourceId, timedKey);
            break;
        }
        case 13: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            double fps = provider.ConsumeFloatingPoint<double>();
            recoderServer->SetCaptureRate(sourceId, fps);
            break;
        }
        case 14: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioEncoder(sourceId, AudioCodecFormat::AUDIO_MPEG);
            break;
        }
        case 15: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioSampleRate(sourceId, 48000);
            break;
        }
        case 16: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioChannels(sourceId, 2);
            break;
        }
        case 17: {
            int32_t duration = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetMaxDuration(duration);
            break;
        }
        case 18: {
            int64_t len = provider.ConsumeIntegral<uint64_t>();
            recoderServer->SetMaxFileSize(len);
            break;
        }
        case 19: {
            float latitude = provider.ConsumeFloatingPoint<float>();
            float longitude = provider.ConsumeFloatingPoint<float>();
            recoderServer->SetLocation(latitude, longitude);
            break;
        }
        case 20: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioAacProfile(sourceId, AacProfile::AAC_LC);
            break;
        }
    }
    return 0;
}
