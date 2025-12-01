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

static const int32_t VIDEO_WIDTH = 10;
static const int32_t VIDEO_HEIGHT = 5;
static const int32_t VIDEO_FRAME_RATE = 60;
static const int32_t VIDEO_ENCODING_BIT_RATE = 48000;
static const int32_t AUDIO_ENCODING_BIT_RATE = 48000;
static const int32_t AUDIO_SAMPLE_RATE = 48000;
static const int32_t AUDIO_CHANNELS = 2;
std::shared_ptr<RecorderServer> recoderServer;
enum RecorderServiceMsg {
    SET_ORIENTATION_HINT = 1,
    SET_VIDEO_ENCODER = 2,
    SET_VIDEO_SIZE = 3,
    SET_VIDEO_FARAME_RATE = 4,
    SET_VIDEO_ENCODING_BIT_RATE = 5,
    SET_AUDIO_ENCODING_BIT_RATE = 6,
    SET_VIDEO_IS_HDR = 7,
    SET_VIDEO_ENABLE_TEMPORAL_SCALE = 8,
    SET_VIDEO_ENABLE_STABLE_QUALITY_MODE = 9,
    SET_VIDEO_ENABLE_B_FRAME = 10,
    SET_META_MIME_TYPE = 11,
    SET_META_TIMED_KEY = 12,
    SET_CAPTURE_RATE = 13,
    SET_AUDIO_ENCODER = 14,
    SET_AUDIO_SAMPLE_RATE = 15,
    SET_AUDIO_CHANNELS = 16,
    SET_MAX_DURATION = 17,
    SET_MAX_FILE_SIZE = 18,
    SET_LOCATION = 19,
    SET_AUDIO_AACPROFILE = 20,
};

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::shared_ptr<IRecorderService> tempServer = RecorderServer::Create();
    if (tempServer) {
        recoderServer = std::static_pointer_cast<RecorderServer>(tempServer);
        int32_t sourceId = 256;
        recoderServer->SetVideoSource(VideoSourceType::VIDEO_SOURCE_SURFACE_YUV, sourceId);
        recoderServer->SetOutputFormat(OutputFormatType::FORMAT_MPEG_4);
    }
    return 0;
}


extern "C" int FuzzRecorderConconcurrentTestOne(FuzzedDataProvider& provider)
{
    if (recoderServer == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        1, 2, 3, 4, 5
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_ORIENTATION_HINT: {
            int32_t rotation = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetOrientationHint(rotation);
            break;
        }
        case SET_VIDEO_ENCODER: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEncoder(sourceId, VideoCodecFormat::MPEG4);
            break;
        }
        case SET_VIDEO_SIZE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoSize(sourceId, VIDEO_WIDTH, VIDEO_HEIGHT);
            break;
        }
        case SET_VIDEO_FARAME_RATE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoFrameRate(sourceId, VIDEO_FRAME_RATE);
            break;
        }
        case SET_VIDEO_ENCODING_BIT_RATE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEncodingBitRate(sourceId, VIDEO_ENCODING_BIT_RATE);
            break;
        }
        
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzRecorderConconcurrentTestTwo(FuzzedDataProvider& provider)
{
    if (recoderServer == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        6, 7, 8, 9, 10
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_AUDIO_ENCODING_BIT_RATE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioEncodingBitRate(sourceId, AUDIO_ENCODING_BIT_RATE);
            break;
        }
        case SET_VIDEO_IS_HDR: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoIsHdr(sourceId, true);
            break;
        }
        case SET_VIDEO_ENABLE_TEMPORAL_SCALE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableTemporalScale(sourceId, true);
            break;
        }
        case SET_VIDEO_ENABLE_STABLE_QUALITY_MODE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableStableQualityMode(sourceId, true);
            break;
        }
        case SET_VIDEO_ENABLE_B_FRAME: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetVideoEnableBFrame(sourceId, true);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzRecorderConconcurrentTestThree(FuzzedDataProvider& provider)
{
    if (recoderServer == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        11, 12, 13, 14, 15
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_META_MIME_TYPE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            const std::string_view type;
            recoderServer->SetMetaMimeType(sourceId, type);
            break;
        }
        case SET_META_TIMED_KEY: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            const std::string_view timedKey;
            recoderServer->SetMetaTimedKey(sourceId, timedKey);
            break;
        }
        case SET_CAPTURE_RATE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            double fps = provider.ConsumeFloatingPoint<double>();
            recoderServer->SetCaptureRate(sourceId, fps);
            break;
        }
        case SET_AUDIO_ENCODER: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioEncoder(sourceId, AudioCodecFormat::AUDIO_MPEG);
            break;
        }
        
        default:
            break;
    }
    return 0;
}

extern "C" int FuzzRecorderConconcurrentTestFour(FuzzedDataProvider& provider)
{
    if (recoderServer == nullptr) {
        return 0;
    }
    static const int ipccodes[] = {
        16, 17, 18, 19, 20
    };
    int code = provider.PickValueInArray(ipccodes);
    switch (code) {
        case SET_AUDIO_SAMPLE_RATE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioSampleRate(sourceId, AUDIO_SAMPLE_RATE);
            break;
        }
        case SET_AUDIO_CHANNELS: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioChannels(sourceId, AUDIO_CHANNELS);
            break;
        }
        case SET_MAX_DURATION: {
            int32_t duration = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetMaxDuration(duration);
            break;
        }
        case SET_MAX_FILE_SIZE: {
            int64_t len = provider.ConsumeIntegral<uint64_t>();
            recoderServer->SetMaxFileSize(len);
            break;
        }
        case SET_LOCATION: {
            float latitude = provider.ConsumeFloatingPoint<float>();
            float longitude = provider.ConsumeFloatingPoint<float>();
            recoderServer->SetLocation(latitude, longitude);
            break;
        }
        case SET_AUDIO_AACPROFILE: {
            int32_t sourceId = provider.ConsumeIntegral<uint32_t>();
            recoderServer->SetAudioAacProfile(sourceId, AacProfile::AAC_LC);
            break;
        }
        default:
            break;
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
    FuzzRecorderConconcurrentTestOne(provider);
    FuzzRecorderConconcurrentTestTwo(provider);
    FuzzRecorderConconcurrentTestThree(provider);
    FuzzRecorderConconcurrentTestFour(provider);
    return 0;
}
