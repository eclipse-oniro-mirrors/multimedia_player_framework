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

#include "transcoderservicestubconcurrent_fuzzer.h"
#include <cmath>
#include <iostream>
#include "string_ex.h"
#include "directory_ex.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_transcoder_service.h"
#include "stub_common.h"
#include "media_log.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
TranscoderServiceStubFuzzerConcurrent::TranscoderServiceStubFuzzerConcurrent()
{
}

TranscoderServiceStubFuzzerConcurrent::~TranscoderServiceStubFuzzerConcurrent()
{
}
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, LOG_DOMAIN_PLAYER, "TranscoderServiceStubFuzzerConcurrent" };
constexpr char INPUT_VIDEO_PATH[] = "/data/local/tmp/input.mp4";
constexpr char OUTPUT_VIDEO_PATH[] = "/data/local/tmp/output.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
sptr<IRemoteStub<IStandardTransCoderService>> transcoderStub;

bool TranscoderServiceStubFuzzerConcurrent::FuzzTranscoderOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    static const int ipccodes[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
    };
    int code = provider.PickValueInArray(ipccodes);
    int colorSpaceArr[] = {
        TranscoderColorSpace::TRANSCODER_COLORSPACE_NONE,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT601_EBU_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT601_SMPTE_C_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT709_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT2020_HLG_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT2020_PQ_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT601_EBU_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT601_SMPTE_C_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT709_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT2020_HLG_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_BT2020_PQ_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_SRGB_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_HLG_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_PQ_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_ADOBERGB_FULL,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_SRGB_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_HLG_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_P3_PQ_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_ADOBERGB_LIMIT,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_LINEAR_SRGB,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_LINEAR_BT709,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_LINEAR_P3,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_LINEAR_BT2020,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_SRGB,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_P3_SRGB,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_P3_HLG,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_P3_PQ,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_BT2020_SRGB,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_BT2020_HLG,
        TranscoderColorSpace::TRANSCODER_COLORSPACE_DISPLAY_BT2020_PQ
    };
    switch (code) {
        case 1: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
            CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

            int encoderType = provider.ConsumeIntegral<int32_t>();
            int32_t encoderArr[] = { VideoCodecFormat::VIDEO_DEFAULT, VideoCodecFormat::H264, VideoCodecFormat::MPEG4,
                VideoCodecFormat::H265, VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT };
            int32_t index = encoderType % std::size(encoderArr);
            int32_t value = encoderArr[std::abs(index)];
            dataSend.WriteInt32(value);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, dataSend, reply, option);
            break;
        }
        case 2: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int width = provider.ConsumeIntegral<int32_t>();
            int height = provider.ConsumeIntegral<int32_t>();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
            dataSend.WriteInt32(width);
            dataSend.WriteInt32(height);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_SIZE, dataSend, reply, option);
            break;
        }
        case 3: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int rate = provider.ConsumeIntegral<int32_t>();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
            dataSend.WriteInt32(rate);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODING_BIT_RATE, dataSend, reply, option);
            break;
        }
        case 4: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int encoderType = provider.ConsumeIntegral<int32_t>();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
            int32_t index = encoderType % std::size(colorSpaceArr);
            int32_t value = colorSpaceArr[std::abs(index)];
            dataSend.WriteInt32(value);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_COLOR_SPACE, dataSend, reply, option);
            break;
        }
        case 5: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int enableBframe = provider.ConsumeBool();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
            dataSend.WriteInt32(enableBframe);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_ENABLE_B_FRAME, dataSend, reply, option);
            break;
        }
        case 6: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int audioEncoderType = provider.ConsumeIntegral<int32_t>();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

            int32_t encoderArr[] = { AudioCodecFormat::AUDIO_DEFAULT, AudioCodecFormat::AAC_LC,
                AudioCodecFormat::AUDIO_MPEG, AudioCodecFormat::AUDIO_G711MU,
                AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT };
            int32_t index = audioEncoderType % std::size(encoderArr);
            int32_t value = encoderArr[std::abs(index)];
            dataSend.WriteInt32(value);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, dataSend, reply, option);
            break;
        }
        case 7: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            int audioBitrate = provider.ConsumeIntegral<int32_t>();
            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");
            dataSend.WriteInt32(audioBitrate);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, dataSend, reply, option);
            break;
        }
        case 8: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

            int outputFormat = provider.ConsumeIntegral<int32_t>();
            int32_t outputFormatArr[] = { OutputFormatType::FORMAT_DEFAULT, OutputFormatType::FORMAT_MPEG_4,
                OutputFormatType::FORMAT_M4A, OutputFormatType::FORMAT_MP3, OutputFormatType::FORMAT_WAV,
                OutputFormatType::FORMAT_BUTT };
            int32_t index = outputFormat % std::size(outputFormatArr);
            int32_t value = outputFormatArr[std::abs(index)];
            dataSend.WriteInt32(value);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, dataSend, reply, option);
            break;
        }
        case 9: {
            break;
        }
        case 10: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
           CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

            int fdInput = open(INPUT_VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            if (fdInput < 0) {
                return false;
            }
            dataSend.WriteFileDescriptor(fdInput);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_INPUT_FILE_FD, dataSend, reply, option);
            close(fdInput);
            break;
        }
        case 11: {
            MessageParcel dataSend;
            MessageParcel reply;
            MessageOption option;

            bool token = dataSend.WriteInterfaceToken(transcoderStub->GetDescriptor());
            CHECK_AND_RETURN_RET_LOG(token, false, "Failed to write descriptor!");

            int fdOutput = open(OUTPUT_VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            if (fdOutput < 0) {
                return false;
            }
            dataSend.WriteFileDescriptor(fdOutput);
            transcoderStub->OnRemoteRequest(
                IStandardTransCoderService::RecorderServiceMsg::SET_OUTPUT_FILE, dataSend, reply, option);
            close(fdOutput);
            break;
        }
        default:
            break;
    }
    return true;
}
}

bool FuzzTestTranscoderOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    TranscoderServiceStubFuzzerConcurrent testTranscoder;
    return testTranscoder.FuzzTranscoderOnRemoteRequest(data, size);
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> transcoder = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_TRANSCODER, listener);
    if (transcoder == nullptr) {
        return 0;
    }
    transcoderStub =
        iface_cast<IRemoteStub<IStandardTransCoderService>>(transcoder);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestTranscoderOnRemoteRequest(data, size);
    return 0;
}