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

#include "transcoderstubconcurrent_fuzzer.h"
#include <cmath>
#include <iostream>
#include "string_ex.h"
#include "directory_ex.h"
#include <unistd.h>
#include <numeric>
#include "fuzzer/FuzzedDataProvider.h"
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_transcoder_service.h"
#include "stub_common.h"
#include "media_log.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "TranscoderStubConcurrentFuzzTest" };
constexpr char INPUT_VIDEO_PATH[] = "/data/local/tmp/input.mp4";
constexpr char OUTPUT_VIDEO_PATH[] = "/data/local/tmp/output.mp4";
constexpr int32_t SYSTEM_ABILITY_ID = 3002;
constexpr bool RUN_ON_CREATE = false;
constexpr uint32_t SECOND_TWO = 2;
}  // namespace

namespace OHOS {
namespace Media {
sptr<IRemoteStub<IStandardTransCoderService>> CreateFuzzTranscoder()
{
    std::shared_ptr<MediaServer> mediaServer = std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new (std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> transcoder =
        mediaServer->GetSubSystemAbility(IStandardMediaService::MediaSystemAbility::MEDIA_TRANSCODER, listener);
    return iface_cast<IRemoteStub<IStandardTransCoderService>>(transcoder);
}

void FuzzTranscoderSetVideoEncoder(sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t encoderType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int32_t encoderArr[] = { VideoCodecFormat::VIDEO_DEFAULT, VideoCodecFormat::H264, VideoCodecFormat::MPEG4,
        VideoCodecFormat::H265, VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT };
    int32_t index = encoderType % std::size(encoderArr);
    int32_t value = encoderArr[std::abs(index)];
    data.WriteInt32(value);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, data, reply, option);
}

void FuzzTranscoderSetVideoSize(sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t width, int32_t height)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    data.WriteInt32(width);
    data.WriteInt32(height);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_SIZE, data, reply, option);
}

void FuzzTranscoderSetVideoEncodingBitRate(sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t rate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    data.WriteInt32(rate);
    transcoder->OnRemoteRequest(
        IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODING_BIT_RATE, data, reply, option);
}

void FuzzTranscoderSetAudioEncoder(sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t audioEncoderType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int32_t encoderArr[] = { AudioCodecFormat::AUDIO_DEFAULT, AudioCodecFormat::AAC_LC, AudioCodecFormat::AUDIO_MPEG,
        AudioCodecFormat::AUDIO_G711MU, AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT };
    int32_t index = audioEncoderType % std::size(encoderArr);
    int32_t value = encoderArr[std::abs(index)];
    data.WriteInt32(value);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, data, reply, option);
}

void FuzzTranscoderSetAudioEncodingBitRate(
    sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t audioBitrate)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    data.WriteInt32(audioBitrate);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, data, reply, option);
}

void FuzzTranscoderSetOutputFormat(sptr<IRemoteStub<IStandardTransCoderService>> transcoder, int32_t outputFormat)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int32_t outputFormatArr[] = { OutputFormatType::FORMAT_DEFAULT, OutputFormatType::FORMAT_MPEG_4,
        OutputFormatType::FORMAT_M4A, OutputFormatType::FORMAT_MP3, OutputFormatType::FORMAT_WAV,
        OutputFormatType::FORMAT_BUTT };
    int32_t index = outputFormat % std::size(outputFormatArr);
    int32_t value = outputFormatArr[std::abs(index)];
    data.WriteInt32(value);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_VIDEO_ENCODER, data, reply, option);
}

void FuzzTranscoderSetInputFile(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int fdInput = open(INPUT_VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fdInput < 0) {
        return;
    }
    data.WriteFileDescriptor(fdInput);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_INPUT_FILE_FD, data, reply, option);
    close(fdInput);
}

void FuzzTranscoderSetOutputFile(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    int fdOutput = open(OUTPUT_VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fdOutput < 0) {
        return;
    }
    data.WriteFileDescriptor(fdOutput);
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::SET_OUTPUT_FILE, data, reply, option);
    close(fdOutput);
}

void FuzzTranscoderPrepare(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::PREPARE, data, reply, option);
}

void FuzzTranscoderStart(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::START, data, reply, option);
}

void FuzzTranscoderPause(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::PAUSE, data, reply, option);
}

void FuzzTranscoderResume(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::RESUME, data, reply, option);
}

void FuzzTranscoderCancel(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::CANCEL, data, reply, option);
}

void FuzzTranscoderRelease(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::RELEASE, data, reply, option);
}

void FuzzTranscoderDestroyStub(sptr<IRemoteStub<IStandardTransCoderService>> transcoder)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(transcoder->GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");
    transcoder->OnRemoteRequest(IStandardTransCoderService::RecorderServiceMsg::DESTROY, data, reply, option);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    int fdInput = open(INPUT_VIDEO_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fdInput < 0) {
        return 0;
    }
    if (write(fdInput, data, size) <= 0) {
        close(fdInput);
        return 0;
    }
    close(fdInput);

    FuzzedDataProvider fdp(data, size);
    auto transcoder = OHOS::Media::CreateFuzzTranscoder();
    OHOS::Media::FuzzTranscoderSetVideoEncoder(transcoder, fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetVideoSize(transcoder, fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetVideoEncodingBitRate(transcoder, fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetAudioEncoder(transcoder, fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetAudioEncodingBitRate(transcoder, fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetOutputFormat(transcoder, fdp.ConsumeIntegral<int32_t>());
    OHOS::Media::FuzzTranscoderSetInputFile(transcoder);
    OHOS::Media::FuzzTranscoderSetOutputFile(transcoder);
    OHOS::Media::FuzzTranscoderPrepare(transcoder);
    sleep(SECOND_TWO);
    OHOS::Media::FuzzTranscoderStart(transcoder);
    sleep(SECOND_TWO);
    static const int threadCode[] = {
        0, 1, 2
    };
    int code = fdp.PickValueInArray(threadCode);
    switch (code)
    {
        case 0 :{
            OHOS::Media::FuzzTranscoderPause(transcoder);
            sleep(SECOND_TWO);
            break;
        }
        case 1 :{
            OHOS::Media::FuzzTranscoderResume(transcoder);
            sleep(SECOND_TWO);
            break;
        }
        case 2 :{
            OHOS::Media::FuzzTranscoderCancel(transcoder);
            break;
        }
        default:
            break;
    }
    OHOS::Media::FuzzTranscoderRelease(transcoder);
    OHOS::Media::FuzzTranscoderDestroyStub(transcoder);

    unlink(INPUT_VIDEO_PATH);
    unlink(OUTPUT_VIDEO_PATH);

    return 0;
}