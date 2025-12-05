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
#include "avscreencaptureservicestub_fuzzer.h"
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
    AvScreenCaptureServiceStubFuzzer::AvScreenCaptureServiceStubFuzzer() {}

    AvScreenCaptureServiceStubFuzzer::~AvScreenCaptureServiceStubFuzzer() {}

    const int32_t SYSTEM_ABILITY_ID = 3002;
    const bool RUN_ON_CREATE = false;
    const uint32_t MAX_LINE_COLOR_RGB = 0x00ffffff;
    const uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;
    const uint32_t SET_HIGH_LIGHT_MODE = 30;
    const uint32_t PRESENT_PICKER = 31;
    const uint32_t EXCLUDE_PICKER_WINDOWS = 32;
    const uint32_t SET_PICKER_MODE = 33;
    const uint32_t MAX_LINE_THICKNESS = 8;
    const uint32_t MIN_LINE_THICKNESS = 1;

    sptr<IRemoteStub<IStandardScreenCaptureService>> AvScreenCaptureServiceStubFuzzer::GetScreenCaptureStub()
    {
        std::shared_ptr<MediaServer> mediaServer = std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
        sptr<IRemoteObject> listener = new (std::nothrow) MediaListenerStubFuzzer();
        sptr<IRemoteObject> screen_capture =
            mediaServer->GetSubSystemAbility(IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE, listener);
        if (screen_capture == nullptr) {
            return nullptr;
        }
        sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub =
            iface_cast<IRemoteStub<IStandardScreenCaptureService>>(screen_capture);
        return screen_capture_Stub;
    }

    void AvScreenCaptureServiceStubFuzzer::FuzzSetCaptureAreaHighlightStub(
        sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub)
    {
        uint32_t lineThickness = GetData<uint32_t>() % MAX_LINE_THICKNESS + MIN_LINE_THICKNESS;
        uint32_t lineColor = GetData<uint32_t>();
        if (lineColor > MAX_LINE_COLOR_RGB && lineColor < MIN_LINE_COLOR_ARGB) {
            return;
        }
        int32_t mode = 0;
        MessageParcel msg;
        msg.WriteInterfaceToken(screencaptureStub->GetDescriptor());
        msg.WriteUint32(lineThickness);
        msg.WriteUint32(lineColor);
        msg.WriteInt32(mode);
        MessageParcel reply;
        MessageOption option;
        screencaptureStub->OnRemoteRequest(SET_HIGH_LIGHT_MODE, msg, reply, option);
    }

    void AvScreenCaptureServiceStubFuzzer::FuzzSetCapturePresentPickerStub(
        sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub)
    {
        MessageParcel msg;
        msg.WriteInterfaceToken(screencaptureStub->GetDescriptor());
        MessageParcel reply;
        MessageOption option;
        screencaptureStub->OnRemoteRequest(PRESENT_PICKER, msg, reply, option);
    }

    void AvScreenCaptureServiceStubFuzzer::FuzzSetCapturePickerModeStub(
        sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub)
    {
        int32_t mode = 0;
        MessageParcel msg;
        msg.WriteInterfaceToken(screencaptureStub->GetDescriptor());
        msg.WriteInt32(mode);
        MessageParcel reply;
        MessageOption option;
        screencaptureStub->OnRemoteRequest(SET_PICKER_MODE, msg, reply, option);
    }

    void AvScreenCaptureServiceStubFuzzer::FuzzExcludePickerWindowsStub(
        sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub)
    {
        std::vector<int32_t> windowIDs = {101, 102, 103};
        MessageParcel msg;
        msg.WriteInterfaceToken(screencaptureStub->GetDescriptor());
        msg.WriteInt32Vector(windowIDs);
        MessageParcel reply;
        MessageOption option;
        screencaptureStub->OnRemoteRequest(EXCLUDE_PICKER_WINDOWS, msg, reply, option);
    }

    bool AvScreenCaptureServiceStubFuzzer::FuzzAvScreenCaptureServiceStub(uint8_t *data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        constexpr uint32_t recorderTime = 3000;
        sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub = GetScreenCaptureStub();
        if (screen_capture_Stub == nullptr) {
            return false;
        }
        PrepareFuzzData(screen_capture_Stub, data, size);
        FuzzStartScreenCapture(screen_capture_Stub, data, size);
        FuzzStartScreenCaptureWithSurface(screen_capture_Stub, data, size);
        sleep(recorderTime);
        FuzzSetCapturePresentPickerStub(screen_capture_Stub);
        screen_capture_Stub->StopScreenCapture();
        screen_capture_Stub->Release();
        return true;
    }
}  // namespace Media

void AvScreenCaptureServiceStubFuzzer::PrepareFuzzData(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    FuzzSetCaptureAreaHighlightStub(screen_capture_Stub);
    FuzzExcludePickerWindowsStub(screen_capture_Stub);
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    screen_capture_Stub->ResizeCanvas(width, height);
    FuzzExcludeContent(screen_capture_Stub, data, size);
    FuzzSetMicrophoneEnabled(screen_capture_Stub, data, size);
    FuzzSetCanvasRotation(screen_capture_Stub, data, size);
    FuzzShowCursor(screen_capture_Stub, data, size);
    FuzzResizeCanvas(screen_capture_Stub, data, size);
    FuzzSkipPrivacyMode(screen_capture_Stub, data, size);
    FuzzSetMaxVideoFrameRate(screen_capture_Stub, data, size);
    FuzzSetCaptureMode(screen_capture_Stub, data, size);
    FuzzSetDataType(screen_capture_Stub, data, size);
    FuzzSetRecorderInfo(screen_capture_Stub, data, size);
    FuzzSetOutputFile(screen_capture_Stub, data, size);
    FuzzSetAndCheckLimit(screen_capture_Stub, data, size);
    FuzzSetAndCheckSaLimit(screen_capture_Stub, data, size);
    FuzzInitAudioEncInfo(screen_capture_Stub, data, size);
    FuzzInitAudioCap(screen_capture_Stub, data, size);
    FuzzInitVideoEncInfo(screen_capture_Stub, data, size);
    FuzzInitVideoCap(screen_capture_Stub, data, size);
    FuzzSetCapturePickerModeStub(screen_capture_Stub);
    FuzzStopScreenCapture(screen_capture_Stub, data, size);
    FuzzAcquireAudioBuffer(screen_capture_Stub, data, size);
    FuzzAcquireVideoBuffer(screen_capture_Stub, data, size);
    FuzzReleaseAudioBuffer(screen_capture_Stub, data, size);
    FuzzReleaseVideoBuffer(screen_capture_Stub, data, size);
    FuzzSetScreenCaptureStrategy(screen_capture_Stub, data, size);
    FuzzSetCaptureArea(screen_capture_Stub, data, size);
    FuzzUpdateSurface(screen_capture_Stub, data, size);
}

bool AvScreenCaptureServiceStubFuzzer::FuzzExcludeContent(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::EXCLUDE_CONTENT, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetMicrophoneEnabled(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_MIC_ENABLE, msg,
                                         reply, option);
    screen_capture_Stub->SetMicrophoneEnabled(true);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetCanvasRotation(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_SCREEN_ROTATION,
                                         msg, reply, option);
    screen_capture_Stub->SetCanvasRotation(true);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzShowCursor(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SHOW_CURSOR, msg,
                                         reply, option);
    screen_capture_Stub->ShowCursor(true);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzResizeCanvas(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::RESIZE_CANVAS, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSkipPrivacyMode(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SKIP_PRIVACY, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetMaxVideoFrameRate(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_MAX_FRAME_RATE,
                                         msg, reply, option);
    int32_t frameRate = GetData<int32_t>();
    screen_capture_Stub->SetMaxVideoFrameRate(frameRate);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetCaptureMode(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_CAPTURE_MODE, msg,
                                         reply, option);
    CaptureMode captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    screen_capture_Stub->SetCaptureMode(captureMode);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetDataType(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_DATA_TYPE, msg,
                                         reply, option);
    DataType dataType = DataType::ORIGINAL_STREAM;
    screen_capture_Stub->SetDataType(dataType);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetRecorderInfo(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_RECORDER_INFO, msg,
                                         reply, option);
    RecorderInfo recorderInfo;
    recorderInfo.url = "";
    recorderInfo.fileFormat = "";
    screen_capture_Stub->SetRecorderInfo(recorderInfo);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetOutputFile(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_OUTPUT_FILE, msg,
                                         reply, option);
    int32_t fd = GetData<int32_t>();
    screen_capture_Stub->SetOutputFile(fd);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetAndCheckLimit(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_CHECK_LIMIT, msg,
                                         reply, option);
    screen_capture_Stub->SetAndCheckLimit();
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetAndCheckSaLimit(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_CHECK_SA_LIMIT,
                                         msg, reply, option);
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appUid = 0;
    appInfo.appTokenId = 0;
    appInfo.appPid = 0;
    appInfo.appFullTokenId = 0;
    screen_capture_Stub->SetAndCheckSaLimit(appInfo);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzInitAudioEncInfo(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::INIT_AUDIO_ENC_INFO,
                                         msg, reply, option);
    AudioEncInfo audioEncInfo;
    screen_capture_Stub->InitAudioEncInfo(audioEncInfo);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzInitAudioCap(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::INIT_AUDIO_CAP, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzInitVideoEncInfo(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::INIT_VIDEO_ENC_INFO,
                                         msg, reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzInitVideoCap(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::INIT_VIDEO_CAP, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzStartScreenCapture(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::START_SCREEN_CAPTURE,
                                         msg, reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzStartScreenCaptureWithSurface(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(
        IStandardScreenCaptureService::ScreenCaptureServiceMsg::START_SCREEN_CAPTURE_WITH_SURFACE, msg, reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzUpdateSurface(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::UPDATE_SURFACE, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzStopScreenCapture(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::STOP_SCREEN_CAPTURE,
                                         msg, reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzAcquireAudioBuffer(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::ACQUIRE_AUDIO_BUF, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzAcquireVideoBuffer(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::ACQUIRE_VIDEO_BUF, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzReleaseAudioBuffer(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::RELEASE_AUDIO_BUF, msg,
                                         reply, option);
    AudioCaptureSourceType audioCaptureSourceType = AudioCaptureSourceType::MIC;
    screen_capture_Stub->ReleaseAudioBuffer(audioCaptureSourceType);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzReleaseVideoBuffer(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::RELEASE_VIDEO_BUF, msg,
                                         reply, option);
    screen_capture_Stub->ReleaseVideoBuffer();
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetScreenCaptureStrategy(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_STRATEGY, msg,
                                         reply, option);
    return true;
}

bool AvScreenCaptureServiceStubFuzzer::FuzzSetCaptureArea(
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub,
    uint8_t *data,
    size_t size)
{
    MessageParcel msg;
    msg.WriteInterfaceToken(screen_capture_Stub->GetDescriptor());
    msg.WriteBuffer(data, size);
    msg.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    screen_capture_Stub->OnRemoteRequest(IStandardScreenCaptureService::ScreenCaptureServiceMsg::SET_CAPTURE_AREA, msg,
                                         reply, option);
    return true;
}

bool FuzzTestAvScreenCaptureServiceStub(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    AvScreenCaptureServiceStubFuzzer testScreenCapture;
    return testScreenCapture.FuzzAvScreenCaptureServiceStub(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestAvScreenCaptureServiceStub(data, size);
    return 0;
}