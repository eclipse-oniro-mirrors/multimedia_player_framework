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
AvScreenCaptureServiceStubFuzzer::AvScreenCaptureServiceStubFuzzer()
{
}

AvScreenCaptureServiceStubFuzzer::~AvScreenCaptureServiceStubFuzzer()
{
}

const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;

sptr<IRemoteStub<IStandardScreenCaptureService>> AvScreenCaptureServiceStubFuzzer::GetScreenCaptureStub()
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> screen_capture = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE, listener);
    if (screen_capture == nullptr) {
        return nullptr;
    }
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub =
        iface_cast<IRemoteStub<IStandardScreenCaptureService>>(screen_capture);
    return screen_capture_Stub;
}
bool AvScreenCaptureServiceStubFuzzer::FuzzAvScreenCaptureServiceStub(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    constexpr uint32_t recorderTime = 3;
    sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_Stub = GetScreenCaptureStub();
    if (screen_capture_Stub == nullptr) {
        return false;
    }
    screen_capture_Stub->SetMicrophoneEnabled(true);
    screen_capture_Stub->SetCanvasRotation(true);
    int32_t fd = GetData<int32_t>();
    screen_capture_Stub->SetOutputFile(fd);
    screen_capture_Stub->SetAndCheckLimit();
    screen_capture_Stub->SetAndCheckLimit();
    screen_capture_Stub->ShowCursor(true);
    int32_t frameRate = GetData<int32_t>();
    screen_capture_Stub->SetMaxVideoFrameRate(frameRate);

    screen_capture_Stub->StartScreenCapture(true);
    sleep(recorderTime);
    screen_capture_Stub->StopScreenCapture();
    screen_capture_Stub->Release();
    return true;
}
} // namespace Media

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