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
#ifndef AVSCREENCAPTURESERVICESTUB_FUZZER
#define AVSCREENCAPTURESERVICESTUB_FUZZER

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include "i_standard_screen_capture_service.h"

#define FUZZ_PROJECT_NAME "avscreencaptureservicestub_fuzzer"

namespace OHOS {
namespace Media {
class AvScreenCaptureServiceStubFuzzer {
public:
    AvScreenCaptureServiceStubFuzzer();
    ~AvScreenCaptureServiceStubFuzzer();
    bool FuzzAvScreenCaptureServiceStub(uint8_t *data, size_t size);
    bool FuzzExcludeContent(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetMicrophoneEnabled(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetCanvasRotation(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzShowCursor(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzResizeCanvas(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSkipPrivacyMode(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetMaxVideoFrameRate(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetCaptureMode(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetDataType(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetRecorderInfo(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetOutputFile(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetAndCheckLimit(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetAndCheckSaLimit(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzInitAudioEncInfo(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzInitAudioCap(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzInitVideoEncInfo(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzInitVideoCap(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzStartScreenCapture(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzStartScreenCaptureWithSurface(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzUpdateSurface(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzStopScreenCapture(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzAcquireAudioBuffer(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzAcquireVideoBuffer(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzReleaseAudioBuffer(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzReleaseVideoBuffer(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetScreenCaptureStrategy(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    bool FuzzSetCaptureArea(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
    sptr<IRemoteStub<IStandardScreenCaptureService>> GetScreenCaptureStub();
    void FuzzSetCaptureAreaHighlightStub(sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub);
    void FuzzSetCapturePresentPickerStub(sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub);
    void FuzzSetCapturePickerModeStub(sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub);
    void FuzzExcludePickerWindowsStub(sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub);
    void PrepareFuzzData(sptr<IRemoteStub<IStandardScreenCaptureService>> screen_capture_stub,
                            uint8_t *data, size_t size);
};
} // namespace Media
bool FuzzTestAvScreenCaptureServiceStub(uint8_t *data, size_t size);
} // namespace OHOS
#endif // AvScreenCaptureServiceStubFuzzer