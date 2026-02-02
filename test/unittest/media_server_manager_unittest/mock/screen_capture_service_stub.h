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

#ifndef SCREEN_CAPTURE_SERVICE_STUB_H
#define SCREEN_CAPTURE_SERVICE_STUB_H

#include <map>
#include <gmock/gmock.h>
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"
#include "media_death_recipient.h"

namespace OHOS {
namespace Media {
class ScreenCaptureServiceStub : public IRemoteStub<IStandardScreenCaptureService>, public NoCopyable {
public:
    static sptr<ScreenCaptureServiceStub> Create()
    {
        sptr<ScreenCaptureServiceStub> screenCaptureStub = new(std::nothrow) ScreenCaptureServiceStub();
        return screenCaptureStub;
    }
    virtual ~ScreenCaptureServiceStub() = default;

    MOCK_METHOD(void, Release, (), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, SetCaptureMode, (CaptureMode captureMode), (override));
    MOCK_METHOD(int32_t, SetDataType, (DataType dataType), (override));
    MOCK_METHOD(int32_t, SetRecorderInfo, (RecorderInfo recorderInfo), (override));
    MOCK_METHOD(int32_t, SetOutputFile, (int32_t fd), (override));
    MOCK_METHOD(int32_t, SetAndCheckLimit, (), (override));
    MOCK_METHOD(int32_t, SetAndCheckSaLimit, (OHOS::AudioStandard::AppInfo &appInfo), (override));
    MOCK_METHOD(int32_t, InitAudioEncInfo, (AudioEncInfo audioEncInfo), (override));
    MOCK_METHOD(int32_t, InitAudioCap, (AudioCaptureInfo audioInfo), (override));
    MOCK_METHOD(int32_t, InitVideoEncInfo, (VideoEncInfo videoEncInfo), (override));
    MOCK_METHOD(int32_t, InitVideoCap, (VideoCaptureInfo videoInfo), (override));
    MOCK_METHOD(int32_t, StartScreenCapture, (bool isPrivacyAuthorityEnabled), (override));
    MOCK_METHOD(int32_t, StartScreenCaptureWithSurface, (sptr<Surface> surface,
        bool isPrivacyAuthorityEnabled), (override));
    MOCK_METHOD(int32_t, StopScreenCapture, (), (override));
    MOCK_METHOD(int32_t, PresentPicker, (), (override));
    MOCK_METHOD(int32_t, AcquireAudioBuffer, (std::shared_ptr<AudioBuffer> &audioBuffer,
        AudioCaptureSourceType type), (override));
    MOCK_METHOD(int32_t, AcquireVideoBuffer, (sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
        int64_t &timestamp, OHOS::Rect &damage), (override));
    MOCK_METHOD(int32_t, ReleaseAudioBuffer, (AudioCaptureSourceType type), (override));
    MOCK_METHOD(int32_t, ReleaseVideoBuffer, (), (override));
    MOCK_METHOD(int32_t, SetMicrophoneEnabled, (bool isMicrophone), (override));
    MOCK_METHOD(int32_t, SetCanvasRotation, (bool canvasRotation), (override));
    MOCK_METHOD(int32_t, ShowCursor, (bool showCursor), (override));
    MOCK_METHOD(int32_t, ResizeCanvas, (int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, SkipPrivacyMode, (const std::vector<uint64_t> &windowIDsVec), (override));
    MOCK_METHOD(int32_t, AddWhiteListWindows, (const std::vector<uint64_t> &windowIDsVec), (override));
    MOCK_METHOD(int32_t, RemoveWhiteListWindows, (const std::vector<uint64_t> &windowIDsVec), (override));
    MOCK_METHOD(int32_t, SetMaxVideoFrameRate, (int32_t frameRate), (override));
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option), (override));
    MOCK_METHOD(int32_t, ExcludeContent, (ScreenCaptureContentFilter &contentFilter), (override));
    MOCK_METHOD(int32_t, ExcludePickerWindows, (std::vector<int32_t> &windowIDsVec), (override));
    MOCK_METHOD(int32_t, SetPickerMode, (PickerMode pickerMode), (override));
    MOCK_METHOD(int32_t, SetScreenCaptureStrategy, (ScreenCaptureStrategy strategy), (override));
    MOCK_METHOD(int32_t, UpdateSurface, (sptr<Surface> surface), (override));
    MOCK_METHOD(int32_t, SetCaptureArea, (uint64_t displayId, OHOS::Rect area), (override));
    MOCK_METHOD(int32_t, SetCaptureAreaHighlight, (AVScreenCaptureHighlightConfig config), (override));
    MOCK_METHOD(int32_t, SetCaptureModeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetDataTypeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetRecorderInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetOutputFileInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetAndCheckLimitInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetAndCheckSaLimitInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, InitAudioEncInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, InitAudioCapInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, InitVideoEncInfoInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, InitVideoCapInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, StartScreenCaptureInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, StartScreenCaptureWithSurfaceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, StopScreenCaptureInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetListenerObjectInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, AcquireAudioBufferInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, AcquireVideoBufferInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ReleaseAudioBufferInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ReleaseVideoBufferInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetMicrophoneEnabledInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetCanvasRotationInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ShowCursorInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ResizeCanvasInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SkipPrivacyModeInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetMaxVideoFrameRateInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ExcludeContentInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetScreenCaptureStrategyInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, UpdateSurfaceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetCaptureAreaInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, SetCaptureAreaHighlightInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, ReleaseInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, DestroyStubInner, (MessageParcel &data, MessageParcel &reply));
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_STUB_H