/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SCREEN_CAPTURE_MOCK_H
#define SCREEN_CAPTURE_MOCK_H

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <securec.h>
#include <string>
#include <thread>
#include <cstdio>
#include "avbuffer.h"
#include "gtest/gtest.h"
#include "screen_capture.h"
#include "screen_capture_controller.h"
#include "unittest_log.h"
#include "media_errors.h"
#include "display_manager.h"
#include "screen_manager.h"
#include "external_window.h"
#include "screen_capture_monitor.h"

namespace OHOS {
namespace Media {
namespace ScreenCaptureTestParam {
    constexpr uint32_t RECORDER_TIME = 2;
    constexpr uint32_t RECORDER_TIME_5 = 5;
    constexpr double EXCESS_RATE = 1.2;
} // namespace ScreenCaptureTestParam

class ScreenCaptureCallbackMock : public NoCopyable {
public:
    virtual void OnError(int32_t errorCode) = 0;
    virtual void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) = 0;
    virtual void OnVideoBufferAvailable(bool isReady) = 0;
    virtual void OnStateChange(AVScreenCaptureStateCode stateCode) = 0;
    virtual void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area) = 0;
    virtual void OnDisplaySelected(uint64_t displayId) = 0;
    virtual void OnUserSelected(ScreenCaptureUserSelectionInfo *selection) = 0;;
    virtual void OnError(int32_t errorCode, void *userData)
    {
        (void)errorCode;
        (void)userData;
    }
    virtual void OnBufferAvailable(const std::shared_ptr<AVBuffer> buffer,
        AVScreenCaptureBufferType bufferType, int64_t timestamp) = 0;
};

class ScreenCaptureMonitorListenerMock : public ScreenCaptureMonitor::ScreenCaptureMonitorListener {
public:
    ScreenCaptureMonitorListenerMock(std::string name):name_(name) {}
    ~ScreenCaptureMonitorListenerMock() = default;
    void OnScreenCaptureStarted(int32_t pid) override;
    void OnScreenCaptureFinished(int32_t pid) override;
    void OnScreenCaptureDied() override;
    int stateFlag_ = 0;
    std::string name_ = "ScreenCaptureMonitor";
};

class ScreenCaptureMock {
public:
    virtual ~ScreenCaptureMock() = default;
    virtual int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackMock>& callback,
        const bool isErrorCallbackEnabled = false, const bool isDataCallbackEnabled = false,
        const bool isStateChangeCallbackEnabled = false, const bool isCaptureContentChangeCallbackEnabled = false) = 0;
    virtual int32_t SetSelectionCallback() = 0;
    virtual int32_t SetDisplayCallback() = 0;
    virtual int32_t Init(AVScreenCaptureConfig config) = 0;
    virtual int32_t Init(OHOS::AudioStandard::AppInfo &appInfo) = 0;
    virtual int32_t StartScreenCapture() = 0;
    virtual int32_t StartScreenCaptureWithSurface(const std::any& value) = 0;
    virtual int32_t StopScreenCapture() = 0;
    virtual int32_t StartScreenRecording() = 0;
    virtual int32_t StopScreenRecording() = 0;
    virtual int32_t PresentPicker() = 0;
    virtual int32_t Release() = 0;
    virtual int32_t SetMicrophoneEnabled(bool isMicrophone) = 0;
    virtual int32_t SetCanvasRotation(bool canvasRotation) = 0;
    virtual int32_t ShowCursor(bool showCursor) = 0;
    virtual int32_t SkipPrivacyMode(int32_t *windowIDs, int32_t windowCount) = 0;
    virtual int32_t ResizeCanvas(int32_t width, int32_t height) = 0;
    virtual int32_t UpdateSurface(const std::any& surface) = 0;
    virtual int32_t SetMaxVideoFrameRate(int32_t frameRate) = 0;
    virtual int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) = 0;
    virtual sptr<OHOS::SurfaceBuffer> AcquireVideoBuffer(int32_t &fence, int64_t &timestamp, OHOS::Rect &damage) = 0;
    virtual int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect &area) = 0;
    virtual int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) = 0;
    virtual int32_t ReleaseVideoBuffer() = 0;
    virtual int32_t ExcludeWindowContent(int32_t *windowIDs, int32_t windowCount) = 0;
    virtual int32_t ExcludeAudioContent(AVScreenCaptureFilterableAudioContent audioType) = 0;
    virtual int32_t SetPickerMode(PickerMode pickerMode) = 0;
    virtual int32_t ExcludePickerWindows(int32_t *windowIDsVec, uint32_t windowCount) = 0;
    virtual bool IsErrorCallbackEnabled()
    {
        return false;
    }
    virtual bool IsDataCallbackEnabled()
    {
        return false;
    }
    virtual bool IsStateChangeCallbackEnabled()
    {
        return false;
    }
    virtual bool IsCaptureContentChangeCallbackEnabled()
    {
        return false;
    }
    virtual int32_t CreateCaptureStrategy();
    virtual int32_t StrategyForKeepCaptureDuringCall(bool value);
    virtual int32_t SetCaptureStrategy();
    virtual int32_t ReleaseCaptureStrategy();
    virtual int32_t SetCanvasFollowRotationStrategy(bool value);
    virtual int32_t StrategyForBFramesEncoding(bool value);
    virtual int32_t StrategyForPrivacyMaskMode(int32_t value);
    virtual int32_t StrategyForPickerPopUp(bool value);
    virtual int32_t StrategyForFillMode(AVScreenCaptureFillMode value);
    virtual int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config);
};

class __attribute__((visibility("default"))) ScreenCaptureMockFactory {
public:
    static std::shared_ptr<ScreenCaptureMock> CreateScreenCapture();
private:
    ScreenCaptureMockFactory() = delete;
    ~ScreenCaptureMockFactory() = delete;
};
} // namespace Media
} // namespace OHOS
#endif