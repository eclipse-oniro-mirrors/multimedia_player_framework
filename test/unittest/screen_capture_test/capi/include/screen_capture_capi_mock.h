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
#ifndef SCREEN_CAPTURE_CAPI_MOCK_H
#define SCREEN_CAPTURE_CAPI_MOCK_H

#include "native_avscreen_capture.h"
#include "screen_capture_mock.h"

namespace OHOS {
namespace Media {
class ScreenCaptureCapiMock : public ScreenCaptureMock {
public:
    explicit ScreenCaptureCapiMock(OH_AVScreenCapture* screencapture) : screenCapture_(screencapture) {}
    ~ScreenCaptureCapiMock() = default;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackMock>& callback,
        const bool isErrorCallbackEnabled, const bool isDataCallbackEnabled,
        const bool isStateChangeCallbackEnabled, const bool isCaptureContentChangeCallbackEnabled) override;
    int32_t Init(AVScreenCaptureConfig config) override;
    int32_t StartScreenCapture() override;
    int32_t StartScreenCaptureWithSurface(const std::any& value) override;
    int32_t StopScreenCapture() override;
    int32_t StartScreenRecording() override;
    int32_t StopScreenRecording() override;
    int32_t Release() override;
    int32_t PresentPicker() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t ShowCursor(bool showCursor) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t UpdateSurface(const std::any& surface) override;
    int32_t SkipPrivacyMode(int32_t *windowIDs, int32_t windowCount) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer,
        OHOS::Media::AudioCaptureSourceType type) override;
    sptr<OHOS::SurfaceBuffer> AcquireVideoBuffer(int32_t &fence, int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect &area) override;
    int32_t ReleaseAudioBuffer(OHOS::Media::AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t ExcludeWindowContent(int32_t *windowIDs, int32_t windowCount) override;
    int32_t ExcludeAudioContent(AVScreenCaptureFilterableAudioContent audioType) override;
    int32_t SetPickerMode(PickerMode pickerMode) override;
    int32_t ExcludePickerWindows(int32_t *windowIDsVec, uint32_t windowCount) override;
    bool IsErrorCallbackEnabled() override
    {
        return isErrorCallbackEnabled_;
    }
    bool IsDataCallbackEnabled() override
    {
        return isDataCallbackEnabled_;
    }
    bool IsStateChangeCallbackEnabled() override
    {
        return isStateChangeCallbackEnabled_;
    }
    bool IsCaptureContentChangeCallbackEnabled() override
    {
        return isCaptureContentChangeCallbackEnabled_;
    }
    int32_t CreateCaptureStrategy() override;
    int32_t StrategyForKeepCaptureDuringCall(bool value) override;
    int32_t SetCaptureStrategy() override;
    int32_t ReleaseCaptureStrategy() override;
    int32_t SetCanvasFollowRotationStrategy(bool value) override;
    int32_t StrategyForBFramesEncoding(bool value) override;
    int32_t StrategyForPrivacyMaskMode(int32_t value) override;
    int32_t StrategyForPickerPopUp(bool value) override;
    int32_t StrategyForFillMode(AVScreenCaptureFillMode value) override;
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override;
private:
    static void SetScreenCaptureCallback(OH_AVScreenCapture *screencapture,
        std::shared_ptr<ScreenCaptureCallbackMock> cb);
    static std::shared_ptr<ScreenCaptureCallbackMock> GetCallback(OH_AVScreenCapture *screenCapture);
    static void DelCallback(OH_AVScreenCapture *screenCapture);
    static void OnError(OH_AVScreenCapture *screenCapture, int32_t errorCode);
    static void OnAudioBufferAvailable(OH_AVScreenCapture *screenCapture, bool isReady, OH_AudioCaptureSourceType type);
    static void OnVideoBufferAvailable(OH_AVScreenCapture *screenCapture, bool isReady);
    static void OnErrorNew(OH_AVScreenCapture *screenCapture, int32_t errorCode, void *userData);
    static void OnBufferAvailable(OH_AVScreenCapture *screenCapture, OH_AVBuffer *buffer,
        OH_AVScreenCaptureBufferType bufferType, int64_t timestamp, void *userData);
    static void OnStateChange(struct OH_AVScreenCapture *capture,
        OH_AVScreenCaptureStateCode stateCode, void *userData);
    static void OnCaptureContentChanged(struct OH_AVScreenCapture *capture, OH_AVScreenCaptureContentChangedEvent
        event, OH_Rect* area, void *userData);
    static void OnDisplaySelected(struct OH_AVScreenCapture *capture, uint64_t displayId, void *userData);
    OH_AVScreenCaptureConfig Convert(AVScreenCaptureConfig config);
    OH_AVScreenCaptureHighlightConfig HighlightConfigConvert(AVScreenCaptureHighlightConfig config);

    int32_t GetCaptureContentChangeCallback(const bool isCaptureContentChangeCallbackEnabled);

    static std::mutex mutex_;
    static std::map<OH_AVScreenCapture *, std::shared_ptr<ScreenCaptureCallbackMock>> mockCbMap_;

    OH_AVScreenCapture* screenCapture_ = nullptr;
    bool isErrorCallbackEnabled_ = false;
    bool isDataCallbackEnabled_ = false;
    bool isStateChangeCallbackEnabled_ = false;
    bool isCaptureContentChangeCallbackEnabled_ = false;
    struct OH_AVScreenCapture_ContentFilter *contentFilter_ = nullptr;
    OH_AVScreenCapture_CaptureStrategy *strategy_ = nullptr;
    OHNativeWindow* nativeWindow_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif