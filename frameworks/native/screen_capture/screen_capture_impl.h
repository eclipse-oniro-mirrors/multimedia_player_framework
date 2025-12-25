/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef SCREEN_CAPTURE_IMPL_H
#define SCREEN_CAPTURE_IMPL_H

#include <media_dfx.h>
#include "screen_capture.h"
#include "nocopyable.h"
#include "i_screen_capture_service.h"
#include "surface_buffer_impl.h"
#include "hitrace/tracechain.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
class ScreenCaptureImpl : public ScreenCapture, public NoCopyable {
public:
    ScreenCaptureImpl();
    ~ScreenCaptureImpl();

    int32_t Init();
    int32_t Init(AVScreenCaptureConfig config) override;
    int32_t Init(OHOS::AudioStandard::AppInfo &appInfo) override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t ShowCursor(bool showCursor) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    int32_t StartScreenCapture() override;
    int32_t StartScreenCaptureWithSurface(sptr<Surface> surface) override;
    int32_t StopScreenCapture() override;
    int32_t StartScreenRecording() override;
    int32_t StopScreenRecording() override;
    int32_t PresentPicker() override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audiobuffer, AudioCaptureSourceType type) override;
    sptr<OHOS::SurfaceBuffer> AcquireVideoBuffer(int32_t &fence, int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t Release() override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override;
    int32_t AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t ExcludePickerWindows(std::vector<int32_t> &windowIDsVec) override;
    int32_t SetPickerMode(PickerMode pickerMode) override;
    int32_t SetPrivacyAuthorityEnabled() override;
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override;
    int32_t SetScreenCaptureStrategy(ScreenCaptureStrategy strategy) override;
    int32_t UpdateSurface(sptr<Surface> surface) override;
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area) override;

private:
    bool IsAudioCapInfoIgnored(const AudioCaptureInfo &audioCapInfo);
    bool IsVideoCapInfoIgnored(const VideoCaptureInfo &videoCapInfo);
    int32_t InitOriginalStream(AVScreenCaptureConfig config);
    int32_t InitCaptureFile(AVScreenCaptureConfig config);
    std::shared_ptr<IScreenCaptureService> screenCaptureService_ = nullptr;
    DataType dataType_ = DataType::INVAILD;
    bool isPrivacyAuthorityEnabled_ = false;
    HiTraceId traceId_;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_IMPL_H