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

#include "screen_capture.h"
#include "nocopyable.h"
#include "i_screen_capture_service.h"
#include "surface_buffer_impl.h"

namespace OHOS {
namespace Media {
class ScreenCaptureImpl : public ScreenCapture, public NoCopyable {
public:
    ScreenCaptureImpl();
    ~ScreenCaptureImpl();

    int32_t Init();
    int32_t Init(AVScreenCaptureConfig config) override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    int32_t StartScreenCapture() override;
    int32_t StopScreenCapture() override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audiobuffer, AudioCaptureSourceType type) override;
    sptr<OHOS::SurfaceBuffer> AcquireVideoBuffer(int32_t &fence, int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t Release() override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;

private:
    bool NeedStartInnerAudio(AudioCaptureSourceType type);
    int32_t InitOriginalStream(AVScreenCaptureConfig config);
    int32_t InitCaptureFile(AVScreenCaptureConfig config);
    std::shared_ptr<IScreenCaptureService> screenCaptureService_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_IMPL_H