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

#ifndef SCREEN_CAPTURE_CLIENT_H
#define SCREEN_CAPTURE_CLIENT_H

#include "i_screen_capture_service.h"
#include "i_standard_screen_capture_service.h"
#include "screen_capture_listener_stub.h"

namespace OHOS {
namespace Media {
class ScreenCaptureClient : public IScreenCaptureService, public NoCopyable {
public:
    static std::shared_ptr<ScreenCaptureClient> Create(const sptr<IStandardScreenCaptureService> &ipcProxy);
    explicit ScreenCaptureClient(const sptr<IStandardScreenCaptureService> &ipcProxy);
    ~ScreenCaptureClient();
    int32_t CreateListenerObject();

    // ScreenCaptureClient
    void MediaServerDied();
    int32_t SetCaptureMode(CaptureMode captureMode) override;
    int32_t SetDataType(DataType dataType) override;
    int32_t SetRecorderInfo(RecorderInfo recorderInfo) override;
    int32_t SetOutputFile(int32_t fd) override;
    int32_t InitAudioEncInfo(AudioEncInfo audioEncInfo) override;
    int32_t InitAudioCap(AudioCaptureInfo audioInfo) override;
    int32_t InitVideoEncInfo(VideoEncInfo videoEncInfo) override;
    int32_t InitVideoCap(VideoCaptureInfo videoInfo) override;
    int32_t StartScreenCapture() override;
    int32_t StopScreenCapture() override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
                               int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;
    void Release() override;

private:
    sptr<IStandardScreenCaptureService> screenCaptureProxy_ = nullptr;
    sptr<ScreenCaptureListenerStub> listenerStub_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> callback_ = nullptr;
    std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_CLIENT_H