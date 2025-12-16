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

#ifndef SCREEN_CAPTURE_SERVICE_STUB_H
#define SCREEN_CAPTURE_SERVICE_STUB_H

#include <map>
#include "i_standard_screen_capture_service.h"
#include "screen_capture_server.h"
#include "media_death_recipient.h"

namespace OHOS {
namespace Media {

#define FALSE_RETURN_AND_REPLY(cond, ret, fmt, ...)   \
    do {                                              \
        if (!(cond)) {                                \
            MEDIA_LOGE(fmt, ##__VA_ARGS__);           \
            reply.WriteInt32(ret);                    \
            return ret;                               \
        }                                             \
    } while (0)

class ScreenCaptureServiceStub : public IRemoteStub<IStandardScreenCaptureService>, public NoCopyable {
public:
    static sptr<ScreenCaptureServiceStub> Create();
    virtual ~ScreenCaptureServiceStub();
    void Release() override;
    int32_t DestroyStub() override;
    int32_t SetCaptureMode(CaptureMode captureMode) override;
    int32_t SetDataType(DataType dataType) override;
    int32_t SetRecorderInfo(RecorderInfo recorderInfo) override;
    int32_t SetOutputFile(int32_t fd) override;
    int32_t SetAndCheckLimit() override;
    int32_t SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo) override;
    int32_t InitAudioEncInfo(AudioEncInfo audioEncInfo) override;
    int32_t InitAudioCap(AudioCaptureInfo audioInfo) override;
    int32_t InitVideoEncInfo(VideoEncInfo videoEncInfo) override;
    int32_t InitVideoCap(VideoCaptureInfo videoInfo) override;
    int32_t StartScreenCapture(bool isPrivacyAuthorityEnabled) override;
    int32_t StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled) override;
    int32_t StopScreenCapture() override;
    int32_t PresentPicker() override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
                               int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t ShowCursor(bool showCursor) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override;
    int32_t IncludeContent(ScreenCaptureContentFilter &contentFilter) override;
    int32_t ExcludePickerWindows(std::vector<int32_t> &windowIDsVec) override;
    int32_t SetPickerMode(PickerMode pickerMode) override;
    int32_t SetScreenCaptureStrategy(ScreenCaptureStrategy strategy) override;
    int32_t UpdateSurface(sptr<Surface> surface) override;
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override;
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area) override;

private:
    ScreenCaptureServiceStub();
    int32_t Init();
    int32_t SetCaptureMode(MessageParcel &data, MessageParcel &reply);
    int32_t SetDataType(MessageParcel &data, MessageParcel &reply);
    int32_t SetRecorderInfo(MessageParcel &data, MessageParcel &reply);
    int32_t SetOutputFile(MessageParcel &data, MessageParcel &reply);
    int32_t SetAndCheckLimit(MessageParcel &data, MessageParcel &reply);
    int32_t SetAndCheckSaLimit(MessageParcel &data, MessageParcel &reply);
    int32_t InitAudioEncInfo(MessageParcel &data, MessageParcel &reply);
    int32_t InitAudioCap(MessageParcel &data, MessageParcel &reply);
    int32_t InitVideoEncInfo(MessageParcel &data, MessageParcel &reply);
    int32_t InitVideoCap(MessageParcel &data, MessageParcel &reply);
    int32_t StartScreenCapture(MessageParcel &data, MessageParcel &reply);
    int32_t StartScreenCaptureWithSurface(MessageParcel &data, MessageParcel &reply);
    int32_t StopScreenCapture(MessageParcel &data, MessageParcel &reply);
    int32_t PresentPicker(MessageParcel &data, MessageParcel &reply);
    int32_t SetListenerObject(MessageParcel &data, MessageParcel &reply);
    int32_t AcquireAudioBuffer(MessageParcel &data, MessageParcel &reply);
    int32_t AcquireVideoBuffer(MessageParcel &data, MessageParcel &reply);
    int32_t ReleaseAudioBuffer(MessageParcel &data, MessageParcel &reply);
    int32_t ReleaseVideoBuffer(MessageParcel &data, MessageParcel &reply);
    int32_t SetMicrophoneEnabled(MessageParcel &data, MessageParcel &reply);
    int32_t SetCanvasRotation(MessageParcel &data, MessageParcel &reply);
    int32_t ShowCursor(MessageParcel &data, MessageParcel &reply);
    int32_t ResizeCanvas(MessageParcel &data, MessageParcel &reply);
    int32_t SkipPrivacyMode(MessageParcel &data, MessageParcel &reply);
    int32_t SetMaxVideoFrameRate(MessageParcel &data, MessageParcel &reply);
    int32_t ExcludeContent(MessageParcel &data, MessageParcel &reply);
    int32_t IncludeContent(MessageParcel &data, MessageParcel &reply);
    int32_t ExcludePickerWindows(MessageParcel &data, MessageParcel &reply);
    int32_t SetPickerMode(MessageParcel &data, MessageParcel &reply);
    int32_t SetScreenCaptureStrategy(MessageParcel &data, MessageParcel &reply);
    int32_t SetCaptureAreaHighlight(MessageParcel &data, MessageParcel &reply);
    int32_t UpdateSurface(MessageParcel &data, MessageParcel &reply);
    int32_t SetCaptureArea(MessageParcel &data, MessageParcel &reply);

    int32_t Release(MessageParcel &data, MessageParcel &reply);
    int32_t DestroyStub(MessageParcel &data, MessageParcel &reply);

    std::mutex mutex_;
    std::shared_ptr<IScreenCaptureService> screenCaptureServer_ = nullptr;
    using screenCaptureStubFuncs = int32_t(ScreenCaptureServiceStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, screenCaptureStubFuncs> screenCaptureStubFuncs_;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_STUB_H