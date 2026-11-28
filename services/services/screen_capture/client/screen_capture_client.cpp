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

#include "screen_capture_client.h"
#include "media_errors.h"
#include "media_log.h"
#include <surface.h>
#include <type_traits>
#include <utility>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureClient"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<ScreenCaptureClient> ScreenCaptureClient::Create(const sptr<IStandardScreenCaptureService> &ipcProxy)
{
    std::shared_ptr<ScreenCaptureClient> screenCapture = std::make_shared<ScreenCaptureClient>(ipcProxy);

    int32_t ret = screenCapture->CreateListenerObject();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to create listener object");

    return screenCapture;
}

std::shared_ptr<ScreenCaptureLocalSurface> ScreenCaptureClient::GetLocalSurface()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return localSurface_;
}

template <typename Method, typename... Args>
auto ScreenCaptureClient::CallProxy(Method method, Args &&...args)
{
    using Result = std::invoke_result_t<Method, IStandardScreenCaptureService *, Args...>;
    sptr<IStandardScreenCaptureService> proxy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        proxy = screenCaptureProxy_;
    }
    if (proxy == nullptr) {
        MEDIA_LOGE("screenCapture service does not exist.");
        if constexpr (!std::is_void_v<Result>) {
            return static_cast<Result>(MSERR_SERVICE_DIED);
        } else {
            return;
        }
    }
    return (proxy.GetRefPtr()->*method)(std::forward<Args>(args)...);
}

std::shared_ptr<ScreenCaptureLocalSurface> ScreenCaptureClient::GetOrCreateLocalSurface()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (localSurface_ == nullptr) {
        localSurface_ = std::make_shared<ScreenCaptureLocalSurface>();
    }
    return localSurface_;
}

void ScreenCaptureClient::ResetLocalSurface()
{
    std::shared_ptr<ScreenCaptureLocalSurface> localSurface;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        localSurface = std::move(localSurface_);
    }
    if (localSurface != nullptr) {
        localSurface->Stop();
    }
}

ScreenCaptureClient::ScreenCaptureClient(const sptr<IStandardScreenCaptureService> &ipcProxy)
    : screenCaptureProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

int32_t ScreenCaptureClient::CreateListenerObject()
{
    sptr<ScreenCaptureListenerStub> listenerStub = sptr<ScreenCaptureListenerStub>::MakeSptr();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        listenerStub_ = listenerStub;
    }
    sptr<IRemoteObject> object = listenerStub->AsObject();
    return CallProxy(&IStandardScreenCaptureService::SetListenerObject, object);
}

ScreenCaptureClient::~ScreenCaptureClient()
{
    (void)CallProxy(&IStandardScreenCaptureService::DestroyStub);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t ScreenCaptureClient::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    sptr<ScreenCaptureListenerStub> listenerStub;
    std::shared_ptr<ScreenCaptureLocalSurface> localSurface;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "input param callback is nullptr.");
        CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, MSERR_NO_MEMORY, "listenerStub_ is nullptr.");
        callback_ = callback;
        listenerStub = listenerStub_;
        localSurface = localSurface_;
    }
    MEDIA_LOGD("SetScreenCaptureCallback");
    listenerStub->SetScreenCaptureCallback(callback);
    if (localSurface != nullptr) {
        localSurface->SetCallback(callback);
    }
    return MSERR_OK;
}

void ScreenCaptureClient::MediaServerDied()
{
    std::shared_ptr<ScreenCaptureCallBack> callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenCaptureProxy_ = nullptr;
        listenerStub_ = nullptr;
        callback = callback_;
    }
    ResetLocalSurface();
    if (callback != nullptr) {
        callback->OnError(SCREEN_CAPTURE_ERROR_INTERNAL, MSERR_SERVICE_DIED);
    }
}

void ScreenCaptureClient::Release()
{
    ResetLocalSurface();
    CallProxy(&IStandardScreenCaptureService::Release);
}

int32_t ScreenCaptureClient::StartScreenCapture(bool isPrivacyAuthorityEnabled)
{
    bool expected = false;
    if (!starting_.compare_exchange_strong(expected, true)) {
        MEDIA_LOGE("start is already in progress");
        return MSERR_INVALID_OPERATION;
    }
    std::shared_ptr<ScreenCaptureCallBack> callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = callback_;
    }
    auto localSurface = GetOrCreateLocalSurface();

    int32_t ret = localSurface->Init(callback);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("start local surface failed, ret:%{public}d", ret);
        starting_.store(false);
        return ret;
    }
    ret = CallProxy(&IStandardScreenCaptureService::StartScreenCaptureWithSurface, localSurface->GetProducerSurface(),
        isPrivacyAuthorityEnabled);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("StartScreenCaptureWithSurface failed, ret:%{public}d", ret);
        starting_.store(false);
        return ret;
    }
    starting_.store(false);
    return MSERR_OK;
}

int32_t ScreenCaptureClient::StopScreenCapture()
{
    auto localSurface = GetLocalSurface();
    int32_t ret = CallProxy(&IStandardScreenCaptureService::StopScreenCapture);
    if (localSurface != nullptr) {
        localSurface->Stop();
    }
    return ret;
}

int32_t ScreenCaptureClient::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    auto localSurface = GetLocalSurface();
    CHECK_AND_RETURN_RET_LOG(localSurface != nullptr, MSERR_INVALID_OPERATION,
        "AcquireVideoBuffer failed, localSurface_ is nullptr (not in BUFFER_MODE or not started)");
    return localSurface->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
}

int32_t ScreenCaptureClient::ReleaseVideoBuffer()
{
    auto localSurface = GetLocalSurface();
    CHECK_AND_RETURN_RET_LOG(localSurface != nullptr, MSERR_INVALID_OPERATION,
        "ReleaseVideoBuffer failed, localSurface_ is nullptr (not in BUFFER_MODE or not started)");
    return localSurface->ReleaseVideoBuffer();
}

int32_t ScreenCaptureClient::UpdateSurface(sptr<Surface> surface)
{
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_VAL, "UpdateSurface fail, invalid param");
    return CallProxy(&IStandardScreenCaptureService::UpdateSurface, surface);
}

int32_t ScreenCaptureClient::SetCaptureMode(CaptureMode captureMode)
{
    return CallProxy(&IStandardScreenCaptureService::SetCaptureMode, captureMode);
}

int32_t ScreenCaptureClient::SetDataType(DataType dataType)
{
    return CallProxy(&IStandardScreenCaptureService::SetDataType, dataType);
}

int32_t ScreenCaptureClient::SetRecorderInfo(RecorderInfo recorderInfo)
{
    return CallProxy(&IStandardScreenCaptureService::SetRecorderInfo, recorderInfo);
}

int32_t ScreenCaptureClient::SetOutputFile(int32_t fd)
{
    return CallProxy(&IStandardScreenCaptureService::SetOutputFile, fd);
}

int32_t ScreenCaptureClient::SetAndCheckLimit()
{
    return CallProxy(&IStandardScreenCaptureService::SetAndCheckLimit);
}

int32_t ScreenCaptureClient::SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo)
{
    return CallProxy(&IStandardScreenCaptureService::SetAndCheckSaLimit, appInfo);
}

int32_t ScreenCaptureClient::InitAudioEncInfo(AudioEncInfo audioEncInfo)
{
    return CallProxy(&IStandardScreenCaptureService::InitAudioEncInfo, audioEncInfo);
}

int32_t ScreenCaptureClient::InitAudioCap(AudioCaptureInfo audioInfo)
{
    return CallProxy(&IStandardScreenCaptureService::InitAudioCap, audioInfo);
}

int32_t ScreenCaptureClient::InitVideoEncInfo(VideoEncInfo videoEncInfo)
{
    return CallProxy(&IStandardScreenCaptureService::InitVideoEncInfo, videoEncInfo);
}

int32_t ScreenCaptureClient::InitVideoCap(VideoCaptureInfo videoInfo)
{
    return CallProxy(&IStandardScreenCaptureService::InitVideoCap, videoInfo);
}

int32_t ScreenCaptureClient::ExcludeContent(ScreenCaptureContentFilter &contentFilter)
{
    return CallProxy(&IStandardScreenCaptureService::ExcludeContent, contentFilter);
}

int32_t ScreenCaptureClient::AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec)
{
    return CallProxy(&IStandardScreenCaptureService::AddWhiteListWindows, windowIDsVec);
}

int32_t ScreenCaptureClient::RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec)
{
    return CallProxy(&IStandardScreenCaptureService::RemoveWhiteListWindows, windowIDsVec);
}

int32_t ScreenCaptureClient::ExcludePickerWindows(const std::vector<int32_t> &windowIDsVec)
{
    return CallProxy(&IStandardScreenCaptureService::ExcludePickerWindows, windowIDsVec);
}

int32_t ScreenCaptureClient::SetPickerMode(PickerMode pickerMode)
{
    return CallProxy(&IStandardScreenCaptureService::SetPickerMode, pickerMode);
}

int32_t ScreenCaptureClient::SetMicrophoneEnabled(bool isMicrophone)
{
    return CallProxy(&IStandardScreenCaptureService::SetMicrophoneEnabled, isMicrophone);
}

int32_t ScreenCaptureClient::SetCanvasRotation(bool canvasRotation)
{
    return CallProxy(&IStandardScreenCaptureService::SetCanvasRotation, canvasRotation);
}

int32_t ScreenCaptureClient::ShowCursor(bool showCursor)
{
    return CallProxy(&IStandardScreenCaptureService::ShowCursor, showCursor);
}

int32_t ScreenCaptureClient::ResizeCanvas(int32_t width, int32_t height)
{
    return CallProxy(&IStandardScreenCaptureService::ResizeCanvas, width, height);
}

int32_t ScreenCaptureClient::SkipPrivacyMode(const std::vector<uint64_t> &windowIDsVec)
{
    return CallProxy(&IStandardScreenCaptureService::SkipPrivacyMode, windowIDsVec);
}

int32_t ScreenCaptureClient::SetMaxVideoFrameRate(int32_t frameRate)
{
    return CallProxy(&IStandardScreenCaptureService::SetMaxVideoFrameRate, frameRate);
}

int32_t ScreenCaptureClient::StartScreenRecording(bool isPrivacyAuthorityEnabled)
{
    return CallProxy(&IStandardScreenCaptureService::StartScreenRecording, isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureClient::StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled)
{
    return CallProxy(&IStandardScreenCaptureService::StartScreenCaptureWithSurface, surface, isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureClient::PresentPicker()
{
    return CallProxy(&IStandardScreenCaptureService::PresentPicker);
}

int32_t ScreenCaptureClient::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type)
{
    return CallProxy(&IStandardScreenCaptureService::AcquireAudioBuffer, audioBuffer, type);
}

int32_t ScreenCaptureClient::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    return CallProxy(&IStandardScreenCaptureService::ReleaseAudioBuffer, type);
}

int32_t ScreenCaptureClient::SetScreenCaptureStrategy(const ScreenCaptureStrategy &strategy)
{
    return CallProxy(&IStandardScreenCaptureService::SetScreenCaptureStrategy, strategy);
}

int32_t ScreenCaptureClient::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    return CallProxy(&IStandardScreenCaptureService::SetCaptureAreaHighlight, config);
}

int32_t ScreenCaptureClient::SetCaptureArea(uint64_t displayId, OHOS::Rect area)
{
    return CallProxy(&IStandardScreenCaptureService::SetCaptureArea, displayId, area);
}

int32_t ScreenCaptureClient::GetMultiDisplayCaptureCapability(const std::vector<uint64_t> &displayIds,
    MultiDisplayCapability &capability)
{
    return CallProxy(&IStandardScreenCaptureService::GetMultiDisplayCaptureCapability, displayIds, capability);
}

int32_t ScreenCaptureClient::PauseScreenCapture()
{
    return CallProxy(&IStandardScreenCaptureService::PauseScreenCapture);
}

int32_t ScreenCaptureClient::ResumeScreenCapture()
{
    return CallProxy(&IStandardScreenCaptureService::ResumeScreenCapture);
}

int32_t ScreenCaptureClient::AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer, int32_t width, int32_t height,
    int32_t &watermarkCount)
{
    return CallProxy(&IStandardScreenCaptureService::AddWatermark, watermarkBuffer, width, height, watermarkCount);
}

int32_t ScreenCaptureClient::SetContentAutoRotation(bool contentAutoRotation)
{
    return CallProxy(&IStandardScreenCaptureService::SetContentAutoRotation, contentAutoRotation);
}

} // namespace Media
} // namespace OHOS