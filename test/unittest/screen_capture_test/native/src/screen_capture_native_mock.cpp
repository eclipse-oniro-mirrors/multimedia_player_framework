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

#include "screen_capture_native_mock.h"
#include "media_log.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;

namespace OHOS {
namespace Media {
void ScreenCaptureNativeCallbackMock::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    (void)errorType;
    if (mockCb_ != nullptr) {
        mockCb_->OnError(errorCode);
    }
}

void ScreenCaptureNativeCallbackMock::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (mockCb_ != nullptr) {
        mockCb_->OnAudioBufferAvailable(isReady, type);
    }
}

void ScreenCaptureNativeCallbackMock::OnVideoBufferAvailable(bool isReady)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (mockCb_ != nullptr) {
        mockCb_->OnVideoBufferAvailable(isReady);
    }
}

void ScreenCaptureNativeCallbackMock::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (mockCb_ != nullptr) {
        mockCb_->OnStateChange(stateCode);
    }
}

void ScreenCaptureNativeCallbackMock::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect* area)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (mockCb_ != nullptr) {
        mockCb_->OnCaptureContentChanged(event, area);
    }
}

void ScreenCaptureNativeCallbackMock::OnDisplaySelected(uint64_t displayId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (mockCb_ != nullptr) {
        mockCb_->OnDisplaySelected(displayId);
    }
}

void ScreenCaptureNativeCallbackMock::OnRelease()
{
    std::unique_lock<std::mutex> lock(mutex_);
    mockCb_ = nullptr;
}

ScreenCaptureNativeMock::~ScreenCaptureNativeMock()
{
    MEDIA_LOGI("ScreenCaptureNativeMock::~ScreenCaptureNativeMock");
}

int32_t ScreenCaptureNativeMock::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackMock>& callback,
    const bool isErrorCallbackEnabled, const bool isDataCallbackEnabled, const bool isStateChangeCallbackEnabled,
    const bool isCaptureContentChangeCallbackEnabled)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    (void)isErrorCallbackEnabled; // Inner is not support to set New ErrorCallback
    (void)isDataCallbackEnabled; // Inner is not support to set New DataCallback
    isStateChangeCallbackEnabled_ = isStateChangeCallbackEnabled;
    isCaptureContentChangeCallbackEnabled_ = isCaptureContentChangeCallbackEnabled;
    if (callback != nullptr) {
        cb_ = std::make_shared<ScreenCaptureNativeCallbackMock>(callback, screenCapture_);
        return screenCapture_->SetScreenCaptureCallback(cb_);
    }
    return MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureNativeMock::SetDisplayCallback()
{
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::SetSelectionCallback()
{
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StartScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (isStateChangeCallbackEnabled_) {
        int32_t ret = screenCapture_->SetPrivacyAuthorityEnabled();
        UNITTEST_CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPrivacyAuthorityEnabled failed");
    }
    return screenCapture_->StartScreenCapture();
}

int32_t ScreenCaptureNativeMock::StartScreenCaptureWithSurface(const std::any& value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (isStateChangeCallbackEnabled_) {
        int32_t ret = screenCapture_->SetPrivacyAuthorityEnabled();
        UNITTEST_CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPrivacyAuthorityEnabled failed");
    }
    sptr<Surface> surface = std::any_cast<sptr<Surface>>(value);
    return screenCapture_->StartScreenCaptureWithSurface(surface);
}

int32_t ScreenCaptureNativeMock::Init(AVScreenCaptureConfig config)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->Init(config);
}

int32_t ScreenCaptureNativeMock::Init(OHOS::AudioStandard::AppInfo &appInfo)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->Init(appInfo);
}

int32_t ScreenCaptureNativeMock::StopScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->StopScreenCapture();
}

int32_t ScreenCaptureNativeMock::StartScreenRecording()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (isStateChangeCallbackEnabled_) {
        int32_t ret = screenCapture_->SetPrivacyAuthorityEnabled();
        UNITTEST_CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPrivacyAuthorityEnabled failed");
    }
    return screenCapture_->StartScreenRecording();
}

int32_t ScreenCaptureNativeMock::StopScreenRecording()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->StopScreenRecording();
}

int32_t ScreenCaptureNativeMock::Release()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    std::shared_ptr<ScreenCaptureCallBack> cb = cb_;
    ScreenCaptureNativeCallbackMock *callback = static_cast<ScreenCaptureNativeCallbackMock *>(cb.get());
    if (callback != nullptr) {
        callback->OnRelease();
        cb_ = nullptr;
    }
    return screenCapture_->Release();
}

int32_t ScreenCaptureNativeMock::PresentPicker()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->PresentPicker();
}

int32_t ScreenCaptureNativeMock::SetMicrophoneEnabled(bool isMicrophone)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetMicrophoneEnabled(isMicrophone);
}

int32_t ScreenCaptureNativeMock::SetCanvasRotation(bool canvasRotation)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetCanvasRotation(canvasRotation);
}

int32_t ScreenCaptureNativeMock::ShowCursor(bool showCursor)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->ShowCursor(showCursor);
}

int32_t ScreenCaptureNativeMock::ResizeCanvas(int32_t width, int32_t height)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->ResizeCanvas(width, height);
}

int32_t ScreenCaptureNativeMock::UpdateSurface(const std::any& surface)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->UpdateSurface(std::any_cast<sptr<Surface>>(surface));
}

int32_t ScreenCaptureNativeMock::SkipPrivacyMode(int32_t *windowIDs, int32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
    }
    return screenCapture_->SkipPrivacyMode(vec);
}

int32_t ScreenCaptureNativeMock::AddWhiteListWindows(int32_t *windowIDs, int32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
    }
    return screenCapture_->AddWhiteListWindows(vec);
}

int32_t ScreenCaptureNativeMock::RemoveWhiteListWindows(int32_t *windowIDs, int32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
    }
    return screenCapture_->RemoveWhiteListWindows(vec);
}

int32_t ScreenCaptureNativeMock::SetMaxVideoFrameRate(int32_t frameRate)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetMaxVideoFrameRate(frameRate);
}

int32_t ScreenCaptureNativeMock::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer,
    AudioCaptureSourceType type)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->AcquireAudioBuffer(audioBuffer, type);
}

sptr<OHOS::SurfaceBuffer> ScreenCaptureNativeMock::AcquireVideoBuffer(int32_t &fence, int64_t &timestamp,
    OHOS::Rect &damage)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, nullptr, "screenCapture_ == nullptr");
    return screenCapture_->AcquireVideoBuffer(fence, timestamp, damage);
}

int32_t ScreenCaptureNativeMock::SetCaptureArea(uint64_t displayId, OHOS::Rect &area)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetCaptureArea(displayId, area);
}

int32_t ScreenCaptureNativeMock::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->ReleaseAudioBuffer(type);
}

int32_t ScreenCaptureNativeMock::ReleaseVideoBuffer()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->ReleaseVideoBuffer();
}

int32_t ScreenCaptureNativeMock::ExcludeWindowContent(int32_t *windowIDs, int32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    ScreenCaptureContentFilter filter;
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
    }
    filter.windowIDsVec = vec;
    return screenCapture_->ExcludeContent(filter);
}

int32_t ScreenCaptureNativeMock::ExcludeAudioContent(AVScreenCaptureFilterableAudioContent audioType)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    ScreenCaptureContentFilter filter;
    filter.filteredAudioContents.insert(audioType);
    return screenCapture_->ExcludeContent(filter);
}

int32_t ScreenCaptureNativeMock::SetPickerMode(PickerMode pickerMode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetPickerMode(pickerMode);
}

int32_t ScreenCaptureNativeMock::ExcludePickerWindows(int32_t *windowIDsVec, uint32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    std::vector<int32_t> vec;
    for (uint32_t i = 0; i < windowCount; i++) {
        vec.push_back(static_cast<int32_t>(*(windowIDsVec + i)));
    }
    return screenCapture_->ExcludePickerWindows(vec);
}

int32_t ScreenCaptureNativeMock::CreateCaptureStrategy()
{
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StrategyForKeepCaptureDuringCall(bool value)
{
    strategy_.keepCaptureDuringCall = value;
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::SetCanvasFollowRotationStrategy(bool value)
{
    strategy_.canvasFollowRotation = value;
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::SetCaptureStrategy()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetScreenCaptureStrategy(strategy_);
}

int32_t ScreenCaptureNativeMock::ReleaseCaptureStrategy()
{
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StrategyForBFramesEncoding(bool value)
{
    strategy_.enableBFrame = value;
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StrategyForPrivacyMaskMode(int32_t value)
{
    strategy_.strategyForPrivacyMaskMode = value;
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StrategyForPickerPopUp(bool value)
{
    strategy_.pickerPopUp = static_cast<AVScreenCapturePickerPopUp>(value);
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::StrategyForFillMode(AVScreenCaptureFillMode value)
{
    strategy_.fillMode = value;
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    return MSERR_OK;
}

int32_t ScreenCaptureNativeMock::GetMultiDisplayCaptureCapability(uint64_t *displayIds, size_t count,
    MultiDisplayCapability *multiDisplayCapability)
{
    std::vector<uint64_t> vec;
    for (uint32_t i = 0; i < count; i++) {
        vec.push_back(*(displayIds + i));
    }
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->GetMultiDisplayCaptureCapability(vec, *multiDisplayCapability);
}
} // namespace Media
} // namespace OHOS