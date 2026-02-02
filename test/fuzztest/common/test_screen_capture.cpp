/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "test_screen_capture.h"
#include <sync_fence.h>
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

void TestScreenCaptureCallbackTest::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    cout << "Error received, errorType: " << errorType << " errorCode: " << errorCode << endl;
}

void TestScreenCaptureCallbackTest::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    cout << "OnAudioBufferAvailable received: " << isReady << ", AudioCaptureSourceType: " << type << endl;
}

void TestScreenCaptureCallbackTest::OnVideoBufferAvailable(bool isReady)
{
    cout << "OnVideoBufferAvailable received: " << isReady << endl;
}

TestScreenCapture::TestScreenCapture()
{
}

TestScreenCapture::~TestScreenCapture()
{
}

bool TestScreenCapture::CreateScreenCapture()
{
    screenCapture = ScreenCaptureFactory::CreateScreenCapture();
    if (screenCapture == nullptr) {
        return false;
    }
    return true;
}

bool TestScreenCapture::CreateScreenCapture(OHOS::AudioStandard::AppInfo& appInfo)
{
    screenCapture = ScreenCaptureFactory::CreateScreenCapture(appInfo);
    if (screenCapture == nullptr) {
        return false;
    }
    return true;
}

int32_t TestScreenCapture::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack>& callback)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetScreenCaptureCallback(callback);
}

int32_t TestScreenCapture::Init(AVScreenCaptureConfig config)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->Init(config);
}

int32_t TestScreenCapture::StartScreenCapture()
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->StartScreenCapture();
}

int32_t TestScreenCapture::StopScreenCapture()
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->StopScreenCapture();
}

int32_t TestScreenCapture::Release()
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    screenCapture->Release();
    screenCapture = nullptr;
    return MSERR_OK;
}

int32_t TestScreenCapture::SetMicrophoneEnabled(bool isMicrophone)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetMicrophoneEnabled(isMicrophone);
}

int32_t TestScreenCapture::ResizeCanvas(int32_t width, int32_t height)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->ResizeCanvas(width, height);
}
 
int32_t TestScreenCapture::UpdateSurface(sptr<Surface> surface)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->UpdateSurface(surface);
}

int32_t TestScreenCapture::SkipPrivacyMode(const std::vector<uint64_t> &windowIDsVec)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SkipPrivacyMode(windowIDsVec);
}

int32_t TestScreenCapture::AddWhiteListWindows(std::vector<uint64_t> &windowIDsVec)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->AddWhiteListWindows(windowIDsVec);
}

int32_t TestScreenCapture::RemoveWhiteListWindows(std::vector<uint64_t> &windowIDsVec)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->RemoveWhiteListWindows(windowIDsVec);
}

int32_t TestScreenCapture::SetMaxFrameRate(int32_t frameRate)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetMaxVideoFrameRate(frameRate);
}

int32_t TestScreenCapture::SetCanvasRotation(bool canvasRotation)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetCanvasRotation(canvasRotation);
}

int32_t TestScreenCapture::ShowCursor(bool showCursor)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->ShowCursor(showCursor);
}

int32_t TestScreenCapture::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->AcquireAudioBuffer(audioBuffer, type);
}

sptr<OHOS::SurfaceBuffer> TestScreenCapture::AcquireVideoBuffer(int32_t &fence, int64_t &timestamp, Rect &damage)
{
    if (screenCapture == nullptr) {
        cout << "error! screenCapture == nullptr!" << endl;
        return nullptr;
    }
    return screenCapture->AcquireVideoBuffer(fence, timestamp, damage);
}

int32_t TestScreenCapture::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->ReleaseAudioBuffer(type);
}

int32_t TestScreenCapture::ReleaseVideoBuffer()
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->ReleaseVideoBuffer();
}

int32_t TestScreenCapture::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetCaptureAreaHighlight(config);
}
 
int32_t TestScreenCapture::PresentPicker()
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->PresentPicker();
}

int32_t TestScreenCapture::SetPickerMode(PickerMode pickerMode)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->SetPickerMode(pickerMode);
}

int32_t TestScreenCapture::ExcludePickerWindows(std::vector<int32_t> &windowIDsVec)
{
    if (screenCapture == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return screenCapture->ExcludePickerWindows(windowIDsVec);
}