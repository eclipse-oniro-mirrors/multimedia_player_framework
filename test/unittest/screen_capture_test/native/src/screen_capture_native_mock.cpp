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

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;

namespace OHOS {
namespace Media {
void ScreenCaptureNativeCallbackMock::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    if (mockCb_ != nullptr) {
        mockCb_->OnError(errorCode);
    }
}

void ScreenCaptureNativeCallbackMock::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    if (mockCb_ != nullptr) {
        mockCb_->OnAudioBufferAvailable(isReady, type);
    }
}

void ScreenCaptureNativeCallbackMock::OnVideoBufferAvailable(bool isReady)
{
    if (mockCb_ != nullptr) {
        mockCb_->OnVideoBufferAvailable(isReady);
    }
}

int32_t ScreenCaptureNativeMock::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBackMock>& callback)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (callback != nullptr) {
        auto cb = std::make_shared<ScreenCaptureNativeCallbackMock>(callback, screenCapture_);
        return screenCapture_->SetScreenCaptureCallback(cb);
    }
    return MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureNativeMock::StartScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->StartScreenCapture();
}

int32_t ScreenCaptureNativeMock::Init(AVScreenCaptureConfig config)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->Init(config);
}

int32_t ScreenCaptureNativeMock::StopScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->StopScreenCapture();
}

int32_t ScreenCaptureNativeMock::Release()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->Release();
}

int32_t ScreenCaptureNativeMock::SetMicrophoneEnabled(bool isMicrophone)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return screenCapture_->SetMicrophoneEnabled(isMicrophone);
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
} // namespace Media
} // namespace OHOS