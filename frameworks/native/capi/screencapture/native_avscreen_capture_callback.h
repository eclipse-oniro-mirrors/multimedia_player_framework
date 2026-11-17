/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef NATIVE_AVSCREEN_CAPTURE_CALLBACK_H
#define NATIVE_AVSCREEN_CAPTURE_CALLBACK_H

#include "native_avscreen_capture.h"
#include "native_avscreen_capture_impl.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <shared_mutex>

#include "buffer/avbuffer.h"
#include "common/native_mfmagic.h"
#include "media_errors.h"
#include "media_log.h"
#include "native_avbuffer.h"
#include "native_avcodec_base.h"
#include "native_avformat.h"
#include "native_avsource.h"
#include "native_window.h"
#include "surface_buffer_impl.h"
#include <v1_0/buffer_handle_meta_key_type.h>

namespace OHOS {
namespace Media {

template <typename CallbackT>
class NativeScreenCaptureForwardCallback {
public:
    NativeScreenCaptureForwardCallback(CallbackT callback, void *userData) : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureForwardCallback() = default;

    template <typename... Args>
    void Invoke(struct OH_AVScreenCapture *capture, Args... args)
    {
        if (callback_ == nullptr) {
            return;
        }
        callback_(capture, args..., userData_);
    }

protected:
    CallbackT callback_;
    void *userData_;
};

class NativeScreenCaptureDataCallback
    : public NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnBufferAvailable> {
public:
    NativeScreenCaptureDataCallback(OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
        : NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnBufferAvailable>(callback, userData)
    {
    }

    void OnBufferAvailable(struct OH_AVScreenCapture *capture, OH_AVScreenCaptureBufferType bufferType);

private:
    static OH_AVSCREEN_CAPTURE_ErrCode AcquireAudioBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp, AudioCaptureSourceType type);
    static OH_AVSCREEN_CAPTURE_ErrCode ReleaseAudioBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        AudioCaptureSourceType type);
    OH_AVSCREEN_CAPTURE_ErrCode OnProcessAudioBuffer(struct OH_AVScreenCapture *capture,
        OH_AVScreenCaptureBufferType bufferType);
    static OH_AVSCREEN_CAPTURE_ErrCode AcquireVideoBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp);
    static OH_AVSCREEN_CAPTURE_ErrCode ReleaseVideoBuffer(const std::shared_ptr<ScreenCapture> &screenCapture);
    OH_AVSCREEN_CAPTURE_ErrCode OnProcessVideoBuffer(struct OH_AVScreenCapture *capture);
};

class NativeScreenCaptureCallback : public ScreenCaptureCallBack {
public:
    explicit NativeScreenCaptureCallback(std::weak_ptr<ScreenCaptureObject> capture,
        struct OH_AVScreenCaptureCallback callback = {})
        : captureObject_(std::move(capture)), callback_(callback)
    {
    }
    virtual ~NativeScreenCaptureCallback() = default;

    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override;
    void OnStateChange(AVScreenCaptureStateCode stateCode) override;
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area) override;
    void OnDisplaySelected(uint64_t displayId) override;
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override;
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) override;
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override;
    void OnVideoBufferAvailable(bool isReady) override;

    void StopDataCallback();
    void StopAllCallbacks();
    void SetCallback(struct OH_AVScreenCaptureCallback callback);
    bool IsDataCallbackEnabled();
    bool IsStateChangeCallbackEnabled();
    void SetStateChangeCallback(OH_AVScreenCapture_OnStateChange callback, void *userData);
    void SetCaptureContentChangedCallback(OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData);
    void SetUserSelectedCallback(OH_AVScreenCapture_OnUserSelected callback, void *userData);
    void SetPrivacyProtectCallback(OH_AVScreenCapture_OnPrivacyProtect callback, void *userData);
    void SetErrorCallback(OH_AVScreenCapture_OnError callback, void *userData);
    void SetDataCallback(OH_AVScreenCapture_OnBufferAvailable callback, void *userData);
    void SetDisplayCallback(OH_AVScreenCapture_OnDisplaySelected callback, void *userData);

private:
    enum CallbackPhase { ACTIVE, DATA_STOPPED, STOPPED };

    struct OH_AVScreenCapture *LockCapture(std::shared_ptr<ScreenCaptureObject> &captureSp);

    template <typename CallbackT, typename F>
    void DispatchCallback(std::shared_ptr<CallbackT> NativeScreenCaptureCallback::*member, F &&f)
    {
        if (callbackPhase_.load() > DATA_STOPPED) {
            return;
        }
        std::shared_ptr<ScreenCaptureObject> captureSp;
        auto capture = LockCapture(captureSp);
        if (capture == nullptr) {
            return;
        }
        std::shared_ptr<CallbackT> cb;
        {
            std::shared_lock<std::shared_mutex> lock(mutex_);
            cb = this->*member;
        }
        if (cb != nullptr) {
            f(capture, cb);
        }
    }

    std::shared_mutex mutex_;
    std::atomic<CallbackPhase> callbackPhase_ = ACTIVE;
    std::weak_ptr<ScreenCaptureObject> captureObject_;
    struct OH_AVScreenCaptureCallback callback_;
    std::atomic<bool> hasDataCallback_ = false;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnStateChange>>
        stateChangeCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnError>> errorCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureDataCallback> dataCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnDisplaySelected>>
        displaySelectedCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnCaptureContentChanged>>
        contentChangedCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnUserSelected>>
        userSelectedCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnPrivacyProtect>>
        privacyProtectCallback_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // NATIVE_AVSCREEN_CAPTURE_CALLBACK_H