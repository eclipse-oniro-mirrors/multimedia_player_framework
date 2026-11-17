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

#include "native_avscreen_capture_callback.h"

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

const char *OH_SCREEN_CAPTURE_CONTENT_RECT = "screen_capture_content_rect";

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "NativeScreenCapture"};

OHOS::Rect GetCropRegionFromMetadata(const OHOS::sptr<OHOS::SurfaceBuffer> &surfaceBuffer)
{
    OHOS::Rect rsRect = {-1, -1, -1, -1};
    if (surfaceBuffer == nullptr) {
        return rsRect;
    }
    OHOS::HDI::Display::Graphic::Common::V1_0::BufferHandleMetaRegion metaRegion;
    std::vector<uint8_t> metaData;
    auto metaRet = surfaceBuffer->GetMetadata(OHOS::HDI::Display::Graphic::Common::V1_0::ATTRKEY_CROP_REGION, metaData);
    if (metaRet == OHOS::GSERROR_OK &&
        memcpy_s(&metaRegion, sizeof(OHOS::HDI::Display::Graphic::Common::V1_0::BufferHandleMetaRegion),
            metaData.data(), metaData.size()) == EOK) {
        rsRect.x = static_cast<int32_t>(metaRegion.left);
        rsRect.y = static_cast<int32_t>(metaRegion.top);
        rsRect.w = static_cast<int32_t>(metaRegion.width);
        rsRect.h = static_cast<int32_t>(metaRegion.height);
        MEDIA_LOGD("GetCropRegionFromMetadata: x:%{public}d, y:%{public}d, w:%{public}d, h:%{public}d", rsRect.x,
            rsRect.y, rsRect.w, rsRect.h);
    } else {
        MEDIA_LOGD("GetCropRegionFromMetadata get crop region metadata failed, ret:%{public}d", metaRet);
    }
    return rsRect;
}
} // namespace

void NativeScreenCaptureDataCallback::OnBufferAvailable(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureBufferType bufferType)
{
    CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
    switch (bufferType) {
        case OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_VIDEO:
            OnProcessVideoBuffer(capture);
            return;
        case OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_INNER: // fall-through
        case OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_MIC:
            OnProcessAudioBuffer(capture, bufferType);
            return;
        default:
            MEDIA_LOGD("OnBufferAvailable() is called, invalid bufferType:%{public}d", bufferType);
            return;
    }
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::AcquireAudioBuffer(
    const std::shared_ptr<ScreenCapture> &screenCapture, OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp,
    AudioCaptureSourceType type)
{
    std::shared_ptr<AudioBuffer> aBuffer;
    int32_t ret = screenCapture->AcquireAudioBuffer(aBuffer, type);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        "AcquireAudioBuffer failed not permit! ret:%{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(aBuffer != nullptr && aBuffer->buffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireAudioBuffer failed aBuffer no memory!");
    std::shared_ptr<AVBuffer> avBuffer = AVBuffer::CreateAVBuffer(aBuffer->buffer, aBuffer->length, aBuffer->length);
    CHECK_AND_RETURN_RET_LOG(avBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireAudioBuffer failed avBuffer no memory!");
    aBuffer->buffer = nullptr; // memory control has transfered to AVBuffer
    timestamp = aBuffer->timestamp;
    ohAvBuffer = new (std::nothrow) OH_AVBuffer(avBuffer);

    CHECK_AND_RETURN_RET_LOG(ohAvBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireAudioBuffer failed ohAvBuffer no memory!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::ReleaseAudioBuffer(
    const std::shared_ptr<ScreenCapture> &screenCapture, AudioCaptureSourceType type)
{
    int32_t ret = screenCapture->ReleaseAudioBuffer(type);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        "ReleaseAudioBuffer failed! ret:%{public}d", ret);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::OnProcessAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureBufferType bufferType)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "screenCapture is null");

    MEDIA_LOGD("OnProcessAudioBuffer() is called, bufferType %{public}d", bufferType);
    AudioCaptureSourceType audioSourceType;
    if (bufferType == OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_INNER) {
        audioSourceType = AudioCaptureSourceType::ALL_PLAYBACK;
    } else if (bufferType == OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_MIC) {
        audioSourceType = AudioCaptureSourceType::MIC;
    } else {
        return AV_SCREEN_CAPTURE_ERR_INVALID_VAL;
    }
    OHOS::sptr<OH_AVBuffer> ohAvBuffer;
    int64_t timestamp = 0;
    OH_AVSCREEN_CAPTURE_ErrCode errCode = AcquireAudioBuffer(screenCaptureObj->screenCapture_, ohAvBuffer, timestamp,
        audioSourceType);
    if (errCode == AV_SCREEN_CAPTURE_ERR_OK) {
        MEDIA_LOGD("OnProcessAudioBuffer: 0x%{public}06" PRIXPTR " In", FAKE_POINTER(capture));
        callback_(capture, reinterpret_cast<OH_AVBuffer *>(ohAvBuffer.GetRefPtr()), bufferType, timestamp, userData_);
        MEDIA_LOGD("OnProcessAudioBuffer: 0x%{public}06" PRIXPTR " Out", FAKE_POINTER(capture));
        if (ohAvBuffer->buffer_ == nullptr || ohAvBuffer->buffer_->memory_ == nullptr) {
            return AV_SCREEN_CAPTURE_ERR_INVALID_VAL;
        }
        free(ohAvBuffer->buffer_->memory_->GetAddr());
    }
    errCode = ReleaseAudioBuffer(screenCaptureObj->screenCapture_, audioSourceType);
    return errCode;
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::AcquireVideoBuffer(
    const std::shared_ptr<ScreenCapture> &screenCapture, OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp)
{
    int32_t fence = -1;
    OHOS::Rect damage;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = screenCapture->AcquireVideoBuffer(fence, timestamp, damage);
    CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireVideoBuffer failed surfaceBuffer no memory!");
    std::shared_ptr<AVBuffer> avBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    CHECK_AND_RETURN_RET_LOG(avBuffer != nullptr && avBuffer->memory_ != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireVideoBuffer failed avBuffer no memory!");
    MEDIA_LOGD("AcquireVideoBuffer Size %{public}d", static_cast<int32_t>(surfaceBuffer->GetSize()));
    avBuffer->memory_->SetSize(static_cast<int32_t>(surfaceBuffer->GetSize()));
    ohAvBuffer = new (std::nothrow) OH_AVBuffer(avBuffer);
    CHECK_AND_RETURN_RET_LOG(ohAvBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
        "AcquireVideoBuffer failed ohAvBuffer no memory!");

    OH_AVFormat *format = OH_AVFormat_Create();
    if (format != nullptr) {
        OHOS::Rect rsRect = GetCropRegionFromMetadata(surfaceBuffer);
        if (rsRect.x >= 0 && rsRect.y >= 0 && rsRect.w >= 0 && rsRect.h >= 0) {
            int32_t rectData[4] = {rsRect.x, rsRect.y, rsRect.w, rsRect.h};
            bool formatRes = OH_AVFormat_SetIntBuffer(format, OH_SCREEN_CAPTURE_CONTENT_RECT, rectData,
                sizeof(rectData));
            OH_AVErrCode paramRes = OH_AVBuffer_SetParameter(reinterpret_cast<OH_AVBuffer *>(ohAvBuffer.GetRefPtr()),
                format);
            TRUE_LOG(!formatRes || paramRes != AV_ERR_OK, MEDIA_LOGE,
                "OH_AVFormat_SetIntBuffer or OH_AVBuffer_SetParameter failed.");
        }
        OH_AVFormat_Destroy(format);
    }

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::ReleaseVideoBuffer(
    const std::shared_ptr<ScreenCapture> &screenCapture)
{
    int32_t ret = screenCapture->ReleaseVideoBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        "ReleaseVideoBuffer failed! ret:%{public}d", ret);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode NativeScreenCaptureDataCallback::OnProcessVideoBuffer(struct OH_AVScreenCapture *capture)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "screenCapture is null");

    OHOS::sptr<OH_AVBuffer> ohAvBuffer;
    int64_t timestamp = 0;
    OH_AVSCREEN_CAPTURE_ErrCode errCode = AcquireVideoBuffer(screenCaptureObj->screenCapture_, ohAvBuffer, timestamp);
    if (errCode == AV_SCREEN_CAPTURE_ERR_OK) {
        MEDIA_LOGD("OnProcessVideoBuffer: 0x%{public}06" PRIXPTR " In", FAKE_POINTER(capture));
        callback_(capture, reinterpret_cast<OH_AVBuffer *>(ohAvBuffer.GetRefPtr()),
            OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_VIDEO, timestamp, userData_);
        MEDIA_LOGD("OnProcessVideoBuffer: 0x%{public}06" PRIXPTR " Out", FAKE_POINTER(capture));
    }
    errCode = ReleaseVideoBuffer(screenCaptureObj->screenCapture_);
    return errCode;
}

void NativeScreenCaptureCallback::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGE("OnError() is called, errorType %{public}d, errorCode %{public}d", errorType, errorCode);
    std::shared_ptr<ScreenCaptureObject> captureSp;
    auto capture = LockCapture(captureSp);
    CHECK_AND_RETURN(capture != nullptr);
    std::shared_ptr<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnError>> errorCallback;
    struct OH_AVScreenCaptureCallback callback{};
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        errorCallback = errorCallback_;
        callback = callback_;
    }
    if (errorCallback != nullptr) {
        errorCallback->Invoke(capture, errorCode);
        return;
    }
    if (callback.onError != nullptr) {
        callback.onError(capture, errorCode);
        return;
    }
}

void NativeScreenCaptureCallback::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("OnStateChange() is called, stateCode %{public}d", stateCode);
    DispatchCallback(&NativeScreenCaptureCallback::stateChangeCallback_,
        [&stateCode](struct OH_AVScreenCapture *capture, const auto &cb) {
            cb->Invoke(capture, static_cast<OH_AVScreenCaptureStateCode>(stateCode));
        });
}

void NativeScreenCaptureCallback::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect *area)
{
    MEDIA_LOGD("OnCaptureContentChanged() is called, event: %{public}d", event);
    DispatchCallback(&NativeScreenCaptureCallback::contentChangedCallback_,
        [&event, area](struct OH_AVScreenCapture *capture, const auto &cb) {
            MEDIA_LOGD("NativeScreenCaptureContentChangedCallback OnCaptureContentChanged");
            cb->Invoke(capture, static_cast<OH_AVScreenCaptureContentChangedEvent>(event),
                area == nullptr ? nullptr : reinterpret_cast<OH_Rect *>(area));
        });
}

void NativeScreenCaptureCallback::OnDisplaySelected(uint64_t displayId)
{
    MEDIA_LOGI("OnDisplaySelected() is called, displayId (%{public}" PRIu64 ")", displayId);
    DispatchCallback(&NativeScreenCaptureCallback::displaySelectedCallback_,
        [&displayId](struct OH_AVScreenCapture *capture, const auto &cb) { cb->Invoke(capture, displayId); });
}

void NativeScreenCaptureCallback::OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    MEDIA_LOGI("OnUserSelected() is called");
    DispatchCallback(&NativeScreenCaptureCallback::userSelectedCallback_,
        [&selectionInfo](struct OH_AVScreenCapture *capture, const auto &cb) {
            std::unique_ptr<ScreenCaptureUserSelectionObject> object(
                new (std::nothrow) ScreenCaptureUserSelectionObject(selectionInfo));
            CHECK_AND_RETURN_LOG(object != nullptr, "failed to new ScreenCaptureUserSelectionObject");
            cb->Invoke(capture, reinterpret_cast<OH_AVScreenCapture_UserSelectionInfo *>(object.get()));
        });
}

void NativeScreenCaptureCallback::OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect)
{
    MEDIA_LOGI("OnPrivacyProtect() is called");
    DispatchCallback(&NativeScreenCaptureCallback::privacyProtectCallback_,
        [&privacyProtect](struct OH_AVScreenCapture *capture, const auto &cb) {
            OH_PrivacyProtectInfo data = {
                .systemWindowProtection = privacyProtect.systemPrivacyProtection,
                .sensitiveAppProtection = privacyProtect.appPrivacyProtection,
            };
            cb->Invoke(capture, &data);
        });
}

void NativeScreenCaptureCallback::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    CHECK_AND_RETURN(callbackPhase_.load() == ACTIVE);
    MEDIA_LOGD("OnAudioBufferAvailable() is called, isReady:%{public}d, type:%{public}d", isReady, type);
    std::shared_ptr<ScreenCaptureObject> captureSp;
    auto capture = LockCapture(captureSp);
    CHECK_AND_RETURN(capture != nullptr);
    std::shared_ptr<NativeScreenCaptureDataCallback> dataCallback;
    struct OH_AVScreenCaptureCallback callback{};
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        dataCallback = dataCallback_;
        callback = callback_;
    }
    if (dataCallback != nullptr) {
        if (!isReady) {
            MEDIA_LOGD("OnAudioBufferAvailable not ready");
            return;
        }
        if (type == AudioCaptureSourceType::SOURCE_DEFAULT || type == AudioCaptureSourceType::MIC) {
            dataCallback->OnBufferAvailable(capture,
                OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_MIC);
        } else if (type == AudioCaptureSourceType::ALL_PLAYBACK || type == AudioCaptureSourceType::APP_PLAYBACK) {
            dataCallback->OnBufferAvailable(capture,
                OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_INNER);
        } else {
            MEDIA_LOGD("OnAudioBufferAvailable() is called, invalid audio source type:%{public}d", type);
        }
        MEDIA_LOGD("OnAudioBufferAvailable finished");
        return;
    }
    if (callback.onAudioBufferAvailable != nullptr) {
        callback.onAudioBufferAvailable(capture, isReady, static_cast<OH_AudioCaptureSourceType>(type));
        MEDIA_LOGD("OnAudioBufferAvailable finished");
        return;
    }
    MEDIA_LOGD("OnAudioBufferAvailable finished");
}

void NativeScreenCaptureCallback::OnVideoBufferAvailable(bool isReady)
{
    CHECK_AND_RETURN(callbackPhase_.load() == ACTIVE);
    MEDIA_LOGD("OnVideoBufferAvailable() is called, isReady:%{public}d", isReady);
    std::shared_ptr<ScreenCaptureObject> captureSp;
    auto capture = LockCapture(captureSp);
    CHECK_AND_RETURN(capture != nullptr);
    std::shared_ptr<NativeScreenCaptureDataCallback> dataCallback;
    struct OH_AVScreenCaptureCallback callback{};
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        dataCallback = dataCallback_;
        callback = callback_;
    }
    if (dataCallback != nullptr) {
        if (!isReady) {
            MEDIA_LOGD("OnVideoBufferAvailable not ready");
            return;
        }
        dataCallback->OnBufferAvailable(capture, OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_VIDEO);
        MEDIA_LOGD("OnVideoBufferAvailable finished");
        return;
    }
    if (callback.onVideoBufferAvailable != nullptr) {
        callback.onVideoBufferAvailable(capture, isReady);
    }
    MEDIA_LOGD("OnVideoBufferAvailable finished");
}

void NativeScreenCaptureCallback::StopDataCallback()
{
    callbackPhase_.store(DATA_STOPPED);
}

void NativeScreenCaptureCallback::StopAllCallbacks()
{
    callbackPhase_.store(STOPPED);
}

void NativeScreenCaptureCallback::SetCallback(struct OH_AVScreenCaptureCallback callback)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    callback_ = callback;
}

bool NativeScreenCaptureCallback::IsDataCallbackEnabled()
{
    return hasDataCallback_.load();
}

bool NativeScreenCaptureCallback::IsStateChangeCallbackEnabled()
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return stateChangeCallback_ != nullptr;
}

void NativeScreenCaptureCallback::SetStateChangeCallback(OH_AVScreenCapture_OnStateChange callback, void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    stateChangeCallback_ = std::make_shared<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnStateChange>>(
        callback, userData);
}

void NativeScreenCaptureCallback::SetCaptureContentChangedCallback(OH_AVScreenCapture_OnCaptureContentChanged callback,
    void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    contentChangedCallback_ = std::make_shared<
        NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnCaptureContentChanged>>(callback, userData);
}

void NativeScreenCaptureCallback::SetUserSelectedCallback(OH_AVScreenCapture_OnUserSelected callback, void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    userSelectedCallback_ = std::make_shared<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnUserSelected>>(
        callback, userData);
}

void NativeScreenCaptureCallback::SetPrivacyProtectCallback(OH_AVScreenCapture_OnPrivacyProtect callback,
    void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    privacyProtectCallback_ = std::make_shared<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnPrivacyProtect>>(
        callback, userData);
}

void NativeScreenCaptureCallback::SetErrorCallback(OH_AVScreenCapture_OnError callback, void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    errorCallback_ = std::make_shared<NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnError>>(callback,
        userData);
}

void NativeScreenCaptureCallback::SetDataCallback(OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    dataCallback_ = std::make_shared<NativeScreenCaptureDataCallback>(callback, userData);
    hasDataCallback_.store(true);
}

void NativeScreenCaptureCallback::SetDisplayCallback(OH_AVScreenCapture_OnDisplaySelected callback, void *userData)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    displaySelectedCallback_ = std::make_shared<
        NativeScreenCaptureForwardCallback<OH_AVScreenCapture_OnDisplaySelected>>(callback, userData);
}

struct OH_AVScreenCapture *NativeScreenCaptureCallback::LockCapture(std::shared_ptr<ScreenCaptureObject> &captureSp)
{
    captureSp = captureObject_.lock();
    return captureSp.get();
}

} // namespace Media
} // namespace OHOS
