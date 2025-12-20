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

#include "native_avscreen_capture.h"

#include <mutex>
#include <queue>
#include <shared_mutex>
#include <set>

#include "buffer/avbuffer.h"
#include "common/native_mfmagic.h"
#include "media_log.h"
#include "media_errors.h"
#include "native_avbuffer.h"
#include "native_player_magic.h"
#include "surface_buffer_impl.h"
#include "native_window.h"

namespace {
constexpr int MAX_WINDOWS_LEN = 1000;
constexpr int VIRTUAL_DISPLAY_ID_START = 1000;
constexpr uint32_t MIN_LINE_THICKNESS = 1;
constexpr uint32_t MAX_LINE_THICKNESS = 8;
constexpr uint32_t MIN_LINE_COLOR_RGB = 0x000000;
constexpr uint32_t MAX_LINE_COLOR_RGB = 0xffffff;
constexpr uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;
constexpr uint32_t MAX_LINE_COLOR_ARGB = 0xffffffff;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "NativeScreenCapture"};
}

typedef struct NativeWindow OHNativeWindow;

using namespace OHOS::Media;
std::mutex g_bufferMutex;
static std::queue<OH_NativeBuffer*> referencedBuffer_;
class NativeScreenCaptureCallback;
struct ScreenCaptureUserSelectionObject;

struct ScreenCaptureObject : public OH_AVScreenCapture {
    explicit ScreenCaptureObject(const std::shared_ptr<ScreenCapture> &capture)
        : screenCapture_(capture) {}
    ~ScreenCaptureObject() = default;

    const std::shared_ptr<ScreenCapture> screenCapture_ = nullptr;
    std::shared_ptr<NativeScreenCaptureCallback> callback_ = nullptr;
    bool isStart = false;
};

struct ScreenCaptureUserSelectionObject : public OH_AVScreenCapture_UserSelectionInfo {
    explicit ScreenCaptureUserSelectionObject(ScreenCaptureUserSelectionInfo selectionInfo)
        : userSelectionInfo_(selectionInfo) {}
    ~ScreenCaptureUserSelectionObject() = default;
    ScreenCaptureUserSelectionInfo userSelectionInfo_;
};

class NativeScreenCaptureStateChangeCallback {
public:
    NativeScreenCaptureStateChangeCallback(OH_AVScreenCapture_OnStateChange callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureStateChangeCallback() = default;

    void OnStateChange(struct OH_AVScreenCapture *capture, AVScreenCaptureStateCode infoType)
    {
        CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
        callback_(capture, static_cast<OH_AVScreenCaptureStateCode>(infoType), userData_);
    }

private:
    OH_AVScreenCapture_OnStateChange callback_;
    void *userData_;
};

class NativeScreenCaptureContentChangedCallback {
public:
    NativeScreenCaptureContentChangedCallback(OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureContentChangedCallback() = default;

    void OnCaptureContentChanged(struct OH_AVScreenCapture *capture, AVScreenCaptureContentChangedEvent event,
        ScreenCaptureRect* area)
    {
        MEDIA_LOGD("NativeScreenCaptureContentChangedCallback OnCaptureContentChanged");
        CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
        callback_(capture, static_cast<OH_AVScreenCaptureContentChangedEvent>(event),
            area == nullptr ? nullptr : reinterpret_cast<OH_Rect*>(area), userData_);
    }

private:
    OH_AVScreenCapture_OnCaptureContentChanged callback_;
    void *userData_;
};

class NativeScreenCaptureDisplaySelectedCallback {
public:
    NativeScreenCaptureDisplaySelectedCallback(OH_AVScreenCapture_OnDisplaySelected callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureDisplaySelectedCallback() = default;

    void OnDisplaySelected(struct OH_AVScreenCapture *capture, uint64_t displayId)
    {
        CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
        callback_(capture, displayId, userData_);
    }

private:
    OH_AVScreenCapture_OnDisplaySelected callback_;
    void *userData_;
};

class NativeScreenCaptureUserSelectedCallback {
public:
    NativeScreenCaptureUserSelectedCallback(OH_AVScreenCapture_OnUserSelected callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureUserSelectedCallback() = default;

    void OnUserSelected(struct OH_AVScreenCapture *capture, ScreenCaptureUserSelectionInfo selectionInfo)
    {
        CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
        struct ScreenCaptureUserSelectionObject *object =
            new(std::nothrow) ScreenCaptureUserSelectionObject(selectionInfo);
        CHECK_AND_RETURN_LOG(object != nullptr, "failed to new ScreenCaptureUserSelectionObject");
        callback_(capture, reinterpret_cast<OH_AVScreenCapture_UserSelectionInfo*>(object), userData_);
        delete object;
        object = nullptr;
    }

private:
    OH_AVScreenCapture_OnUserSelected callback_;
    void *userData_;
};

class NativeScreenCaptureErrorCallback {
public:
    NativeScreenCaptureErrorCallback(OH_AVScreenCapture_OnError callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureErrorCallback() = default;

    void OnError(struct OH_AVScreenCapture *capture, int32_t errorCode)
    {
        CHECK_AND_RETURN(capture != nullptr && callback_ != nullptr);
        callback_(capture, errorCode, userData_);
    }

private:
    OH_AVScreenCapture_OnError callback_;
    void *userData_;
};

class NativeScreenCaptureDataCallback {
public:
    NativeScreenCaptureDataCallback(OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeScreenCaptureDataCallback() = default;

    void OnBufferAvailable(struct OH_AVScreenCapture *capture, OH_AVScreenCaptureBufferType bufferType)
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

private:
    static OH_AVSCREEN_CAPTURE_ErrCode AcquireAudioBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp, AudioCaptureSourceType type)
    {
        std::shared_ptr<AudioBuffer> aBuffer;
        int32_t ret = screenCapture->AcquireAudioBuffer(aBuffer, type);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "AcquireAudioBuffer failed not permit! ret:%{public}d", ret);
        CHECK_AND_RETURN_RET_LOG(aBuffer != nullptr && aBuffer->buffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireAudioBuffer failed aBuffer no memory!");
        std::shared_ptr<AVBuffer> avBuffer = AVBuffer::CreateAVBuffer(aBuffer->buffer, aBuffer->length,
            aBuffer->length);
        CHECK_AND_RETURN_RET_LOG(avBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireAudioBuffer failed avBuffer no memory!");
        aBuffer->buffer = nullptr; // memory control has transfered to AVBuffer
        timestamp = aBuffer->timestamp;
        ohAvBuffer = new(std::nothrow) OH_AVBuffer(avBuffer);

        CHECK_AND_RETURN_RET_LOG(ohAvBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireAudioBuffer failed ohAvBuffer no memory!");
        return AV_SCREEN_CAPTURE_ERR_OK;
    }

    static OH_AVSCREEN_CAPTURE_ErrCode ReleaseAudioBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        AudioCaptureSourceType type)
    {
        int32_t ret = screenCapture->ReleaseAudioBuffer(type);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "ReleaseAudioBuffer failed! ret:%{public}d", ret);
        return AV_SCREEN_CAPTURE_ERR_OK;
    }

    OH_AVSCREEN_CAPTURE_ErrCode OnProcessAudioBuffer(struct OH_AVScreenCapture *capture,
        OH_AVScreenCaptureBufferType bufferType)
    {
        CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
        struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
        CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
            AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");

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
        OH_AVSCREEN_CAPTURE_ErrCode errCode =
            AcquireAudioBuffer(screenCaptureObj->screenCapture_, ohAvBuffer, timestamp, audioSourceType);
        if (errCode == AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGD("OnProcessAudioBuffer: 0x%{public}06" PRIXPTR " In", FAKE_POINTER(capture));
            callback_(capture, reinterpret_cast<OH_AVBuffer *>(ohAvBuffer.GetRefPtr()), bufferType, timestamp,
                userData_);
            MEDIA_LOGD("OnProcessAudioBuffer: 0x%{public}06" PRIXPTR " Out", FAKE_POINTER(capture));
            if (ohAvBuffer->buffer_ == nullptr || ohAvBuffer->buffer_->memory_ == nullptr) {
                return AV_SCREEN_CAPTURE_ERR_INVALID_VAL;
            }
            free(ohAvBuffer->buffer_->memory_->GetAddr());
        }
        errCode = ReleaseAudioBuffer(screenCaptureObj->screenCapture_, audioSourceType);
        return errCode;
    }
    static OH_AVSCREEN_CAPTURE_ErrCode AcquireVideoBuffer(const std::shared_ptr<ScreenCapture> &screenCapture,
        OHOS::sptr<OH_AVBuffer> &ohAvBuffer, int64_t &timestamp)
    {
        int32_t fence = -1;
        OHOS::Rect damage;
        OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer =
            screenCapture->AcquireVideoBuffer(fence, timestamp, damage);
        CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireVideoBuffer failed surfaceBuffer no memory!");
        std::shared_ptr<AVBuffer> avBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
        CHECK_AND_RETURN_RET_LOG(avBuffer != nullptr && avBuffer->memory_ != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireVideoBuffer failed avBuffer no memory!");
        MEDIA_LOGD("AcquireVideoBuffer Size %{public}d", static_cast<int32_t>(surfaceBuffer->GetSize()));
        avBuffer->memory_->SetSize(static_cast<int32_t>(surfaceBuffer->GetSize()));
        ohAvBuffer = new(std::nothrow) OH_AVBuffer(avBuffer);
        CHECK_AND_RETURN_RET_LOG(ohAvBuffer != nullptr, AV_SCREEN_CAPTURE_ERR_NO_MEMORY,
            "AcquireVideoBuffer failed ohAvBuffer no memory!");
        return AV_SCREEN_CAPTURE_ERR_OK;
    }

    static OH_AVSCREEN_CAPTURE_ErrCode ReleaseVideoBuffer(const std::shared_ptr<ScreenCapture> &screenCapture)
    {
        int32_t ret = screenCapture->ReleaseVideoBuffer();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "ReleaseVideoBuffer failed! ret:%{public}d", ret);
        return AV_SCREEN_CAPTURE_ERR_OK;
    }

    OH_AVSCREEN_CAPTURE_ErrCode OnProcessVideoBuffer(struct OH_AVScreenCapture *capture)
    {
        CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
        struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
        CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
            AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");

        OHOS::sptr<OH_AVBuffer> ohAvBuffer;
        int64_t timestamp = 0;
        OH_AVSCREEN_CAPTURE_ErrCode errCode =
            AcquireVideoBuffer(screenCaptureObj->screenCapture_, ohAvBuffer, timestamp);
        if (errCode == AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGD("OnProcessVideoBuffer: 0x%{public}06" PRIXPTR " In", FAKE_POINTER(capture));
            callback_(capture, reinterpret_cast<OH_AVBuffer *>(ohAvBuffer.GetRefPtr()),
                OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_VIDEO, timestamp, userData_);
            MEDIA_LOGD("OnProcessVideoBuffer: 0x%{public}06" PRIXPTR " Out", FAKE_POINTER(capture));
        }
        errCode = ReleaseVideoBuffer(screenCaptureObj->screenCapture_);
        return errCode;
    }

private:
    OH_AVScreenCapture_OnBufferAvailable callback_;
    void *userData_;
};

class NativeScreenCaptureCallback : public ScreenCaptureCallBack {
public:
    NativeScreenCaptureCallback(struct OH_AVScreenCapture *capture, struct OH_AVScreenCaptureCallback callback)
        : capture_(capture), callback_(callback) {}
    virtual ~NativeScreenCaptureCallback() = default;

    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override
    {
        MEDIA_LOGE("OnError() is called, errorType %{public}d, errorCode %{public}d", errorType, errorCode);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (errorCallback_ != nullptr) {
            errorCallback_->OnError(capture_, errorCode);
            return;
        }

        if (callback_.onError != nullptr) {
            callback_.onError(capture_, errorCode);
            return;
        }
    }

    void OnStateChange(AVScreenCaptureStateCode stateCode) override
    {
        MEDIA_LOGI("OnStateChange() is called, stateCode %{public}d", stateCode);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (stateChangeCallback_ != nullptr) {
            stateChangeCallback_->OnStateChange(capture_, stateCode);
            return;
        }
    }

    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area) override
    {
        MEDIA_LOGD("OnCaptureContentChanged() is called, event: %{public}d", event);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr && contentChangedCallback_ != nullptr);
        contentChangedCallback_->OnCaptureContentChanged(capture_, event, area);
    }

    void OnDisplaySelected(uint64_t displayId) override
    {
        MEDIA_LOGI("OnDisplaySelected() is called, displayId (%{public}" PRIu64 ")", displayId);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (displaySelectedCallback_ != nullptr) {
            displaySelectedCallback_->OnDisplaySelected(capture_, displayId);
            return;
        }
    }

    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override
    {
        MEDIA_LOGI("OnUserSelected() is called");
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (userSelectedCallback_ != nullptr) {
            userSelectedCallback_->OnUserSelected(capture_, selectionInfo);
            return;
        }
    }

    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override
    {
        CHECK_AND_RETURN(!isBufferAvailableCallbackStop_.load());
        MEDIA_LOGD("OnAudioBufferAvailable() is called, isReady:%{public}d, type:%{public}d", isReady, type);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (dataCallback_ != nullptr && hasDataCallback_.load()) {
            if (!isReady) {
                MEDIA_LOGD("OnAudioBufferAvailable not ready");
                return;
            }
            if (type == AudioCaptureSourceType::SOURCE_DEFAULT || type == AudioCaptureSourceType::MIC) {
                dataCallback_->OnBufferAvailable(capture_,
                    OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_MIC);
            } else if (type == AudioCaptureSourceType::ALL_PLAYBACK || type == AudioCaptureSourceType::APP_PLAYBACK) {
                dataCallback_->OnBufferAvailable(capture_,
                    OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_AUDIO_INNER);
            } else {
                MEDIA_LOGD("OnAudioBufferAvailable() is called, invalid audio source type:%{public}d", type);
            }
            MEDIA_LOGD("OnAudioBufferAvailable finished");
            return;
        }
        if (callback_.onAudioBufferAvailable != nullptr) {
            callback_.onAudioBufferAvailable(capture_, isReady, static_cast<OH_AudioCaptureSourceType>(type));
            MEDIA_LOGD("OnAudioBufferAvailable finished");
            return;
        }
        MEDIA_LOGD("OnAudioBufferAvailable finished");
    }

    void OnVideoBufferAvailable(bool isReady) override
    {
        CHECK_AND_RETURN(!isBufferAvailableCallbackStop_.load());
        MEDIA_LOGD("OnVideoBufferAvailable() is called, isReady:%{public}d", isReady);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(capture_ != nullptr);

        if (dataCallback_ != nullptr && hasDataCallback_.load()) {
            if (!isReady) {
                MEDIA_LOGD("OnVideoBufferAvailable not ready");
                return;
            }
            dataCallback_->OnBufferAvailable(capture_,
                OH_AVScreenCaptureBufferType::OH_SCREEN_CAPTURE_BUFFERTYPE_VIDEO);
            MEDIA_LOGD("OnVideoBufferAvailable finished");
            return;
        }
        if (capture_ != nullptr && callback_.onVideoBufferAvailable != nullptr) {
            callback_.onVideoBufferAvailable(capture_, isReady);
        }
        MEDIA_LOGD("OnVideoBufferAvailable finished");
    }

    void StopCallback()
    {
        isBufferAvailableCallbackStop_.store(true);
        MEDIA_LOGD("StopCallback before lock"); // waiting for OnBufferAvailable
        std::unique_lock<std::shared_mutex> lock(mutex_);
        MEDIA_LOGD("StopCallback after lock");
    }

    void SetCallback(struct OH_AVScreenCaptureCallback callback)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        callback_ = callback;
    }

    bool IsDataCallbackEnabled()
    {
        return hasDataCallback_.load();
    }

    bool IsStateChangeCallbackEnabled()
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return stateChangeCallback_ != nullptr;
    }

    bool SetStateChangeCallback(OH_AVScreenCapture_OnStateChange callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        stateChangeCallback_ = std::make_shared<NativeScreenCaptureStateChangeCallback>(callback, userData);
        return stateChangeCallback_ != nullptr;
    }

    bool SetCaptureContentChangedCallback(OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        contentChangedCallback_ = std::make_shared<NativeScreenCaptureContentChangedCallback>(callback, userData);
        return contentChangedCallback_ != nullptr;
    }

    bool SetUserSelectedCallback(OH_AVScreenCapture_OnUserSelected callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        userSelectedCallback_ = std::make_shared<NativeScreenCaptureUserSelectedCallback>(callback, userData);
        return userSelectedCallback_ != nullptr;
    }

    bool SetErrorCallback(OH_AVScreenCapture_OnError callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        errorCallback_ = std::make_shared<NativeScreenCaptureErrorCallback>(callback, userData);
        return errorCallback_ != nullptr;
    }

    bool SetDataCallback(OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        dataCallback_ = std::make_shared<NativeScreenCaptureDataCallback>(callback, userData);
        hasDataCallback_.store(true);
        return dataCallback_ != nullptr;
    }

    bool SetDisplayCallback(OH_AVScreenCapture_OnDisplaySelected callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        displaySelectedCallback_ = std::make_shared<NativeScreenCaptureDisplaySelectedCallback>(callback, userData);
        return displaySelectedCallback_ != nullptr;
    }

private:
    std::shared_mutex mutex_;
    struct OH_AVScreenCapture *capture_ = nullptr;
    struct OH_AVScreenCaptureCallback callback_;
    std::atomic<bool> isBufferAvailableCallbackStop_ = false;
    std::atomic<bool> hasDataCallback_ = false;
    std::shared_ptr<NativeScreenCaptureStateChangeCallback> stateChangeCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureDataCallback> dataCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureDisplaySelectedCallback> displaySelectedCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureContentChangedCallback> contentChangedCallback_ = nullptr;
    std::shared_ptr<NativeScreenCaptureUserSelectedCallback> userSelectedCallback_ = nullptr;
};

struct ScreenCaptureContentFilterObject : public OH_AVScreenCapture_ContentFilter {
    ScreenCaptureContentFilterObject() = default;
    ~ScreenCaptureContentFilterObject() = default;

    ScreenCaptureContentFilter screenCaptureContentFilter;
};

struct OH_AVScreenCapture_ContentFilter *OH_AVScreenCapture_CreateContentFilter(void)
{
    struct ScreenCaptureContentFilterObject *object = new(std::nothrow) ScreenCaptureContentFilterObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new ScreenCaptureContentFilterObject");
    return object;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseContentFilter(struct OH_AVScreenCapture_ContentFilter *filter)
{
    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
        reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);
    delete contentFilterObj;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ContentFilter_AddAudioContent(
    struct OH_AVScreenCapture_ContentFilter *filter, OH_AVScreenCaptureFilterableAudioContent content)
{
    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
        reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);

    CHECK_AND_RETURN_RET_LOG(
        content >= OH_AVScreenCaptureFilterableAudioContent::OH_SCREEN_CAPTURE_NOTIFICATION_AUDIO ||
        content <= OH_AVScreenCaptureFilterableAudioContent::OH_SCREEN_CAPTURE_CURRENT_APP_AUDIO,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input content invalid!");
    contentFilterObj->screenCaptureContentFilter.filteredAudioContents.insert(
        static_cast<AVScreenCaptureFilterableAudioContent>(content));
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ExcludeContent(struct OH_AVScreenCapture *capture,
    struct OH_AVScreenCapture_ContentFilter *filter)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");

    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
        reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);

    int32_t ret = screenCaptureObj->screenCapture_->ExcludeContent(contentFilterObj->screenCaptureContentFilter);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_UNSUPPORT, "StartScreenCapture failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

struct OH_AVScreenCapture *OH_AVScreenCapture_Create(void)
{
    std::shared_ptr<ScreenCapture> screenCapture = ScreenCaptureFactory::CreateScreenCapture();
    CHECK_AND_RETURN_RET_LOG(screenCapture != nullptr, nullptr, "failed to ScreenCaptureFactory::CreateScreenCapture");

    struct ScreenCaptureObject *object = new(std::nothrow) ScreenCaptureObject(screenCapture);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new ScreenCaptureObject");

    return object;
}

namespace {
void SetVideoCapInfo(OH_AVScreenCaptureConfig config, AVScreenCaptureConfig& config_)
{
    config_.videoInfo.videoCapInfo.displayId = config.videoInfo.videoCapInfo.displayId;
    int32_t *taskIds = config.videoInfo.videoCapInfo.missionIDs;
    int32_t size = config.videoInfo.videoCapInfo.missionIDsLen;
    size = size >= MAX_WINDOWS_LEN ? MAX_WINDOWS_LEN : size;
    config_.videoInfo.videoCapInfo.taskIDs = {};
    while (size > 0) {
        if (taskIds == nullptr) {
            break;
        }
        if (*(taskIds) >= 0) {
            config_.videoInfo.videoCapInfo.taskIDs.push_back(*(taskIds));
        }
        taskIds++;
        size--;
    }
    config_.videoInfo.videoCapInfo.videoFrameWidth = config.videoInfo.videoCapInfo.videoFrameWidth;
    config_.videoInfo.videoCapInfo.videoFrameHeight = config.videoInfo.videoCapInfo.videoFrameHeight;
    config_.videoInfo.videoCapInfo.videoSource =
        static_cast<VideoSourceType>(config.videoInfo.videoCapInfo.videoSource);
}

VideoCodecFormat ConvertOHVideoCodecFormat(OH_VideoCodecFormat ohVideoCodec)
{
    static const std::map<OH_VideoCodecFormat, VideoCodecFormat> codecFormatMap = {
        {OH_VideoCodecFormat::OH_VIDEO_DEFAULT, VideoCodecFormat::H264},
        {OH_VideoCodecFormat::OH_H264, VideoCodecFormat::H264},
        {OH_VideoCodecFormat::OH_H265, VideoCodecFormat::H265},
        {OH_VideoCodecFormat::OH_MPEG4, VideoCodecFormat::MPEG4},
    };
    if (codecFormatMap.find(ohVideoCodec) != codecFormatMap.end()) {
        return codecFormatMap.at(ohVideoCodec);
    }
    MEDIA_LOGE("videoCodec is invalid, value is: %{public}d", static_cast<int32_t>(ohVideoCodec));
    return VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT;
}
}

AVScreenCaptureConfig OH_AVScreenCapture_Convert(OH_AVScreenCaptureConfig config)
{
    AVScreenCaptureConfig config_;
    config_.captureMode = static_cast<CaptureMode>(config.captureMode);
    config_.dataType = static_cast<DataType>(config.dataType);
    config_.audioInfo.micCapInfo = {
        .audioSampleRate = config.audioInfo.micCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.micCapInfo.audioChannels,
        .audioSource = static_cast<AudioCaptureSourceType>(config.audioInfo.micCapInfo.audioSource)
    };
    config_.audioInfo.innerCapInfo = {
        .audioSampleRate = config.audioInfo.innerCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.innerCapInfo.audioChannels,
        .audioSource = static_cast<AudioCaptureSourceType>(config.audioInfo.innerCapInfo.audioSource)
    };
    config_.audioInfo.audioEncInfo.audioBitrate = config.audioInfo.audioEncInfo.audioBitrate;
    config_.audioInfo.audioEncInfo.audioCodecformat =
        static_cast<AudioCodecFormat>(config.audioInfo.audioEncInfo.audioCodecformat);
    SetVideoCapInfo(config, config_);
    config_.videoInfo.videoEncInfo = {
        .videoCodec = ConvertOHVideoCodecFormat(config.videoInfo.videoEncInfo.videoCodec),
        .videoBitrate = config.videoInfo.videoEncInfo. videoBitrate,
        .videoFrameRate = config.videoInfo.videoEncInfo.videoFrameRate
    };
    if (config.recorderInfo.url != nullptr) {
        config_.recorderInfo.url = config.recorderInfo.url;
    }
    if (config.recorderInfo.fileFormat == CFT_MPEG_4A) {
        config_.recorderInfo.fileFormat = ContainerFormatType::CFT_MPEG_4A;
    } else if (config.recorderInfo.fileFormat == CFT_MPEG_4) {
        config_.recorderInfo.fileFormat = ContainerFormatType::CFT_MPEG_4;
    }
    return config_;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ExcludePickerWindows(
    struct OH_AVScreenCapture *capture, const int32_t *excludedWindowIDs, uint32_t windowCount)
{
#ifdef PC_STANDARD
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");

    CHECK_AND_RETURN_RET_LOG(!(excludedWindowIDs == nullptr && windowCount > 0),
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input excludedWindowIDs invalid, nullptr but size is not 0!");

    std::vector<int32_t> vec;
    for (uint32_t i = 0; i < windowCount; i++) {
        if (static_cast<int32_t>(*(excludedWindowIDs + i)) > 0) {
            vec.push_back(static_cast<int32_t>(*(excludedWindowIDs + i)));
        }
    }

    int32_t ret = screenCaptureObj->screenCapture_->ExcludePickerWindows(vec);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "ExcludePickerWindows failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
#else
    return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
#endif
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetPickerMode(
    struct OH_AVScreenCapture *capture, OH_CapturePickerMode pickerMode)
{
#ifdef PC_STANDARD
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");

    PickerMode mode = static_cast<PickerMode>(pickerMode);
    CHECK_AND_RETURN_RET_LOG(mode >= PickerMode::MIN_VAL && mode <= PickerMode::MAX_VAL,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "pickerMode is invalid!");

    int32_t ret = screenCaptureObj->screenCapture_->SetPickerMode(mode);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "SetPickerMode failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
#else
    return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
#endif
}

AVScreenCaptureHighlightConfig OH_AVCaptureArea_Convert(OH_AVScreenCaptureHighlightConfig config)
{
    AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.lineThickness = config.lineThickness;
    highlightConfig.lineColor = config.lineColor;
    highlightConfig.mode = static_cast<ScreenCaptureHighlightMode>(config.mode);
    return highlightConfig;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Init(struct OH_AVScreenCapture *capture, OH_AVScreenCaptureConfig config)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    AVScreenCaptureConfig config_ = OH_AVScreenCapture_Convert(config);
    int32_t ret = screenCaptureObj->screenCapture_->Init(config_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "screenCapture init failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

static int32_t SetPrivacyAuthorityEnabled(struct ScreenCaptureObject *screenCaptureObj)
{
    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsStateChangeCallbackEnabled()) {
        int32_t ret = screenCaptureObj->screenCapture_->SetPrivacyAuthorityEnabled();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPrivacyAuthorityEnabled failed!");
    }
    return MSERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenCapture(struct OH_AVScreenCapture *capture)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = SetPrivacyAuthorityEnabled(screenCaptureObj);
    CHECK_AND_RETURN_RET(ret == AV_SCREEN_CAPTURE_ERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT);
    ret = screenCaptureObj->screenCapture_->StartScreenCapture();
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "StartScreenCapture failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "StartScreenCapture failed!");
    screenCaptureObj->isStart = true;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenCaptureWithSurface(struct OH_AVScreenCapture *capture,
    OHNativeWindow* window)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window->surface != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "Input window surface is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = SetPrivacyAuthorityEnabled(screenCaptureObj);
    CHECK_AND_RETURN_RET(ret == AV_SCREEN_CAPTURE_ERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT);
    ret = screenCaptureObj->screenCapture_->StartScreenCaptureWithSurface(window->surface);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "StartScreenCaptureWithSurface failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "StartScreenCapture failed!");
    screenCaptureObj->isStart = true;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StopScreenCapture(struct OH_AVScreenCapture *capture)
{
    MEDIA_LOGI("OH_AVScreenCapture_StopScreenCapture In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->StopScreenCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "StopScreenCapture failed!");
    screenCaptureObj->isStart = false;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenRecording(struct OH_AVScreenCapture *capture)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = SetPrivacyAuthorityEnabled(screenCaptureObj);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT);
    ret = screenCaptureObj->screenCapture_->StartScreenRecording();
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "StartScreenRecording failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "StartScreenRecording failed!");
    screenCaptureObj->isStart = true;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StopScreenRecording(struct OH_AVScreenCapture *capture)
{
    MEDIA_LOGI("OH_AVScreenCapture_StopScreenRecording In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->StopScreenRecording();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "StopScreenRecording failed!");
    screenCaptureObj->isStart = false;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_PresentPicker(struct OH_AVScreenCapture *capture)
{
    MEDIA_LOGI("OH_AVScreenCapture_PresentPicker In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->PresentPicker();
    if (ret == MSERR_INVALID_OPERATION) {
        MEDIA_LOGE("PresentPicker failed, ret: %{public}d", ret);
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "PresentPicker failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_AcquireAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AudioBuffer **audiobuffer, OH_AudioCaptureSourceType type)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(audiobuffer != nullptr && (*audiobuffer != nullptr), AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "input OH_AudioBuffer **audiobuffer is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsDataCallbackEnabled()) {
        MEDIA_LOGE("AcquireAudioBuffer() not permit for has set DataCallback");
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }
    std::shared_ptr<AudioBuffer> aBuffer;
    int32_t ret =
        screenCaptureObj->screenCapture_->AcquireAudioBuffer(aBuffer, static_cast<AudioCaptureSourceType>(type));
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "AcquireAudioBuffer failed!");
    if ((aBuffer == nullptr) || (audiobuffer == nullptr)) {
        return AV_SCREEN_CAPTURE_ERR_NO_MEMORY;
    }
    if (aBuffer->buffer != nullptr) {
        (*audiobuffer)->buf = std::move(aBuffer->buffer);
        aBuffer->buffer = nullptr;
    }
    (*audiobuffer)->size = aBuffer->length;
    (*audiobuffer)->timestamp = aBuffer->timestamp;
    (*audiobuffer)->type = static_cast<OH_AudioCaptureSourceType>(aBuffer->sourcetype);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_NativeBuffer* OH_AVScreenCapture_AcquireVideoBuffer(struct OH_AVScreenCapture *capture,
    int32_t *fence, int64_t *timestamp, struct OH_Rect *region)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, nullptr, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr, nullptr, "screenCapture_ is null");

    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsDataCallbackEnabled()) {
        MEDIA_LOGE("AcquireVideoBuffer() not permit for has set DataCallback");
        return nullptr;
    }
    OHOS::Rect damage;
    OHOS::sptr<OHOS::SurfaceBuffer> sufacebuffer =
        screenCaptureObj->screenCapture_->AcquireVideoBuffer(*fence, *timestamp, damage);
    region->x = damage.x;
    region->y = damage.y;
    region->width = damage.w;
    region->height = damage.h;
    CHECK_AND_RETURN_RET_LOG(sufacebuffer != nullptr, nullptr, "AcquireVideoBuffer failed!");

    OH_NativeBuffer* nativebuffer = sufacebuffer->SurfaceBufferToNativeBuffer();
    OH_NativeBuffer_Reference(nativebuffer);
    std::unique_lock<std::mutex> lock(g_bufferMutex);
    referencedBuffer_.push(nativebuffer);
    MEDIA_LOGD("return and reference the nativebuffer");

    return nativebuffer;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseVideoBuffer(struct OH_AVScreenCapture *capture)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsDataCallbackEnabled()) {
        MEDIA_LOGE("ReleaseVideoBuffer() not permit for has set DataCallback");
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }

    if (!referencedBuffer_.empty()) {
        std::unique_lock<std::mutex> lock(g_bufferMutex);
        OH_NativeBuffer* nativebuffer = referencedBuffer_.front();
        OH_NativeBuffer_Unreference(nativebuffer);
        referencedBuffer_.pop();
        MEDIA_LOGD("unreference the front nativebuffer");
    }

    int32_t ret = screenCaptureObj->screenCapture_->ReleaseVideoBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "ReleaseVideoBuffer failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AudioCaptureSourceType type)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsDataCallbackEnabled()) {
        MEDIA_LOGE("ReleaseAudioBuffer() not permit for has set DataCallback");
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }
    int32_t ret = screenCaptureObj->screenCapture_->ReleaseAudioBuffer(static_cast<AudioCaptureSourceType>(type));
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "ReleaseSurfaceBuffer failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCallback(struct OH_AVScreenCapture *capture,
    struct OH_AVScreenCaptureCallback callback)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    if (screenCaptureObj->callback_ == nullptr) {
        screenCaptureObj->callback_ = std::make_shared<NativeScreenCaptureCallback>(capture, callback);
        CHECK_AND_RETURN_RET_LOG(screenCaptureObj->callback_ != nullptr,
            AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "callback_ is nullptr!");
    } else {
        screenCaptureObj->callback_->SetCallback(callback);
    }

    int32_t ret = screenCaptureObj->screenCapture_->SetScreenCaptureCallback(screenCaptureObj->callback_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        "SetScreenCaptureCallback failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Release(struct OH_AVScreenCapture *capture)
{
    MEDIA_LOGI("OH_AVScreenCapture_Release In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);

    if (screenCaptureObj != nullptr && screenCaptureObj->screenCapture_ != nullptr) {
        if (screenCaptureObj->callback_ != nullptr) {
            screenCaptureObj->callback_->StopCallback();
        }
        int32_t ret = screenCaptureObj->screenCapture_->Release();
        delete capture;
        capture = nullptr;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "screen capture Release failed!");
    } else {
        MEDIA_LOGD("screen capture is nullptr!");
    }
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetMicrophoneEnabled(struct OH_AVScreenCapture *capture,
    bool isMicrophone)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->SetMicrophoneEnabled(isMicrophone);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "setMicrophoneEnable failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

static OH_AVSCREEN_CAPTURE_ErrCode AVScreenCaptureSetCallback(struct OH_AVScreenCapture *capture,
    struct ScreenCaptureObject *screenCaptureObj)
{
    MEDIA_LOGD("AVScreenCaptureSetCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj != nullptr && screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is nullptr!");
    if (screenCaptureObj->callback_ == nullptr) {
        MEDIA_LOGD("AVScreenCaptureSetCallback new NativeScreenCaptureCallback");
        OH_AVScreenCaptureCallback dummyCallback = {
            .onError = nullptr,
            .onAudioBufferAvailable = nullptr,
            .onVideoBufferAvailable = nullptr
        };
        screenCaptureObj->callback_ = std::make_shared<NativeScreenCaptureCallback>(capture, dummyCallback);
        CHECK_AND_RETURN_RET_LOG(screenCaptureObj->callback_ != nullptr,
            AV_SCREEN_CAPTURE_ERR_NO_MEMORY, "callback_ is nullptr!");

        int32_t ret = screenCaptureObj->screenCapture_->SetScreenCaptureCallback(screenCaptureObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "SetScreenCaptureCallback failed!");
    }
    MEDIA_LOGD("AVScreenCaptureSetCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetStateCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnStateChange callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetStateCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input stateCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetStateCallback is null");

    if (screenCaptureObj->callback_ == nullptr ||
        !screenCaptureObj->callback_->SetStateChangeCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetStateCallback error");
        return AV_SCREEN_CAPTURE_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetStateCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureContentChangedCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureContentChangedCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "input contentChangedCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetCaptureContentChangedCallback is null");

    if (screenCaptureObj->callback_ == nullptr ||
        !screenCaptureObj->callback_->SetCaptureContentChangedCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetCaptureContentChangedCallback error");
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureContentChangedCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetErrorCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnError callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetErrorCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input errorCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetErrorCallback is null");

    if (screenCaptureObj->callback_ == nullptr || !screenCaptureObj->callback_->SetErrorCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetErrorCallback error");
        return AV_SCREEN_CAPTURE_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetErrorCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetDataCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetDataCallback E");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input dataCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetDataCallback is null");

    if (screenCaptureObj->callback_ == nullptr ||
        !screenCaptureObj->callback_->SetDataCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetDataCallback error");
        return AV_SCREEN_CAPTURE_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetDataCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCanvasRotation(struct OH_AVScreenCapture *capture,
    bool canvasRotation)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->SetCanvasRotation(canvasRotation);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "SetCanvasRotation failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "SetCanvasRotation failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ShowCursor(struct OH_AVScreenCapture *capture,
    bool showCursor)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    int32_t ret = screenCaptureObj->screenCapture_->ShowCursor(showCursor);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "ShowCursor failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "ShowCursor failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ContentFilter_AddWindowContent(
    struct OH_AVScreenCapture_ContentFilter *filter, int32_t *windowIDs, int32_t windowCount)
{
    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
            reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);
    CHECK_AND_RETURN_RET_LOG(windowIDs != nullptr && windowCount > 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid!");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        if (static_cast<int32_t>(*(windowIDs + i)) >= 0) {
            vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
        }
    }
    contentFilterObj->screenCaptureContentFilter.windowIDsVec = vec;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ResizeCanvas(struct OH_AVScreenCapture *capture,
    int32_t width, int32_t height)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(width > 0 && height > 0, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "input width or height invalid!");

    int32_t ret = screenCaptureObj->screenCapture_->ResizeCanvas(width, height);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "ResizeCanvas failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "ResizeCanvas failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SkipPrivacyMode(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid!");
    CHECK_AND_RETURN_RET_LOG(!(windowIDs == nullptr && windowCount > 0),
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid, nullptr but size not 0!");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        if (static_cast<int32_t>(*(windowIDs + i)) >= 0) {
            vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
        }
    }
    CHECK_AND_RETURN_RET_LOG(vec.size() >= 0, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window content invalid!");
    int32_t ret = screenCaptureObj->screenCapture_->SkipPrivacyMode(vec);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "SkipPrivacyMode failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "SkipPrivacyMode failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_AddWhiteListWindows(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid!");
    CHECK_AND_RETURN_RET_LOG(!(windowIDs == nullptr && windowCount > 0),
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid, nullptr but size not 0!");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        if (static_cast<int32_t>(*(windowIDs + i)) >= 0) {
            vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
        }
    }
    CHECK_AND_RETURN_RET_LOG(vec.size() > 0, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window content invalid!");
    int32_t ret = screenCaptureObj->screenCapture_->AddWhiteListWindows(vec);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "AddWhiteListWindows failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "AddWhiteListWindows failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_RemoveWhiteListWindows(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid!");
    CHECK_AND_RETURN_RET_LOG(!(windowIDs == nullptr && windowCount > 0),
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid, nullptr but size not 0!");
    std::vector<uint64_t> vec;
    for (int32_t i = 0; i < windowCount; i++) {
        if (static_cast<int32_t>(*(windowIDs + i)) >= 0) {
            vec.push_back(static_cast<uint64_t>(*(windowIDs + i)));
        }
    }
    CHECK_AND_RETURN_RET_LOG(vec.size() > 0, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window content invalid!");
    int32_t ret = screenCaptureObj->screenCapture_->RemoveWhiteListWindows(vec);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "RemoveWhiteListWindows failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "RemoveWhiteListWindows failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetMaxVideoFrameRate(struct OH_AVScreenCapture *capture,
    int32_t frameRate)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(frameRate > 0, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input frameRate invalid!");

    int32_t ret = screenCaptureObj->screenCapture_->SetMaxVideoFrameRate(frameRate);
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "SetMaxVideoFrameRate failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "SetMaxVideoFrameRate failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetDisplayCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnDisplaySelected callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetDisplayCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(!screenCaptureObj->isStart,
        AV_SCREEN_CAPTURE_ERR_INVALID_STATE, "This interface should be called before Start is called!");
    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetDisplayCallback is null");

    if (screenCaptureObj->callback_ == nullptr ||
        !screenCaptureObj->callback_->SetDisplayCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetDisplayCallback error");
        return AV_SCREEN_CAPTURE_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetDisplayCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

struct ScreenCaptureStrategyObject : public OH_AVScreenCapture_CaptureStrategy {
    ScreenCaptureStrategyObject() = default;
    ~ScreenCaptureStrategyObject() = default;

    ScreenCaptureStrategy strategy;
};

OH_AVScreenCapture_CaptureStrategy* OH_AVScreenCapture_CreateCaptureStrategy(void)
{
    struct ScreenCaptureStrategyObject *object = new(std::nothrow) ScreenCaptureStrategyObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new ScreenCaptureStrategyObject");
    return object;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseCaptureStrategy(OH_AVScreenCapture_CaptureStrategy* strategy)
{
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    delete strategyObj;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureAreaHighlight(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureHighlightConfig config)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is nullptr");

    CHECK_AND_RETURN_RET_LOG(config.mode == OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CLOSED ||
        config.mode == OH_ScreenCaptureHighlightMode::OH_HIGHLIGHT_MODE_CORNER_WRAP,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input highlight mode is invalid");
    CHECK_AND_RETURN_RET_LOG(config.lineThickness >= MIN_LINE_THICKNESS && config.lineThickness <= MAX_LINE_THICKNESS,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input lineThickness is invalid");
    CHECK_AND_RETURN_RET_LOG((config.lineColor >= MIN_LINE_COLOR_RGB) && (config.lineColor <= MAX_LINE_COLOR_RGB) ||
        (config.lineColor >= MIN_LINE_COLOR_ARGB) && (config.lineColor <= MAX_LINE_COLOR_ARGB),
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input lineColor is invalid");

    AVScreenCaptureHighlightConfig highlightConfig = OH_AVCaptureArea_Convert(config);
    int32_t ret = screenCaptureObj->screenCapture_->SetCaptureAreaHighlight(highlightConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_STATE, "SetCaptureAreaHighlight failed");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureStrategy(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_CaptureStrategy *strategy)
{
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is nullptr");

    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");

    int32_t ret = screenCaptureObj->screenCapture_->SetScreenCaptureStrategy(strategyObj->strategy);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_STATE, "SetScreenCaptureStrategy failed");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForKeepCaptureDuringCall(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value)
{
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.keepCaptureDuringCall = value;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureArea(struct OH_AVScreenCapture *capture,
    uint64_t displayId, OH_Rect* area)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureArea S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(displayId >= 0 && displayId < VIRTUAL_DISPLAY_ID_START,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayId invalid");
    CHECK_AND_RETURN_RET_LOG(area != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input area is nullptr");
    CHECK_AND_RETURN_RET_LOG(area->x > 0 && area->y > 0 && area->width > 0 && area->height > 0,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input area invalid");
    OHOS::Rect region;
    region.x = area->x;
    region.y = area->y;
    region.w = area->width;
    region.h = area->height;

    int32_t ret = screenCaptureObj->screenCapture_->SetCaptureArea(displayId, region);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "SetCaptureArea failed!");
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureArea E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPrivacyMaskMode(
    OH_AVScreenCapture_CaptureStrategy *strategy, int32_t value)
{
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForPrivacyMaskMode S");
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(value == 0 || value == 1, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input value is invalid");
    strategyObj->strategy.strategyForPrivacyMaskMode = value;
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForPrivacyMaskMode E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForCanvasFollowRotation(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value)
{
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForCanvasFollowRotation S");
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.canvasFollowRotation = value;
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForCanvasFollowRotation E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetSelectionCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnUserSelected callback, void *userData)
{
    MEDIA_LOGD("OH_AVScreenCapture_SetSelectionCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input callback is nullptr");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(!screenCaptureObj->isStart,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "This interface should be called before Start is called!");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = AVScreenCaptureSetCallback(capture, screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "SetSelectionCallback is null");
    if (screenCaptureObj->callback_ == nullptr ||
        !screenCaptureObj->callback_->SetUserSelectedCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVScreenCapture_SetSelectionCallback error");
        return AV_SCREEN_CAPTURE_ERR_INVALID_VAL;
    }
    MEDIA_LOGD("OH_AVScreenCapture_SetSelectionCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetCaptureTypeSelected(OH_AVScreenCapture_UserSelectionInfo *selection,
    int32_t* type)
{
    MEDIA_LOGD("OH_AVScreenCapture_GetCaptureTypeSelected S");
    CHECK_AND_RETURN_RET_LOG(selection != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input selection is nullptr");
    CHECK_AND_RETURN_RET_LOG(type != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input type is nullptr");
    struct ScreenCaptureUserSelectionObject *selectionObj =
        reinterpret_cast<ScreenCaptureUserSelectionObject *>(selection);
    CHECK_AND_RETURN_RET_LOG(selectionObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "selectionObj is null");
    *type = selectionObj->userSelectionInfo_.selectType;
    MEDIA_LOGD("OH_AVScreenCapture_GetCaptureTypeSelected type: %{public}d", *type);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetDisplayIdSelected(OH_AVScreenCapture_UserSelectionInfo *selection,
    uint64_t* displayId)
{
    MEDIA_LOGD("OH_AVScreenCapture_GetDisplayIdSelected S");
    CHECK_AND_RETURN_RET_LOG(selection != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input selection is nullptr");
    CHECK_AND_RETURN_RET_LOG(displayId != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayId is nullptr");
    struct ScreenCaptureUserSelectionObject *selectionObj =
        reinterpret_cast<ScreenCaptureUserSelectionObject *>(selection);
    CHECK_AND_RETURN_RET_LOG(selectionObj->userSelectionInfo_.displayIds.size() == 1, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "display id unsupport %{public}zu", selectionObj->userSelectionInfo_.displayIds.size());
    *displayId = selectionObj->userSelectionInfo_.displayIds.front();
    MEDIA_LOGD("OH_AVScreenCapture_GetDisplayIdSelected displayId: %{public}" PRIu64, *displayId);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForBFramesEncoding(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value)
{
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.enableBFrame = value;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPickerPopUp(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value)
{
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForPickerPopUp S");
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    auto *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.pickerPopUp = value ? AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE
        : AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_DISABLE;
    MEDIA_LOGD("OH_AVScreenCapture_StrategyForPickerPopUp E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForFillMode(
    OH_AVScreenCapture_CaptureStrategy *strategy, OH_AVScreenCapture_FillMode mode)
{
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr");
    CHECK_AND_RETURN_RET_LOG(mode == OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_ASPECT_SCALE_FIT ||
                                 mode == OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_SCALE_TO_FILL,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input mode is invalid");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.fillMode = static_cast<AVScreenCaptureFillMode>(mode);
    return AV_SCREEN_CAPTURE_ERR_OK;
}