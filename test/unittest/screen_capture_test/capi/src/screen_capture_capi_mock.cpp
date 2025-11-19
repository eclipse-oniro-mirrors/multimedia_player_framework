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

#include "screen_capture_capi_mock.h"
#include "native_mfmagic.h"
#include "external_window.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
std::mutex ScreenCaptureCapiMock::mutex_;
std::map<OH_AVScreenCapture *, std::shared_ptr<ScreenCaptureCallbackMock>> ScreenCaptureCapiMock::mockCbMap_;

typedef struct NativeWindow OHNativeWindow;

void ScreenCaptureCapiMock::OnError(OH_AVScreenCapture *screenCapture, int32_t errorCode)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnError(errorCode);
    }
}

void ScreenCaptureCapiMock::OnAudioBufferAvailable(OH_AVScreenCapture *screenCapture, bool isReady,
    OH_AudioCaptureSourceType type)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnAudioBufferAvailable(isReady, static_cast<AudioCaptureSourceType>(type));
    }
}

void ScreenCaptureCapiMock::OnVideoBufferAvailable(OH_AVScreenCapture *screenCapture, bool isReady)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnVideoBufferAvailable(isReady);
    }
}

void ScreenCaptureCapiMock::OnErrorNew(OH_AVScreenCapture *screenCapture, int32_t errorCode, void *userData)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnError(errorCode, userData);
    }
}

void ScreenCaptureCapiMock::OnBufferAvailable(OH_AVScreenCapture *screenCapture, OH_AVBuffer *buffer,
    OH_AVScreenCaptureBufferType bufferType, int64_t timestamp, void *userData)
{
    UNITTEST_CHECK_AND_RETURN_LOG(buffer != nullptr, "OH_AVBuffer buffer == nullptr");
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnBufferAvailable(buffer->buffer_, static_cast<AVScreenCaptureBufferType>(bufferType), timestamp);
    }
}

void ScreenCaptureCapiMock::OnStateChange(OH_AVScreenCapture *screenCapture,
    OH_AVScreenCaptureStateCode stateCode, void *userData)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnStateChange(static_cast<AVScreenCaptureStateCode>(stateCode));
    }
}

void ScreenCaptureCapiMock::OnCaptureContentChanged(OH_AVScreenCapture *screenCapture,
    OH_AVScreenCaptureContentChangedEvent event, OH_Rect* area, void *userData)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnCaptureContentChanged(static_cast<AVScreenCaptureContentChangedEvent>(event),
            reinterpret_cast<ScreenCaptureRect*>(area));
    }
}

void ScreenCaptureCapiMock::OnDisplaySelected(OH_AVScreenCapture *screenCapture, uint64_t displayId, void *userData)
{
    std::shared_ptr<ScreenCaptureCallbackMock> mockCb = GetCallback(screenCapture);
    if (mockCb != nullptr) {
        mockCb->OnDisplaySelected(displayId);
    }
}

OH_AVScreenCaptureConfig ScreenCaptureCapiMock::Convert(AVScreenCaptureConfig config)
{
    OH_AVScreenCaptureConfig tempConfig;
    tempConfig.captureMode = static_cast<OH_CaptureMode>(config.captureMode);
    tempConfig.dataType = static_cast<OH_DataType>(config.dataType);
    tempConfig.audioInfo.micCapInfo = {
        .audioSampleRate = config.audioInfo.micCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.micCapInfo.audioChannels,
        .audioSource = static_cast<OH_AudioCaptureSourceType>(config.audioInfo.micCapInfo.audioSource)
    };
    tempConfig.audioInfo.innerCapInfo = {
        .audioSampleRate = config.audioInfo.innerCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.innerCapInfo.audioChannels,
        .audioSource = static_cast<OH_AudioCaptureSourceType>(config.audioInfo.innerCapInfo.audioSource)
    };
    tempConfig.audioInfo.audioEncInfo.audioBitrate = config.audioInfo.audioEncInfo.audioBitrate;
    tempConfig.audioInfo.audioEncInfo.audioCodecformat =
        static_cast<OH_AudioCodecFormat>(config.audioInfo.audioEncInfo.audioCodecformat);
    tempConfig.videoInfo.videoCapInfo.displayId = config.videoInfo.videoCapInfo.displayId;
    std::list<int32_t> taskIds = config.videoInfo.videoCapInfo.taskIDs;
    if (taskIds.size() > 0) {
        int32_t *taskIds_temp = static_cast<int*>(malloc(sizeof(int)));
        for (std::list<int32_t>::iterator its = taskIds.begin(); its != taskIds.end(); ++its) {
            *taskIds_temp = *its;
            taskIds_temp++;
        }
        tempConfig.videoInfo.videoCapInfo.missionIDs = taskIds_temp;
    }
    tempConfig.videoInfo.videoCapInfo.missionIDsLen = taskIds.size();
    tempConfig.videoInfo.videoCapInfo.videoFrameWidth = config.videoInfo.videoCapInfo.videoFrameWidth;
    tempConfig.videoInfo.videoCapInfo.videoFrameHeight = config.videoInfo.videoCapInfo.videoFrameHeight;
    tempConfig.videoInfo.videoCapInfo.videoSource =
        static_cast<OH_VideoSourceType>(config.videoInfo.videoCapInfo.videoSource);
    tempConfig.videoInfo.videoEncInfo = {
        .videoCodec = static_cast<OH_VideoCodecFormat>(config.videoInfo.videoEncInfo.videoCodec),
        .videoBitrate = static_cast<OH_VideoCodecFormat>(config.videoInfo.videoEncInfo.videoBitrate),
        .videoFrameRate = static_cast<OH_VideoCodecFormat>(config.videoInfo.videoEncInfo.videoFrameRate)
    };
    std::string url = config.recorderInfo.url;
    if (!(url.empty())) {
        tempConfig.recorderInfo.url = const_cast<char *>(config.recorderInfo.url.c_str());
        tempConfig.recorderInfo.urlLen = config.recorderInfo.url.size();
    }
    if (config.recorderInfo.fileFormat == ContainerFormatType::CFT_MPEG_4A) {
        tempConfig.recorderInfo.fileFormat = OH_ContainerFormatType::CFT_MPEG_4A;
    } else if (config.recorderInfo.fileFormat == ContainerFormatType::CFT_MPEG_4) {
        tempConfig.recorderInfo.fileFormat = OH_ContainerFormatType::CFT_MPEG_4;
    }
    return tempConfig;
}

std::shared_ptr<ScreenCaptureCallbackMock> ScreenCaptureCapiMock::GetCallback(OH_AVScreenCapture *screenCapture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mockCbMap_.empty()) {
        return nullptr;
    }
    if (mockCbMap_.find(screenCapture) != mockCbMap_.end()) {
        return mockCbMap_.at(screenCapture);
    }
    return nullptr;
}

void ScreenCaptureCapiMock::DelCallback(OH_AVScreenCapture *screenCapture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mockCbMap_.empty()) {
        return;
    }
    auto it = mockCbMap_.find(screenCapture);
    if (it != mockCbMap_.end()) {
        mockCbMap_.erase(it);
    }
}

void ScreenCaptureCapiMock::SetScreenCaptureCallback(OH_AVScreenCapture *screencapture,
    std::shared_ptr<ScreenCaptureCallbackMock> cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    mockCbMap_[screencapture] = cb;
}

int32_t ScreenCaptureCapiMock::GetCaptureContentChangeCallback(const bool isCaptureContentChangeCallbackEnabled)
{
    if (isCaptureContentChangeCallbackEnabled) {
        MEDIA_LOGD("ScreenCaptureCapiMock SetCaptureContentChangedCallback");
        isCaptureContentChangeCallbackEnabled_ = isCaptureContentChangeCallbackEnabled;
        int32_t ret = OH_AVScreenCapture_SetCaptureContentChangedCallback(screenCapture_,
            ScreenCaptureCapiMock::OnCaptureContentChanged, this);
        if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGE("ScreenCaptureCapiMock SetCaptureContentChangedCallback failed, ret: %{public}d", ret);
            return MSERR_UNKNOWN;
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureCapiMock::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackMock>& callback,
    const bool isErrorCallbackEnabled, const bool isDataCallbackEnabled, const bool isStateChangeCallbackEnabled,
    const bool isCaptureContentChangeCallbackEnabled)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (callback == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    MEDIA_LOGD("ScreenCaptureCapiMock SetScreenCaptureCallback");
    SetScreenCaptureCallback(screenCapture_, callback);
    struct OH_AVScreenCaptureCallback ohCallback;
    ohCallback.onError = ScreenCaptureCapiMock::OnError;
    ohCallback.onAudioBufferAvailable = ScreenCaptureCapiMock::OnAudioBufferAvailable;
    ohCallback.onVideoBufferAvailable = ScreenCaptureCapiMock::OnVideoBufferAvailable;
    int ret = OH_AVScreenCapture_SetCallback(screenCapture_, ohCallback);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        MEDIA_LOGE("ScreenCaptureCapiMock SetCallback failed, ret: %{public}d", ret);
        return MSERR_UNKNOWN;
    }
    if (isErrorCallbackEnabled) {
        MEDIA_LOGD("ScreenCaptureCapiMock SetErrorCallback");
        isErrorCallbackEnabled_ = isErrorCallbackEnabled;
        ret = OH_AVScreenCapture_SetErrorCallback(screenCapture_, ScreenCaptureCapiMock::OnErrorNew, this);
        if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGE("ScreenCaptureCapiMock SetErrorCallback failed, ret: %{public}d", ret);
            return MSERR_UNKNOWN;
        }
    }
    if (isDataCallbackEnabled) {
        MEDIA_LOGD("ScreenCaptureCapiMock SetDataCallback");
        isDataCallbackEnabled_ = isDataCallbackEnabled;
        ret = OH_AVScreenCapture_SetDataCallback(screenCapture_, ScreenCaptureCapiMock::OnBufferAvailable, this);
        if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGE("ScreenCaptureCapiMock SetDataCallback failed, ret: %{public}d", ret);
            return MSERR_UNKNOWN;
        }
    }
    if (isStateChangeCallbackEnabled) {
        MEDIA_LOGD("ScreenCaptureCapiMock SetStateCallback");
        isStateChangeCallbackEnabled_ = isStateChangeCallbackEnabled;
        ret = OH_AVScreenCapture_SetStateCallback(screenCapture_, ScreenCaptureCapiMock::OnStateChange, this);
        if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
            MEDIA_LOGE("ScreenCaptureCapiMock SetStateCallback failed, ret: %{public}d", ret);
            return MSERR_UNKNOWN;
        }
    }

    return GetCaptureContentChangeCallback(isCaptureContentChangeCallbackEnabled);
}

int32_t ScreenCaptureCapiMock::SetDisplayCallback()
{
    MEDIA_LOGD("ScreenCaptureCapiMock SetDisplayCallback");
    int32_t ret = OH_AVScreenCapture_SetDisplayCallback(screenCapture_, ScreenCaptureCapiMock::OnDisplaySelected, this);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        MEDIA_LOGE("ScreenCaptureCapiMock SetDisplayCallback failed, ret: %{public}d", ret);
        return MSERR_UNKNOW;
    }
    return AV_SCREEN_CAPTURE_ERR_OK;
}

int32_t ScreenCaptureCapiMock::StartScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_StartScreenCapture(screenCapture_);
}

int32_t ScreenCaptureCapiMock::StartScreenCaptureWithSurface(const std::any& value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    sptr<Surface> surface = std::any_cast<sptr<Surface>>(value);
    OH_NativeWindow_CreateNativeWindowFromSurfaceId(surface->GetUniqueId(), &nativeWindow_);
    return OH_AVScreenCapture_StartScreenCaptureWithSurface(screenCapture_, nativeWindow_);
}

int32_t ScreenCaptureCapiMock::Init(AVScreenCaptureConfig config)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    OH_AVScreenCaptureConfig tempConfig = Convert(config);
    return OH_AVScreenCapture_Init(screenCapture_, tempConfig);
}

int32_t ScreenCaptureCapiMock::Init(OHOS::AudioStandard::AppInfo &appInfo)
{
    return MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureCapiMock::StopScreenCapture()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_StopScreenCapture(screenCapture_);
}

int32_t ScreenCaptureCapiMock::StartScreenRecording()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_StartScreenRecording(screenCapture_);
}

int32_t ScreenCaptureCapiMock::StopScreenRecording()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_StopScreenRecording(screenCapture_);
}

int32_t ScreenCaptureCapiMock::PresentPicker()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_PresentPicker(screenCapture_);
}

int32_t ScreenCaptureCapiMock::Release()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    DelCallback(screenCapture_);
    if (nativeWindow_ != nullptr) {
        OH_NativeWindow_DestroyNativeWindow(nativeWindow_);
        nativeWindow_ = nullptr;
    }
    int32_t ret = OH_AVScreenCapture_Release(screenCapture_);
    screenCapture_ = nullptr;
    return ret;
}

int32_t ScreenCaptureCapiMock::SetMicrophoneEnabled(bool isMicrophone)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_SetMicrophoneEnabled(screenCapture_, isMicrophone);
}

int32_t ScreenCaptureCapiMock::SetCanvasRotation(bool canvasRotation)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_SetCanvasRotation(screenCapture_, canvasRotation);
}

int32_t ScreenCaptureCapiMock::ShowCursor(bool showCursor)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_ShowCursor(screenCapture_, showCursor);
}

int32_t ScreenCaptureCapiMock::ResizeCanvas(int32_t width, int32_t height)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_ResizeCanvas(screenCapture_, width, height);
}

int32_t ScreenCaptureCapiMock::UpdateSurface(const std::any& surface)
{
    return MSERR_OK;
}

int32_t ScreenCaptureCapiMock::SkipPrivacyMode(int32_t *windowIDs, int32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_SkipPrivacyMode(screenCapture_, windowIDs, windowCount);
}

int32_t ScreenCaptureCapiMock::SetMaxVideoFrameRate(int32_t frameRate)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_SetMaxVideoFrameRate(screenCapture_, frameRate);
}

int32_t ScreenCaptureCapiMock::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer,
    AudioCaptureSourceType type)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    OH_AudioBuffer *buffer = static_cast<OH_AudioBuffer *>(malloc(sizeof(OH_AudioBuffer)));
    if (buffer == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    auto t_type = static_cast<OH_AudioCaptureSourceType>(type);
    int32_t ret = OH_AVScreenCapture_AcquireAudioBuffer(screenCapture_, &buffer, t_type);
    if (ret == AV_SCREEN_CAPTURE_ERR_OK) {
        // If ret is not AV_SCREEN_CAPTURE_ERR_OK, the object referenced by buffer is not initialized and can't be used.
        audioBuffer =
            std::make_shared<AudioBuffer>(buffer->buf, buffer->size, buffer->timestamp,
                static_cast<AudioCaptureSourceType>(buffer->type));
    }
    free(buffer);
    buffer = nullptr;
    return ret;
}

sptr<OHOS::SurfaceBuffer> ScreenCaptureCapiMock::AcquireVideoBuffer(int32_t &fence, int64_t &timestamp,
    OHOS::Rect &damage)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, nullptr, "screenCapture_ == nullptr");
    OH_Rect damage_ = {
        .x = damage.x,
        .y = damage.y,
        .width = damage.w,
        .height = damage.h,
    };
    OH_NativeBuffer* buffer = OH_AVScreenCapture_AcquireVideoBuffer(screenCapture_, &fence, &timestamp, &damage_);
    sptr<OHOS::SurfaceBuffer> surfacebuffer;
    if (buffer != nullptr) {
        surfacebuffer =  OHOS::SurfaceBuffer::NativeBufferToSurfaceBuffer(buffer);
    }
    return surfacebuffer;
}

int32_t ScreenCaptureCapiMock::SetCaptureArea(uint64_t displayId, OHOS::Rect &area)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    OH_Rect area_ = {
        .x = area.x,
        .y = area.y,
        .width = area.w,
        .height = area.h,
    };
    return OH_AVScreenCapture_SetCaptureArea(screenCapture_, displayId, &area_);
}

int32_t ScreenCaptureCapiMock::ReleaseAudioBuffer(OHOS::Media::AudioCaptureSourceType type)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    auto t_type = static_cast<OH_AudioCaptureSourceType>(type);
    return OH_AVScreenCapture_ReleaseAudioBuffer(screenCapture_, t_type);
}

int32_t ScreenCaptureCapiMock::ReleaseVideoBuffer()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_ReleaseVideoBuffer(screenCapture_);
}

int32_t ScreenCaptureCapiMock::ExcludeWindowContent(int32_t *windowIDs, int32_t windowCount)
{
    int32_t ret = MSERR_OK;
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (contentFilter_ != nullptr) {
        ret = OH_AVScreenCapture_ReleaseContentFilter(contentFilter_);
        UNITTEST_CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "release content failed");
    }
    contentFilter_ = OH_AVScreenCapture_CreateContentFilter();
    OH_AVScreenCapture_ContentFilter_AddWindowContent(contentFilter_, windowIDs, windowCount);
    return OH_AVScreenCapture_ExcludeContent(screenCapture_, contentFilter_);
}

int32_t ScreenCaptureCapiMock::ExcludeAudioContent(AVScreenCaptureFilterableAudioContent audioType)
{
    int32_t ret = MSERR_OK;
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    if (contentFilter_ != nullptr) {
        ret = OH_AVScreenCapture_ReleaseContentFilter(contentFilter_);
        UNITTEST_CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "release content failed");
    }
    contentFilter_ = OH_AVScreenCapture_CreateContentFilter();
    OH_AVScreenCapture_ContentFilter_AddAudioContent(contentFilter_,
        static_cast<OH_AVScreenCaptureFilterableAudioContent>(audioType));
    return OH_AVScreenCapture_ExcludeContent(screenCapture_, contentFilter_);
}

int32_t ScreenCaptureCapiMock::SetPickerMode(PickerMode pickerMode)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_SetPickerMode(screenCapture_, static_cast<OH_CapturePickerMode>(pickerMode));
}

int32_t ScreenCaptureCapiMock::ExcludePickerWindows(int32_t *windowIDsVec, uint32_t windowCount)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    return OH_AVScreenCapture_ExcludePickerWindows(screenCapture_, windowIDsVec, windowCount);
}

int32_t ScreenCaptureCapiMock::CreateCaptureStrategy()
{
    strategy_ = OH_AVScreenCapture_CreateCaptureStrategy();
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_CreateCaptureStrategy failed");
    return MSERR_OK;
}

int32_t ScreenCaptureCapiMock::StrategyForKeepCaptureDuringCall(bool value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_CreateCaptureStrategy failed");
    return OH_AVScreenCapture_StrategyForKeepCaptureDuringCall(strategy_, value);
}

int32_t ScreenCaptureCapiMock::SetCanvasFollowRotationStrategy(bool value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_StrategyForCanvasFollowRotation failed");
    return OH_AVScreenCapture_StrategyForCanvasFollowRotation(strategy_, value);
}

int32_t ScreenCaptureCapiMock::SetCaptureStrategy()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_INVALID_OPERATION, "screenCapture_ == nullptr");
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_CreateCaptureStrategy failed");
    return OH_AVScreenCapture_SetCaptureStrategy(screenCapture_, strategy_);
}

int32_t ScreenCaptureCapiMock::ReleaseCaptureStrategy()
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_INVALID_OPERATION, "strategy_ == nullptr");
    return OH_AVScreenCapture_ReleaseCaptureStrategy(strategy_);
}

int32_t ScreenCaptureCapiMock::StrategyForBFramesEncoding(bool value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_CreateCaptureStrategy failed");
    return OH_AVScreenCapture_StrategyForBFramesEncoding(strategy_, value);
}

int32_t ScreenCaptureCapiMock::StrategyForPrivacyMaskMode(int32_t value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_StrategyForPrivacyMaskMode failed");
    return OH_AVScreenCapture_StrategyForPrivacyMaskMode(strategy_, value);
}

int32_t ScreenCaptureCapiMock::StrategyForPickerPopUp(bool value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN,
        "OH_AVScreenCapture_CreateCaptureStrategy failed");
    return OH_AVScreenCapture_StrategyForPickerPopUp(strategy_, value);
}

int32_t ScreenCaptureCapiMock::StrategyForFillMode(AVScreenCaptureFillMode value)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, MSERR_UNKNOWN, "strategy_ == nullptr");
    return OH_AVScreenCapture_StrategyForFillMode(strategy_, static_cast<OH_AVScreenCapture_FillMode>(value));
}

OH_AVScreenCaptureHighlightConfig ScreenCaptureCapiMock::HighlightConfigConvert(AVScreenCaptureHighlightConfig config)
{
    OH_AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.lineThickness = config.lineThickness;
    highlightConfig.lineColor = config.lineColor;
    highlightConfig.mode = static_cast<OH_ScreenCaptureHighlightMode>(config.mode);
    return highlightConfig;
}

int32_t ScreenCaptureCapiMock::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(screenCapture_ != nullptr, MSERR_UNKNOWN, "screenCapture_ == nullptr");
    OH_AVScreenCaptureHighlightConfig highlightConfig = HighlightConfigConvert(config);
    return OH_AVScreenCapture_SetCaptureAreaHighlight(screenCapture_, highlightConfig);
}