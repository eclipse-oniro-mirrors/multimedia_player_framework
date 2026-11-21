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
#include "native_avscreen_capture_impl.h"
#include "native_avscreen_capture_callback.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <unordered_map>

#include "buffer/avbuffer.h"
#include "common/native_mfmagic.h"
#include "media_log.h"
#include "media_errors.h"
#include "native_avbuffer.h"
#include "surface_buffer_impl.h"
#include "native_window.h"
#include "native_avformat.h"
#include "native_avcodec_base.h"
#include "native_avsource.h"
#include <v1_0/buffer_handle_meta_key_type.h>

namespace {
constexpr int MAX_WINDOWS_LEN = 1000;
constexpr int MAX_DISPLAYS_LEN = 1000;
constexpr int VIRTUAL_DISPLAY_ID_START = 1000;
constexpr uint32_t MIN_LINE_THICKNESS = 1;
constexpr uint32_t MAX_LINE_THICKNESS = 8;
constexpr uint32_t MIN_LINE_COLOR_RGB = 0x000000;
constexpr uint32_t MAX_LINE_COLOR_RGB = 0xffffff;
constexpr uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;
constexpr uint32_t MAX_LINE_COLOR_ARGB = 0xffffffff;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "NativeScreenCapture"};
} // namespace

using namespace OHOS::Media;
std::mutex g_captureSetMutex;

std::unordered_map<struct OH_AVScreenCapture *, std::shared_ptr<ScreenCaptureObject>> g_captureMap;

struct ScreenCaptureContentFilterObject : public OH_AVScreenCapture_ContentFilter {
    ScreenCaptureContentFilterObject() = default;
    ~ScreenCaptureContentFilterObject() = default;

    ScreenCaptureContentFilter screenCaptureContentFilter;
};

struct ScreenCaptureStrategyObject : public OH_AVScreenCapture_CaptureStrategy {
    ScreenCaptureStrategyObject() = default;
    ~ScreenCaptureStrategyObject() = default;

    ScreenCaptureStrategy strategy;
};

namespace {
void SetVideoCapInfo(OH_AVScreenCaptureConfig config, AVScreenCaptureConfig &config_)
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
    config_.videoInfo.videoCapInfo.videoSource = static_cast<VideoSourceType>(
        config.videoInfo.videoCapInfo.videoSource);
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

AVScreenCaptureConfig ConvertOHScreenCaptureConfig(OH_AVScreenCaptureConfig config)
{
    AVScreenCaptureConfig config_;
    config_.captureMode = static_cast<CaptureMode>(config.captureMode);
    config_.dataType = static_cast<DataType>(config.dataType);
    config_.audioInfo.micCapInfo = {.audioSampleRate = config.audioInfo.micCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.micCapInfo.audioChannels,
        .audioSource = static_cast<AudioCaptureSourceType>(config.audioInfo.micCapInfo.audioSource)};
    config_.audioInfo.innerCapInfo = {.audioSampleRate = config.audioInfo.innerCapInfo.audioSampleRate,
        .audioChannels = config.audioInfo.innerCapInfo.audioChannels,
        .audioSource = static_cast<AudioCaptureSourceType>(config.audioInfo.innerCapInfo.audioSource)};
    config_.audioInfo.audioEncInfo.audioBitrate = config.audioInfo.audioEncInfo.audioBitrate;
    config_.audioInfo.audioEncInfo.audioCodecformat = static_cast<AudioCodecFormat>(
        config.audioInfo.audioEncInfo.audioCodecformat);
    SetVideoCapInfo(config, config_);
    config_.videoInfo.videoEncInfo = {.videoCodec = ConvertOHVideoCodecFormat(config.videoInfo.videoEncInfo.videoCodec),
        .videoBitrate = config.videoInfo.videoEncInfo.videoBitrate,
        .videoFrameRate = config.videoInfo.videoEncInfo.videoFrameRate};
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

AVScreenCaptureHighlightConfig ConvertOHHighlightConfig(OH_AVScreenCaptureHighlightConfig config)
{
    AVScreenCaptureHighlightConfig highlightConfig;
    highlightConfig.lineThickness = config.lineThickness;
    highlightConfig.lineColor = config.lineColor;
    highlightConfig.mode = static_cast<ScreenCaptureHighlightMode>(config.mode);
    return highlightConfig;
}

int32_t SetPrivacyAuthorityEnabled(struct ScreenCaptureObject *screenCaptureObj)
{
    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsStateChangeCallbackEnabled()) {
        int32_t ret = screenCaptureObj->screenCapture_->SetPrivacyAuthorityEnabled();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPrivacyAuthorityEnabled failed!");
    }
    return MSERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode EnsureCallbackRegistered(struct ScreenCaptureObject *screenCaptureObj)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "screenCapture_ is nullptr!");
    bool needRegister = false;
    std::shared_ptr<NativeScreenCaptureCallback> cb;
    {
        std::lock_guard<std::mutex> lock(screenCaptureObj->callbackMutex);
        if (screenCaptureObj->callback_ == nullptr) {
            screenCaptureObj->callback_ = std::make_shared<NativeScreenCaptureCallback>(
                screenCaptureObj->shared_from_this());
            needRegister = true;
        }
        cb = screenCaptureObj->callback_;
    }
    if (needRegister) {
        int32_t ret = screenCaptureObj->screenCapture_->SetScreenCaptureCallback(cb);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
            "SetScreenCaptureCallback failed!");
    }
    return AV_SCREEN_CAPTURE_ERR_OK;
}

void SetMultiDisplayCapability(MultiDisplayCapability displayCapability, OH_MultiDisplayCapability *capability)
{
    capability->width = displayCapability.width;
    capability->height = displayCapability.height;
    capability->isMultiDisplaySupport = displayCapability.isMultiDisplaySupport;
}

template <typename T>
OH_AVSCREEN_CAPTURE_ErrCode SetStrategyValue(OH_AVScreenCapture_CaptureStrategy *strategy,
    T ScreenCaptureStrategy::*field, T value)
{
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    CHECK_AND_RETURN_RET_LOG(strategyObj != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "strategyObj is nullptr");
    strategyObj->strategy.*field = value;
    return AV_SCREEN_CAPTURE_ERR_OK;
}
} // namespace

struct OH_AVScreenCapture_ContentFilter *OH_AVScreenCapture_CreateContentFilter(void)
{
    struct ScreenCaptureContentFilterObject *object = new(std::nothrow) ScreenCaptureContentFilterObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new ScreenCaptureContentFilterObject");
    return object;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseContentFilter(struct OH_AVScreenCapture_ContentFilter *filter)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
        reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);
    delete contentFilterObj;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ContentFilter_AddAudioContent(
    struct OH_AVScreenCapture_ContentFilter *filter, OH_AVScreenCaptureFilterableAudioContent content)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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

    std::shared_ptr<ScreenCaptureObject> object = std::make_shared<ScreenCaptureObject>(screenCapture);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to make_shared ScreenCaptureObject");

    std::lock_guard<std::mutex> lock(g_captureSetMutex);
    g_captureMap.insert({object.get(), object});
    return object.get();
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ExcludePickerWindows(
    struct OH_AVScreenCapture *capture, const int32_t *excludedWindowIDs, uint32_t windowCount)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture is null");
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "windowCount out of range!");
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
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

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Init(struct OH_AVScreenCapture *capture, OH_AVScreenCaptureConfig config)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    AVScreenCaptureConfig config_ = ConvertOHScreenCaptureConfig(config);
    int32_t ret = screenCaptureObj->screenCapture_->Init(config_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "screenCapture init failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenCapture(struct OH_AVScreenCapture *capture)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, nullptr, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(fence != nullptr, nullptr, "input fence is nullptr!");
    CHECK_AND_RETURN_RET_LOG(timestamp != nullptr, nullptr, "input timestamp is nullptr!");
    CHECK_AND_RETURN_RET_LOG(region != nullptr, nullptr, "input region is nullptr!");

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

    OH_NativeBuffer *nativebuffer = sufacebuffer->SurfaceBufferToNativeBuffer();
    NativeBufferRef ref = NativeBufferRef::Acquire(nativebuffer);
    if (ref) {
        std::lock_guard<std::mutex> lock(screenCaptureObj->bufferMutex);
        screenCaptureObj->referencedBuffer_.push(std::move(ref));
        MEDIA_LOGD("return and reference the nativebuffer");
        return nativebuffer;
    }
    MEDIA_LOGE("OH_NativeBuffer_Reference failed");
    return nullptr;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseVideoBuffer(struct OH_AVScreenCapture *capture)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    if (screenCaptureObj->callback_ != nullptr && screenCaptureObj->callback_->IsDataCallbackEnabled()) {
        MEDIA_LOGE("ReleaseVideoBuffer() not permit for has set DataCallback");
        return AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT;
    }
    NativeBufferRef ref;
    {
        std::lock_guard<std::mutex> lock(screenCaptureObj->bufferMutex);
        if (!screenCaptureObj->referencedBuffer_.empty()) {
            ref = std::move(screenCaptureObj->referencedBuffer_.front());
            screenCaptureObj->referencedBuffer_.pop();
            MEDIA_LOGD("unreference the front nativebuffer");
        }
    }
    int32_t ret = screenCaptureObj->screenCapture_->ReleaseVideoBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "ReleaseVideoBuffer failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AudioCaptureSourceType type)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    std::shared_ptr<NativeScreenCaptureCallback> cb;
    {
        std::lock_guard<std::mutex> lock(screenCaptureObj->callbackMutex);
        if (screenCaptureObj->callback_ == nullptr) {
            screenCaptureObj->callback_ = std::make_shared<NativeScreenCaptureCallback>(
                screenCaptureObj->shared_from_this(), callback);
        }
        cb = screenCaptureObj->callback_;
    }
    cb->SetCallback(callback);
    int32_t ret = screenCaptureObj->screenCapture_->SetScreenCaptureCallback(cb);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        "SetScreenCaptureCallback failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Release(struct OH_AVScreenCapture *capture)
{
    MEDIA_LOGI("OH_AVScreenCapture_Release In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    std::shared_ptr<ScreenCaptureObject> screenCaptureObj;
    {
        std::lock_guard<std::mutex> lock(g_captureSetMutex);
        auto it = g_captureMap.find(capture);
        if (it == g_captureMap.end()) {
            MEDIA_LOGW("OH_AVScreenCapture_Release: capture 0x%{public}06" PRIXPTR
                " is not a valid or already released capture, skip release.", FAKE_POINTER(capture));
            return AV_SCREEN_CAPTURE_ERR_INVALID_VAL;
        }
        screenCaptureObj = it->second;
        g_captureMap.erase(it);
    }

    if (screenCaptureObj->screenCapture_ != nullptr) {
        if (screenCaptureObj->callback_ != nullptr) {
            screenCaptureObj->callback_->StopDataCallback();
        }
        int32_t ret = screenCaptureObj->screenCapture_->Release();
        {
            std::queue<NativeBufferRef> drained;
            std::lock_guard<std::mutex> lock(screenCaptureObj->bufferMutex);
            drained.swap(screenCaptureObj->referencedBuffer_);
        }
        if (screenCaptureObj->callback_ != nullptr) {
            screenCaptureObj->callback_->StopAllCallbacks();
        }
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->SetMicrophoneEnabled(isMicrophone);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "setMicrophoneEnable failed!");

    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetStateCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnStateChange callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetStateCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input stateCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetStateCallback is null");

    screenCaptureObj->callback_->SetStateChangeCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetStateCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureContentChangedCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureContentChangedCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "input contentChangedCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetCaptureContentChangedCallback is null");
    screenCaptureObj->callback_->SetCaptureContentChangedCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureContentChangedCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetErrorCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnError callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetErrorCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input errorCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetErrorCallback is null");
    screenCaptureObj->callback_->SetErrorCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetErrorCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetDataCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnBufferAvailable callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetDataCallback E");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input dataCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetDataCallback is null");
    screenCaptureObj->callback_->SetDataCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetDataCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCanvasRotation(struct OH_AVScreenCapture *capture,
    bool canvasRotation)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(filter != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input filter is nullptr!");
    struct ScreenCaptureContentFilterObject *contentFilterObj =
            reinterpret_cast<ScreenCaptureContentFilterObject *>(filter);
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "windowCount out of range!");
    CHECK_AND_RETURN_RET_LOG(!(windowIDs == nullptr && windowCount > 0),
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input window invalid, nullptr but size is not 0!");
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(windowCount >= 0 && windowCount < MAX_WINDOWS_LEN,
                             AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "windowCount out of range!");
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
    CHECK_AND_RETURN_RET_LOG(ret != MSERR_UNKNOWN_UNSUPPORT, AV_SCREEN_CAPTURE_ERR_UNSUPPORT,
        "SkipPrivacyMode failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
                             "SkipPrivacyMode failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetMaxVideoFrameRate(struct OH_AVScreenCapture *capture,
    int32_t frameRate)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetDisplayCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayCallback is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(!screenCaptureObj->isStart,
        AV_SCREEN_CAPTURE_ERR_INVALID_STATE, "This interface should be called before Start is called!");
    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, errCode, "SetDisplayCallback is null");
    screenCaptureObj->callback_->SetDisplayCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetDisplayCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVScreenCapture_CaptureStrategy* OH_AVScreenCapture_CreateCaptureStrategy(void)
{
    struct ScreenCaptureStrategyObject *object = new(std::nothrow) ScreenCaptureStrategyObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new ScreenCaptureStrategyObject");
    return object;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseCaptureStrategy(OH_AVScreenCapture_CaptureStrategy* strategy)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(strategy != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input strategy is nullptr!");
    struct ScreenCaptureStrategyObject *strategyObj = reinterpret_cast<ScreenCaptureStrategyObject *>(strategy);
    delete strategyObj;
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureAreaHighlight(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureHighlightConfig config)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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

    AVScreenCaptureHighlightConfig highlightConfig = ConvertOHHighlightConfig(config);
    int32_t ret = screenCaptureObj->screenCapture_->SetCaptureAreaHighlight(highlightConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_STATE, "SetCaptureAreaHighlight failed");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureStrategy(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_CaptureStrategy *strategy)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::keepCaptureDuringCall, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureArea(struct OH_AVScreenCapture *capture,
    uint64_t displayId, OH_Rect* area)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetCaptureArea S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    CHECK_AND_RETURN_RET_LOG(displayId >= 0 && displayId < VIRTUAL_DISPLAY_ID_START,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayId invalid");
    CHECK_AND_RETURN_RET_LOG(area != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input area is nullptr");
    CHECK_AND_RETURN_RET_LOG(area->x >= 0 && area->y >= 0 && area->width >= 0 && area->height >= 0,
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(value == 0 || value == 1, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input value is invalid");
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::strategyForPrivacyMaskMode, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForCanvasFollowRotation(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::canvasFollowRotation, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetSelectionCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnUserSelected callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetSelectionCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input callback is nullptr");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(!screenCaptureObj->isStart,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "This interface should be called before Start is called!");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "SetSelectionCallback is null");
    screenCaptureObj->callback_->SetUserSelectedCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetSelectionCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetCaptureTypeSelected(OH_AVScreenCapture_UserSelectionInfo *selection,
    int32_t* type)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
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

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetMultiDisplayIdsSelected(
    OH_AVScreenCapture_UserSelectionInfo *selection, uint64_t** displayIds, size_t *count)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_GetMultiDisplayIdsSelected S");
    CHECK_AND_RETURN_RET_LOG(selection != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input selection is nullptr");
    CHECK_AND_RETURN_RET_LOG(displayIds != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input displayIds is nullptr");
    CHECK_AND_RETURN_RET_LOG(count != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input count is nullptr");
    auto *selectionObj = reinterpret_cast<ScreenCaptureUserSelectionObject *>(selection);
    *count = selectionObj->userSelectionInfo_.displayIds.size();
    *displayIds = selectionObj->userSelectionInfo_.displayIds.data();
    MEDIA_LOGD("OH_AVScreenCapture_GetMultiDisplayIdsSelected displayIds size: %{public}zu", *count);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForBFramesEncoding(OH_AVScreenCapture_CaptureStrategy *strategy,
    bool value)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::enableBFrame, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPickerPopUp(OH_AVScreenCapture_CaptureStrategy *strategy,
    bool value)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    AVScreenCapturePickerPopUp popUp = value ? AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE
                                             : AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_DISABLE;
    OH_AVSCREEN_CAPTURE_ErrCode ret = SetStrategyValue(strategy, &ScreenCaptureStrategy::pickerPopUp, popUp);
    return ret;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForFillMode(OH_AVScreenCapture_CaptureStrategy *strategy,
    OH_AVScreenCapture_FillMode mode)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(mode == OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_ASPECT_SCALE_FIT ||
            mode == OH_AVScreenCapture_FillMode::OH_SCREENCAPTURE_FILLMODE_SCALE_TO_FILL,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input mode is invalid");
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::fillMode, static_cast<AVScreenCaptureFillMode>(mode));
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPause(OH_AVScreenCapture_CaptureStrategy *strategy,
    bool value)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::enablePause, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForMicAEC(OH_AVScreenCapture_CaptureStrategy *strategy,
    bool value)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::enableAEC, value);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForContentAutoPauseScenes(
    OH_AVScreenCapture_CaptureStrategy *strategy, OH_AVScreenCapture_AutoPauseSceneSet scenes)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::contentAutoPauseScenes, scenes);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForHDRCapture(OH_AVScreenCapture_CaptureStrategy *strategy,
    bool enable)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    return SetStrategyValue(strategy, &ScreenCaptureStrategy::enableHDRCapture, enable);
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetMultiDisplayCaptureCapability(struct OH_AVScreenCapture *capture,
    uint64_t *displayIds, size_t count, OH_MultiDisplayCapability *capability)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");
    CHECK_AND_RETURN_RET_LOG(count < MAX_DISPLAYS_LEN && count > 1, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "input count invalid!");
    CHECK_AND_RETURN_RET_LOG(displayIds != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "input displayIds invalid, nullptr but size not 0!");
    CHECK_AND_RETURN_RET_LOG(capability != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capability invalid!");
    auto *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "screenCapture_ is null");
    std::vector<uint64_t> displayIdList;
    for (size_t i = 0; i < count; i++) {
        displayIdList.push_back(displayIds[i]);
    }
    MultiDisplayCapability displayCapability;
    SetMultiDisplayCapability(displayCapability, capability);
    int32_t ret = screenCaptureObj->screenCapture_->GetMultiDisplayCaptureCapability(displayIdList, displayCapability);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK,
        AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "GetMultiDisplayCaptureCapability failed!");
    SetMultiDisplayCapability(displayCapability, capability);
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetPrivacyProtectCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnPrivacyProtect callback, void *userData)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGD("OH_AVScreenCapture_SetPrivacyProtectCallback S");
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input callback is nullptr");
    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");
    CHECK_AND_RETURN_RET_LOG(!screenCaptureObj->isStart,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "This interface should be called before Start is called!");

    OH_AVSCREEN_CAPTURE_ErrCode errCode = EnsureCallbackRegistered(screenCaptureObj);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SCREEN_CAPTURE_ERR_OK, AV_SCREEN_CAPTURE_ERR_INVALID_VAL,
        "SetPrivacyProtectCallback is null");
    screenCaptureObj->callback_->SetPrivacyProtectCallback(callback, userData);
    MEDIA_LOGD("OH_AVScreenCapture_SetPrivacyProtectCallback E");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_PauseScreenCapture(struct OH_AVScreenCapture *capture)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGI("OH_AVScreenCapture_PauseScreenCapture In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->PauseScreenCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "PauseScreenCapture failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ResumeScreenCapture(struct OH_AVScreenCapture *capture)
{
#ifdef EMULATOR_ENABLED
    return AV_SCREEN_CAPTURE_ERR_EMULATOR;
#endif
    MEDIA_LOGI("OH_AVScreenCapture_ResumeScreenCapture In: 0x%{public}06" PRIXPTR, FAKE_POINTER(capture));
    CHECK_AND_RETURN_RET_LOG(capture != nullptr, AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "input capture is nullptr!");

    struct ScreenCaptureObject *screenCaptureObj = reinterpret_cast<ScreenCaptureObject *>(capture);
    CHECK_AND_RETURN_RET_LOG(screenCaptureObj->screenCapture_ != nullptr,
        AV_SCREEN_CAPTURE_ERR_INVALID_VAL, "screenCapture_ is null");

    int32_t ret = screenCaptureObj->screenCapture_->ResumeScreenCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT, "ResumeScreenCapture failed!");
    return AV_SCREEN_CAPTURE_ERR_OK;
}
