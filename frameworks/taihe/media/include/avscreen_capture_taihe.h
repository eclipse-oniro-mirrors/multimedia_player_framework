/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef AVSCREEN_CAPTURE_TAIHE_H
#define AVSCREEN_CAPTURE_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "media_ani_common.h"
#include "task_queue.h"
#include "screen_capture.h"
#include "screen_capture_controller.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;
namespace AVScreenCapturegOpt {
    const std::string INIT = "Init";
    const std::string REPORT_USER_CHOICE = "ReportAVScreenCaptureUserChoice";
    const std::string GET_CONFIG_PARAMS = "GetAVScreenCaptureconfigurableParameters";
    const std::string START_RECORDING = "StartRecording";
    const std::string STOP_RECORDING = "StopRecording";
    const std::string SKIP_PRIVACY_MODE = "SkipPrivacyMode";
    const std::string SET_MIC_ENABLE = "SetMicrophoneEnable";
    const std::string RELEASE = "Release";
}
constexpr int32_t AVSCREENCAPTURE_DEFAULT_AUDIO_BIT_RATE = 96000;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_VIDEO_FRAME_RATE = 60;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_VIDEO_BIT_RATE = 10000000;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t AVSCREENCAPTURE_DEFAULT_DISPLAY_ID = 0;
const std::string AVSCREENCAPTURE_DEFAULT_FILE_FORMAT = "mp4";

namespace AVScreenCaptureEvent {
    const std::string EVENT_STATE_CHANGE = "stateChange";
    const std::string EVENT_ERROR = "error";
}

enum AVScreenCaptureRecorderPreset: int32_t {
    SCREEN_RECORD_PRESET_H264_AAC_MP4 = 0,
    SCREEN_RECORD_PRESET_H265_AAC_MP4 = 1
};

struct AVScreenCaptureAsyncContext;

using RetInfo = std::pair<int32_t, std::string>;

class AVScreenCaptureRecorderImpl {
public:
    AVScreenCaptureRecorderImpl();
    void InitSync(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config);
    void StartRecordingSync();
    void StopRecordingSync();
    void SkipPrivacyModeSync(::taihe::array_view<int32_t> windowIDs);
    void SetMicEnabledSync(bool enable);
    void ReleaseSync();

    RetInfo StartRecording();
    RetInfo StopRecording();
    RetInfo Release();

    int32_t CheckAudioSampleRate(const int32_t &audioSampleRate);
    int32_t CheckAudioChannelCount(const int32_t &audioChannelCount);
    int32_t CheckVideoCodecFormat(const int32_t &preset);
    int32_t CheckVideoFrameFormat(const int32_t &frameWidth, const int32_t &frameHeight,
        int32_t &videoFrameWidth, int32_t &videoFrameHeight);
    OHOS::Media::AVScreenCaptureFillMode GetScreenCaptureFillMode(const int32_t &fillMode);
    VideoCodecFormat GetVideoCodecFormat(const int32_t &preset);
    int32_t GetConfig(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config);
    int32_t GetAudioInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config);
    int32_t GetVideoInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config);
    int32_t GetRecorderInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    ::taihe::string GetAVScreenCaptureconfigurableParametersSync(int32_t sessionId);
    void ExecuteByPromise(const std::string &opt);
    std::shared_ptr<TaskHandler<RetInfo>> GetPromiseTask(AVScreenCaptureRecorderImpl *avtaihe, const std::string &opt);
    static std::shared_ptr<TaskHandler<RetInfo>> GetInitTask(
        const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx);
    std::shared_ptr<TaskHandler<RetInfo>> GetSkipPrivacyModeTask(
        const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx, const std::vector<uint64_t> windowIDsVec);
    std::shared_ptr<TaskHandler<RetInfo>> GetSetMicrophoneEnableTask(
        const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx, const bool enable);
    void OnStateChange(callback_view<void(ohos::multimedia::media::AVScreenCaptureStateCode)> callback);
    void OffStateChange(optional_view<callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>> callback);

    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);

    using AvScreenCaptureTaskqFunc = RetInfo (AVScreenCaptureRecorderImpl::*)();
private:
    std::mutex mutex_;
    std::shared_ptr<ScreenCapture> screenCapture_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
    std::unique_ptr<TaskQueue> taskQue_;
    static std::map<std::string, AvScreenCaptureTaskqFunc> taskQFuncs_;
};

struct AVScreenCaptureAsyncContext {
    explicit AVScreenCaptureAsyncContext() {}
    ~AVScreenCaptureAsyncContext() = default;

    void AVScreenCaptureSignError(int32_t errCode, const std::string &operate,
        const std::string &param, const std::string &add = "");

    AVScreenCaptureRecorderImpl *taihe = nullptr;
    OHOS::Media::AVScreenCaptureConfig config_;
    std::shared_ptr<ScreenCaptureController> controller_ = nullptr;
    std::string opt_ = "";
    std::shared_ptr<TaskHandler<RetInfo>> task_ = nullptr;
};
}
#endif // AVSCREEN_CAPTURE_TAIHE_H