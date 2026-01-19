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
#ifndef AVRECORDER_TAIHE_H
#define AVRECORDER_TAIHE_H

#include "recorder.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "task_queue.h"
#include "media_core.h"
#include "media_errors.h"
#include "media_ani_common.h"
#include "pixel_map.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;

using RetInfo = std::pair<int32_t, std::string>;
using StateChangeCallback = void(string_view, ohos::multimedia::media::StateChangeReason);

namespace AVRecorderState {
    const std::string STATE_IDLE = "idle";
    const std::string STATE_PREPARED = "prepared";
    const std::string STATE_STARTED = "started";
    const std::string STATE_PAUSED = "paused";
    const std::string STATE_STOPPED = "stopped";
    const std::string STATE_RELEASED = "released";
    const std::string STATE_ERROR = "error";
}

namespace AVRecordergOpt {
    const std::string PREPARE = "Prepare";
    const std::string SET_ORIENTATION_HINT = "SetOrientationHint";
    const std::string GETINPUTSURFACE = "GetInputSurface";
    const std::string GETINPUTMETASURFACE = "GetInputMetaSurface";
    const std::string START = "Start";
    const std::string PAUSE = "Pause";
    const std::string RESUME = "Resume";
    const std::string STOP = "Stop";
    const std::string RESET = "Reset";
    const std::string RELEASE = "Release";
    const std::string GET_AV_RECORDER_PROFILE = "GetAVRecorderProfile";
    const std::string SET_AV_RECORDER_CONFIG = "SetAVRecorderConfig";
    const std::string GET_AV_RECORDER_CONFIG = "GetAVRecorderConfig";
    const std::string GET_CURRENT_AUDIO_CAPTURER_INFO = "GetCurrentAudioCapturerInfo";
    const std::string GET_MAX_AMPLITUDE = "GetMaxAmplitude";
    const std::string GET_ENCODER_INFO = "GetEncoderInfo";
    const std::string IS_WATERMARK_SUPPORTED = "IsWatermarkSupported";
    const std::string SET_WATERMARK = "SetWatermark";
    const std::string SET_METADATA = "SetMetadata";
}

constexpr int32_t AVRECORDER_DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t AVRECORDER_DEFAULT_AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_VIDEO_BIT_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_RATE = 30;

const std::map<std::string, std::vector<std::string>> stateCtrlList = {
    {AVRecorderState::STATE_IDLE, {
        AVRecordergOpt::PREPARE,
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE,
        AVRecordergOpt::GET_AV_RECORDER_PROFILE,
        AVRecordergOpt::SET_AV_RECORDER_CONFIG,
        AVRecordergOpt::GET_ENCODER_INFO
    }},
    {AVRecorderState::STATE_PREPARED, {
        AVRecordergOpt::SET_ORIENTATION_HINT,
        AVRecordergOpt::GETINPUTSURFACE,
        AVRecordergOpt::GETINPUTMETASURFACE,
        AVRecordergOpt::START,
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE,
        AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        AVRecordergOpt::GET_MAX_AMPLITUDE,
        AVRecordergOpt::GET_ENCODER_INFO,
        AVRecordergOpt::GET_AV_RECORDER_CONFIG,
        AVRecordergOpt::IS_WATERMARK_SUPPORTED,
        AVRecordergOpt::SET_WATERMARK
    }},
    {AVRecorderState::STATE_STARTED, {
        AVRecordergOpt::START,
        AVRecordergOpt::RESUME,
        AVRecordergOpt::PAUSE,
        AVRecordergOpt::STOP,
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE,
        AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        AVRecordergOpt::GET_MAX_AMPLITUDE,
        AVRecordergOpt::GET_ENCODER_INFO,
        AVRecordergOpt::GET_AV_RECORDER_CONFIG,
        AVRecordergOpt::IS_WATERMARK_SUPPORTED
    }},
    {AVRecorderState::STATE_PAUSED, {
        AVRecordergOpt::PAUSE,
        AVRecordergOpt::RESUME,
        AVRecordergOpt::STOP,
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE,
        AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        AVRecordergOpt::GET_MAX_AMPLITUDE,
        AVRecordergOpt::GET_ENCODER_INFO,
        AVRecordergOpt::GET_AV_RECORDER_CONFIG,
        AVRecordergOpt::IS_WATERMARK_SUPPORTED
    }},
    {AVRecorderState::STATE_STOPPED, {
        AVRecordergOpt::STOP,
        AVRecordergOpt::PREPARE,
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE,
        AVRecordergOpt::GET_ENCODER_INFO,
        AVRecordergOpt::GET_AV_RECORDER_CONFIG
    }},
    {AVRecorderState::STATE_RELEASED, {
        AVRecordergOpt::RELEASE
    }},
    {AVRecorderState::STATE_ERROR, {
        AVRecordergOpt::RESET,
        AVRecordergOpt::RELEASE
    }},
};

namespace AVRecorderEvent {
    const std::string EVENT_STATE_CHANGE = "stateChange";
    const std::string EVENT_ERROR = "error";
    const std::string EVENT_AUDIO_CAPTURE_CHANGE = "audioCapturerChange";
    const std::string EVENT_PHOTO_ASSET_AVAILABLE = "photoAssetAvailable";
}

struct AVRecorderAsyncContext;
struct WatermarkConfig;
struct AVRecorderConfig;
struct AVRecorderProfile;

class AVRecorderImpl {
public:
    using AvRecorderTaskqFunc = RetInfo (AVRecorderImpl::*)();
    AVRecorderImpl();
    string GetState();
    void PrepareSync(ohos::multimedia::media::AVRecorderConfig const& config);
    void StartSync();
    optional<string> GetInputSurfaceSync();
    void PauseSync();
    void StopSync();
    void ReleaseSync();
    void ResetSync();
    void ResumeSync();
    void SetMetadataSync(std::map<std::string, std::string> metadata);

    optional<::ohos::multimedia::media::AVRecorderConfig> GetAVRecorderConfigSync();
    std::shared_ptr<TaskHandler<RetInfo>> GetAVRecorderConfigTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t GetAVRecorderConfig(std::shared_ptr<AVRecorderConfig> &config);
    ::ohos::multimedia::media::AVRecorderConfig CreateDefaultAVRecorderConfig();
    ::ohos::multimedia::media::AVRecorderProfile CreateDefaultAVRecorderProfile();
    void SetAVRecorderConfig(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, ::ohos::multimedia::media::AVRecorderConfig &res);
    ::ohos::multimedia::media::AVRecorderProfile CreateAVRecorderProfile(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);

    optional<string> GetInputMetaSurfaceSync(::ohos::multimedia::media::MetaSourceType type);
    int32_t GetMetaType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::MetaSourceType type);
    std::shared_ptr<TaskHandler<RetInfo>> GetInputMetaSurface(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);

    bool IsWatermarkSupportedSync();
    std::shared_ptr<TaskHandler<RetInfo>> IsWatermarkSupportedTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t IsWatermarkSupported(bool &isWatermarkSupported);

    void UpdateRotationSync(int32_t rotation);
    int32_t GetRotation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, int32_t rotation);
    std::shared_ptr<TaskHandler<RetInfo>> GetSetOrientationHintTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);

    int32_t GetAudioCapturerMaxAmplitudeSync();
    std::shared_ptr<TaskHandler<RetInfo>> GetMaxAmplitudeTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t GetMaxAmplitude(int32_t &maxAmplitude);

    ::taihe::array<::ohos::multimedia::media::EncoderInfo> GetAvailableEncoderSync();
    std::shared_ptr<TaskHandler<RetInfo>> GetEncoderInfoTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t GetEncoderInfo(std::vector<EncoderCapabilityData> &encoderInfo);
    ::taihe::array<::ohos::multimedia::media::EncoderInfo> GetTaiheResult(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    ::taihe::array<::ohos::multimedia::media::EncoderInfo> GetDefaultResult();
    void GetAudioEncoderInfo(EncoderCapabilityData encoderCapData,
        std::vector<::ohos::multimedia::media::EncoderInfo> &TaiheEncoderInfos);
    void GetVideoEncoderInfo(EncoderCapabilityData encoderCapData,
        std::vector<::ohos::multimedia::media::EncoderInfo> &TaiheEncoderInfos);
    ::ohos::multimedia::media::Range GetRange(int32_t min, int32_t max);

    void SetWatermarkSync(::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfig const& config);
    std::shared_ptr<TaskHandler<RetInfo>> SetWatermarkTask(const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t SetWatermark(std::shared_ptr<PixelMap> &pixelMap,
        std::shared_ptr<WatermarkConfig> &watermarkConfig);
    int32_t ConfigAVBufferMeta(std::shared_ptr<PixelMap> &pixelMap,
        std::shared_ptr<WatermarkConfig> &watermarkConfig, std::shared_ptr<Meta> &meta);
    int32_t GetWatermarkParameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ::ohos::multimedia::image::image::weak::PixelMap watermark,
        ::ohos::multimedia::media::WatermarkConfig const& config);
    int32_t GetWatermark(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ::ohos::multimedia::image::image::weak::PixelMap watermark);
    int32_t GetWatermarkConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ::ohos::multimedia::media::WatermarkConfig const& config);

    optional<::ohos::multimedia::audio::AudioCapturerChangeInfo> GetCurrentAudioCapturerInfoSync();
    std::shared_ptr<TaskHandler<RetInfo>> GetCurrentCapturerChangeInfoTask(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo);
    ::ohos::multimedia::audio::AudioDeviceDescriptor GetDeviceInfo(
        const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    void GetAudioCapturerChangeInfo(const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ::ohos::multimedia::audio::AudioCapturerChangeInfo &res);
    ::ohos::multimedia::audio::AudioCapturerChangeInfo GetAudioDefaultInfo();

    int32_t GetConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    std::shared_ptr<TaskHandler<RetInfo>> GetPromiseTask(AVRecorderImpl *avtaihe, const std::string &opt);
    int32_t CheckStateMachine(const std::string &opt);
    int32_t CheckRepeatOperation(const std::string &opt);
    void ExecuteByPromise(const std::string &opt);
    optional<string> GetInputSurfaceExecuteByPromise(const std::string &opt);
    void RemoveSurface();
    std::shared_ptr<TaskHandler<RetInfo>> GetPrepareTask(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
    int32_t GetSourceType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    int32_t GetProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    int32_t GetAudioProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    int32_t GetVideoProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    int32_t GetModeAndUrl(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVRecorderConfig const& config);
    bool GetLocation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::Location const& locations);
    int32_t GetAVMetaData(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
        ohos::multimedia::media::AVMetadata const& metadata);
    int32_t GetAudioCodecFormat(const std::string &mime, OHOS::Media::AudioCodecFormat &codecFormat);
    int32_t SetAudioCodecFormat(OHOS::Media::AudioCodecFormat &codecFormat, std::string &mime);
    int32_t GetVideoCodecFormat(const std::string &mime, OHOS::Media::VideoCodecFormat &codecFormat);
    int32_t SetVideoCodecFormat(OHOS::Media::VideoCodecFormat &codecFormat, std::string &mime);
    int32_t SetFileFormat(OutputFormatType &type, std::string &extension);
    int32_t GetOutputFormat(const std::string &extension, OutputFormatType &type);
    void MediaProfileLog(bool isVideo, AVRecorderProfile &profile);

    RetInfo Configure(std::shared_ptr<AVRecorderConfig> config);
    RetInfo ConfigureUrl(std::shared_ptr<AVRecorderConfig> config);
    RetInfo SetProfile(std::shared_ptr<AVRecorderConfig> config);
    RetInfo GetInputSurface();
    RetInfo Start();
    RetInfo Pause();
    RetInfo Resume();
    RetInfo Stop();
    RetInfo Reset();
    RetInfo Release();
    void CancelCallback();
    void StateCallback(const std::string &state);
    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);
    void ErrorCallback(int32_t errCode, const std::string &operate, const std::string &add);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OnStateChange(callback_view<void(string_view, ohos::multimedia::media::StateChangeReason)> callback);
    void OnAudioCapturerChange(
        ::taihe::callback_view<void(::ohos::multimedia::audio::AudioCapturerChangeInfo const&)> callback);
    void OnPhotoAssetAvailable(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OffStateChange(optional_view<callback<void(string_view,
                        ohos::multimedia::media::StateChangeReason)>> callback);
    void OffAudioCapturerChange(::taihe::optional_view<::taihe::callback<void(
        ::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>> callback);
    void OffPhotoAssetAvailable(optional_view<callback<void(uintptr_t)>> callback);
private:
    OHOS::sptr<OHOS::Surface> surface_ = nullptr;
    bool getVideoInputSurface_ = false;
    bool withVideo_ = false;
    bool hasConfiged_ = false;

    std::shared_ptr<RecorderCallback> recorderCb_ = nullptr;
    std::shared_ptr<Recorder> recorder_ = nullptr;
    std::unique_ptr<TaskQueue> taskQue_;
    static std::map<std::string, AvRecorderTaskqFunc> taskQFuncs_;
    int32_t videoSourceID_ = -1;
    std::map<OHOS::Media::MetaSourceType, int32_t> metaSourceIDMap_;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
    int32_t audioSourceID_ = -1;
    int32_t metaSourceID_ = -1;
    int32_t rotation_ = 0;
    int32_t videoFrameWidth_ = -1;
    int32_t videoFrameHeight_ = -1;
    OHOS::sptr<OHOS::Surface> metaSurface_ = nullptr;
    int32_t SetMetadata(const std::map<std::string, std::string> &recordMeta);
};

struct AVRecorderAsyncContext {
    explicit AVRecorderAsyncContext() = default;
    ~AVRecorderAsyncContext() = default;

    AVRecorderImpl *taihe = nullptr;
    std::shared_ptr<AVRecorderConfig> config_ = nullptr;
    std::string opt_ = "";
    std::shared_ptr<TaskHandler<RetInfo>> task_ = nullptr;
    std::shared_ptr<AVRecorderProfile> profile_ = nullptr;
    AudioRecorderChangeInfo changeInfo_;
    int32_t maxAmplitude_ = 0;
    std::vector<EncoderCapabilityData> encoderInfo_;
    OHOS::Media::MetaSourceType metaType_ = OHOS::Media::MetaSourceType::VIDEO_META_SOURCE_INVALID;
    std::shared_ptr<WatermarkConfig> watermarkConfig_ = nullptr;
    std::shared_ptr<PixelMap> pixelMap_ = nullptr;
    bool isWatermarkSupported_ = false;
};

struct AVRecorderProfile {
    int32_t audioBitrate = AVRECORDER_DEFAULT_AUDIO_BIT_RATE;
    int32_t audioChannels = AVRECORDER_DEFAULT_AUDIO_CHANNELS;
    int32_t audioSampleRate = AVRECORDER_DEFAULT_AUDIO_SAMPLE_RATE;
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_DEFAULT;

    int32_t videoBitrate = AVRECORDER_DEFAULT_VIDEO_BIT_RATE;
    int32_t videoFrameWidth = AVRECORDER_DEFAULT_FRAME_HEIGHT;
    int32_t videoFrameHeight = AVRECORDER_DEFAULT_FRAME_WIDTH;
    int32_t videoFrameRate = AVRECORDER_DEFAULT_FRAME_RATE;
    bool isHdr = false;
    bool enableTemporalScale = false;
    bool enableStableQualityMode = false;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;

    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
};

struct AVRecorderConfig {
    OHOS::Media::AudioSourceType audioSourceType; // source type;
    OHOS::Media::VideoSourceType videoSourceType;
    std::vector<OHOS::Media::MetaSourceType> metaSourceTypeVec;
    AVRecorderProfile profile;
    std::string url;
    int32_t rotation = 0; // Optional
    int32_t maxDuration = INT32_MAX; // Optional
    OHOS::Media::Location location; // Optional
    OHOS::Media::AVMetadata metadata; // Optional
    OHOS::Media::FileGenerationMode fileGenerationMode = OHOS::Media::FileGenerationMode::APP_CREATE;
    bool withVideo = false;
    bool withAudio = false;
    bool withLocation = false;
};

struct WatermarkConfig {
    int32_t top = -1; // offset of the watermark to the top line of pixel
    int32_t left = -1; // offset of the watermark to the left line if pixel
};
} // namespace ANI::Media
#endif // AVRECORDER_TAIHE_H