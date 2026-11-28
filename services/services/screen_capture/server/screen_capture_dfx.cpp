/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "screen_capture_dfx.h"

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include <hisysevent.h>
#include <meta/meta.h>
#include <res_sched_client.h>
#include <res_type.h>

#include "nlohmann/json.hpp"

#include "media_dfx.h"
#include "media_errors.h"
#include "screen_capture.h"
#include "screen_capture_server_base.h"

namespace OHOS {
namespace Media {

namespace {

int64_t NowMs()
{
    std::chrono::system_clock::duration duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

bool HasInnerAudio(const AVScreenCaptureConfig &config)
{
    const AudioCaptureInfo &inner = config.audioInfo.innerCapInfo;
    return inner.audioSource == AudioCaptureSourceType::ALL_PLAYBACK ||
        inner.audioSource == AudioCaptureSourceType::APP_PLAYBACK;
}

bool HasVideo(const AVScreenCaptureConfig &config)
{
    const VideoCaptureInfo &video = config.videoInfo.videoCapInfo;
    return video.videoSource != VideoSourceType::VIDEO_SOURCE_BUTT || video.videoFrameWidth > 0 ||
        video.videoFrameHeight > 0;
}

bool MicRequired(const AVScreenCaptureConfig &config)
{
    const AudioCaptureInfo &mic = config.audioInfo.micCapInfo;
    return mic.audioSampleRate > 0 || mic.audioChannels > 0;
}

void BuildContext(const AVScreenCaptureConfig &config, bool hasRecorder, int8_t &avType, int8_t &dataMode)
{
    dataMode = 0;
    if (config.dataType == DataType::ORIGINAL_STREAM) {
        dataMode = static_cast<int8_t>(AVScreenCaptureDataMode::SUFFACE_MODE);
    } else if (config.dataType == DataType::CAPTURE_FILE) {
        dataMode = static_cast<int8_t>(AVScreenCaptureDataMode::FILE_MODE);
    }

    bool hasInnerAudio = HasInnerAudio(config);
    bool hasVideo = HasVideo(config);
    if (hasRecorder || (hasVideo && hasInnerAudio)) {
        avType = static_cast<int8_t>(AVScreenCaptureAvType::AV_TYPE);
    } else if (hasVideo) {
        avType = static_cast<int8_t>(AVScreenCaptureAvType::VIDEO_TYPE);
    } else if (hasInnerAudio) {
        avType = static_cast<int8_t>(AVScreenCaptureAvType::AUDIO_TYPE);
    } else {
        avType = static_cast<int8_t>(AVScreenCaptureAvType::INVALID_TYPE);
    }
}

std::string BuildMediaKitEvents(const AVScreenCaptureConfig &config, uint32_t maxRefreshRate)
{
    nlohmann::json events;
    events["captureMode"] = config.captureMode;
    events["dataType"] = std::to_string(config.dataType);
    events["videoCapDisplayId"] = config.videoInfo.videoCapInfo.displayId;
    events["videoFrameWidth"] = config.videoInfo.videoCapInfo.videoFrameWidth;
    events["videoFrameHeight"] = config.videoInfo.videoCapInfo.videoFrameHeight;
    events["videoSourceType"] = config.videoInfo.videoCapInfo.videoSource;
    events["videoCapState"] = config.videoInfo.videoCapInfo.state;
    events["videoCodec"] = config.videoInfo.videoEncInfo.videoCodec;
    events["videoBitrate"] = config.videoInfo.videoEncInfo.videoBitrate;
    events["videoFrameRate"] = config.videoInfo.videoEncInfo.videoFrameRate;
    events["videoEncState"] = config.videoInfo.videoEncInfo.state;
    events["micAudioSampleRate"] = config.audioInfo.micCapInfo.audioSampleRate;
    events["micChannels"] = config.audioInfo.micCapInfo.audioChannels;
    events["micAudioSource"] = config.audioInfo.micCapInfo.audioSource;
    events["micState"] = config.audioInfo.micCapInfo.state;
    events["innerAudioSampleRate"] = config.audioInfo.innerCapInfo.audioSampleRate;
    events["innerChannels"] = config.audioInfo.innerCapInfo.audioChannels;
    events["innerAudioSource"] = config.audioInfo.innerCapInfo.audioSource;
    events["innerState"] = config.audioInfo.innerCapInfo.state;
    events["audioBitrate"] = config.audioInfo.audioEncInfo.audioBitrate;
    events["audioCodecformat"] = config.audioInfo.audioEncInfo.audioCodecformat;
    events["audioEncState"] = config.audioInfo.audioEncInfo.state;
    events["recorderFileFormat"] = config.recorderInfo.fileFormat;
    events["enableDeviceLevelCapture"] = config.strategy.enableDeviceLevelCapture;
    events["keepCaptureDuringCall"] = config.strategy.keepCaptureDuringCall;
    events["strategyForPrivacyMaskMode"] = config.strategy.strategyForPrivacyMaskMode;
    events["canvasFollowRotation"] = config.strategy.canvasFollowRotation;
    events["enableBFrame"] = config.strategy.enableBFrame;
    events["enableAEC"] = config.strategy.enableAEC;
    events["enableHDRCapture"] = config.strategy.enableHDRCapture;
    events["enablePause"] = config.strategy.enablePause;
    events["contentAutoPauseScenes"] = config.strategy.contentAutoPauseScenes;
    events["setByUser"] = config.strategy.setByUser;
    events["pickerPopUp"] = config.strategy.pickerPopUp;
    events["fillMode"] = config.strategy.fillMode;
    events["highlightLineThickness"] = config.highlightConfig.lineThickness;
    events["highlightLineColor"] = config.highlightConfig.lineColor;
    events["highlightMode"] = config.highlightConfig.mode;
    events["virtualScreenMaxRefreshRate"] = maxRefreshRate;
    return events.dump();
}

const char *GetEndReasonMessage(CaptureEndReason reason)
{
    switch (reason) {
        case CaptureEndReason::NORMAL_STOPPED:
            return "normal stop";
        case CaptureEndReason::RECEIVE_USER_PRIVACY_AUTHORITY_FAILED:
            return "user denied privacy";
        case CaptureEndReason::REQUEST_USER_PRIVACY_AUTHORITY_FAILED:
            return "privacy request failed";
        case CaptureEndReason::POST_START_SCREENCAPTURE_HANDLE_FAILURE:
            return "post-start failed";
        case CaptureEndReason::START_PREPARE_FAILED:
            return "prepare failed";
        case CaptureEndReason::START_INVALID_STATE:
            return "invalid state";
        case CaptureEndReason::START_NOTIFICATION_FAILED:
            return "notification failed";
        default:
            return "start failed";
    }
}

void FillOutcome(StatisticalEventInfo &statistic, int32_t startRet, CaptureEndReason startReason, int64_t startMs,
    int64_t startedMs, int64_t stoppedMs)
{
    if (startedMs > 0) {
        statistic.startLatency = static_cast<int32_t>(startedMs - startMs);
        statistic.captureDuration = stoppedMs > 0 ? static_cast<int32_t>(stoppedMs - startedMs) : -1;
    } else {
        statistic.startLatency = -1;
        statistic.captureDuration = -1;
    }

    if (startRet != MSERR_OK) {
        statistic.errCode = startRet;
        statistic.errMsg = GetEndReasonMessage(startReason);
        statistic.stopReason = startReason;
        return;
    }
    if (stoppedMs > 0) {
        statistic.errCode = MSERR_OK;
        statistic.errMsg = GetEndReasonMessage(CaptureEndReason::NORMAL_STOPPED);
        statistic.stopReason = CaptureEndReason::NORMAL_STOPPED;
    }
}

struct FaultInfo {
    int32_t errorCode;
    const char *message;
};

FaultInfo GetFaultInfo(ScFault fault)
{
    switch (fault) {
        case ScFault::INVALID_FILE_FORMAT:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "invalid fileFormat type"};
        case ScFault::INVALID_OUTPUT_FD:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "invalid outputFd"};
        case ScFault::GET_FILE_STATUS_FLAGS_FAILED:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "Fail to get File Status Flags"};
        case ScFault::OUTPUT_FD_NOT_WRITABLE:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "File descriptor is not in read-write mode or write-only mode"};
        case ScFault::VIDEO_CAP_INVALID:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "video Cap state fault, videoCapInfo is invalid"};
        case ScFault::INNER_OR_VIDEO_CAP_INVALID:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "audio inner cap or video cap state invalid"};
        case ScFault::INNER_OR_VIDEO_CAP_IGNORED:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "audio inner cap or video cap state ignore"};
        case ScFault::CAP_PARAMS_INVALID:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "innerCap audioEnc videoCap videoEnc state invalid"};
        case ScFault::MIC_CAP_INVALID:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL, "audio mic cap state invalid"};
        case ScFault::INNER_MIC_PARAM_MISMATCH:
            return {SCREEN_CAPTURE_ERR_INVALID_VAL,
                "CheckCaptureFileParams failed, inner and mic param not consistent"};
        case ScFault::START_IN_CALL:
            return {SCREEN_CAPTURE_ERR_UNSUPPORT, "ScreenCaptureServer Start InCall Abort"};
        case ScFault::GET_SCREEN_FAILED:
            return {SCREEN_CAPTURE_ERR_UNKNOWN, "GetScreenById failed"};
        case ScFault::NO_VALID_DISPLAY:
            return {SCREEN_CAPTURE_ERR_UNKNOWN, "MakeMirror failed to find valid displayId"};
        case ScFault::ACQUIRE_AUDIO_SOURCE_UNSUPPORTED:
            return {SCREEN_CAPTURE_ERR_UNKNOWN, "AcquireAudioBuffer failed, source type not support"};
        case ScFault::RELEASE_AUDIO_SOURCE_UNSUPPORTED:
            return {SCREEN_CAPTURE_ERR_UNKNOWN, "ReleaseAudioBuffer failed, source type not support"};
        case ScFault::EXCLUDE_CONTENT_FAILED:
            return {SCREEN_CAPTURE_ERR_UNSUPPORT, "ExcludeContent failed, UpdateAudioCapturerConfig failed"};
        default:
            return {SCREEN_CAPTURE_ERR_UNKNOWN, "unknown fault"};
    }
}

void WriteSessionStatistic(const ScDfxHeader &header, const StatisticalEventInfo &statistic)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_CODE, statistic.errCode);
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_MSG, statistic.errMsg);
    meta->SetData(Tag::SCREEN_CAPTURE_DURATION, statistic.captureDuration);
    meta->SetData(Tag::SCREEN_CAPTURE_AV_TYPE, header.avType);
    meta->SetData(Tag::SCREEN_CAPTURE_DATA_TYPE, header.dataMode);
    meta->SetData(Tag::SCREEN_CAPTURE_USER_AGREE, statistic.userAgree);
    meta->SetData(Tag::SCREEN_CAPTURE_REQURE_MIC, statistic.requireMic);
    meta->SetData(Tag::SCREEN_CAPTURE_ENABLE_MIC, statistic.enableMic);
    meta->SetData(Tag::SCREEN_CAPTURE_VIDEO_RESOLUTION, statistic.videoResolution);
    meta->SetData(Tag::SCREEN_CAPTURE_STOP_REASON, statistic.stopReason);
    meta->SetData(Tag::SCREEN_CAPTURE_START_LATENCY, statistic.startLatency);
    AppendMediaInfo(meta, header.identity.instanceId);
    ReportMediaInfo(header.identity.instanceId);
}

void ReportResSched(const ScDfxIdentity &identity, int64_t value)
{
    std::unordered_map<std::string, std::string> payload;
    payload["uid"] = std::to_string(identity.uid);
    payload["pid"] = std::to_string(identity.pid);
    uint32_t type = ResourceSchedule::ResType::RES_TYPE_REPORT_SCREEN_CAPTURE;
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, value, payload);
}

} // namespace

ScreenCaptureDfx::ScreenCaptureDfx(ScDfxIdentity identity) : header_{std::move(identity)}
{
    CreateMediaInfo(SCREEN_CAPTURER, header_.identity.uid, header_.identity.instanceId);
}

ScDfxHeader ScreenCaptureDfx::Snapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return header_;
}

void ScreenCaptureDfx::BindAppInfo(int32_t uid, int32_t pid, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    header_.identity.uid = uid;
    header_.identity.pid = pid;
    header_.identity.bundleName = bundleName;
}

void ScreenCaptureDfx::BindConfig(const AVScreenCaptureConfig &config, uint32_t maxRefreshRate, bool hasRecorder)
{
    std::string events = BuildMediaKitEvents(config, maxRefreshRate);
    int8_t avType = -1;
    int8_t dataMode = 0;
    BuildContext(config, hasRecorder, avType, dataMode);

    StatisticalEventInfo statistic;
    statistic.requireMic = MicRequired(config);
    if (HasVideo(config)) {
        statistic.videoResolution = std::to_string(config.videoInfo.videoCapInfo.videoFrameWidth) + " * " +
            std::to_string(config.videoInfo.videoCapInfo.videoFrameHeight);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    header_.avType = avType;
    header_.dataMode = dataMode;
    mediaKitEvents_ = std::move(events);
    statistic_ = statistic;
    startTimeMs_ = NowMs();
    startedTimeMs_ = -1;
    stoppedTimeMs_ = -1;
    startRet_ = MSERR_OK;
    startReason_ = CaptureEndReason::NORMAL_STOPPED;
}

int32_t ScreenCaptureDfx::Fault(ScFault fault, int32_t result)
{
    FaultInfo info = GetFaultInfo(fault);
    ScDfxHeader header = Snapshot();
    const std::string instanceId = std::to_string(header.identity.instanceId);
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, "SCREEN_CAPTURE_FAILURE",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, "APP_NAME", header.identity.bundleName, "INSTANCE_ID",
        instanceId, "CAPTURE_MODE", header.avType, "DATA_MODE", header.dataMode, "ERROR_CODE", info.errorCode,
        "ERROR_MESG", info.message);
    return result;
}

void ScreenCaptureDfx::StartResult(int32_t result, CaptureEndReason reason)
{
    ScDfxHeader header;
    std::string events;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        startRet_ = result;
        startReason_ = reason;
        if (result == MSERR_OK) {
            startedTimeMs_ = NowMs();
        }
        header = header_;
        events = mediaKitEvents_;
    }
    if (events.empty()) {
        return;
    }
    MediaEvent event;
    event.MediaKitStatistics("AVScreenCapture", header.identity.bundleName, std::to_string(header.identity.instanceId),
        result == MSERR_OK ? "startRecording" : "startRecording fail", events);
}

void ScreenCaptureDfx::CaptureStarted()
{
    ScDfxIdentity identity;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        identity = header_.identity;
    }
    ReportResSched(identity, ResourceSchedule::ResType::ScreenCaptureStatus::START_SCREEN_CAPTURE);
}

void ScreenCaptureDfx::CaptureStopped()
{
    ScDfxIdentity identity;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stoppedTimeMs_ = NowMs();
        identity = header_.identity;
    }
    ReportResSched(identity, ResourceSchedule::ResType::ScreenCaptureStatus::STOP_SCREEN_CAPTURE);
}

void ScreenCaptureDfx::Finish(bool userAgree, bool micEnabled)
{
    ScDfxHeader header;
    StatisticalEventInfo statistic;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (finished_) {
            return;
        }
        finished_ = true;
        header = header_;
        statistic = statistic_;
        statistic.userAgree = userAgree;
        statistic.enableMic = micEnabled;
        FillOutcome(statistic, startRet_, startReason_, startTimeMs_, startedTimeMs_, stoppedTimeMs_);
    }
    WriteSessionStatistic(header, statistic);
}

std::unique_ptr<ICaptureDfx> CreateScreenCaptureDfx(ScDfxIdentity identity)
{
    return std::make_unique<ScreenCaptureDfx>(std::move(identity));
}

} // namespace Media
} // namespace OHOS
