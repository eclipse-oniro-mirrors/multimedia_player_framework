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

#include "media_errors.h"
#include "media_log.h"
#include "media_dfx.h"
#include "media_taihe_utils.h"
#include "avscreen_capture_callback_taihe.h"
#ifndef CROSS_PLATFORM
#include "display_manager.h"
#endif

using namespace ANI::Media;
using namespace OHOS::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVScreenCaptureTaihe"};
}

namespace ANI::Media {
std::map<std::string,
    AVScreenCaptureRecorderImpl::AvScreenCaptureTaskqFunc> AVScreenCaptureRecorderImpl::taskQFuncs_ = {
    {AVScreenCapturegOpt::START_RECORDING, &AVScreenCaptureRecorderImpl::StartRecording},
    {AVScreenCapturegOpt::STOP_RECORDING, &AVScreenCaptureRecorderImpl::StopRecording},
    {AVScreenCapturegOpt::RELEASE, &AVScreenCaptureRecorderImpl::Release},
};

AVScreenCaptureRecorderImpl::AVScreenCaptureRecorderImpl()
{
    screenCapture_ = ScreenCaptureFactory::CreateScreenCapture();
    if (screenCapture_ == nullptr) {
        MEDIA_LOGE("failed to CreateScreenCapture");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateScreenCapture");
        return;
    }
    taskQue_ = std::make_unique<TaskQueue>("OS_AVScreenCaptureTaihe");
    (void)taskQue_->Start();
    screenCaptureCb_ = std::make_shared<AVScreenCaptureCallback>();
    if (screenCaptureCb_ == nullptr) {
        MEDIA_LOGE("failed to CreateScreenCaptureCb");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateScreenCaptureCb");
        return;
    }
    (void)screenCapture_->SetScreenCaptureCallback(screenCaptureCb_);
}

optional<AVScreenCaptureRecorder> CreateAVScreenCaptureRecorderSync()
{
    MediaTrace trace("AVScreenCapture::CreateAVScreenRecorder");
    auto res = make_holder<AVScreenCaptureRecorderImpl, AVScreenCaptureRecorder>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVScreenCaptureRecorder failed!");
        taihe::reset_error();
        return optional<AVScreenCaptureRecorder>(std::nullopt);
    }
    return optional<AVScreenCaptureRecorder>(std::in_place, res);
}

void ReportAVScreenCaptureUserChoiceSync(int32_t sessionId, string_view choice)
{
    MediaTrace trace("AVScreenCapture::TaiheReportAVScreenCaptureUserChoice");
    const std::string &opt = AVScreenCapturegOpt::REPORT_USER_CHOICE;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    MEDIA_LOGI("TaiheReportAVScreenCaptureUserChoice sessionId: %{public}d, choice: %{public}s",
        sessionId, static_cast<std::string>(choice).c_str());
    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->controller_ = ScreenCaptureControllerFactory::CreateScreenCaptureController();
    asyncCtx->controller_->ReportAVScreenCaptureUserChoice(sessionId, static_cast<std::string>(choice));
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
}

string GetAVScreenCaptureConfigurableParametersSync(int32_t sessionId)
{
    MediaTrace trace("AVScreenCapture::TaiheGetAVScreenCaptureconfigurableParameters");
    const std::string &opt = AVScreenCapturegOpt::GET_CONFIG_PARAMS;
    MEDIA_LOGI("Taihe %{public}s Start. TaiheGetAVScreenCaptureconfigurableParameters sessionId: %{public}d",
        opt.c_str(), sessionId);
    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    auto res = ::taihe::string("");
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    if (!MediaTaiheUtils::SystemPermission()) {
        set_business_error(MSERR_EXT_API9_PERMISSION_DENIED, "permission denied");
        return res;
    }
    std::string resultStr = "";
    asyncCtx->controller_ = ScreenCaptureControllerFactory::CreateScreenCaptureController();
    if (asyncCtx->controller_ == nullptr) {
        set_business_error(MSERR_EXT_API9_PERMISSION_DENIED, "failed to create controller.");
        return res;
    }
    
    int32_t ret = asyncCtx->controller_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    if (ret != MSERR_OK) {
        set_business_error(MSERR_EXT_API20_SESSION_NOT_EXIST, "session does not exist.");
        return res;
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return MediaTaiheUtils::ToTaiheString(resultStr);
}

RetInfo GetReturnInfo(int32_t errCode, const std::string &operate, const std::string &param,
    const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d",
        operate.c_str(), param.c_str(), errCode);
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    
    std::string message;
    if (err == MSERR_EXT_API9_INVALID_PARAMETER) {
        message = MSExtErrorAPI9ToString(err, param, "") + add;
    } else {
        message = MSExtErrorAPI9ToString(err, operate, "") + add;
    }

    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, message.c_str());
    return RetInfo(err, message);
}

int32_t AVScreenCaptureRecorderImpl::CheckAudioSampleRate(const int32_t &audioSampleRate)
{
    if (audioSampleRate == 48000 || audioSampleRate == 16000) { // 16000 48000 AudioSampleRate options
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVScreenCaptureRecorderImpl::CheckAudioChannelCount(const int32_t &audioChannelCount)
{
    if (audioChannelCount == 1 || audioChannelCount == 2) { // 1 2 channelCount number options
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVScreenCaptureRecorderImpl::CheckVideoCodecFormat(const int32_t &preset)
{
    if (static_cast<int32_t>(AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H264_AAC_MP4) <= preset &&
        static_cast<int32_t>(AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H265_AAC_MP4) >= preset) {
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

VideoCodecFormat AVScreenCaptureRecorderImpl::GetVideoCodecFormat(const int32_t &preset)
{
    const std::map<AVScreenCaptureRecorderPreset, VideoCodecFormat> presetToCodecFormat = {
        { AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H264_AAC_MP4, VideoCodecFormat::H264 },
        { AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H265_AAC_MP4, VideoCodecFormat::H265 }
    };
    VideoCodecFormat codecFormat = VideoCodecFormat::H264;
    auto iter = presetToCodecFormat.find(static_cast<AVScreenCaptureRecorderPreset>(preset));
    if (iter != presetToCodecFormat.end()) {
        codecFormat = iter->second;
    }
    return codecFormat;
}

int32_t AVScreenCaptureRecorderImpl::CheckVideoFrameFormat(const int32_t &frameWidth, const int32_t &frameHeight,
    int32_t &videoFrameWidth, int32_t &videoFrameHeight)
{
#ifndef CROSS_PLATFORM
    if (frameWidth == AVSCREENCAPTURE_DEFAULT_FRAME_WIDTH || frameHeight == AVSCREENCAPTURE_DEFAULT_FRAME_HEIGHT ||
        !(frameWidth == 0 && frameHeight == 0)) { // 0 one of width height is zero, use default display
        OHOS::sptr<OHOS::Rosen::Display> display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
        if (display == nullptr) {
            return MSERR_INVALID_VAL;
        }
        MEDIA_LOGI("check video frame get displayInfo width:%{public}d,height:%{public}d,density:%{public}f",
            display->GetWidth(), display->GetHeight(), display->GetVirtualPixelRatio());
        if (frameWidth == AVSCREENCAPTURE_DEFAULT_FRAME_WIDTH || frameWidth == 0) { // 0 use default display
            videoFrameWidth = display->GetWidth();
        } else {
            videoFrameWidth = frameWidth;
        }
        if (frameHeight == AVSCREENCAPTURE_DEFAULT_FRAME_HEIGHT || frameHeight == 0) { // 0 use default display
            videoFrameHeight = display->GetHeight();
        } else {
            videoFrameHeight = frameHeight;
        }
    } else {
        videoFrameWidth = frameWidth;
        videoFrameHeight = frameHeight;
    }
#else
    videoFrameWidth = frameWidth;
    videoFrameHeight = frameHeight;
#endif
    return MSERR_OK;
}

OHOS::Media::AVScreenCaptureFillMode AVScreenCaptureRecorderImpl::GetScreenCaptureFillMode(const int32_t &fillMode)
{
    MEDIA_LOGI("AVScreenCaptureTaihe::GetScreenCaptureFillMode in!");
    const std::map<int32_t, OHOS::Media::AVScreenCaptureFillMode> intToFillMode = {
        { 0, OHOS::Media::AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO },
        { 1, OHOS::Media::AVScreenCaptureFillMode::SCALE_TO_FILL }
    };
    OHOS::Media::AVScreenCaptureFillMode screenCaptureFillMode =
        OHOS::Media::AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO;
    auto iter = intToFillMode.find(fillMode);
    if (iter != intToFillMode.end()) {
        screenCaptureFillMode = iter->second;
    }
    MEDIA_LOGI("AVScreenCaptureTaihe::GetScreenCaptureFillMode succeed, screenCaptureFillMode: %{public}d",
        screenCaptureFillMode);
    return screenCaptureFillMode;
}

int32_t AVScreenCaptureRecorderImpl::GetConfig(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    asyncCtx->config_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    asyncCtx->config_.dataType = DataType::CAPTURE_FILE;

    int32_t ret =  GetAudioInfo(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetAudioInfo");
    ret =  GetVideoInfo(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetVideoInfo");
    ret =  GetRecorderInfo(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetRecorderInfo");
    ret = GetStrategy(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetStrategy");
    return MSERR_OK;
}

int32_t AVScreenCaptureRecorderImpl::GetAudioInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    int32_t audioSampleRate = AVSCREENCAPTURE_DEFAULT_AUDIO_SAMPLE_RATE;
    int32_t audioChannels = AVSCREENCAPTURE_DEFAULT_AUDIO_CHANNELS;
    int32_t audioBitrate = AVSCREENCAPTURE_DEFAULT_AUDIO_BIT_RATE;

    AudioCaptureInfo &micConfig = asyncCtx->config_.audioInfo.micCapInfo;
    AudioCaptureInfo &innerConfig = asyncCtx->config_.audioInfo.innerCapInfo;
    AudioEncInfo &encoderConfig = asyncCtx->config_.audioInfo.audioEncInfo;

    if (config.audioSampleRate.has_value()) {
        audioSampleRate = config.audioSampleRate.value();
    }
    int32_t ret = CheckAudioSampleRate(audioSampleRate);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVScreenCaptureSignError(ret, "getAudioSampleRate", "audioSampleRate"), ret));
    micConfig.audioSampleRate = audioSampleRate;
    innerConfig.audioSampleRate = audioSampleRate;
    MEDIA_LOGI("input audioSampleRate %{public}d", micConfig.audioSampleRate);

    if (config.audioChannelCount.has_value()) {
        audioChannels = config.audioChannelCount.value();
    }
    ret = CheckAudioChannelCount(audioChannels);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVScreenCaptureSignError(ret, "getAudioChannelCount", "audioChannelCount"), ret));
    micConfig.audioChannels = audioChannels;
    innerConfig.audioChannels = audioChannels;
    MEDIA_LOGI("input audioChannelCount %{public}d", micConfig.audioChannels);
    micConfig.audioSource = AudioCaptureSourceType::MIC;
    innerConfig.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;

    if (config.audioBitrate.has_value()) {
        audioBitrate = config.audioBitrate.value();
    }
    encoderConfig.audioBitrate = audioBitrate;
    encoderConfig.audioCodecformat = AudioCodecFormat::AAC_LC;
    MEDIA_LOGI("input audioBitrate %{public}d", encoderConfig.audioBitrate);
    return MSERR_OK;
}

int32_t AVScreenCaptureRecorderImpl::GetVideoInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    int32_t videoBitrate = AVSCREENCAPTURE_DEFAULT_VIDEO_BIT_RATE;
    int32_t preset = AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H264_AAC_MP4;
    int32_t frameWidth = AVSCREENCAPTURE_DEFAULT_FRAME_WIDTH;
    int32_t frameHeight = AVSCREENCAPTURE_DEFAULT_FRAME_HEIGHT;
    int32_t displayId = AVSCREENCAPTURE_DEFAULT_DISPLAY_ID;
    int32_t fillMode = OHOS::Media::AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO;
    VideoEncInfo &encoderConfig = asyncCtx->config_.videoInfo.videoEncInfo;
    VideoCaptureInfo &videoConfig = asyncCtx->config_.videoInfo.videoCapInfo;
    if (config.displayId.has_value()) {
        displayId = config.displayId.value();
    }
    CHECK_AND_RETURN_RET(displayId >= 0,
        (asyncCtx->AVScreenCaptureSignError(MSERR_INVALID_VAL, "getDisplayId", "displayId"), MSERR_INVALID_VAL));
    videoConfig.displayId = static_cast<uint64_t>(displayId);
    if (videoConfig.displayId > 0) {
        asyncCtx->config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;
    }
    MEDIA_LOGI("input displayId %{public}" PRIu64, videoConfig.displayId);
    if (config.videoBitrate.has_value()) {
        videoBitrate = config.videoBitrate.value();
    }
    encoderConfig.videoBitrate = videoBitrate;
    encoderConfig.videoFrameRate = AVSCREENCAPTURE_DEFAULT_VIDEO_FRAME_RATE;
    MEDIA_LOGI("input videoBitrate %{public}d", encoderConfig.videoBitrate);
    if (config.preset.has_value()) {
        preset = static_cast<int32_t>(config.preset.value().get_value());
    }
    int32_t ret = CheckVideoCodecFormat(preset);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (asyncCtx->AVScreenCaptureSignError(ret, "getPreset", "preset"), ret));
    encoderConfig.videoCodec = GetVideoCodecFormat(preset);
    MEDIA_LOGI("input videoCodec %{public}d", encoderConfig.videoCodec);
    if (config.frameWidth.has_value()) {
        frameWidth = config.frameWidth.value();
    }
    if (config.frameHeight.has_value()) {
        frameHeight = config.frameHeight.value();
    }
    MEDIA_LOGI("input frameWidth %{public}d, frameHeight %{public}d", frameWidth, frameHeight);
    ret = CheckVideoFrameFormat(frameWidth, frameHeight, videoConfig.videoFrameWidth, videoConfig.videoFrameHeight);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (asyncCtx->AVScreenCaptureSignError(ret,
        "getVideoFrame", "VideoFrame"), ret));
    videoConfig.videoSource = OHOS::Media::VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA;
    if (config.fillMode.has_value()) {
        fillMode = config.fillMode.value().get_value();
    }
    asyncCtx->config_.strategy.fillMode = GetScreenCaptureFillMode(fillMode);
    MEDIA_LOGI("input screenCaptureFillMode %{public}d", asyncCtx->config_.strategy.fillMode);
    return MSERR_OK;
}

int32_t AVScreenCaptureRecorderImpl::GetRecorderInfo(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    RecorderInfo &recorderConfig = asyncCtx->config_.recorderInfo;
    recorderConfig.fileFormat = AVSCREENCAPTURE_DEFAULT_FILE_FORMAT;
    int32_t fd = -1;
    fd = config.fd;
    CHECK_AND_RETURN_RET(fd > 0, // 0 to 2 for system std log
        (asyncCtx->AVScreenCaptureSignError(MSERR_INVALID_VAL, "GetRecorderInfo", "url"), MSERR_INVALID_VAL));
    recorderConfig.url = "fd://" + std::to_string(fd);
    CHECK_AND_RETURN_RET(recorderConfig.url != "",
        (asyncCtx->AVScreenCaptureSignError(MSERR_INVALID_VAL, "GetRecorderInfo", "url"), MSERR_INVALID_VAL));
    MEDIA_LOGI("input url %{public}s", recorderConfig.url.c_str());
    return MSERR_OK;
}

RetInfo AVScreenCaptureRecorderImpl::StartRecording()
{
    int32_t ret = screenCapture_->SetPrivacyAuthorityEnabled();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(ret, "SetPrivacyAuthorityEnabled", ""));
    ret = screenCapture_->StartScreenRecording();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(ret, "StartRecording", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVScreenCaptureRecorderImpl::StopRecording()
{
    int32_t ret = screenCapture_->StopScreenRecording();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(ret, "StopRecording", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

int32_t AVScreenCaptureRecorderImpl::GetStrategy(std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    // return MSERR_OK, because strategy is optional.
    CHECK_AND_RETURN_RET_LOG(config.strategy.has_value(), MSERR_OK, "without strategy");
    ScreenCaptureStrategy &strategy = asyncCtx->config_.strategy;
    AVScreenCaptureStrategy avStrategy = config.strategy.value();
    // get enableDeviceLevelCapture
    if (avStrategy.enableDeviceLevelCapture.has_value()) {
        strategy.enableDeviceLevelCapture = avStrategy.enableDeviceLevelCapture.value();
        strategy.setByUser = true;
    }
    // get keepCaptureDuringCall
    if (avStrategy.keepCaptureDuringCall.has_value()) {
        strategy.keepCaptureDuringCall = avStrategy.keepCaptureDuringCall.value();
        strategy.setByUser = true;
    }
    // get enableBFrame
    if (avStrategy.enableBFrame.has_value()) {
        strategy.enableBFrame = avStrategy.enableBFrame.value();
        strategy.setByUser = true;
    }
    // get strategyForPrivacyMaskMode
    if (avStrategy.privacyMaskMode.has_value()) {
        CHECK_AND_RETURN_RET_LOG(avStrategy.privacyMaskMode.value() == 0 || avStrategy.privacyMaskMode.value() == 1,
            MSERR_INVALID_VAL, "privacyMaskMode invalid");
        strategy.strategyForPrivacyMaskMode = avStrategy.privacyMaskMode.value();
        strategy.setByUser = true;
    }
    MEDIA_LOGI("GetStrategy enableDeviceLevelCapture: %{public}d, keepCaptureDuringCall: %{public}d, "
        "enableBFrame: %{public}d, strategyForPrivacyMaskMode: %{public}d", strategy.enableDeviceLevelCapture,
        strategy.keepCaptureDuringCall, strategy.enableBFrame, strategy.strategyForPrivacyMaskMode);
    return MSERR_OK;
}

void AVScreenCaptureRecorderImpl::InitSync(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    MediaTrace trace("AVScreenCapture::TaiheInit");
    const std::string &opt = AVScreenCapturegOpt::INIT;
    MEDIA_LOGI("%{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    if (asyncCtx->taihe->GetConfig(asyncCtx, config) == MSERR_OK) {
        asyncCtx->task_ = AVScreenCaptureRecorderImpl::GetInitTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
    }

    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
}

std::shared_ptr<TaskHandler<RetInfo>> AVScreenCaptureRecorderImpl::GetInitTask(
    const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, config = asyncCtx->config_]() {
        const std::string &option = AVScreenCapturegOpt::INIT;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->screenCapture_ != nullptr,
            GetReturnInfo(MSERR_INVALID_OPERATION, option, ""));

        int32_t ret = taihe->screenCapture_->Init(config);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)taihe->screenCapture_->Release(), GetReturnInfo(ret, "Init", "")));

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

void AVScreenCaptureRecorderImpl::ExecuteByPromise(const std::string &opt)
{
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    asyncCtx->task_ = AVScreenCaptureRecorderImpl::GetPromiseTask(asyncCtx->taihe, opt);
    (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
    asyncCtx->opt_ = opt;

    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
}

std::shared_ptr<TaskHandler<RetInfo>> AVScreenCaptureRecorderImpl::GetPromiseTask(
    AVScreenCaptureRecorderImpl *avtaihe, const std::string &opt)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = avtaihe, option = opt]() {
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->screenCapture_ != nullptr,
            GetReturnInfo(MSERR_INVALID_OPERATION, option, ""));

        RetInfo ret(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
        auto itFunc = taskQFuncs_.find(option);
        CHECK_AND_RETURN_RET_LOG(itFunc != taskQFuncs_.end(), ret, "%{public}s not found in map!", option.c_str());
        auto memberFunc = itFunc->second;
        CHECK_AND_RETURN_RET_LOG(memberFunc != nullptr, ret, "memberFunc is nullptr!");
        ret = (taihe->*memberFunc)();
        
        MEDIA_LOGI("%{public}s End", option.c_str());
        return ret;
    });
}

void AVScreenCaptureRecorderImpl::StartRecordingSync()
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::TaiheStartRecording");
    return ExecuteByPromise(AVScreenCapturegOpt::START_RECORDING);
}

void AVScreenCaptureRecorderImpl::StopRecordingSync()
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::TaiheStopRecording");
    return ExecuteByPromise(AVScreenCapturegOpt::STOP_RECORDING);
}

std::shared_ptr<TaskHandler<RetInfo>> AVScreenCaptureRecorderImpl::GetSkipPrivacyModeTask(
    const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx, const std::vector<uint64_t> windowIDsVec)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, windowIDsVec]() {
        const std::string &option = AVScreenCapturegOpt::SKIP_PRIVACY_MODE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->screenCapture_ != nullptr,
            GetReturnInfo(MSERR_INVALID_OPERATION, option, ""));
        int32_t ret = taihe->screenCapture_->SkipPrivacyMode(const_cast<std::vector<uint64_t> &>(windowIDsVec));
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(MSERR_UNKNOWN, option, ""));
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

void AVScreenCaptureRecorderImpl::SkipPrivacyModeSync(::taihe::array_view<int32_t> windowIDs)
{
    MediaTrace trace("AVScreenCapture::TaiheSkipPrivacyMode");
    const std::string &option = AVScreenCapturegOpt::SKIP_PRIVACY_MODE;
    MEDIA_LOGI("%{public}s Start", option.c_str());
    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    std::vector<uint64_t> windowIDsVec;
    for (size_t i = 0; i < windowIDs.size(); i++) {
        int32_t tempValue = windowIDs[i];
        if (tempValue >= 0) {
            windowIDsVec.push_back(static_cast<uint64_t>(tempValue));
        } else {
            MEDIA_LOGI("JsSkipPrivacyMode skip %{public}d", tempValue);
        }
    }
    asyncCtx->task_ = AVScreenCaptureRecorderImpl::GetSkipPrivacyModeTask(asyncCtx, windowIDsVec);
    (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);

    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("%{public}s End", option.c_str());
}

std::shared_ptr<TaskHandler<RetInfo>> AVScreenCaptureRecorderImpl::GetSetMicrophoneEnableTask(
    const std::unique_ptr<AVScreenCaptureAsyncContext> &asyncCtx, const bool enable)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, enable]() {
        const std::string &option = AVScreenCapturegOpt::SET_MIC_ENABLE;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->screenCapture_ != nullptr,
            GetReturnInfo(MSERR_INVALID_OPERATION, option, ""));

        int32_t ret = taihe->screenCapture_->SetMicrophoneEnabled(enable);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(MSERR_UNKNOWN, option, ""));

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

void AVScreenCaptureRecorderImpl::SetMicEnabledSync(bool enable)
{
    MediaTrace trace("AVScreenCapture::TaiheSetMicrophoneEnabled");
    const std::string &option = AVScreenCapturegOpt::SET_MIC_ENABLE;
    MEDIA_LOGI("Taihe %{public}s Start", option.c_str());

    auto asyncCtx = std::make_unique<AVScreenCaptureAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    asyncCtx->task_ = AVScreenCaptureRecorderImpl::GetSetMicrophoneEnableTask(asyncCtx, enable);
    (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);

    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", option.c_str());
}

RetInfo AVScreenCaptureRecorderImpl::Release()
{
    int32_t ret = screenCapture_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(ret, "Release", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

void AVScreenCaptureRecorderImpl::ReleaseSync()
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::Release");
    return ExecuteByPromise(AVScreenCapturegOpt::RELEASE);
}

void AVScreenCaptureRecorderImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::OnError");
    MEDIA_LOGI("OnError Start");

    std::string callbackName = AVScreenCaptureEvent::EVENT_ERROR;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnError End");
}

void AVScreenCaptureRecorderImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::OffError");
    MEDIA_LOGI("OffError Start");

    std::string callbackName = AVScreenCaptureEvent::EVENT_ERROR;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffError End");
}
void AVScreenCaptureRecorderImpl::OnStateChange(
    callback_view<void(ohos::multimedia::media::AVScreenCaptureStateCode)> callback)
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::OnStateChange");
    MEDIA_LOGI("OnStateChange Start");

    std::string callbackName = AVScreenCaptureEvent::EVENT_STATE_CHANGE;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>> taiheCallback =
            std::make_shared<taihe::callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnError End");
}

void AVScreenCaptureRecorderImpl::OffStateChange(
    optional_view<callback<void(ohos::multimedia::media::AVScreenCaptureStateCode)>> callback)
{
    MediaTrace trace("AVScreenCaptureRecorderImpl::OffStateChange");
    MEDIA_LOGI("OffStateChange Start");

    std::string callbackName = AVScreenCaptureEvent::EVENT_STATE_CHANGE;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffStateChange End");
}

void AVScreenCaptureRecorderImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "screenCaptureCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVScreenCaptureCallback>(screenCaptureCb_);
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void AVScreenCaptureRecorderImpl::CancelCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "screenCaptureCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVScreenCaptureCallback>(screenCaptureCb_);
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}

void AVScreenCaptureAsyncContext::AVScreenCaptureSignError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add)
{
    RetInfo retInfo = GetReturnInfo(errCode, operate, param, add);
    set_business_error(retInfo.first, retInfo.second);
}

} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVScreenCaptureRecorderSync(CreateAVScreenCaptureRecorderSync);
TH_EXPORT_CPP_API_ReportAVScreenCaptureUserChoiceSync(ReportAVScreenCaptureUserChoiceSync);
TH_EXPORT_CPP_API_GetAVScreenCaptureConfigurableParametersSync(GetAVScreenCaptureConfigurableParametersSync);