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

#include <map>
#include <string>
#include "media_errors.h"
#include "media_log.h"
#include "media_dfx.h"
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
AVScreenCaptureRecorderImpl::AVScreenCaptureRecorderImpl()
{
    screenCapture_ = ScreenCaptureFactory::CreateScreenCapture();
    if (screenCapture_ == nullptr) {
        MEDIA_LOGE("failed to CreateScreenCapture");
        return;
    }
    screenCaptureCb_ = std::make_shared<AVScreenCaptureCallback>();
    if (screenCaptureCb_ == nullptr) {
        MEDIA_LOGE("failed to CreateScreenCaptureCb");
        return;
    }
    (void)screenCapture_->SetScreenCaptureCallback(screenCaptureCb_);
}

AVScreenCaptureRecorder CreateAVScreenCaptureRecorderSync()
{
    MediaTrace trace("AVScreenCapture::CreateAVScreenRecorder");
    return make_holder<AVScreenCaptureRecorderImpl, AVScreenCaptureRecorder>();
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

int32_t AVScreenCaptureRecorderImpl::GetConfig(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    config_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    config_.dataType = DataType::CAPTURE_FILE;

    int32_t ret =  GetAudioInfo(config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetAudioInfo");
    ret =  GetVideoInfo(config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetVideoInfo");
    ret =  GetRecorderInfo(config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetRecorderInfo");
    return MSERR_OK;
}

int32_t AVScreenCaptureRecorderImpl::GetAudioInfo(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    int32_t audioSampleRate = AVSCREENCAPTURE_DEFAULT_AUDIO_SAMPLE_RATE;
    int32_t audioChannels = AVSCREENCAPTURE_DEFAULT_AUDIO_CHANNELS;
    int32_t audioBitrate = AVSCREENCAPTURE_DEFAULT_AUDIO_BIT_RATE;

    AudioCaptureInfo &micConfig = config_.audioInfo.micCapInfo;
    AudioCaptureInfo &innerConfig = config_.audioInfo.innerCapInfo;
    AudioEncInfo &encoderConfig = config_.audioInfo.audioEncInfo;

    if (config.audioSampleRate.has_value()) {
        audioSampleRate = config.audioSampleRate.value();
    }
    int32_t ret = CheckAudioSampleRate(audioSampleRate);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (AVScreenCaptureSignError(ret, "getAudioChannelCount", "audioChannelCount"), ret));
    micConfig.audioSampleRate = audioSampleRate;
    innerConfig.audioSampleRate = audioSampleRate;
    MEDIA_LOGI("input audioSampleRate %{public}d", micConfig.audioSampleRate);

    if (config.audioChannelCount.has_value()) {
        audioChannels = config.audioChannelCount.value();
    }
    ret = CheckAudioChannelCount(audioChannels);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (AVScreenCaptureSignError(ret, "getAudioChannelCount", "audioChannelCount"), ret));
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

int32_t AVScreenCaptureRecorderImpl::GetVideoInfo(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    int32_t videoBitrate = AVSCREENCAPTURE_DEFAULT_VIDEO_BIT_RATE;
    int32_t preset = AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H264_AAC_MP4;
    int32_t frameWidth = AVSCREENCAPTURE_DEFAULT_FRAME_WIDTH;
    int32_t frameHeight = AVSCREENCAPTURE_DEFAULT_FRAME_HEIGHT;
    int32_t displayId = AVSCREENCAPTURE_DEFAULT_DISPLAY_ID;
    int32_t fillMode = OHOS::Media::AVScreenCaptureFillMode::PRESERVE_ASPECT_RATIO;
    VideoEncInfo &encoderConfig = config_.videoInfo.videoEncInfo;
    VideoCaptureInfo &videoConfig = config_.videoInfo.videoCapInfo;
    if (config.displayId.has_value()) {
        displayId = config.displayId.value();
    }
    CHECK_AND_RETURN_RET(displayId >= 0,
        (AVScreenCaptureSignError(MSERR_INVALID_VAL, "getDisplayId", "displayId"), MSERR_INVALID_VAL));
    videoConfig.displayId = static_cast<uint64_t>(displayId);
    if (videoConfig.displayId > 0) {
        config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;
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
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (AVScreenCaptureSignError(ret, "getPreset", "preset"), ret));
    encoderConfig.videoCodec = GetVideoCodecFormat(preset);
    MEDIA_LOGI("input videoCodec %{public}d", encoderConfig.videoCodec);
    if (config.frameWidth.has_value()) {
        frameWidth = config.frameWidth.value();
    }
    if (config.frameHeight.has_value()) {
        frameWidth = config.frameHeight.value();
    }
    MEDIA_LOGI("input frameWidth %{public}d, frameHeight %{public}d", frameWidth, frameHeight);
    ret = CheckVideoFrameFormat(frameWidth, frameHeight, videoConfig.videoFrameWidth, videoConfig.videoFrameHeight);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (AVScreenCaptureSignError(ret, "getVideoFrame", "VideoFrame"), ret));
    videoConfig.videoSource = OHOS::Media::VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA;
    if (config.fillMode.has_value()) {
        fillMode = config.fillMode.value();
    }
    videoConfig.screenCaptureFillMode = GetScreenCaptureFillMode(fillMode);
    MEDIA_LOGI("input screenCaptureFillMode %{public}d", videoConfig.screenCaptureFillMode);
    return MSERR_OK;
}

int32_t AVScreenCaptureRecorderImpl::GetRecorderInfo(
    ::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    RecorderInfo &recorderConfig = config_.recorderInfo;
    recorderConfig.fileFormat = AVSCREENCAPTURE_DEFAULT_FILE_FORMAT;
    int32_t fd = -1;
    fd = config.fd;
    CHECK_AND_RETURN_RET(fd > 0, // 0 to 2 for system std log
        (AVScreenCaptureSignError(MSERR_INVALID_VAL, "GetRecorderInfo", "url"), MSERR_INVALID_VAL));
    recorderConfig.url = "fd://" + std::to_string(fd);
    CHECK_AND_RETURN_RET(recorderConfig.url != "",
        (AVScreenCaptureSignError(MSERR_INVALID_VAL, "GetRecorderInfo", "url"), MSERR_INVALID_VAL));
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

void AVScreenCaptureRecorderImpl::InitSync(::ohos::multimedia::media::AVScreenCaptureRecordConfig const& config)
{
    MediaTrace trace("AVScreenCapture::TaiheInit");
    const std::string &option = AVScreenCapturegOpt::INIT;
    MEDIA_LOGI("%{public}s Start", option.c_str());
    RetInfo retInfo(MSERR_EXT_API9_OK, "");
    if (GetConfig(config) == MSERR_OK) {
        MEDIA_LOGI("%{public}s Start", option.c_str());
        if (screenCapture_ == nullptr) {
            retInfo = GetReturnInfo(MSERR_INVALID_OPERATION, option, "");
            set_business_error(retInfo.first, retInfo.second);
            return;
        }
        int32_t ret = screenCapture_->Init(config_);
        if (ret != MSERR_OK) {
            screenCapture_->Release();
            retInfo = GetReturnInfo(ret, "Init", "");
        }
        MEDIA_LOGI("%{public}s End", option.c_str());
    }
    if (retInfo.first != MSERR_EXT_API9_OK) {
        set_business_error(retInfo.first, retInfo.second);
    }
}

void AVScreenCaptureRecorderImpl::StartRecordingSync()
{
    MediaTrace trace("AVScreenCapture::TaiheStartRecording");
    RetInfo ret(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
    ret = StartRecording();
    if (ret.first != MSERR_EXT_API9_OK) {
        set_business_error(ret.first, ret.second);
    }
}

void AVScreenCaptureRecorderImpl::StopRecordingSync()
{
    MediaTrace trace("AVScreenCapture::TaiheStartRecording");
    RetInfo ret(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
    ret = StopRecording();
    if (ret.first != MSERR_EXT_API9_OK) {
        set_business_error(ret.first, ret.second);
    }
}

void AVScreenCaptureRecorderImpl::SkipPrivacyModeSync(::taihe::array_view<double> windowIDs)
{
    MediaTrace trace("AVScreenCapture::TaiheSkipPrivacyMode");
    const std::string &option = AVScreenCapturegOpt::SKIP_PRIVACY_MODE;
    MEDIA_LOGI("%{public}s Start", option.c_str());
    std::vector<uint64_t> windowIDsVec;
    for (int i = 0; i < windowIDs.size(); i++) {
        windowIDsVec.push_back(static_cast<uint64_t>(windowIDs[i]));
    }
    if (screenCapture_ == nullptr) {
        MEDIA_LOGE("CreateScreenCapture_ is nullptr");
        return;
    }
    int32_t ret = screenCapture_->SkipPrivacyMode(const_cast<std::vector<uint64_t> &>(windowIDsVec));
    RetInfo retInfo(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
    if (ret != MSERR_OK) {
        retInfo = GetReturnInfo(MSERR_UNKNOWN, option, "");
        set_business_error(retInfo.first, retInfo.second);
    }
    MEDIA_LOGI("%{public}s End", option.c_str());
}

void AVScreenCaptureRecorderImpl::SetMicEnabledSync(bool enable)
{
    MediaTrace trace("AVScreenCapture::TaiheSetMicrophoneEnabled");
    const std::string &option = AVScreenCapturegOpt::SET_MIC_ENABLE;
    MEDIA_LOGI("%{public}s Start", option.c_str());
    if (screenCapture_ == nullptr) {
        MEDIA_LOGE("CreateScreenCapture_ is nullptr");
        return;
    }
    int32_t ret = screenCapture_->SetMicrophoneEnabled(enable);
    RetInfo retInfo(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
    if (ret != MSERR_OK) {
        retInfo = GetReturnInfo(MSERR_UNKNOWN, option, "");
        set_business_error(retInfo.first, retInfo.second);
    }
    MEDIA_LOGI("%{public}s End", option.c_str());
}

RetInfo AVScreenCaptureRecorderImpl::Release()
{
    int32_t ret = screenCapture_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnInfo(ret, "Release", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

void AVScreenCaptureRecorderImpl::ReleaseSync()
{
    MediaTrace trace("AVScreenCapture::Release");
    RetInfo ret(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
    ret = Release();
    if (ret.first != MSERR_EXT_API9_OK) {
        set_business_error(ret.first, ret.second);
    }
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
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "screenCaptureCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVScreenCaptureCallback>(screenCaptureCb_);
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void AVScreenCaptureRecorderImpl::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "screenCaptureCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVScreenCaptureCallback>(screenCaptureCb_);
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}

void AVScreenCaptureRecorderImpl::AVScreenCaptureSignError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add)
{
    RetInfo retInfo = GetReturnInfo(errCode, operate, param, add);
    set_business_error(retInfo.first, retInfo.second);
}

} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVScreenCaptureRecorderSync(CreateAVScreenCaptureRecorderSync);