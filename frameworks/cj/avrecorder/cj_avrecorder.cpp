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

#include <climits>
#include "cj_avrecorder.h"
#include "cj_avrecorder_callback.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_core.h"
#include "scope_guard.h"
#include "surface_utils.h"
#include "string_ex.h"
#include "avcodec_info.h"
#include "av_common.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderFfi"};
}

namespace OHOS {
namespace Media {
// customInfo max count
constexpr uint32_t CUSTOM_MAX_COUNT = 500;
// use on AVRecorderConfig.metadata.customInfo
constexpr uint32_t CUSTOM_INFO_MAX_LENGTH = 1001;

constexpr int32_t AVRECORDER_GETINPUTSURFACE = 1;
constexpr int32_t AVRECORDER_START = 2;
constexpr int32_t AVRECORDER_PAUSE = 3;
constexpr int32_t AVRECORDER_RESUME = 4;
constexpr int32_t AVRECORDER_STOP = 5;
constexpr int32_t AVRECORDER_RESET = 6;
constexpr int32_t AVRECORDER_RELEASE = 7;

int64_t CjAVRecorder::CreateAVRecorder(int32_t *errCode)
{
    auto cjAVRecorder = FFIData::Create<CjAVRecorder>();
    if (!cjAVRecorder) {
        *errCode = MSERR_NO_MEMORY;
        MEDIA_LOGE("createAVRecorder fail. No memory!");
        return 0;
    }
    cjAVRecorder->recorder_ = RecorderFactory::CreateRecorder();
    if (!cjAVRecorder->recorder_) {
        MEDIA_LOGE("recorder_ is null");
        *errCode = MSERR_NO_MEMORY;
        return 0;
    }

    cjAVRecorder->recorderCb_ = std::make_shared<CJAVRecorderCallback>();
    if (!cjAVRecorder->recorderCb_) {
        MEDIA_LOGE("recorderCb_ is null");
        *errCode = MSERR_NO_MEMORY;
        return 0;
    }
    cjAVRecorder->recorder_->SetRecorderCallback(cjAVRecorder->recorderCb_);
    return cjAVRecorder->GetID();
}

RetInfo CjAVRecorder::DealTask(std::string opt)
{
    std::map<std::string, int32_t> taskOptMap = {
        {CjAVRecordergOpt::GETINPUTSURFACE, AVRECORDER_GETINPUTSURFACE},
        {CjAVRecordergOpt::START, AVRECORDER_START},
        {CjAVRecordergOpt::PAUSE, AVRECORDER_PAUSE},
        {CjAVRecordergOpt::RESUME, AVRECORDER_RESUME},
        {CjAVRecordergOpt::STOP, AVRECORDER_STOP},
        {CjAVRecordergOpt::RESET, AVRECORDER_RESET},
        {CjAVRecordergOpt::RELEASE, AVRECORDER_RELEASE},
    };
    int32_t optValue = taskOptMap[opt];
    switch (optValue) {
        case AVRECORDER_GETINPUTSURFACE:
            return DoGetInputSurface();
        case AVRECORDER_START:
            return DoStart();
        case AVRECORDER_PAUSE:
            return DoPause();
        case AVRECORDER_RESUME:
            return DoResume();
        case AVRECORDER_STOP:
            return DoStop();
        case AVRECORDER_RESET:
            return DoReset();
        case AVRECORDER_RELEASE:
            return DoRelease();
        default:
            return GetRetInfo(MSERR_INVALID_OPERATION, "invalid options", "");
    }
}

int32_t CjAVRecorder::Prepare(CAVRecorderConfig config)
{
    MEDIA_LOGD("CjAVRecorder::prepare");
    const std::string &opt = CjAVRecordergOpt::PREPARE;
    RetInfo retInfo = RetInfo(MSERR_OK, "");
    if (!recorder_) {
        MEDIA_LOGE("Not initialized before prepare");
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "Prepare", "", "recorder_ is nullptr");
        return retInfo.first;
    }
    if (CheckStateMachine(opt)) {
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "Prepare", "");
        return retInfo.first;
    }
    int32_t ret = GetConfig(config);
    if (ret != MSERR_OK) {
        retInfo = GetRetInfo(ret, "Prepare", "");
        return retInfo.first;
    }

    retInfo = SetAVConfigParams();
    CHECK_AND_RETURN_RET(retInfo.first == MSERR_OK, (recorder_->Reset(), retInfo.first));

    ret = recorder_->Prepare();
    if (ret != MSERR_OK) {
        recorder_->Reset();
        retInfo = GetRetInfo(ret, "Prepare", "");
        return retInfo.first;
    }
    RemoveSurface();
    StateCallback(CjAVRecorderState::STATE_PREPARED);
    getVideoInputSurface_ = false;
    withVideo_ = config_->withVideo;
    return MSERR_OK;
}

int32_t CjAVRecorder::CheckStateMachine(const std::string &opt)
{
    auto napiCb = std::static_pointer_cast<CJAVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(napiCb != nullptr, MSERR_INVALID_OPERATION, "napiCb is nullptr!");
    std::string curState = napiCb->GetState();
    std::vector<std::string> allowedOpt = STATE_CTRL_LIST.at(curState);
    if (find(allowedOpt.begin(), allowedOpt.end(), opt) == allowedOpt.end()) {
        MEDIA_LOGE("The %{public}s operation is not allowed in the %{public}s state!", opt.c_str(), curState.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

int32_t CjAVRecorder::GetConfig(CAVRecorderConfig config)
{
    int32_t ret = GetSourceType(config);
    if (ret != MSERR_OK) {
        return ret;
    }
    ret = GetProfile(config.profile);
    if (ret != MSERR_OK) {
        return ret;
    }
    ret = GetModeAndUrl(config);
    if (ret != MSERR_OK) {
        return ret;
    }
    config_->maxDuration = config.maxDuration == -1 ? INT32_MAX : config.maxDuration;
    ret = GetAVMetaData(config.metadata);
    if (ret != MSERR_OK) {
        return ret;
    }
    return MSERR_OK;
}

int32_t CjAVRecorder::GetSourceType(CAVRecorderConfig config)
{
    if (config.audioSourceType == INVALID_AV_VALUE && config.videoSourceType == INVALID_AV_VALUE) {
        MEDIA_LOGE("No audioSourceType or videoSourceType param, should have one of them at least");
        return MSERR_INVALID_VAL;
    }
    config_ = std::make_shared<CjAVRecorderConfig>();
    if (config.audioSourceType != INVALID_AV_VALUE) {
        config_->audioSourceType = static_cast<AudioSourceType>(config.audioSourceType);
        config_->withAudio = true;
    }
    if (config.videoSourceType != INVALID_AV_VALUE) {
        config_->videoSourceType = static_cast<VideoSourceType>(config.videoSourceType);
        config_->withVideo = true;
    }
    return MSERR_OK;
}

int32_t CjAVRecorder::GetAVMetaData(CAVMetadata metaData)
{
    if (!metaData.isValid) {
        MEDIA_LOGI("No metaData, ok");
        return MSERR_OK;
    }
    config_->metadata.genre = metaData.genre;
    if (metaData.location.isValid) {
        config_->withLocation = true;
        config_->metadata.location.latitude = static_cast<float>(metaData.location.latitude);
        config_->metadata.location.longitude = static_cast<float>(metaData.location.longitude);
    }
    std::string strRotation = metaData.videoOrientation;
    if (strRotation == "0" || strRotation == "90" || strRotation == "180" || strRotation == "270") {
        config_->rotation = std::stoi(strRotation);
        MEDIA_LOGI("rotation: %{public}d", config_->rotation);
    } else if (strRotation != "") {
        MEDIA_LOGE("not support the videoOrientation: %{public}s!", metaData.videoOrientation);
        return MSERR_INVALID_VAL;
    }
    int64_t infoCount = metaData.customInfo.size;
    if (infoCount != 0) {
        if (infoCount > CUSTOM_MAX_COUNT) {
            MEDIA_LOGE("the count of customInfo cannot be more than %{public}d", CUSTOM_MAX_COUNT);
            return MSERR_INVALID_VAL;
        }
        for (int64_t i = 0; i < infoCount; i++) {
            std::string strKey = metaData.customInfo.headers[i].key;
            std::string strValue = metaData.customInfo.headers[i].value;
            if (strKey.length() >= CUSTOM_INFO_MAX_LENGTH || strValue.length() >= CUSTOM_INFO_MAX_LENGTH) {
                MEDIA_LOGE("customInfo str too long, cannot be longer than %{public}d", CUSTOM_INFO_MAX_LENGTH);
                return MSERR_INVALID_VAL;
            }
            config_->metadata.customInfo.SetData(strKey, strValue);
        }
    }
    return MSERR_OK;
}

int32_t CjAVRecorder::GetModeAndUrl(CAVRecorderConfig config)
{
    int32_t mode = config.fileGenerationMode;
    if (mode != INVALID_AV_VALUE) {
        if (mode >= FileGenerationMode::APP_CREATE && mode <= FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
            config_->fileGenerationMode = static_cast<FileGenerationMode>(mode);
            MEDIA_LOGI("FileGenerationMode %{public}d!", mode);
        } else {
            MEDIA_LOGE("invalide fileGenerationMode");
            return MSERR_INVALID_VAL;
        }
    }

    config_->url = config.url;
    MEDIA_LOGI("url %{public}s!", config_->url.c_str());
    if (config_->fileGenerationMode == FileGenerationMode::APP_CREATE && config_->url == "") {
        MEDIA_LOGE("url cannot be null while fileGenerationMode=0");
        return MSERR_PARAMETER_VERIFICATION_FAILED;
    }
    return MSERR_OK;
}

int32_t CjAVRecorder::GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, AudioCodecFormat> mimeStrToCodecFormat = {
        { CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
        { CodecMimeType::AUDIO_MPEG, AudioCodecFormat::AUDIO_MPEG },
        { CodecMimeType::AUDIO_G711MU, AudioCodecFormat::AUDIO_G711MU },
        { "", AudioCodecFormat::AUDIO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CjAVRecorder::GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, VideoCodecFormat> mimeStrToCodecFormat = {
        { CodecMimeType::VIDEO_AVC, VideoCodecFormat::H264 },
        { CodecMimeType::VIDEO_MPEG4, VideoCodecFormat::MPEG4 },
        { CodecMimeType::VIDEO_HEVC, VideoCodecFormat::H265 },
        { "", VideoCodecFormat::VIDEO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CjAVRecorder::GetOutputFormat(const std::string &extension, OutputFormatType &type)
{
    MEDIA_LOGI("mime %{public}s", extension.c_str());
    const std::map<std::string, OutputFormatType> extensionToOutputFormat = {
        { "mp4", OutputFormatType::FORMAT_MPEG_4 },
        { "m4a", OutputFormatType::FORMAT_M4A },
        { "mp3", OutputFormatType::FORMAT_MP3 },
        { "wav", OutputFormatType::FORMAT_WAV },
        { "", OutputFormatType::FORMAT_DEFAULT },
    };

    auto iter = extensionToOutputFormat.find(extension);
    if (iter != extensionToOutputFormat.end()) {
        type = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

void CjAVRecorder::MediaProfileLog(bool isVideo, CjAVRecorderProfile &profile)
{
    if (isVideo) {
        MEDIA_LOGD("videoBitrate %{public}d, videoCodecFormat %{public}d, videoFrameWidth %{public}d,"
            " videoFrameHeight %{public}d, videoFrameRate %{public}d, isHdr %{public}d, enableTemporalScale %{public}d",
            profile.videoBitrate, profile.videoCodecFormat, profile.videoFrameWidth,
            profile.videoFrameHeight, profile.videoFrameRate, profile.isHdr, profile.enableTemporalScale);
        return;
    }
    MEDIA_LOGD("audioBitrate %{public}d, audioChannels %{public}d, audioCodecFormat %{public}d,"
        " audioSampleRate %{public}d!", profile.audioBitrate, profile.audioChannels,
        profile.audioCodecFormat, profile.audioSampleRate);
}

int32_t CjAVRecorder::GetProfile(CAVRecorderProfile profile)
{
    int32_t ret = MSERR_OK;
    if (config_->withAudio) {
        std::string audioCodec = profile.audioCodec;
        ret = GetAudioCodecFormat(audioCodec, config_->profile.audioCodecFormat);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("GetAudioCodecFormat error, audioCodec %{public}s", profile.audioCodec);
            return ret;
        }
        config_->profile.audioBitrate = profile.audioBitrate;
        config_->profile.audioChannels = profile.audioChannels;
        config_->profile.audioSampleRate = profile.audioSampleRate;
        MediaProfileLog(false, config_->profile);
    }
    if (config_->withVideo) {
        std::string videoCodec = profile.videoCodec;
        ret = GetVideoCodecFormat(videoCodec, config_->profile.videoCodecFormat);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("GetVideoCodecFormat error, videoCodec %{public}s", profile.videoCodec);
            return ret;
        }
        config_->profile.videoBitrate = profile.videoBitrate;
        config_->profile.videoFrameWidth = profile.videoFrameWidth;
        config_->profile.videoFrameHeight = profile.videoFrameHeight;
        config_->profile.videoFrameRate = profile.videoFrameRate;
        config_->profile.isHdr = profile.isHdr;
        if (config_->profile.isHdr && config_->profile.videoCodecFormat != VideoCodecFormat::H265) {
            MEDIA_LOGE("isHdr needs to match video/hevc");
            return MSERR_UNSUPPORT_VID_PARAMS;
        }
        config_->profile.enableTemporalScale = profile.enableTemporalScale;
        MediaProfileLog(true, config_->profile);
    }
    std::string outputFile = profile.fileFormat;
    ret = GetOutputFormat(outputFile, config_->profile.fileFormat);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("GetOutputFormat error, fileFormat %{public}s", profile.fileFormat);
    }
    return ret;
}

RetInfo CjAVRecorder::GetRetInfo(int32_t errCode, const std::string &opt, const std::string &param,
    const std::string &add)
{
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    if (errCode == MSERR_UNSUPPORT_VID_PARAMS || errCode == MSERR_UNSUPPORT_AUD_PARAMS) {
        MEDIA_LOGE("The parameter is not supported. Please check the type and range.");
        return RetInfo(err, "The parameter is not supported. Please check the type and range.");
    }
    std::string msg = MSExtErrorAPI9ToString(err, err == MSERR_EXT_API9_INVALID_PARAMETER ? param : opt, "") + add;
    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, msg.c_str());
    return RetInfo(err, msg);
}

RetInfo CjAVRecorder::SetProfile(std::shared_ptr<CjAVRecorderConfig> config)
{
    CjAVRecorderProfile &profile = config->profile;
    int32_t ret = recorder_->SetOutputFormat(profile.fileFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetOutputFormat", "fileFormat"));

    if (config->withAudio) {
        ret = recorder_->SetAudioEncoder(audioSourceID_, profile.audioCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioEncoder", "audioCodecFormat"));

        ret = recorder_->SetAudioSampleRate(audioSourceID_, profile.audioSampleRate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioSampleRate", "audioSampleRate"));

        ret = recorder_->SetAudioChannels(audioSourceID_, profile.audioChannels);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioChannels", "audioChannels"));

        ret = recorder_->SetAudioEncodingBitRate(audioSourceID_, profile.audioBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioEncodingBitRate", "audioBitrate"));
    }

    if (config->withVideo) {
        ret = recorder_->SetVideoEncoder(videoSourceID_, profile.videoCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEncoder", "videoCodecFormat"));

        ret = recorder_->SetVideoSize(videoSourceID_, profile.videoFrameWidth, profile.videoFrameHeight);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoSize", "VideoSize"));

        ret = recorder_->SetVideoFrameRate(videoSourceID_, profile.videoFrameRate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoFrameRate", "videoFrameRate"));

        ret = recorder_->SetVideoEncodingBitRate(videoSourceID_, profile.videoBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEncodingBitRate", "videoBitrate"));

        ret = recorder_->SetVideoIsHdr(videoSourceID_, profile.isHdr);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoIsHdr", "isHdr"));

        ret = recorder_->SetVideoEnableTemporalScale(videoSourceID_, profile.enableTemporalScale);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEnableTemporalScale", "enableTemporalScale"));
    }

    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::SetConfigUrl(std::shared_ptr<CjAVRecorderConfig> config)
{
    int32_t ret;
    if (config->fileGenerationMode == FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
        ret = recorder_->SetFileGenerationMode(config->fileGenerationMode);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetFileGenerationMode", "fileGenerationMode"));
    } else {
        ret = MSERR_PARAMETER_VERIFICATION_FAILED;
        const std::string fdHead = "fd://";
        CHECK_AND_RETURN_RET(config->url.find(fdHead) != std::string::npos, GetRetInfo(ret, "Getfd", "uri"));
        int32_t fd = -1;
        std::string inputFd = config->url.substr(fdHead.size());
        CHECK_AND_RETURN_RET(StrToInt(inputFd, fd) == true && fd >= 0, GetRetInfo(ret, "Getfd", "uri"));

        ret = recorder_->SetOutputFile(fd);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetOutputFile", "uri"));
    }
    hasConfiged_ = true;
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::SetAVConfigParams()
{
    if (!recorder_) {
        MEDIA_LOGE("recorder_ nullptr");
        return GetRetInfo(MSERR_INVALID_OPERATION, "Configure", "");
    }
    if (!config_) {
        MEDIA_LOGE("config_ nullptr");
        return GetRetInfo(MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "Configure", "config");
    }

    if (hasConfiged_) {
        MEDIA_LOGE("CjAVRecorderConfig has been configured and will not be configured again");
        return RetInfo(MSERR_OK, "");
    }

    int32_t ret;
    if (config_->withAudio) {
        ret = recorder_->SetAudioSource(config_->audioSourceType, audioSourceID_);
        if (ret != MSERR_OK) {
            return GetRetInfo(ret, "SetVideoSource", "audioSourceType");
        }
    }

    if (config_->withVideo) {
        ret = recorder_->SetVideoSource(config_->videoSourceType, videoSourceID_);
        if (ret != MSERR_OK) {
            return GetRetInfo(ret, "SetVideoSource", "videoSourceType");
        }
    }

    RetInfo retInfo = SetProfile(config_);
    CHECK_AND_RETURN_RET_LOG(retInfo.first == MSERR_OK, retInfo, "Fail to set videoBitrate");

    if (config_->maxDuration < 1) {
        config_->maxDuration = INT32_MAX;
    }
    recorder_->SetMaxDuration(config_->maxDuration);
    MEDIA_LOGI("CjAVRecorder::Configure SetMaxDuration = %{public}d", config_->maxDuration);

    if (config_->withLocation) {
        recorder_->SetLocation(config_->metadata.location.latitude, config_->metadata.location.longitude);
    }

    if (config_->withVideo) {
        recorder_->SetOrientationHint(config_->rotation);
    }

    if (!config_->metadata.genre.empty()) {
        ret = recorder_->SetGenre(config_->metadata.genre);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetGenre", "Genre"));
    }
    if (!config_->metadata.customInfo.Empty()) {
        ret = recorder_->SetUserCustomInfo(config_->metadata.customInfo);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetUserCustomInfo", "customInfo"));
    }
    return SetConfigUrl(config_);
}

void CjAVRecorder::RemoveSurface()
{
    if (surface_ != nullptr) {
        auto id = surface_->GetUniqueId();
        auto surface = SurfaceUtils::GetInstance()->GetSurface(id);
        if (surface) {
            (void)SurfaceUtils::GetInstance()->Remove(id);
        }
        surface_ = nullptr;
    }
}

char *CjAVRecorder::GetInputSurface(int32_t *errCode)
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::GETINPUTSURFACE);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("getInputSurface failed, errCode %{public}d, errMsg %{public}s",
            result.first, result.second.c_str());
        *errCode = result.first;
        return nullptr;
    }
    return MallocCString(std::to_string(surfaceId_));
}

int32_t CjAVRecorder::Start()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::START);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("start failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

int32_t CjAVRecorder::Pause()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::PAUSE);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("pause failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

int32_t CjAVRecorder::Resume()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::RESUME);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("resume failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

int32_t CjAVRecorder::Stop()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::STOP);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("stop failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

int32_t CjAVRecorder::Reset()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::RESET);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("reset failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

int32_t CjAVRecorder::Release()
{
    RetInfo result = ExecuteOptTask(CjAVRecordergOpt::RELEASE);
    if (result.first != MSERR_OK) {
        MEDIA_LOGE("release failed, errCode %{public}d, errMsg %{public}s", result.first, result.second.c_str());
    }
    return result.first;
}

CAVRecorderConfig CjAVRecorder::GetAVRecorderConfig(int32_t *errCode)
{
    const std::string &opt = CjAVRecordergOpt::GET_AV_RECORDER_CONFIG;
    CAVRecorderConfig retConfig = {};
    RetInfo retInfo = RetInfo(MSERR_OK, "");
    if (!config_ || !recorder_) {
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetAVRecorderConfig", "");
        *errCode = retInfo.first;
        return retConfig;
    }

    if (CheckStateMachine(opt) == MSERR_OK && DoGetAVRecorderConfig(config_) == MSERR_OK) {
        int32_t ret = ToCAVRecorderConfig(retConfig);
        retInfo = GetRetInfo(ret, "GetAVRecorderConfig", "");
        *errCode = retInfo.first;
    } else {
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetAVRecorderConfig", "", "CheckStateMachine failed");
        *errCode = retInfo.first;
    }
    return retConfig;
}

int32_t CjAVRecorder::GetCurrentAudioCapturerInfo(AudioRecorderChangeInfo &changeInfo)
{
    const std::string &opt = CjAVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO;
    RetInfo retInfo = RetInfo(MSERR_OK, "");
    if (!recorder_) {
        MEDIA_LOGE("recorder_ is nullptr!");
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetCurrentAudioCapturerInfo", "", "recorder_ is nullptr");
        return retInfo.first;
    }

    if (CheckStateMachine(opt) != MSERR_OK) {
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetCurrentAudioCapturerInfo", "", "CheckStateMachine failed");
        return retInfo.first;
    }

    if (CheckRepeatOperation(opt) != MSERR_OK) {
        return retInfo.first;
    }

    int32_t result = recorder_->GetCurrentCapturerChangeInfo(changeInfo);
    if (result != MSERR_OK) {
        retInfo = GetRetInfo(MSERR_INVALID_VAL, "GetCurrentAudioCapturerInfo", "");
        return retInfo.first;
    }

    return result;
}

int32_t CjAVRecorder::GetAvailableEncoder(std::vector<EncoderCapabilityData> &encoderInfo)
{
    const std::string &opt = CjAVRecordergOpt::GET_ENCODER_INFO;
    RetInfo retInfo = RetInfo(MSERR_OK, "");
    if (!recorder_) {
        MEDIA_LOGE("recorder_ is nullptr!");
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetAvailableEncoder", "", "recorder_ is nullptr");
        return retInfo.first;
    }

    if (CheckStateMachine(opt) != MSERR_OK) {
        retInfo = GetRetInfo(MSERR_INVALID_OPERATION, "GetAvailableEncoder", "", "CheckStateMachine failed");
        return retInfo.first;
    }

    if (CheckRepeatOperation(opt) != MSERR_OK) {
        return retInfo.first;
    }

    int32_t result = recorder_->GetAvailableEncoder(encoderInfo);
    if (result != MSERR_OK) {
        retInfo = GetRetInfo(MSERR_INVALID_VAL, "GetCurrentAudioCapturerInfo", "");
        return retInfo.first;
    }

    return result;
}

int32_t CjAVRecorder::GetAudioCapturerMaxAmplitude(int32_t *errCode)
{
    const std::string &opt = CjAVRecordergOpt::GET_MAX_AMPLITUDE;
    RetInfo ret = RetInfo(MSERR_OK, "");
    int32_t retMaxAmplitude = -1;
    if (!recorder_) {
        MEDIA_LOGE("recorder_ is nullptr!");
        ret = GetRetInfo(MSERR_INVALID_OPERATION, "GetAudioCapturerMaxAmplitude", "", "recorder_ is nullptr");
        *errCode = ret.first;
        return retMaxAmplitude;
    }
    if (CheckStateMachine(opt) == MSERR_OK) {
        retMaxAmplitude = recorder_->GetMaxAmplitude();
    } else {
        ret = GetRetInfo(MSERR_INVALID_OPERATION, "GetAudioCapturerMaxAmplitude", "", "CheckStateMachine failed");
        *errCode = ret.first;
    }
    return retMaxAmplitude;
}

void CjAVRecorder::UpdateRotation(int32_t rotation, int32_t *errCode)
{
    const std::string &opt = CjAVRecordergOpt::SET_ORIENTATION_HINT;
    RetInfo ret = RetInfo(MSERR_OK, "");
    *errCode = MSERR_OK;
    if (!recorder_ && !config_) {
        ret = GetRetInfo(MSERR_INVALID_OPERATION, "UpdateRotation", "", "nullptr");
        *errCode = ret.first;
        return;
    }

    if (CheckStateMachine(opt) == MSERR_OK) {
        recorder_->SetOrientationHint(config_->rotation);
    } else {
        ret = GetRetInfo(MSERR_INVALID_OPERATION, "UpdateRotation", "", "CheckStateMachine failed");
        *errCode = ret.first;
    }
    return;
}

int32_t CjAVRecorder::SetAudioCodecFormat(AudioCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("audioCodecFormat %{public}d", codecFormat);
    const std::map<AudioCodecFormat, std::string_view> codecFormatToMimeStr = {
        { AudioCodecFormat::AAC_LC, CodecMimeType::AUDIO_AAC },
        { AudioCodecFormat::AUDIO_MPEG, CodecMimeType::AUDIO_MPEG },
        { AudioCodecFormat::AUDIO_G711MU, CodecMimeType::AUDIO_G711MU },
        { AudioCodecFormat::AUDIO_DEFAULT, "" },
    };

    auto iter = codecFormatToMimeStr.find(codecFormat);
    if (iter != codecFormatToMimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CjAVRecorder::SetVideoCodecFormat(VideoCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("VideoCodecFormat %{public}d", codecFormat);
    const std::map<VideoCodecFormat, std::string_view> codecFormatToMimeStr = {
        { VideoCodecFormat::H264, CodecMimeType::VIDEO_AVC },
        { VideoCodecFormat::MPEG4, CodecMimeType::VIDEO_MPEG4 },
        { VideoCodecFormat::H265, CodecMimeType::VIDEO_HEVC },
        { VideoCodecFormat::VIDEO_DEFAULT, ""},
    };

    auto iter = codecFormatToMimeStr.find(codecFormat);
    if (iter != codecFormatToMimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CjAVRecorder::SetFileFormat(OutputFormatType &type, std::string &extension)
{
    MEDIA_LOGI("OutputFormatType %{public}d", type);
    const std::map<OutputFormatType, std::string> outputFormatToExtension = {
        { OutputFormatType::FORMAT_MPEG_4, "mp4" },
        { OutputFormatType::FORMAT_M4A, "m4a" },
        { OutputFormatType::FORMAT_MP3, "mp3" },
        { OutputFormatType::FORMAT_WAV, "wav" },
        { OutputFormatType::FORMAT_DEFAULT, "" },
    };

    auto iter = outputFormatToExtension.find(type);
    if (iter != outputFormatToExtension.end()) {
        extension = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CjAVRecorder::ToCAVRecorderConfig(CAVRecorderConfig &retConfig)
{
    int32_t ret;
    if (!config_) {
        MEDIA_LOGE("config_ nullptr");
        return MSERR_INVALID_OPERATION;
    }
    // get audio
    if (config_->withAudio) {
        retConfig.audioSourceType = config_->audioSourceType;
        retConfig.profile.audioBitrate = config_->profile.audioBitrate;
        retConfig.profile.audioChannels = config_->profile.audioChannels;
        retConfig.profile.audioSampleRate = config_->profile.audioSampleRate;
        std::string audioCodec;
        ret = SetAudioCodecFormat(config_->profile.audioCodecFormat, audioCodec);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("SetAudioCodecFormat failed");
            return ret;
        }
        retConfig.profile.audioCodec = MallocCString(audioCodec);
    }

    // get video
    if (config_->withVideo) {
        retConfig.videoSourceType = config_->videoSourceType;
        retConfig.profile.videoBitrate = config_->profile.videoBitrate;
        retConfig.profile.videoFrameWidth = config_->profile.videoFrameWidth;
        retConfig.profile.videoFrameHeight = config_->profile.videoFrameHeight;
        retConfig.profile.videoFrameRate = config_->profile.videoFrameRate;
        std::string videoCodec;
        ret = SetVideoCodecFormat(config_->profile.videoCodecFormat, videoCodec);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("SetVideoCodecFormat failed");
            return ret;
        }
        retConfig.profile.videoCodec = MallocCString(videoCodec);
    }

    // get location
    retConfig.metadata.location.latitude = config_->location.latitude;
    retConfig.metadata.location.longitude = config_->location.longitude;
    retConfig.metadata.isValid = true;
    // get profile
    if (config_->withAudio || config_->withVideo) {
        retConfig.url = MallocCString(config_->url);
        std::string fileFormat;
        ret = SetFileFormat(config_->profile.fileFormat, fileFormat);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("SetFileFormat failed");
            return ret;
        }
        retConfig.profile.fileFormat = MallocCString(fileFormat);
    }
    return MSERR_OK;
}

RetInfo CjAVRecorder::DoGetInputSurface()
{
    CHECK_AND_RETURN_RET_LOG(withVideo_, GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", "",
        "The VideoSourceType is not configured. Please do not call getInputSurface"), "No video recording");

    if (surface_ == nullptr) {
        surface_ = recorder_->GetSurface(videoSourceID_);
        CHECK_AND_RETURN_RET_LOG(surface_ != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to GetSurface");

        SurfaceError error = SurfaceUtils::GetInstance()->Add(surface_->GetUniqueId(), surface_);
        CHECK_AND_RETURN_RET_LOG(error == SURFACE_ERROR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to AddSurface");
    }
    surfaceId_ = surface_->GetUniqueId();
    getVideoInputSurface_ = true;
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoStart()
{
    if (withVideo_ && !getVideoInputSurface_) {
        return GetRetInfo(MSERR_INVALID_OPERATION, "Start", "",
            " Please get the video input surface through GetInputSurface first!");
    }

    int32_t ret = recorder_->Start();
    if (ret != MSERR_OK) {
        StateCallback(CjAVRecorderState::STATE_ERROR);
    }
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Start", ""));
    StateCallback(CjAVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoPause()
{
    int32_t ret = recorder_->Pause();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Pause", ""));
    StateCallback(CjAVRecorderState::STATE_PAUSED);
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoResume()
{
    int32_t ret = recorder_->Resume();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Resume", ""));
    StateCallback(CjAVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoStop()
{
    int32_t ret = recorder_->Stop(false);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Stop", ""));
    StateCallback(CjAVRecorderState::STATE_STOPPED);
    hasConfiged_ = false;
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoReset()
{
    RemoveSurface();
    int32_t ret = recorder_->Reset();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Reset", ""));
    StateCallback(CjAVRecorderState::STATE_IDLE);
    hasConfiged_ = false;
    return RetInfo(MSERR_OK, "");
}

RetInfo CjAVRecorder::DoRelease()
{
    RemoveSurface();
    int32_t ret = recorder_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Release", ""));
    StateCallback(CjAVRecorderState::STATE_RELEASED);
    hasConfiged_ = false;
    return RetInfo(MSERR_OK, "");
}

int32_t CjAVRecorder::CheckRepeatOperation(const std::string &opt)
{
    const std::map<std::string, std::vector<std::string>> stateCtrl = {
        {CjAVRecorderState::STATE_IDLE, {
            CjAVRecordergOpt::RESET,
            CjAVRecordergOpt::GET_AV_RECORDER_PROFILE,
            CjAVRecordergOpt::GET_AV_RECORDER_CONFIG,
        }},
        {CjAVRecorderState::STATE_PREPARED, {}},
        {CjAVRecorderState::STATE_STARTED, {
            CjAVRecordergOpt::START,
            CjAVRecordergOpt::RESUME
        }},
        {CjAVRecorderState::STATE_PAUSED, {
            CjAVRecordergOpt::PAUSE
        }},
        {CjAVRecorderState::STATE_STOPPED, {
            CjAVRecordergOpt::STOP
        }},
        {CjAVRecorderState::STATE_RELEASED, {
            CjAVRecordergOpt::RELEASE
        }},
        {CjAVRecorderState::STATE_ERROR, {}},
    };

    auto napiCb = std::static_pointer_cast<CJAVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(napiCb != nullptr, MSERR_INVALID_OPERATION, "napiCb is nullptr!");
    std::string curState = napiCb->GetState();
    std::vector<std::string> repeatOpt = stateCtrl.at(curState);
    if (find(repeatOpt.begin(), repeatOpt.end(), opt) != repeatOpt.end()) {
        MEDIA_LOGI("Current state is %{public}s. Please do not call %{public}s again!", curState.c_str(), opt.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

int32_t CjAVRecorder::DoGetAVRecorderConfig(std::shared_ptr<CjAVRecorderConfig> &config)
{
    ConfigMap configMap;
    recorder_->GetAVRecorderConfig(configMap);
    Location location;
    recorder_->GetLocation(location);

    config->profile.audioBitrate = configMap["audioBitrate"];
    config->profile.audioChannels = configMap["audioChannels"];
    config->profile.audioCodecFormat = static_cast<AudioCodecFormat>(configMap["audioCodec"]);
    config->profile.audioSampleRate = configMap["audioSampleRate"];
    config->profile.fileFormat = static_cast<OutputFormatType>(configMap["fileFormat"]);
    config->profile.videoBitrate = configMap["videoBitrate"];
    config->profile.videoCodecFormat = static_cast<VideoCodecFormat>(configMap["videoCodec"]);
    config->profile.videoFrameHeight = configMap["videoFrameHeight"];
    config->profile.videoFrameWidth = configMap["videoFrameWidth"];
    config->profile.videoFrameRate = configMap["videoFrameRate"];

    config->audioSourceType = static_cast<AudioSourceType>(configMap["audioSourceType"]);
    config->videoSourceType = static_cast<VideoSourceType>(configMap["videoSourceType"]);
    const std::string fdHead = "fd://";
    config->url = fdHead + std::to_string(configMap["url"]);
    config->maxDuration = configMap["maxDuration"];
    config->withVideo = configMap["withVideo"];
    config->withAudio = configMap["withAudio"];
    config->withLocation = configMap["withLocation"];
    config->location.latitude = location.latitude;
    config->location.longitude = location.longitude;
    return MSERR_OK;
}

RetInfo CjAVRecorder::ExecuteOptTask(const std::string &opt)
{
    if (CheckStateMachine(opt) != MSERR_OK) {
        return GetRetInfo(MSERR_INVALID_OPERATION, opt, "");
    }
    if (recorder_ == nullptr) {
        MEDIA_LOGE("recorder_ nullptr");
        return GetRetInfo(MSERR_INVALID_OPERATION, opt, "");
    }
    if (CheckRepeatOperation(opt) != MSERR_OK) {
        return RetInfo(MSERR_OK, "");
    }
    return DealTask(opt);
}

void CjAVRecorder::StateCallback(const std::string &state)
{
    MEDIA_LOGI("Change state to %{public}s", state.c_str());
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<CJAVRecorderCallback>(recorderCb_);
    CStateChangeHandler handler;
    handler.state = MallocCString(state);
    handler.reason = static_cast<int32_t>(StateChangeReason::USER);
    napiCb->ExecuteStateCallback(handler);
}

char *MallocCString(const std::string &origin)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}
}
}