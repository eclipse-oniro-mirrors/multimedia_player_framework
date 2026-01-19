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
#include "avrecorder_callback_taihe.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "surface_utils.h"
#include "string_ex.h"
#include "avcodec_info.h"
#include "av_common.h"
#include "media_taihe_utils.h"
#include "pixel_map_taihe.h"
#include "ipc_skeleton.h"

using namespace ANI::Media;
using namespace ohos::multimedia::media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVRecorderTaihe"};
}
namespace ANI::Media {
using namespace OHOS::MediaAVCodec;
const std::string CLASS_NAME = "AVRecorder";
std::map<std::string, AVRecorderImpl::AvRecorderTaskqFunc> AVRecorderImpl::taskQFuncs_ = {
    {AVRecordergOpt::GETINPUTSURFACE, &AVRecorderImpl::GetInputSurface},
    {AVRecordergOpt::START, &AVRecorderImpl::Start},
    {AVRecordergOpt::PAUSE, &AVRecorderImpl::Pause},
    {AVRecordergOpt::RESUME, &AVRecorderImpl::Resume},
    {AVRecordergOpt::STOP, &AVRecorderImpl::Stop},
    {AVRecordergOpt::RESET, &AVRecorderImpl::Reset},
    {AVRecordergOpt::RELEASE, &AVRecorderImpl::Release},
};

AVRecorderImpl::AVRecorderImpl()
{
    MediaTrace trace("AVRecorder::Constructor");
    MEDIA_LOGI("Taihe Constructor Start");
    recorder_ = OHOS::Media::RecorderFactory::CreateRecorder();
    if (recorder_ == nullptr) {
        MEDIA_LOGE("failed to CreateRecorder");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateRecorder");
        return;
    }
    taskQue_ = std::make_unique<OHOS::Media::TaskQueue>("OS_AVRecorderTaihe");
    (void)taskQue_->Start();
    recorderCb_ = std::make_shared<AVRecorderCallback>();
    if (recorderCb_ == nullptr) {
        MEDIA_LOGE("failed to CreateRecorderCb");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateRecorderCb");
        return;
    }
    (void)recorder_->SetRecorderCallback(recorderCb_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(this));
}

string AVRecorderImpl::GetState()
{
    MediaTrace trace("AVRecorder::GetState");
    auto recorderCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(recorderCb != nullptr, "", "taiheCb is nullptr!");
    return string(recorderCb->GetState());
}

RetInfo GetRetInfo(int32_t errCode, const std::string &operate, const std::string &param, const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d", operate.c_str(), param.c_str(), errCode);
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    if (errCode == MSERR_UNSUPPORT_VID_PARAMS) {
        return RetInfo(err, "The video parameter is not supported. Please check the type and range.");
    }

    if (errCode == MSERR_UNSUPPORT_AUD_PARAMS) {
        return RetInfo(err, "The audio parameter is not supported. Please check the type and range.");
    }

    std::string message;
    if (err == MSERR_EXT_API9_INVALID_PARAMETER) {
        message = MSExtErrorAPI9ToString(err, param, "") + add;
    } else {
        message = MSExtErrorAPI9ToString(err, operate, "") + add;
    }

    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, message.c_str());
    return RetInfo(err, message);
}

void SetRetInfoError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d", operate.c_str(), param.c_str(), errCode);
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    if (errCode == MSERR_UNSUPPORT_VID_PARAMS) {
        set_business_error(err, "The video parameter is not supported. Please check the type and range.");
        return;
    }

    if (errCode == MSERR_UNSUPPORT_AUD_PARAMS) {
        set_business_error(err, "The audio parameter is not supported. Please check the type and range.");
        return;
    }

    std::string message;
    if (err == MSERR_EXT_API9_INVALID_PARAMETER) {
        message = MSExtErrorAPI9ToString(err, param, "") + add;
    } else {
        message = MSExtErrorAPI9ToString(err, operate, "") + add;
    }

    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, message.c_str());
    set_business_error(err, message);
}

void AVRecorderImpl::PrepareSync(ohos::multimedia::media::AVRecorderConfig const& config)
{
    MediaTrace trace("AVRecorder::PrepareSync");
    const std::string &opt = AVRecordergOpt::PREPARE;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");
    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->GetConfig(asyncCtx, config) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderImpl::GetPrepareTask(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
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

void AVRecorderImpl::StartSync()
{
    MEDIA_LOGI("Taihe Start Enter");
    return ExecuteByPromise(AVRecordergOpt::START);
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetPromiseTask(AVRecorderImpl *avtaihe, const std::string &opt)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = avtaihe, option = opt]() {
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe->recorder_ != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

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

int32_t AVRecorderImpl::CheckRepeatOperation(const std::string &opt)
{
    const std::map<std::string, std::vector<std::string>> stateCtrl = {
        {AVRecorderState::STATE_IDLE, {
            AVRecordergOpt::RESET,
            AVRecordergOpt::GET_AV_RECORDER_PROFILE,
            AVRecordergOpt::SET_AV_RECORDER_CONFIG,
            AVRecordergOpt::GET_AV_RECORDER_CONFIG,
        }},
        {AVRecorderState::STATE_PREPARED, {}},
        {AVRecorderState::STATE_STARTED, {
            AVRecordergOpt::START,
            AVRecordergOpt::RESUME
        }},
        {AVRecorderState::STATE_PAUSED, {
            AVRecordergOpt::PAUSE
        }},
        {AVRecorderState::STATE_STOPPED, {
            AVRecordergOpt::STOP
        }},
        {AVRecorderState::STATE_RELEASED, {
            AVRecordergOpt::RELEASE
        }},
        {AVRecorderState::STATE_ERROR, {}},
    };

    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(taiheCb != nullptr, MSERR_INVALID_OPERATION, "taiheCb is nullptr!");

    std::string curState = taiheCb->GetState();
    if (stateCtrl.find(curState) == stateCtrl.end()) {
        MEDIA_LOGI("Invalid state: %{public}s.", curState.c_str());
        return MSERR_INVALID_OPERATION;
    }
    std::vector<std::string> repeatOpt = stateCtrl.at(curState);
    if (find(repeatOpt.begin(), repeatOpt.end(), opt) != repeatOpt.end()) {
        MEDIA_LOGI("Current state is %{public}s. Please do not call %{public}s again!", curState.c_str(), opt.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetPrepareTask(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::PREPARE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        RetInfo retinfo = taihe->Configure(config);
        CHECK_AND_RETURN_RET(retinfo.first == MSERR_OK, ((void)taihe->recorder_->Reset(), retinfo));
        int32_t ret = taihe->recorder_->Prepare();
        CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)taihe->recorder_->Reset(), GetRetInfo(ret, "Prepare", "")));
        taihe->RemoveSurface();
        taihe->StateCallback(AVRecorderState::STATE_PREPARED);
        taihe->getVideoInputSurface_ = false;
        taihe->withVideo_ = config->withVideo;
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

RetInfo AVRecorderImpl::Configure(std::shared_ptr<AVRecorderConfig> config)
{
    CHECK_AND_RETURN_RET(recorder_ != nullptr, GetRetInfo(MSERR_INVALID_OPERATION, "Configure", ""));
    CHECK_AND_RETURN_RET(config != nullptr, GetRetInfo(MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "Configure", "config"));

    if (hasConfiged_) {
        MEDIA_LOGE("AVRecorderConfig has been configured and will not be configured again");
        return RetInfo(MSERR_EXT_API9_OK, "");
    }

    int32_t ret;
    if (config->withAudio) {
        ret = recorder_->SetAudioSource(config->audioSourceType, audioSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioSource", "audioSourceType"));
    }

    if (config->withVideo) {
        ret = recorder_->SetVideoSource(config->videoSourceType, videoSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoSource", "videoSourceType"));
    }

    if (config->metaSourceTypeVec.size() != 0 &&
        std::find(config->metaSourceTypeVec.cbegin(), config->metaSourceTypeVec.cend(),
        OHOS::Media::MetaSourceType::VIDEO_META_MAKER_INFO) != config->metaSourceTypeVec.cend()) {
        ret = recorder_->SetMetaSource(OHOS::Media::MetaSourceType::VIDEO_META_MAKER_INFO, metaSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetMetaSource", "metaSourceType"));
        metaSourceIDMap_.emplace(std::make_pair(OHOS::Media::MetaSourceType::VIDEO_META_MAKER_INFO, metaSourceID_));
    }

    RetInfo retInfo = SetProfile(config);
    CHECK_AND_RETURN_RET_LOG(retInfo.first == MSERR_OK, retInfo, "Fail to set videoBitrate");

    if (config->maxDuration < 1) {
        config->maxDuration = INT32_MAX;
        MEDIA_LOGI("AVRecorderTaihe::Configure maxDuration = %{public}d is invalid, set to default",
            config->maxDuration);
    }
    recorder_->SetMaxDuration(config->maxDuration);
    MEDIA_LOGI("AVRecorderTaihe::Configure SetMaxDuration = %{public}d", config->maxDuration);

    if (config->withLocation) {
        recorder_->SetLocation(config->metadata.location.latitude, config->metadata.location.longitude);
    }

    if (config->withVideo) {
        recorder_->SetOrientationHint(config->rotation);
    }

    if (!config->metadata.genre.empty()) {
        ret = recorder_->SetGenre(config->metadata.genre);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetGenre", "Genre"));
    }
    if (!config->metadata.customInfo.Empty()) {
        ret = recorder_->SetUserCustomInfo(config->metadata.customInfo);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetUserCustomInfo", "customInfo"));
    }
    return ConfigureUrl(config);
}

template<typename T, typename = std::enable_if_t<std::is_same_v<int64_t, T> || std::is_same_v<int32_t, T>>>
bool StrToInt(const std::string_view& str, T& value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front()) || (str.front() == '-')), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    const char* addr = valStr.c_str();
    long long result = strtoll(addr, &end, 10); /* 10 means decimal */
    CHECK_AND_RETURN_RET_LOG(end != addr && end[0] == '\0' && errno != ERANGE, false,
        "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
    if constexpr (std::is_same<int32_t, T>::value) {
        CHECK_AND_RETURN_RET_LOG(result >= INT_MIN && result <= INT_MAX, false,
            "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
        value = static_cast<int32_t>(result);
        return true;
    }
    value = result;
    return true;
}

RetInfo AVRecorderImpl::ConfigureUrl(std::shared_ptr<AVRecorderConfig> config)
{
    int32_t ret;
    if (config->fileGenerationMode == OHOS::Media::FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
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
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::SetProfile(std::shared_ptr<AVRecorderConfig> config)
{
    int32_t ret;
    AVRecorderProfile &profile = config->profile;

    ret = recorder_->SetOutputFormat(profile.fileFormat);
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

        ret = recorder_->SetVideoEnableStableQualityMode(videoSourceID_, profile.enableStableQualityMode);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEnableStableQualityMode",
            "enableStableQualityMode"));
    }

    if (config->metaSourceTypeVec.size() != 0 &&
        std::find(config->metaSourceTypeVec.cbegin(), config->metaSourceTypeVec.cend(),
        OHOS::Media::MetaSourceType::VIDEO_META_MAKER_INFO) != config->metaSourceTypeVec.cend()) {
        ret = recorder_->SetMetaConfigs(metaSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetMetaConfigs", "metaSourceType"));
    }

    return RetInfo(MSERR_EXT_API9_OK, "");
}

void AVRecorderImpl::RemoveSurface()
{
    if (surface_ != nullptr) {
        auto id = surface_->GetUniqueId();
        auto surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(id);
        if (surface) {
            (void)OHOS::SurfaceUtils::GetInstance()->Remove(id);
        }
        surface_ = nullptr;
    }
}

int32_t AVRecorderImpl::GetConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    int32_t ret = GetSourceType(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetSourceType");
    ret = GetProfile(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetProfile");
    ret = GetModeAndUrl(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetModeAndUrl");
    if (config.maxDuration.has_value()) {
        asyncCtx->config_->maxDuration = static_cast<int32_t>(config.maxDuration.value());
    }
    if (config.metadata.has_value()) {
        CHECK_AND_RETURN_RET_LOG(GetAVMetaData(asyncCtx, config.metadata.value()) == MSERR_OK,
            MSERR_INVALID_VAL, "failed to GetAVMetaData");
    }
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetAVMetaData(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVMetadata const& metadata)
{
    OHOS::Media::AVMetadata &avMetadata = asyncCtx->config_->metadata;
    if (metadata.location.has_value()) {
        if (!GetLocation(asyncCtx, metadata.location.value())) {
            SetRetInfoError(MSERR_INCORRECT_PARAMETER_TYPE, "GetLocation", "Location",
                "location type should be Location.");
            return MSERR_INCORRECT_PARAMETER_TYPE;
        }
    }
    if (metadata.genre.has_value()) {
        avMetadata.genre = metadata.genre.value();
    } else {
        avMetadata.genre = "";
    }
    if (avMetadata.genre != "") {
        SetRetInfoError(MSERR_INVALID_VAL, "getgenre", "genre");
        return MSERR_INVALID_VAL;
    }
    std::string strRotation = "";
    if (metadata.videoOrientation.has_value()) {
        strRotation = static_cast<std::string>(metadata.videoOrientation.value());
    }
    if (strRotation == "0" || strRotation == "90" || strRotation == "180" || strRotation == "270") {
        asyncCtx->config_->rotation = std::stoi(strRotation);
        rotation_ = asyncCtx->config_->rotation;
        MEDIA_LOGI("rotation: %{public}d", asyncCtx->config_->rotation);
    } else if (strRotation != "") {
        SetRetInfoError(MSERR_INVALID_VAL, "not support rotation", "videoOrientation");
        return MSERR_INVALID_VAL;
    }
    if (metadata.customInfo.has_value()) {
        for (const auto& [key, value] : metadata.customInfo.value()) {
            avMetadata.customInfo.SetData(std::string(key), std::string(value));
        }
    }
    return MSERR_OK;
}

bool AVRecorderImpl::GetLocation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::Location const& locations)
{
    OHOS::Media::userLocation &location = asyncCtx->config_->metadata.location;

    double tempLatitude = static_cast<double>(locations.latitude);
    double tempLongitude = static_cast<double>(locations.longitude);
    location.latitude = static_cast<float>(tempLatitude);
    location.longitude = static_cast<float>(tempLongitude);
    asyncCtx->config_->withLocation = true;
    return true;
}

int32_t AVRecorderImpl::GetModeAndUrl(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    if (config.fileGenerationMode.has_value()) {
        int32_t mode = 0;
        mode = config.fileGenerationMode.value().get_value();
        if (mode < OHOS::Media::FileGenerationMode::APP_CREATE ||
            mode > OHOS::Media::FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
            SetRetInfoError(MSERR_INVALID_VAL, "fileGenerationMode", "fileGenerationMode",
                "invalide fileGenerationMode");
            return MSERR_INVALID_VAL;
        }
        asyncCtx->config_->fileGenerationMode = static_cast<OHOS::Media::FileGenerationMode>(mode);
        MEDIA_LOGI("FileGenerationMode %{public}d!", mode);
    }
    asyncCtx->config_->url = static_cast<std::string>(config.url);
    MEDIA_LOGI("url %{public}s!", asyncCtx->config_->url.c_str());
    if (asyncCtx->config_->fileGenerationMode == OHOS::Media::FileGenerationMode::APP_CREATE) {
        if (asyncCtx->config_->url == "") {
            SetRetInfoError(MSERR_PARAMETER_VERIFICATION_FAILED, "geturl", "url",
                "config->url cannot be null");
            return MSERR_PARAMETER_VERIFICATION_FAILED;
        }
    }
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetSourceType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    if (config.audioSourceType.has_value()) {
        asyncCtx->config_->audioSourceType = static_cast<OHOS::Media::AudioSourceType>(
            static_cast<int32_t>(config.audioSourceType.value()));
        asyncCtx->config_->withAudio = true;
        MEDIA_LOGI("audioSource Type %{public}d!", asyncCtx->config_->audioSourceType);
    } else {
        asyncCtx->config_->audioSourceType = static_cast<OHOS::Media::AudioSourceType>(AUDIO_SOURCE_INVALID);
    }

    if (config.videoSourceType.has_value()) {
        asyncCtx->config_->videoSourceType = static_cast<OHOS::Media::VideoSourceType>(
            static_cast<int32_t>(config.videoSourceType.value()));
        asyncCtx->config_->withVideo = true;
        MEDIA_LOGI("videoSource Type %{public}d!", asyncCtx->config_->videoSourceType);
    } else {
        asyncCtx->config_->videoSourceType = static_cast<OHOS::Media::VideoSourceType>(VIDEO_SOURCE_BUTT);
    }

    if (config.metaSourceTypes.has_value()) {
        for (auto item : config.metaSourceTypes.value()) {
            asyncCtx->config_->metaSourceTypeVec.push_back(
                static_cast<OHOS::Media::MetaSourceType>((item.get_value())));
        }
    }
    if (!(asyncCtx->config_->withAudio) && !(asyncCtx->config_->withVideo)) {
        SetRetInfoError(MSERR_INVALID_VAL, "getsourcetype", "SourceType");
    }
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    int32_t ret = MSERR_OK;
    if (asyncCtx->config_->withAudio) {
        ret = GetAudioProfile(asyncCtx, config);
    }
    if (asyncCtx->config_->withVideo) {
        ret = GetVideoProfile(asyncCtx, config);
    }

    std::string outputFile = static_cast<std::string>(config.profile.fileFormat.get_value());
    ret = GetOutputFormat(outputFile, asyncCtx->config_->profile.fileFormat);
    if (ret != MSERR_OK) {
        SetRetInfoError(ret, "GetOutputFormat", "fileFormat");
        return ret;
    }
    MEDIA_LOGI("fileFormat %{public}d", asyncCtx->config_->profile.fileFormat);
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetVideoProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    int32_t ret = MSERR_OK;
    std::string videoCodec = "";
    if (config.profile.videoCodec.has_value()) {
        videoCodec = static_cast<std::string>(config.profile.videoCodec.value());
    }
    ret = GetVideoCodecFormat(videoCodec, asyncCtx->config_->profile.videoCodecFormat);
    if (ret != MSERR_OK) {
        SetRetInfoError(ret, "GetVideoCodecFormat", "videoCodecFormat");
        return ret;
    }
    if (config.profile.videoBitrate.has_value()) {
        asyncCtx->config_->profile.videoBitrate = config.profile.videoBitrate.value();
    }
    if (config.profile.videoFrameWidth.has_value()) {
        asyncCtx->config_->profile.videoFrameWidth = config.profile.videoFrameWidth.value();
    }
    videoFrameWidth_ = asyncCtx->config_->profile.videoFrameWidth;
    if (config.profile.videoFrameHeight.has_value()) {
        asyncCtx->config_->profile.videoFrameHeight = config.profile.videoFrameHeight.value();
    }
    videoFrameHeight_ = asyncCtx->config_->profile.videoFrameHeight;
    if (config.profile.videoFrameRate.has_value()) {
        asyncCtx->config_->profile.videoFrameRate = config.profile.videoFrameRate.value();
    }
    if (config.profile.isHdr.has_value()) {
        asyncCtx->config_->profile.isHdr = config.profile.isHdr.value();
        if (asyncCtx->config_->profile.isHdr &&
            (asyncCtx->config_->profile.videoCodecFormat != VideoCodecFormat::H265)) {
            SetRetInfoError(MSERR_UNSUPPORT_VID_PARAMS, "isHdr needs to match video/hevc", "");
            return MSERR_UNSUPPORT_VID_PARAMS;
        }
    } else {
        asyncCtx->config_->profile.isHdr = false;
    }
    if (config.profile.enableTemporalScale.has_value()) {
        asyncCtx->config_->profile.enableTemporalScale = config.profile.enableTemporalScale.value();
    } else {
        MEDIA_LOGI("avRecorderProfile enableTemporalScale is not set.");
        asyncCtx->config_->profile.enableTemporalScale = false;
    }
    if (config.profile.enableStableQualityMode.has_value()) {
        asyncCtx->config_->profile.enableStableQualityMode = config.profile.enableStableQualityMode.value();
    } else {
        MEDIA_LOGI("avRecorderProfile enableStableQualityMode is not set.");
        asyncCtx->config_->profile.enableStableQualityMode = false;
    }
    MediaProfileLog(true, asyncCtx->config_->profile);
    return ret;
}

int32_t AVRecorderImpl::GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, VideoCodecFormat> mimeStrToCodecFormat = {
        { OHOS::MediaAVCodec::CodecMimeType::VIDEO_AVC, OHOS::Media::VideoCodecFormat::H264 },
        { OHOS::MediaAVCodec::CodecMimeType::VIDEO_MPEG4, OHOS::Media::VideoCodecFormat::MPEG4 },
        { OHOS::MediaAVCodec::CodecMimeType::VIDEO_HEVC, OHOS::Media::VideoCodecFormat::H265 },
        { "", VideoCodecFormat::VIDEO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::GetOutputFormat(const std::string &extension, OutputFormatType &type)
{
    MEDIA_LOGI("mime %{public}s", extension.c_str());
    const std::map<std::string, OutputFormatType> extensionToOutputFormat = {
        { "mp4", OutputFormatType::FORMAT_MPEG_4 },
        { "m4a", OutputFormatType::FORMAT_M4A },
        { "mp3", OutputFormatType::FORMAT_MP3 },
        { "wav", OutputFormatType::FORMAT_WAV },
        { "amr", OutputFormatType::FORMAT_AMR },
        { "", OutputFormatType::FORMAT_DEFAULT },
    };

    auto iter = extensionToOutputFormat.find(extension);
    if (iter != extensionToOutputFormat.end()) {
        type = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::GetAudioProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ohos::multimedia::media::AVRecorderConfig const& config)
{
    int32_t ret = MSERR_OK;
    std::string audioCodec = "";
    if (config.profile.audioCodec.has_value()) {
        audioCodec = static_cast<std::string>(config.profile.audioCodec.value());
    }
    ret = GetAudioCodecFormat(audioCodec, asyncCtx->config_->profile.audioCodecFormat);
    if (ret != MSERR_OK) {
        SetRetInfoError(ret, "GetAudioCodecFormat", "audioCodecFormat");
        return ret;
    }
    if (config.profile.audioBitrate.has_value()) {
        asyncCtx->config_->profile.audioBitrate = config.profile.audioBitrate.value();
    }
    if (config.profile.audioChannels.has_value()) {
        asyncCtx->config_->profile.audioChannels = config.profile.audioChannels.value();
    }
    if (config.profile.audioSampleRate.has_value()) {
        asyncCtx->config_->profile.audioSampleRate = config.profile.audioSampleRate.value();
    }
    MediaProfileLog(false, asyncCtx->config_->profile);
    return ret;
}

void AVRecorderImpl::MediaProfileLog(bool isVideo, AVRecorderProfile &profile)
{
    if (isVideo) {
        MEDIA_LOGI("videoBitrate %{public}d, videoCodecFormat %{public}d, videoFrameWidth %{public}d,"
            " videoFrameHeight %{public}d, videoFrameRate %{public}d, isHdr %{public}d, enableTemporalScale %{public}d",
            profile.videoBitrate, profile.videoCodecFormat, profile.videoFrameWidth,
            profile.videoFrameHeight, profile.videoFrameRate, profile.isHdr, profile.enableTemporalScale);
        return;
    }
    MEDIA_LOGI("audioBitrate %{public}d, audioChannels %{public}d, audioCodecFormat %{public}d,"
        " audioSampleRate %{public}d!", profile.audioBitrate, profile.audioChannels,
        profile.audioCodecFormat, profile.audioSampleRate);
}

int32_t AVRecorderImpl::GetAudioCodecFormat(const std::string &mime, OHOS::Media::AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, OHOS::Media::AudioCodecFormat> mimeStrToCodecFormat = {
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC, OHOS::Media::AudioCodecFormat::AAC_LC },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_MPEG, OHOS::Media::AudioCodecFormat::AUDIO_MPEG },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_G711MU, OHOS::Media::AudioCodecFormat::AUDIO_G711MU },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_NB, OHOS::Media::AudioCodecFormat::AUDIO_AMR_NB },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_WB, OHOS::Media::AudioCodecFormat::AUDIO_AMR_WB },
        { "", OHOS::Media::AudioCodecFormat::AUDIO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::SetAudioCodecFormat(OHOS::Media::AudioCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("audioCodecFormat %{public}d", codecFormat);
    const std::map<OHOS::Media::AudioCodecFormat, std::string_view> codecFormatToMimeStr = {
        { OHOS::Media::AudioCodecFormat::AAC_LC, OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC },
        { OHOS::Media::AudioCodecFormat::AUDIO_MPEG, OHOS::MediaAVCodec::CodecMimeType::AUDIO_MPEG },
        { OHOS::Media::AudioCodecFormat::AUDIO_G711MU, OHOS::MediaAVCodec::CodecMimeType::AUDIO_G711MU },
        { OHOS::Media::AudioCodecFormat::AUDIO_AMR_NB, OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_NB },
        { OHOS::Media::AudioCodecFormat::AUDIO_AMR_WB, OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_WB },
        { OHOS::Media::AudioCodecFormat::AUDIO_DEFAULT, "" },
    };

    auto iter = codecFormatToMimeStr.find(codecFormat);
    if (iter != codecFormatToMimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::SetVideoCodecFormat(OHOS::Media::VideoCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("VideoCodecFormat %{public}d", codecFormat);
    const std::map<OHOS::Media::VideoCodecFormat, std::string_view> codecFormatTomimeStr = {
        { OHOS::Media::VideoCodecFormat::H264, OHOS::MediaAVCodec::CodecMimeType::VIDEO_AVC },
        { OHOS::Media::VideoCodecFormat::MPEG4, OHOS::MediaAVCodec::CodecMimeType::VIDEO_MPEG4 },
        { OHOS::Media::VideoCodecFormat::H265, OHOS::MediaAVCodec::CodecMimeType::VIDEO_HEVC },
        { OHOS::Media::VideoCodecFormat::VIDEO_DEFAULT, ""},
    };

    auto iter = codecFormatTomimeStr.find(codecFormat);
    if (iter != codecFormatTomimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::SetFileFormat(OutputFormatType &type, std::string &extension)
{
    MEDIA_LOGI("OutputFormatType %{public}d", type);
    const std::map<OutputFormatType, std::string> outputFormatToextension = {
        { OutputFormatType::FORMAT_MPEG_4, "mp4" },
        { OutputFormatType::FORMAT_M4A, "m4a" },
        { OutputFormatType::FORMAT_MP3, "mp3" },
        { OutputFormatType::FORMAT_WAV, "wav" },
        { OutputFormatType::FORMAT_AMR, "amr" },
        { OutputFormatType::FORMAT_DEFAULT, "" },
    };

    auto iter = outputFormatToextension.find(type);
    if (iter != outputFormatToextension.end()) {
        extension = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderImpl::CheckStateMachine(const std::string &opt)
{
    auto recorderCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(recorderCb != nullptr, MSERR_INVALID_OPERATION, "taiheCb is nullptr!");

    std::string curState = recorderCb->GetState();
    if (stateCtrlList.find(curState) == stateCtrlList.end()) {
        MEDIA_LOGI("Invalid state: %{public}s.", curState.c_str());
        return MSERR_INVALID_OPERATION;
    }
    std::vector<std::string> allowedOpt = stateCtrlList.at(curState);
    if (find(allowedOpt.begin(), allowedOpt.end(), opt) == allowedOpt.end()) {
        MEDIA_LOGE("The %{public}s operation is not allowed in the %{public}s state!", opt.c_str(), curState.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

optional<string> AVRecorderImpl::GetInputSurfaceSync()
{
    MediaTrace trace("AVRecorder::GetInputSurfaceSync");
    MEDIA_LOGI("Taihe GetInputSurface Enter");
    return GetInputSurfaceExecuteByPromise(AVRecordergOpt::GETINPUTSURFACE);
}

optional<string> AVRecorderImpl::GetInputSurfaceExecuteByPromise(const std::string &opt)
{
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    auto res = optional<string>(std::nullopt);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, res, "failed to GetTaiheInstance");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetPromiseTask(asyncCtx->taihe, opt);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) && (asyncCtx->opt_ == AVRecordergOpt::GETINPUTSURFACE)) {
            res = optional<string>(std::in_place, MediaTaiheUtils::ToTaiheString(result.Value().second));
        }
    }
    asyncCtx.release();
    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return res;
}

void AVRecorderImpl::PauseSync()
{
    MediaTrace trace("AVRecorder::PauseSync");
    MEDIA_LOGI("Taihe Pause Enter");
    return ExecuteByPromise(AVRecordergOpt::PAUSE);
}

void AVRecorderImpl::StopSync()
{
    MediaTrace trace("AVRecorder::StopSync");
    MEDIA_LOGI("Taihe Stop Enter");
    return ExecuteByPromise(AVRecordergOpt::STOP);
}

void AVRecorderImpl::ReleaseSync()
{
    MediaTrace trace("AVRecorder::ReleaseSync");
    MEDIA_LOGI("Taihe Release Enter");
    return ExecuteByPromise(AVRecordergOpt::RELEASE);
}

void AVRecorderImpl::ResetSync()
{
    MediaTrace trace("AVRecorder::ResetSync");
    MEDIA_LOGI("Taihe Reset Enter");
    return ExecuteByPromise(AVRecordergOpt::RESET);
}

void AVRecorderImpl::ResumeSync()
{
    MediaTrace trace("AVRecorder::ResumeSync");
    MEDIA_LOGI("Taihe Resume Enter");
    return ExecuteByPromise(AVRecordergOpt::RESUME);
}

void AVRecorderImpl::ExecuteByPromise(const std::string &opt)
{
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetTaiheInstance");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");
    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetPromiseTask(asyncCtx->taihe, opt);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
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

optional<AVRecorder> CreateAVRecorderSync()
{
    MediaTrace trace("AVRecorder::CreateAVRecorderSync");
    MEDIA_LOGI("Taihe CreateAVRecorder Start");
    auto res = make_holder<AVRecorderImpl, AVRecorder>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVRecorder failed!");
        taihe::reset_error();
        return optional<AVRecorder>(std::nullopt);
    }
    return optional<AVRecorder>(std::in_place, res);
}

optional<::ohos::multimedia::media::AVRecorderConfig> AVRecorderImpl::GetAVRecorderConfigSync()
{
    MediaTrace trace("AVRecorder::GetAVRecorderConfigSync");
    const std::string &opt = AVRecordergOpt::GET_AV_RECORDER_CONFIG;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto res = optional<::ohos::multimedia::media::AVRecorderConfig>(std::nullopt);
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, res, "failed to GetTaiheInstance");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");
    ::ohos::multimedia::media::AVRecorderConfig config = CreateDefaultAVRecorderConfig();

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetAVRecorderConfigTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) &&
            (asyncCtx->opt_ == AVRecordergOpt::GET_AV_RECORDER_CONFIG)) {
                SetAVRecorderConfig(asyncCtx, config);
        }
    }
    asyncCtx.release();
    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return optional<::ohos::multimedia::media::AVRecorderConfig>(std::in_place, config);
}

void AVRecorderImpl::SetAVRecorderConfig(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, ::ohos::multimedia::media::AVRecorderConfig &res)
{
    auto config = asyncCtx->config_;
    if (config->withAudio == true) {
        ohos::multimedia::media::AudioSourceType::key_t audioSourceTypeKey;
        MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::AudioSourceType>(
            config->audioSourceType, audioSourceTypeKey);
        res.audioSourceType =
            optional<::ohos::multimedia::media::AudioSourceType>(std::in_place_t{}, audioSourceTypeKey);
    }
    if (config->withVideo == true) {
        ohos::multimedia::media::VideoSourceType::key_t videoSourceTypeKey;
        MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::VideoSourceType>(
            config->videoSourceType, videoSourceTypeKey);
        res.videoSourceType =
            optional<::ohos::multimedia::media::VideoSourceType>(std::in_place_t{}, videoSourceTypeKey);
    }
    auto profile = CreateAVRecorderProfile(asyncCtx);
    res.profile = profile;
    if (config->withAudio || config->withVideo) {
        res.url = MediaTaiheUtils::ToTaiheString(config->url);
    }
}

::ohos::multimedia::media::AVRecorderConfig AVRecorderImpl::CreateDefaultAVRecorderConfig()
{
    ::ohos::multimedia::media::AVRecorderConfig config {
        optional<::ohos::multimedia::media::AudioSourceType>(std::nullopt),
        optional<::ohos::multimedia::media::VideoSourceType>(std::nullopt),
        CreateDefaultAVRecorderProfile(),
        "",
        optional<::taihe::array<::ohos::multimedia::media::MetaSourceType>>(std::nullopt),
        optional<::ohos::multimedia::media::FileGenerationMode>(std::nullopt),
        optional<::ohos::multimedia::media::AVMetadata>(std::nullopt),
        optional<int32_t>(std::nullopt),
    };
    return config;
}

::ohos::multimedia::media::AVRecorderProfile AVRecorderImpl::CreateAVRecorderProfile(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    auto config = asyncCtx->config_;
    std::string fileFormat = "";
    if (config->withAudio || config->withVideo) {
        SetFileFormat(config->profile.fileFormat, fileFormat);
    }
    taihe::string fileFormatValue = MediaTaiheUtils::ToTaiheString(fileFormat);
    ohos::multimedia::media::ContainerFormatType::key_t containerFormatTypeKey;
    MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::ContainerFormatType>(
        fileFormatValue, containerFormatTypeKey);
    ::ohos::multimedia::media::AVRecorderProfile aVRecorderProfile {
        optional<int32_t>(std::nullopt), optional<int32_t>(std::nullopt),
        optional<::ohos::multimedia::media::CodecMimeType>(std::nullopt),
        optional<int32_t>(std::nullopt),
        containerFormatTypeKey,
        optional<int32_t>(std::nullopt),
        optional<::ohos::multimedia::media::CodecMimeType>(std::nullopt),
        optional<int32_t>(std::nullopt), optional<int32_t>(std::nullopt),
        optional<int32_t>(std::nullopt), optional<bool>(std::nullopt),
        optional<bool>(std::nullopt), optional<bool>(std::nullopt),
    };
    if (config->withAudio) {
        aVRecorderProfile.audioBitrate = optional<int32_t>(std::in_place_t{}, config->profile.audioBitrate);
        aVRecorderProfile.audioChannels = optional<int32_t>(std::in_place_t{}, config->profile.audioChannels);
        aVRecorderProfile.audioSampleRate = optional<int32_t>(std::in_place_t{}, config->profile.audioSampleRate);
        std::string audioCodec = "";
        SetAudioCodecFormat(config->profile.audioCodecFormat, audioCodec);
        taihe::string audioValue = MediaTaiheUtils::ToTaiheString(audioCodec);
        ohos::multimedia::media::CodecMimeType::key_t codecMimeTypeKey;
        MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(audioValue, codecMimeTypeKey);
        aVRecorderProfile.audioCodec =
            optional<::ohos::multimedia::media::CodecMimeType>(std::in_place_t{}, codecMimeTypeKey);
    }
    if (config->withVideo) {
        aVRecorderProfile.videoBitrate = optional<int32_t>(std::in_place_t{}, config->profile.videoBitrate);
        aVRecorderProfile.videoFrameWidth = optional<int32_t>(std::in_place_t{}, config->profile.videoFrameWidth);
        aVRecorderProfile.videoFrameHeight = optional<int32_t>(std::in_place_t{}, config->profile.videoFrameHeight);
        aVRecorderProfile.videoFrameRate = optional<int32_t>(std::in_place_t{}, config->profile.videoFrameRate);
        std::string videoCodec = "";
        SetVideoCodecFormat(config->profile.videoCodecFormat, videoCodec);
        taihe::string videoValue = MediaTaiheUtils::ToTaiheString(videoCodec);
        ohos::multimedia::media::CodecMimeType::key_t codecMimeTypeKey;
        MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(videoValue, codecMimeTypeKey);
        aVRecorderProfile.videoCodec =
            optional<::ohos::multimedia::media::CodecMimeType>(std::in_place_t{}, codecMimeTypeKey);
    }
    return aVRecorderProfile;
}

::ohos::multimedia::media::AVRecorderProfile AVRecorderImpl::CreateDefaultAVRecorderProfile()
{
    taihe::string value = MediaTaiheUtils::ToTaiheString("");
    ohos::multimedia::media::CodecMimeType::key_t codecMimeTypeKey;
    MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(
        value, codecMimeTypeKey);
    ohos::multimedia::media::ContainerFormatType::key_t containerFormatTypeKey;
    MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::ContainerFormatType>(
        value, containerFormatTypeKey);
    ::ohos::multimedia::media::AVRecorderProfile aVRecorderProfile {
        optional<int32_t>(std::nullopt),
        optional<int32_t>(std::nullopt),
        optional<::ohos::multimedia::media::CodecMimeType>(std::nullopt),
        optional<int32_t>(std::nullopt),
        containerFormatTypeKey,
        optional<int32_t>(std::nullopt),
        optional<::ohos::multimedia::media::CodecMimeType>(std::nullopt),
        optional<int32_t>(std::nullopt),
        optional<int32_t>(std::nullopt),
        optional<int32_t>(std::nullopt),
        optional<bool>(std::nullopt),
        optional<bool>(std::nullopt),
        optional<bool>(std::nullopt),
    };
    return aVRecorderProfile;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetAVRecorderConfigTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, &config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::GET_AV_RECORDER_CONFIG;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        config = std::make_shared<AVRecorderConfig>();

        CHECK_AND_RETURN_RET(taihe != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe->GetAVRecorderConfig(config);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetAVRecorderConfigTask", ""),
            "get AVRecorderConfigTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::GetAVRecorderConfig(std::shared_ptr<AVRecorderConfig> &config)
{
    ConfigMap configMap;
    recorder_->GetAVRecorderConfig(configMap);
    OHOS::Media::Location location;
    recorder_->GetLocation(location);

    config->profile.audioBitrate = configMap["audioBitrate"];
    config->profile.audioChannels = configMap["audioChannels"];
    config->profile.audioCodecFormat = static_cast<OHOS::Media::AudioCodecFormat>(configMap["audioCodec"]);
    config->profile.audioSampleRate = configMap["audioSampleRate"];
    config->profile.fileFormat = static_cast<OutputFormatType>(configMap["fileFormat"]);
    config->profile.videoBitrate = configMap["videoBitrate"];
    config->profile.videoCodecFormat = static_cast<OHOS::Media::VideoCodecFormat>(configMap["videoCodec"]);
    config->profile.videoFrameHeight = configMap["videoFrameHeight"];
    config->profile.videoFrameWidth = configMap["videoFrameWidth"];
    config->profile.videoFrameRate = configMap["videoFrameRate"];

    config->audioSourceType = static_cast<OHOS::Media::AudioSourceType>(configMap["audioSourceType"]);
    config->videoSourceType = static_cast<OHOS::Media::VideoSourceType>(configMap["videoSourceType"]);
    const std::string fdHead = "fd://";
    config->url = fdHead + std::to_string(configMap["url"]);
    config->rotation = configMap["rotation"];
    config->maxDuration = configMap["maxDuration"];
    config->withVideo = configMap["withVideo"];
    config->withAudio = configMap["withAudio"];
    config->withLocation = configMap["withLocation"];
    config->location.latitude = location.latitude;
    config->location.longitude = location.longitude;
    return MSERR_OK;
}

::taihe::array<::ohos::multimedia::media::EncoderInfo> AVRecorderImpl::GetAvailableEncoderSync()
{
    MediaTrace trace("AVRecorder::GetAvailableEncoderSync");
    const std::string &opt = AVRecordergOpt::GET_ENCODER_INFO;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    ::taihe::array<::ohos::multimedia::media::EncoderInfo> res = GetDefaultResult();
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");
    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetEncoderInfoTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) &&
            (asyncCtx->opt_ == AVRecordergOpt::GET_ENCODER_INFO)) {
            res = GetTaiheResult(asyncCtx);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return res;
}

::taihe::array<::ohos::multimedia::media::EncoderInfo> AVRecorderImpl::GetTaiheResult(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    std::vector<::ohos::multimedia::media::EncoderInfo> TaiheEncoderInfo_;
    for (uint32_t i = 0; i < asyncCtx->encoderInfo_.size(); i++) {
        if (asyncCtx->encoderInfo_[i].type == "audio") {
            GetAudioEncoderInfo(asyncCtx->encoderInfo_[i], TaiheEncoderInfo_);
        } else {
            GetVideoEncoderInfo(asyncCtx->encoderInfo_[i], TaiheEncoderInfo_);
        }
    }
    return array<::ohos::multimedia::media::EncoderInfo>(TaiheEncoderInfo_);
}

void AVRecorderImpl::GetAudioEncoderInfo(EncoderCapabilityData encoderCapData,
    std::vector<::ohos::multimedia::media::EncoderInfo> &TaiheEncoderInfos)
{
    taihe::string audioMimeType = MediaTaiheUtils::ToTaiheString(encoderCapData.mimeType);
    ohos::multimedia::media::CodecMimeType::key_t audioCodecMimeTypeKey;
    MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(
        audioMimeType, audioCodecMimeTypeKey);
    ::ohos::multimedia::media::EncoderInfo TaiheEncoderInfo = {
        audioCodecMimeTypeKey,
        MediaTaiheUtils::ToTaiheString(encoderCapData.type),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.bitrate.minVal, encoderCapData.bitrate.maxVal)),
        optional<::ohos::multimedia::media::Range>(std::nullopt),
        optional<::ohos::multimedia::media::Range>(std::nullopt),
        optional<::ohos::multimedia::media::Range>(std::nullopt),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.channels.minVal, encoderCapData.channels.maxVal)),
        optional<::taihe::array<int32_t>>(std::in_place_t{}, array<int32_t>(copy_data_t{},
            encoderCapData.sampleRate.data(), encoderCapData.sampleRate.size())),
    };
    TaiheEncoderInfos.push_back(TaiheEncoderInfo);
}

void AVRecorderImpl::GetVideoEncoderInfo(EncoderCapabilityData encoderCapData,
    std::vector<::ohos::multimedia::media::EncoderInfo> &TaiheEncoderInfos)
{
    taihe::string audioMimeType = MediaTaiheUtils::ToTaiheString(encoderCapData.mimeType);
    ohos::multimedia::media::CodecMimeType::key_t audioCodecMimeTypeKey;
    MediaTaiheUtils::GetEnumKeyByStringValue<ohos::multimedia::media::CodecMimeType>(
        audioMimeType, audioCodecMimeTypeKey);
    ::ohos::multimedia::media::EncoderInfo TaiheEncoderInfo = {
        audioCodecMimeTypeKey,
        MediaTaiheUtils::ToTaiheString(encoderCapData.type),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.bitrate.minVal, encoderCapData.bitrate.maxVal)),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.frameRate.minVal, encoderCapData.frameRate.maxVal)),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.width.minVal, encoderCapData.width.maxVal)),
        optional<::ohos::multimedia::media::Range>(std::in_place_t{}, GetRange(
            encoderCapData.height.minVal, encoderCapData.height.maxVal)),
        optional<::ohos::multimedia::media::Range>(std::nullopt),
        optional<::taihe::array<int32_t>>(std::nullopt),
    };
    TaiheEncoderInfos.push_back(TaiheEncoderInfo);
}

::ohos::multimedia::media::Range AVRecorderImpl::GetRange(int32_t min, int32_t max)
{
    ::ohos::multimedia::media::Range range = {
        min,
        max,
    };
    return range;
}

::taihe::array<::ohos::multimedia::media::EncoderInfo> AVRecorderImpl::GetDefaultResult()
{
    std::vector<::ohos::multimedia::media::EncoderInfo> TaiheEncoderInfo_;
    return array<::ohos::multimedia::media::EncoderInfo>(TaiheEncoderInfo_);
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetEncoderInfoTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, &encoderInfo = asyncCtx->encoderInfo_]() {
        const std::string &option = AVRecordergOpt::GET_ENCODER_INFO;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe->GetEncoderInfo(encoderInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetEncoderInfoTask", ""),
            "get GetEncoderInfoTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::GetEncoderInfo(std::vector<EncoderCapabilityData> &encoderInfo)
{
    int32_t ret = recorder_->GetAvailableEncoder(encoderInfo);
    return ret;
}

optional<::taihe::string> AVRecorderImpl::GetInputMetaSurfaceSync(::ohos::multimedia::media::MetaSourceType type)
{
    MediaTrace trace("AVRecorder::GetInputMetaSurfaceSync");
    const std::string &opt = AVRecordergOpt::GETINPUTMETASURFACE;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto res = optional<string>(std::nullopt);
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, res, "failed to GetTaiheInstance");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->GetMetaType(asyncCtx, type) == MSERR_OK) {
            asyncCtx->task_ = GetInputMetaSurface(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        } else {
            res = optional<string>(std::in_place, MediaTaiheUtils::ToTaiheString(result.Value().second));
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return res;
}

int32_t AVRecorderImpl::GetMetaType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::MetaSourceType type)
{
    if (!(type.get_value())) {
        SetRetInfoError(MSERR_INCORRECT_PARAMETER_TYPE, "GetConfig", "AVRecorderConfig",
            "meta type should be number.");
        return MSERR_INCORRECT_PARAMETER_TYPE;
    }

    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (SetRetInfoError(MSERR_NO_MEMORY, "AVRecorderConfig", "AVRecorderConfig"), MSERR_NO_MEMORY));

    int32_t metaSourceType = VIDEO_META_SOURCE_INVALID;
    metaSourceType = (int32_t)(type.get_value());
    asyncCtx->metaType_ = static_cast<OHOS::Media::MetaSourceType>(metaSourceType);
    MEDIA_LOGI("metaSource Type %{public}d!", metaSourceType);
    return MSERR_OK;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetInputMetaSurface(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>(
        [taihe = asyncCtx->taihe, config = asyncCtx->config_, type = asyncCtx->metaType_]() {
        const std::string &option = AVRecordergOpt::GETINPUTMETASURFACE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET_LOG(taihe->metaSourceIDMap_.find(type) != taihe->metaSourceIDMap_.end(),
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", "no meta source type"),
            "failed to find meta type");
        if (taihe->metaSurface_ == nullptr) {
            MEDIA_LOGI("The meta source type is %{public}d", static_cast<int32_t>(type));
            taihe->metaSurface_ = taihe->recorder_->GetMetaSurface(taihe->metaSourceIDMap_.at(type));
            CHECK_AND_RETURN_RET_LOG(taihe->metaSurface_ != nullptr,
                GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", ""), "failed to GetInputMetaSurface");

            OHOS::SurfaceError error =
                OHOS::SurfaceUtils::GetInstance()->Add(taihe->metaSurface_->GetUniqueId(), taihe->metaSurface_);
            CHECK_AND_RETURN_RET_LOG(error == OHOS::SURFACE_ERROR_OK,
                GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", "add surface failed"),
                "failed to AddSurface");
        }

        auto surfaceId = std::to_string(taihe->metaSurface_->GetUniqueId());
        MEDIA_LOGI("surfaceId:%{public}s", surfaceId.c_str());
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, surfaceId);
    });
}

bool AVRecorderImpl::IsWatermarkSupportedSync()
{
    MediaTrace trace("AVRecorder::IsWatermarkSupportedSync");
    const std::string &opt = AVRecordergOpt::IS_WATERMARK_SUPPORTED;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    bool res = false;
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, res, "failed to GetInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = IsWatermarkSupportedTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) &&
            (asyncCtx->opt_ == AVRecordergOpt::IS_WATERMARK_SUPPORTED)) {
            res = asyncCtx->isWatermarkSupported_;
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return res;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::IsWatermarkSupportedTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe,
        &isWatermarkSupported = asyncCtx->isWatermarkSupported_]() {
        const std::string &option = AVRecordergOpt::IS_WATERMARK_SUPPORTED;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe->IsWatermarkSupported(isWatermarkSupported);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "IsWatermarkSupportedTask", ""),
            "IsWatermarkSupportedTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::IsWatermarkSupported(bool &isWatermarkSupported)
{
    return recorder_->IsWatermarkSupported(isWatermarkSupported);
}

void AVRecorderImpl::UpdateRotationSync(int32_t rotation)
{
    MediaTrace trace("AVRecorder::UpdateRotationSync");
    const std::string &opt = AVRecordergOpt::SET_ORIENTATION_HINT;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->GetRotation(asyncCtx, rotation) == MSERR_OK) {
            asyncCtx->task_ = GetSetOrientationHintTask(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return;
}

int32_t AVRecorderImpl::GetRotation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, int32_t rotation)
{
    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (SetRetInfoError(MSERR_NO_MEMORY, "AVRecorderConfig", "AVRecorderConfig"), MSERR_NO_MEMORY));

    std::shared_ptr<AVRecorderConfig> config = asyncCtx->config_;

    config->rotation = rotation;
    MEDIA_LOGI("rotation %{public}d!", config->rotation);
    CHECK_AND_RETURN_RET((config->rotation == OHOS::Media::VIDEO_ROTATION_0 ||
        config->rotation == OHOS::Media::VIDEO_ROTATION_90 ||
        config->rotation == OHOS::Media::VIDEO_ROTATION_180 ||
        config->rotation == OHOS::Media::VIDEO_ROTATION_270),
        (SetRetInfoError(MSERR_INVALID_VAL, "getrotation", "rotation"), MSERR_INVALID_VAL));
    MEDIA_LOGI("GetRecordRotation success %{public}d", config->rotation);
    rotation_ = config->rotation;
    return MSERR_OK;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetSetOrientationHintTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::SET_ORIENTATION_HINT;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        taihe->recorder_->SetOrientationHint(config->rotation);

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::GetAudioCapturerMaxAmplitudeSync()
{
    MediaTrace trace("AVRecorder::GetAudioCapturerMaxAmplitudeSync");
    const std::string &opt = AVRecordergOpt::GET_MAX_AMPLITUDE;
    MEDIA_LOGD("Taihe %{public}s Start", opt.c_str());

    int32_t ret = -1;
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, ret, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, ret, "failed to GetInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, ret, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetMaxAmplitudeTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) &&
            (asyncCtx->opt_ == AVRecordergOpt::GET_MAX_AMPLITUDE)) {
            ret = asyncCtx->maxAmplitude_;
        }
    }
    asyncCtx.release();

    MEDIA_LOGD("Taihe %{public}s End", opt.c_str());
    return ret;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetMaxAmplitudeTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, &maxAmplitude = asyncCtx->maxAmplitude_]() {
        const std::string &option = AVRecordergOpt::GET_MAX_AMPLITUDE;
        MEDIA_LOGD("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe->GetMaxAmplitude(maxAmplitude);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetMaxAmplitudeTask", ""),
            "get GetMaxAmplitudeTask failed");

        MEDIA_LOGD("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::GetMaxAmplitude(int32_t &maxAmplitude)
{
    maxAmplitude = recorder_->GetMaxAmplitude();
    return MSERR_OK;
}

void AVRecorderImpl::SetWatermarkSync(::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfig const& config)
{
    MediaTrace trace("AVRecorder::SetWatermarkSync");
    const std::string &opt = AVRecordergOpt::SET_WATERMARK;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_LOG(asyncCtx->taihe != nullptr, "failed to GetInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->taihe->taskQue_ != nullptr, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->GetWatermarkParameter(asyncCtx, watermark, config) == MSERR_OK) {
            asyncCtx->task_ = SetWatermarkTask(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
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

int32_t AVRecorderImpl::GetWatermarkParameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfig const& config)
{
    int32_t ret = GetWatermark(asyncCtx, watermark);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermark");
    ret = GetWatermarkConfig(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermarkConfig");
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetWatermark(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::image::image::weak::PixelMap watermark)
{
    asyncCtx->pixelMap_ = Image::PixelMapImpl::GetPixelMap(watermark);
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_ != nullptr,
        (SetRetInfoError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap"), MSERR_INVALID_VAL));
    return MSERR_OK;
}

int32_t AVRecorderImpl::GetWatermarkConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::WatermarkConfig const& config)
{
    asyncCtx->watermarkConfig_ = std::make_shared<WatermarkConfig>();
    asyncCtx->watermarkConfig_->top = config.top;
    CHECK_AND_RETURN_RET(asyncCtx->watermarkConfig_->top >= 0,
        (SetRetInfoError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "top",
            "config top cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));

    asyncCtx->watermarkConfig_->left = config.left;
    CHECK_AND_RETURN_RET(asyncCtx->watermarkConfig_->left >= 0,
        (SetRetInfoError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "left",
            "config left cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    return MSERR_OK;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::SetWatermarkTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, &pixelMap = asyncCtx->pixelMap_,
        &watermarkConfig = asyncCtx->watermarkConfig_]() {
        const std::string &option = AVRecordergOpt::SET_WATERMARK;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));
        bool isWatermarkSupported = false;
        int32_t ret = taihe->IsWatermarkSupported(isWatermarkSupported);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_UNKNOWN, "SetWatermarkTask", ""),
            "IsWatermarkSupported fail");
        CHECK_AND_RETURN_RET_LOG(isWatermarkSupported, GetRetInfo(MSERR_UNSUPPORT_WATER_MARK, "SetWatermarkTask", ""),
            "capability not supported");

        ret = taihe->SetWatermark(pixelMap, watermarkConfig);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(ret, "SetWatermarkTask", ""),
            "SetWatermarkTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::SetWatermark(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig)
{
#ifndef CROSS_PLATFORM
    MEDIA_LOGD("pixelMap Width %{public}d, height %{public}d, pixelformat %{public}d, RowStride %{public}d",
        pixelMap->GetWidth(), pixelMap->GetHeight(), pixelMap->GetPixelFormat(), pixelMap->GetRowStride());
    CHECK_AND_RETURN_RET_LOG(pixelMap->GetPixelFormat() == OHOS::Media::PixelFormat::RGBA_8888, MSERR_INVALID_VAL,
        "Invalid pixel format");
    std::shared_ptr<Meta> avBufferConfig = std::make_shared<Meta>();
    int32_t ret = ConfigAVBufferMeta(pixelMap, watermarkConfig, avBufferConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "ConfigAVBufferMeta is failed");
    Image::sptr<Image::SurfaceBuffer> surfaceBuffer = Image::SurfaceBuffer::Create();
    Image::BufferRequestConfig bufferConfig = {
        .width = pixelMap->GetWidth(),
        .height = pixelMap->GetHeight(),
        .strideAlignment = 0x8,
        .format = Image::GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = Image::BUFFER_USAGE_CPU_READ | Image::BUFFER_USAGE_CPU_WRITE | Image::BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    surfaceBuffer->Alloc(bufferConfig);

    MEDIA_LOGD("surface size %{public}d, surface stride %{public}d",
        surfaceBuffer->GetSize(), surfaceBuffer->GetStride());

    for (int i = 0; i < pixelMap->GetHeight(); i++) {
        ret = memcpy_s(static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + i * surfaceBuffer->GetStride(),
            pixelMap->GetRowStride(), pixelMap->GetPixels() + i * pixelMap->GetRowStride(), pixelMap->GetRowStride());
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "memcpy failed");
    }
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    CHECK_AND_RETURN_RET_LOG(waterMarkBuffer != nullptr, MSERR_NO_MEMORY, "surfaceBuffer is nullptr");
    waterMarkBuffer->meta_ = avBufferConfig;
    return recorder_->SetWatermark(waterMarkBuffer);
#endif
    return MSERR_OK;
}

int32_t AVRecorderImpl::ConfigAVBufferMeta(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig, std::shared_ptr<Meta> &meta)
{
    int32_t top = watermarkConfig->top;
    int32_t left = watermarkConfig->left;
    int32_t watermarkWidth = pixelMap->GetWidth();
    int32_t watermarkHeight = pixelMap->GetHeight();
    meta->Set<Tag::VIDEO_ENCODER_ENABLE_WATERMARK>(true);
    switch (rotation_) {
        case OHOS::Media::VIDEO_ROTATION_0:
            meta->Set<Tag::VIDEO_COORDINATE_X>(left);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(top);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkHeight);
            break;
        case OHOS::Media::VIDEO_ROTATION_90:
            MEDIA_LOGI("rotation %{public}d", OHOS::Media::VIDEO_ROTATION_90);
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_ - left - watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(OHOS::Media::VIDEO_ROTATION_270);
            meta->Set<Tag::VIDEO_COORDINATE_X>(top);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(videoFrameHeight_ - left - watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkWidth);
            break;
        case OHOS::Media::VIDEO_ROTATION_180:
            MEDIA_LOGI("rotation %{public}d", OHOS::Media::VIDEO_ROTATION_180);
            CHECK_AND_RETURN_RET_LOG(videoFrameWidth_-left-watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_-top-watermarkHeight >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(OHOS::Media::VIDEO_ROTATION_180);
            meta->Set<Tag::VIDEO_COORDINATE_X>(videoFrameWidth_-left-watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(videoFrameHeight_-top-watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkHeight);
            break;
        case OHOS::Media::VIDEO_ROTATION_270:
            MEDIA_LOGI("rotation %{public}d", OHOS::Media::VIDEO_ROTATION_270);
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_ - left - watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(OHOS::Media::VIDEO_ROTATION_90);
            meta->Set<Tag::VIDEO_COORDINATE_X>(videoFrameWidth_ - top - watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(left);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkWidth);
            break;
        default:
            break;
    }
    return MSERR_OK;
}

optional<::ohos::multimedia::audio::AudioCapturerChangeInfo> AVRecorderImpl::GetCurrentAudioCapturerInfoSync()
{
    MediaTrace trace("AVRecorder::GetCurrentAudioCapturerInfoSync");
    const std::string &opt = AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto res = optional<::ohos::multimedia::audio::AudioCapturerChangeInfo>(std::nullopt);
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, res, "failed to get AsyncContext");
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, res, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, res, "taskQue is nullptr!");
    ::ohos::multimedia::audio::AudioCapturerChangeInfo changeInfo = GetAudioDefaultInfo();

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = GetCurrentCapturerChangeInfoTask(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
        if ((result.Value().first == MSERR_EXT_API9_OK) &&
            (asyncCtx->opt_ == AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO)) {
            GetAudioCapturerChangeInfo(asyncCtx, changeInfo);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return optional<::ohos::multimedia::audio::AudioCapturerChangeInfo>(std::in_place, changeInfo);
}

void AVRecorderImpl::GetAudioCapturerChangeInfo(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, ::ohos::multimedia::audio::AudioCapturerChangeInfo &res)
{
    ohos::multimedia::audio::AudioState::key_t audioStateKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioState>(
        asyncCtx->changeInfo_.capturerState, audioStateKey);
    ohos::multimedia::audio::SourceType::key_t sourceTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::SourceType>(
        asyncCtx->changeInfo_.capturerInfo.sourceType, sourceTypeKey);

    ::ohos::multimedia::audio::AudioCapturerInfo audioCapturerInfo {
        std::move(::ohos::multimedia::audio::SourceType(sourceTypeKey)),
        asyncCtx->changeInfo_.capturerInfo.capturerFlags
    };

    std::vector<::ohos::multimedia::audio::AudioDeviceDescriptor> audioDeviceDescriptor;
    audioDeviceDescriptor.push_back(GetDeviceInfo(asyncCtx));
    res.streamId = asyncCtx->changeInfo_.sessionId;
    res.clientUid = asyncCtx->changeInfo_.clientUID;
    res.capturerState = ::ohos::multimedia::audio::AudioState(audioStateKey);
    res.muted = optional<bool>(std::in_place_t{}, asyncCtx->changeInfo_.muted);
    res.deviceDescriptors = array<::ohos::multimedia::audio::AudioDeviceDescriptor>(audioDeviceDescriptor);
    res.capturerInfo = audioCapturerInfo;
}

::ohos::multimedia::audio::AudioDeviceDescriptor AVRecorderImpl::GetDeviceInfo(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    ohos::multimedia::audio::DeviceRole::key_t deviceRoleKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceRole>(
        asyncCtx->changeInfo_.inputDeviceInfo.deviceRole, deviceRoleKey);
    ohos::multimedia::audio::DeviceType::key_t deviceTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceType>(
        asyncCtx->changeInfo_.inputDeviceInfo.deviceType, deviceTypeKey);
    taihe::string name = MediaTaiheUtils::ToTaiheString(asyncCtx->changeInfo_.inputDeviceInfo.deviceName);
    taihe::string address =
        MediaTaiheUtils::ToTaiheString(asyncCtx->changeInfo_.inputDeviceInfo.macAddress);
    std::vector<int32_t> samplingRateVec(
        asyncCtx->changeInfo_.inputDeviceInfo.audioStreamInfo.samplingRate.begin(),
        asyncCtx->changeInfo_.inputDeviceInfo.audioStreamInfo.samplingRate.end());
    std::vector<int32_t> channelsVec(asyncCtx->changeInfo_.inputDeviceInfo.audioStreamInfo.channels.begin(),
        asyncCtx->changeInfo_.inputDeviceInfo.audioStreamInfo.channels.end());
    taihe::string networkId =
        MediaTaiheUtils::ToTaiheString(asyncCtx->changeInfo_.inputDeviceInfo.networkId);
    taihe::string displayName = MediaTaiheUtils::ToTaiheString(
        asyncCtx->changeInfo_.inputDeviceInfo.displayName);
    ohos::multimedia::audio::AudioEncodingType::key_t audioEncodingTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEncodingType>(
        asyncCtx->changeInfo_.inputDeviceInfo.audioStreamInfo.encoding, audioEncodingTypeKey);
    std::vector<int32_t> channelMasks;
    channelMasks.push_back(asyncCtx->changeInfo_.inputDeviceInfo.channelMasks);
    std::vector<::ohos::multimedia::audio::AudioEncodingType> AudioEncodingType;
    AudioEncodingType.push_back(audioEncodingTypeKey);

    ::ohos::multimedia::audio::AudioDeviceDescriptor descriptor {
        std::move(::ohos::multimedia::audio::DeviceRole(deviceRoleKey)),
        std::move(::ohos::multimedia::audio::DeviceType(deviceTypeKey)),
        std::move(asyncCtx->changeInfo_.inputDeviceInfo.deviceId),
        std::move(name),
        std::move(address),
        array<int32_t>(samplingRateVec),
        array<int32_t>(channelsVec),
        array<int32_t>(channelMasks),
        std::move(networkId),
        std::move(asyncCtx->changeInfo_.inputDeviceInfo.interruptGroupId),
        std::move(asyncCtx->changeInfo_.inputDeviceInfo.volumeGroupId),
        std::move(displayName),
        optional<::taihe::array<::ohos::multimedia::audio::AudioEncodingType>>(
            std::in_place_t{}, array<::ohos::multimedia::audio::AudioEncodingType>(AudioEncodingType)),
        optional<bool>(std::nullopt),
        optional<int32_t>(std::nullopt),
    };
    return descriptor;
}

::ohos::multimedia::audio::AudioCapturerChangeInfo AVRecorderImpl::GetAudioDefaultInfo()
{
    int32_t res = -1;
    ohos::multimedia::audio::AudioState::key_t audioStateKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioState>(
        res, audioStateKey);
    ohos::multimedia::audio::SourceType::key_t sourceTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::SourceType>(
        res, sourceTypeKey);
    ::ohos::multimedia::audio::AudioCapturerInfo audioCapturerInfo {
        std::move(::ohos::multimedia::audio::SourceType(sourceTypeKey)),
        res,
    };
    std::vector<::ohos::multimedia::audio::AudioDeviceDescriptor> audioDeviceDescriptor;
    ::ohos::multimedia::audio::AudioCapturerChangeInfo audioCapturerChangeInfo {
        std::move(res), std::move(res),
        std::move(audioCapturerInfo),
        std::move(::ohos::multimedia::audio::AudioState(audioStateKey)),
        array<::ohos::multimedia::audio::AudioDeviceDescriptor>(audioDeviceDescriptor),
        optional<bool>(std::nullopt),
    };
    return audioCapturerChangeInfo;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::GetCurrentCapturerChangeInfoTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe, &changeInfo = asyncCtx->changeInfo_]() {
        const std::string &option = AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe->GetCurrentCapturerChangeInfo(changeInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetCurrentCapturerChangeInfoTask", ""),
            "get GetCurrentCapturerChangeInfoTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

int32_t AVRecorderImpl::GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo)
{
    int32_t ret = recorder_->GetCurrentCapturerChangeInfo(changeInfo);
    return ret;
}

RetInfo AVRecorderImpl::GetInputSurface()
{
    CHECK_AND_RETURN_RET_LOG(withVideo_, GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", "",
        "The VideoSourceType is not configured. Please do not call getInputSurface"), "No video recording");

    if (surface_ == nullptr) {
        surface_ = recorder_->GetSurface(videoSourceID_);
        CHECK_AND_RETURN_RET_LOG(surface_ != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to GetSurface");

            OHOS::SurfaceError error = OHOS::SurfaceUtils::GetInstance()->Add(surface_->GetUniqueId(), surface_);
        CHECK_AND_RETURN_RET_LOG(error == OHOS::SURFACE_ERROR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to AddSurface");
    }

    auto surfaceId = std::to_string(surface_->GetUniqueId());
    getVideoInputSurface_ = true;
    return RetInfo(MSERR_EXT_API9_OK, surfaceId);
}

RetInfo AVRecorderImpl::Start()
{
    if (withVideo_ && !getVideoInputSurface_) {
        return GetRetInfo(MSERR_INVALID_OPERATION, "Start", "",
            " Please get the video input surface through GetInputSurface first!");
    }
    int32_t ret = recorder_->Start();
    if (ret != MSERR_OK) {
        StateCallback(AVRecorderState::STATE_ERROR);
    }
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Start", ""));
    StateCallback(AVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::Pause()
{
    int32_t ret = recorder_->Pause();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Pause", ""));
    StateCallback(AVRecorderState::STATE_PAUSED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::Resume()
{
    int32_t ret = recorder_->Resume();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Resume", ""));
    StateCallback(AVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::Stop()
{
    int32_t ret = recorder_->Stop(false);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Stop", ""));
    StateCallback(AVRecorderState::STATE_STOPPED);
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::Reset()
{
    RemoveSurface();
    int32_t ret = recorder_->Reset();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Reset", ""));

    StateCallback(AVRecorderState::STATE_IDLE);
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderImpl::Release()
{
    RemoveSurface();
    int32_t ret = recorder_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Release", ""));

    StateCallback(AVRecorderState::STATE_RELEASED);
    CancelCallback();
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

void AVRecorderImpl::StateCallback(const std::string &state)
{
    MEDIA_LOGI("Change state to %{public}s", state.c_str());
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    taiheCb->SendStateCallback(state, OHOS::Media::StateChangeReason::USER);
}

void AVRecorderImpl::CancelCallback()
{
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    taiheCb->ClearCallbackReference();
}

void AVRecorderImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void AVRecorderImpl::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}

void AVRecorderImpl::ErrorCallback(int32_t errCode, const std::string &operate, const std::string &add)
{
    MEDIA_LOGE("failed to %{public}s, errCode = %{public}d", operate.c_str(), errCode);
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);

    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    std::string msg = MSExtErrorAPI9ToString(err, operate, "") + add;
    taiheCb->SendErrorCallback(errCode, msg);
}

void AVRecorderImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVRecorderTaihe::OnError");
    MEDIA_LOGD("TaiheOnError In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(AVRecorderEvent::EVENT_ERROR, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnError callbackName: error success", FAKE_POINTER(this));
    return;
}

void AVRecorderImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVRecorderTaihe::OffError");
    MEDIA_LOGD("TaiheOffError In");

    CancelCallbackReference(AVRecorderEvent::EVENT_ERROR);
}

void AVRecorderImpl::OnStateChange(callback_view<void(string_view,
                                   ohos::multimedia::media::StateChangeReason)> callback)
{
    MediaTrace trace("AVRecorderTaihe::OnStateChange");
    MEDIA_LOGD("TaiheOnStateChange In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(string_view, ohos::multimedia::media::StateChangeReason)>> taiheCallback =
            std::make_shared<taihe::callback<void(string_view, ohos::multimedia::media::StateChangeReason)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(AVRecorderEvent::EVENT_STATE_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnStateChange callbackName: stateChange success", FAKE_POINTER(this));
    return;
}

void AVRecorderImpl::OffStateChange(optional_view<callback<void(string_view,
                                    ohos::multimedia::media::StateChangeReason)>> callback)
{
    MediaTrace trace("AVRecorderTaihe::OffStateChange");
    MEDIA_LOGD("TaiheOffStateChange In");

    CancelCallbackReference(AVRecorderEvent::EVENT_STATE_CHANGE);
}

void AVRecorderImpl::OnAudioCapturerChange(
    ::taihe::callback_view<void(::ohos::multimedia::audio::AudioCapturerChangeInfo const&)> callback)
{
    MediaTrace trace("AVRecorderTaihe::OnAudioCapturerChange");
    MEDIA_LOGD("TaiheOnAudioCapturerChange In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>> taiheCallback =
        std::make_shared<taihe::callback<void(::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnStateChange callbackName: stateChange success", FAKE_POINTER(this));
    return;
}

void AVRecorderImpl::OffAudioCapturerChange(
    ::taihe::optional_view<::taihe::callback<void(::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>> callback)
{
    MediaTrace trace("AVRecorderTaihe::OffAudioCapturerChange");
    MEDIA_LOGD("TaiheOffAudioCapturerChange In");

    CancelCallbackReference(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE);
}

void AVRecorderImpl::OnPhotoAssetAvailable(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVRecorderTaihe::OnPhotoAssetAvailable");
    MEDIA_LOGD("TaiheOnPhotoAssetAvailable In");

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " TaiheOnStateChange callbackName: stateChange success", FAKE_POINTER(this));
    return;
}

void AVRecorderImpl::OffPhotoAssetAvailable(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVRecorderTaihe::OffPhotoAssetAvailable");
    MEDIA_LOGD("TaiheOffPhotoAssetAvailable In");

    ErrorCallback(MSERR_PARAMETER_VERIFICATION_FAILED, "CancelEventCallback",
        "type must be error, stateChange or audioCapturerChange.");
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVRecorderSync(CreateAVRecorderSync);