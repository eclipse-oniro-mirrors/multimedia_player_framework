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
#include "avcodec_info.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "media_log.h"
#include "media_errors.h"
#include "surface_utils.h"
#include "tokenid_kit.h"
#include "video_recorder_taihe.h"
#include "media_taihe_utils.h"

using namespace ohos::multimedia::media;
using namespace OHOS::Security::AccessToken;
using namespace ANI::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "VideoRecorderTaiHe"};
}

namespace ANI {
namespace Media {
using namespace OHOS::MediaAVCodec;

const std::map<std::string_view, int32_t> g_mimeStrToCodecFormat = {
    { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC, OHOS::Media::AudioCodecFormat::AAC_LC },
    { OHOS::MediaAVCodec::CodecMimeType::VIDEO_AVC, OHOS::Media::VideoCodecFormat::H264 },
    { OHOS::MediaAVCodec::CodecMimeType::VIDEO_MPEG4, OHOS::Media::VideoCodecFormat::MPEG4 },
};


const std::map<std::string, OutputFormatType> g_extensionToOutputFormat = {
    { "mp4", OHOS::Media::OutputFormatType::FORMAT_MPEG_4 },
    { "m4a", OHOS::Media::OutputFormatType::FORMAT_M4A },
};

VideoRecorderImpl::VideoRecorderImpl()
{
    recorder_ = RecorderFactory::CreateRecorder();
    if (recorder_ == nullptr) {
        MEDIA_LOGE("failed to CreateRecorder");
        return;
    }
    callback_ = std::make_shared<RecorderCallbackTaihe>(true);
    (void)recorder_->SetRecorderCallback(callback_);
}

bool IsSystemApp()
{
    uint64_t accessTokenIDEx = OHOS::IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx);
    return isSystemApp;
}

bool SystemPermission()
{
    auto tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE ||
        tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        return true;
    }
    return IsSystemApp();
}

int32_t MapMimeToAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat)
{
    auto iter = g_mimeStrToCodecFormat.find(mime);
    if (iter != g_mimeStrToCodecFormat.end()) {
        codecFormat = static_cast<AudioCodecFormat>(iter->second);
    }
    return MSERR_INVALID_VAL;
}

int32_t MapMimeToVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    auto iter = g_mimeStrToCodecFormat.find(mime);
    if (iter != g_mimeStrToCodecFormat.end()) {
        codecFormat = static_cast<VideoCodecFormat>(iter->second);
    }
    return MSERR_INVALID_VAL;
}

int32_t MapExtensionNameToOutputFormat(const std::string &extension, OutputFormatType &type)
{
    auto iter = g_extensionToOutputFormat.find(extension);
    if (iter != g_extensionToOutputFormat.end()) {
        type = iter->second;
    }
    return MSERR_INVALID_VAL;
}

bool VideoRecorderImpl::IsSurfaceIdVaild(uint64_t surfaceID)
{
    auto surface = OHOS::SurfaceUtils::GetInstance()->GetSurface(surfaceID);
    if (surface == nullptr) {
        return false;
    }
    return true;
}

static void SignError(VideoRecorderAsyncContext *asyncCtx, int32_t code,
    const std::string &param1, const std::string &param2, const std::string &add = "")
{
    std::string message = MSExtErrorAPI9ToString(static_cast<MediaServiceExtErrCodeAPI9>(code), param1, param2) + add;
    asyncCtx->SignError(code, message);
}

void VideoRecorderAsyncContext::SignError(int32_t code, const std::string &message, bool del)
{
    errMessage = message;
    errCode = code;
    errFlag = true;
    delFlag = del;
    MEDIA_LOGE("SignError: %{public}s", message.c_str());
    set_business_error(errCode, errMessage);
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
    CHECK_AND_RETURN_RET_LOG(result >= LLONG_MIN && result <= LLONG_MAX, false,
        "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
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

VideoRecorder CreateVideoRecorderSync()
{
    MEDIA_LOGD("CreateVideoRecorder In");
    return make_holder<VideoRecorderImpl, VideoRecorder>();
}

string VideoRecorderImpl::GetInputSurfaceSync()
{
    MEDIA_LOGD("GetInputSurface In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;
    std::string surfaceId;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "GetInputSurface", "");
        return surfaceId;
    }

    asyncCtx->taihe->surface_ = asyncCtx->taihe->recorder_->GetSurface(asyncCtx->taihe->videoSourceID); // source id
    if (asyncCtx->taihe->surface_ != nullptr) {
        OHOS::SurfaceError error = OHOS::SurfaceUtils::GetInstance()->Add(asyncCtx->taihe->surface_->GetUniqueId(),
            asyncCtx->taihe->surface_);
        if (error != OHOS::SURFACE_ERROR_OK) {
            SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "GetInputSurface", "");
        }
        surfaceId = std::to_string(asyncCtx->taihe->surface_->GetUniqueId());
    } else {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "GetInputSurface", "");
    }
    asyncCtx.release();
    return MediaTaiheUtils::ToTaiheString(surfaceId);
}

void VideoRecorderImpl::PrepareSync(VideoRecorderConfig const& config)
{
    MEDIA_LOGD("VideoRecorderNapi Prepare In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    std::string urlPath = static_cast<std::string>(config.url);

    VideoRecorderProperties videoProperties;
    asyncCtx->taihe->GetConfig(config, asyncCtx, videoProperties);

    if (asyncCtx->taihe->GetVideoRecorderProperties(config, videoProperties) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_INVALID_PARAMETER, "prepare", "", "get videoProperties failed.");
    }

    if (asyncCtx->taihe->SetVideoRecorderProperties(asyncCtx, videoProperties) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_INVALID_PARAMETER, "prepare", "", "set videoProperties failed.");
    }
    if (asyncCtx->taihe->SetUrl(urlPath) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_INVALID_PARAMETER, "urlPath", "", "the url is not valid.");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "prepare", "");
        return;
    }
    if (asyncCtx->taihe->recorder_->Prepare() != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "prepare", "");
    }
    asyncCtx.release();
}

void VideoRecorderImpl::PauseSync()
{
    MEDIA_LOGD("Pause In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Pause", "");
        return;
    }
    if (asyncCtx->taihe->recorder_->Pause() != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Pause", "");
    }
    asyncCtx->taihe->currentStates_ = VideoRecorderState::STATE_PAUSED;
    asyncCtx.release();
}

void VideoRecorderImpl::StopSync()
{
    MEDIA_LOGD("Stop In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Stop", "");
        return;
    }
    if (asyncCtx->taihe->recorder_->Stop(false) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Stop", "");
    }
    asyncCtx->taihe->currentStates_ = VideoRecorderState::STATE_STOPPED;
    asyncCtx.release();
}

void VideoRecorderImpl::ResetSync()
{
    MEDIA_LOGD("Reset In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Stop", "");
        return;
    }
    if (asyncCtx->taihe->surface_ != nullptr) {
        auto id = asyncCtx->taihe->surface_->GetUniqueId();
        if (asyncCtx->taihe->IsSurfaceIdVaild(id)) {
            (void)OHOS::SurfaceUtils::GetInstance()->Remove(id);
        }
        asyncCtx->taihe->surface_ = nullptr;
    }
    if (asyncCtx->taihe->recorder_->Stop(false) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Reset", "");
    }
    asyncCtx->taihe->currentStates_ = VideoRecorderState::STATE_IDLE;
    asyncCtx.release();
}

void VideoRecorderImpl::ReleaseSync()
{
    MEDIA_LOGD("Release In");
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    if (asyncCtx->taihe == nullptr || asyncCtx->taihe->recorder_ == nullptr) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Stop", "");
        return;
    }
    if (asyncCtx->taihe->surface_ != nullptr) {
        auto id = asyncCtx->taihe->surface_->GetUniqueId();
        if (asyncCtx->taihe->IsSurfaceIdVaild(id)) {
            (void)OHOS::SurfaceUtils::GetInstance()->Remove(id);
        }
        asyncCtx->taihe->surface_ = nullptr;
    }
    if (asyncCtx->taihe->recorder_->Stop(false) != MSERR_OK) {
        SignError(asyncCtx.get(), MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Reset", "");
    }
    asyncCtx->taihe->currentStates_ = VideoRecorderState::STATE_IDLE;
    asyncCtx->taihe->CancelCallback();
    asyncCtx.release();
}

string VideoRecorderImpl::GetState()
{
    VideoRecorderImpl *impl = new VideoRecorderImpl();

    std::string curState = VideoRecorderState::STATE_ERROR;
    if (impl->callback_ != nullptr) {
        curState = impl->currentStates_;
        MEDIA_LOGD("GetState success, State: %{public}s", curState.c_str());
    }
    return MediaTaiheUtils::ToTaiheString(curState);
}

void VideoRecorderImpl::GetConfig(const VideoRecorderConfig &config, std::unique_ptr<VideoRecorderAsyncContext> &ctx,
    VideoRecorderProperties &properties)
{
    int32_t audioSource = AUDIO_SOURCE_INVALID;

    bool ret = static_cast<bool>(config.audioSourceType);
    if (ret) {
        properties.audioSourceType = static_cast<OHOS::Media::AudioSourceType>(audioSource);
    } else {
        ctx->taihe->isPureVideo = true;
        MEDIA_LOGI("No audioSource Type input!");
    }

    properties.videoSourceType =
        static_cast<OHOS::Media::VideoSourceType>(static_cast<int32_t>(config.videoSourceType));
    if (config.rotation.has_value()) {
        properties.orientationHint = static_cast<int32_t>(config.rotation.value());
    }

    properties.location.latitude = static_cast<float>(config.location->latitude);
    properties.location.longitude = static_cast<float>(config.location->longitude);
}

int32_t VideoRecorderImpl::GetVideoRecorderProperties(VideoRecorderConfig const& config,
    VideoRecorderProperties &properties)
{
    properties.profile.audioBitrate = static_cast<int32_t>(config.profile.audioBitrate);
    properties.profile.audioChannels = static_cast<int32_t>(config.profile.audioChannels);
    std::string audioCodec = static_cast<std::string>(config.profile.audioCodec);
    (void)MapMimeToAudioCodecFormat(audioCodec, properties.profile.audioCodecFormat);
    properties.profile.auidoSampleRate = static_cast<int32_t>(config.profile.audioSampleRate);
    std::string outputFile = static_cast<std::string>(config.profile.fileFormat);
    (void)MapExtensionNameToOutputFormat(outputFile, properties.profile.outputFormat);
    properties.profile.videoBitrate = static_cast<int32_t>(config.profile.videoBitrate);
    std::string videoCodec = static_cast<std::string>(config.profile.videoCodec);
    (void)MapMimeToVideoCodecFormat(videoCodec, properties.profile.videoCodecFormat);
    properties.profile.videoFrameWidth = static_cast<int32_t>(config.profile.videoFrameWidth);
    properties.profile.videoFrameHeight = static_cast<int32_t>(config.profile.videoFrameHeight);
    properties.profile.videoFrameRate = static_cast<int32_t>(config.profile.videoFrameRate);

    return MSERR_OK;
}

int32_t VideoRecorderImpl::SetVideoRecorderProperties(std::unique_ptr<VideoRecorderAsyncContext> &ctx,
    const VideoRecorderProperties &properties)
{
    int32_t ret;
    CHECK_AND_RETURN_RET(recorder_ != nullptr, MSERR_INVALID_OPERATION);
    if (ctx->taihe->isPureVideo != true) {
        ret = recorder_->SetAudioSource(properties.audioSourceType, ctx->taihe->audioSourceID);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set AudioSource");

        ret = recorder_->SetVideoSource(properties.videoSourceType, ctx->taihe->videoSourceID);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set VideoSource");

        ret = recorder_->SetOutputFormat(properties.profile.outputFormat);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set OutputFormat");

        ret = recorder_->SetAudioEncoder(ctx->taihe->audioSourceID, properties.profile.audioCodecFormat);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set audioCodec");

        ret = recorder_->SetAudioSampleRate(ctx->taihe->audioSourceID, properties.profile.auidoSampleRate);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set auidoSampleRate");

        ret = recorder_->SetAudioChannels(ctx->taihe->audioSourceID, properties.profile.audioChannels);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set audioChannels");

        ret = recorder_->SetAudioEncodingBitRate(ctx->taihe->audioSourceID, properties.profile.audioBitrate);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set audioBitrate");
    } else {
        ret = recorder_->SetVideoSource(properties.videoSourceType, ctx->taihe->videoSourceID);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set VideoSource");

        ret = recorder_->SetOutputFormat(properties.profile.outputFormat);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set OutputFormat");
    }
    ret = recorder_->SetVideoEncoder(ctx->taihe->videoSourceID, properties.profile.videoCodecFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set videoCodec");

    ret = recorder_->SetVideoSize(ctx->taihe->videoSourceID, properties.profile.videoFrameWidth,
        properties.profile.videoFrameHeight);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set videoSize");

    ret = recorder_->SetVideoFrameRate(ctx->taihe->videoSourceID, properties.profile.videoFrameRate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set videoFrameRate");

    ret = recorder_->SetVideoEncodingBitRate(ctx->taihe->videoSourceID, properties.profile.videoBitrate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_OPERATION, "Fail to set videoBitrate");

    recorder_->SetLocation(properties.location.latitude, properties.location.longitude);
    recorder_->SetOrientationHint(properties.orientationHint);
    return MSERR_OK;
}

int32_t VideoRecorderImpl::SetUrl(const std::string &urlPath)
{
    CHECK_AND_RETURN_RET_LOG(recorder_ != nullptr, MSERR_INVALID_OPERATION, "No memory");
    const std::string fdHead = "fd://";

    if (urlPath.find(fdHead) != std::string::npos) {
        int32_t fd = -1;
        std::string inputFd = urlPath.substr(fdHead.size());
        CHECK_AND_RETURN_RET(StrToInt(inputFd, fd) == true, MSERR_INVALID_VAL);
        CHECK_AND_RETURN_RET(fd >= 0, MSERR_INVALID_OPERATION);
        CHECK_AND_RETURN_RET(recorder_->SetOutputFile(fd) == MSERR_OK, MSERR_INVALID_OPERATION);
    } else {
        MEDIA_LOGE("invalid input uri, not a fd!");
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

void VideoRecorderImpl::CancelCallback()
{
    if (callback_ != nullptr) {
        auto taiheCb = std::static_pointer_cast<RecorderCallbackTaihe>(callback_);
        taiheCb->ClearCallbackReference();
    }
}

void VideoRecorderImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    VideoRecorderImpl *impl = new VideoRecorderImpl();
    auto asyncCtx = std::make_unique<VideoRecorderAsyncContext>();
    asyncCtx->taihe = impl;

    if (!SystemPermission()) {
        SignError(asyncCtx.get(),
            MSERR_EXT_API9_PERMISSION_DENIED, "CreateVideoRecorder", "system");
    }

    std::string callbackName = "error";
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    asyncCtx->taihe->SetCallbackReference(callbackName, autoRef);
}

void VideoRecorderImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    refMap_[callbackName] = ref;
    if (callback_ != nullptr) {
        auto taiheCb = std::static_pointer_cast<RecorderCallbackTaihe>(callback_);
        taiheCb->SaveCallbackReference(callbackName, ref);
    }
}
} // namespace Media
} // namespace ANI

TH_EXPORT_CPP_API_CreateVideoRecorderSync(CreateVideoRecorderSync);