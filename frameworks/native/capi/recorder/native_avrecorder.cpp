/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "avrecorder.h"
#include "avrecorder_extension.h"

#include <mutex>
#include <shared_mutex>

#include "media_log.h"
#include "string_ex.h"
#include "av_common.h"
#include "meta/meta.h"
#include "media_errors.h"
#include "surface_utils.h"
#include "native_window.h"
#include "media_asset_helper.h"
#include "native_player_magic.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_RECORDER, "NativeAVRecorder" };
}

using namespace OHOS;
using namespace OHOS::Media;

class NativeRecorderCallback;

struct RecorderObject : public OH_AVRecorder {
    explicit RecorderObject(const std::shared_ptr<Recorder>& recorder)
        : recorder_(recorder) {}
    ~RecorderObject()
    {
        ReleaseConfig(config_);
        ReleaseEncoderInfo(info_, length_);
    }

    void ReleaseConfig(OH_AVRecorder_Config *config)
    {
        if (config == nullptr) {
            return;
        }
        if (config->url) {
            free(config->url);
            config->url = nullptr;
        }
        if (config->metadata.videoOrientation) {
            free(config->metadata.videoOrientation);
            config->metadata.videoOrientation = nullptr;
        }
    }

    void ReleaseEncoderInfo(OH_AVRecorder_EncoderInfo *info, int32_t length)
    {
        if (info == nullptr || length <= 0) {
            return;
        }
        for (int i = 0; i < length; ++i) {
            free(info[i].sampleRate);
            info[i].sampleRate = nullptr;
            free(info[i].type);
            info[i].type = nullptr;
        }
        free(info);
        info = nullptr;
    }

    const std::shared_ptr<Recorder> recorder_ = nullptr;
    std::atomic<bool> isReleased_ = false;
    std::shared_ptr<NativeRecorderCallback> callback_ = nullptr;
    int32_t videoSourceId_ = -1;
    int32_t audioSourceId_ = -1;
    bool hasConfigured_ = false;
    OH_AVRecorder_Config *config_ = nullptr;
    OH_AVRecorder_EncoderInfo *info_ = nullptr;
    int32_t length_ = -1;
};


class NativeRecorderStateChangeCallback {
public:
    NativeRecorderStateChangeCallback(OH_AVRecorder_OnStateChange callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeRecorderStateChangeCallback() = default;

    void OnStateChange(struct OH_AVRecorder *recorder, OH_AVRecorder_State state,
        OH_AVRecorder_StateChangeReason reason)
    {
        CHECK_AND_RETURN(recorder != nullptr && callback_ != nullptr);
        callback_(recorder, state, reason, userData_);
    }

private:
    OH_AVRecorder_OnStateChange callback_;
    void *userData_;
};

class NativeRecorderErrorCallback {
public:
    NativeRecorderErrorCallback(OH_AVRecorder_OnError callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeRecorderErrorCallback() = default;

    void OnError(struct OH_AVRecorder *recorder, int32_t errorCode, const char *errorMsg)
    {
        CHECK_AND_RETURN(recorder != nullptr && callback_ != nullptr);
        callback_(recorder, errorCode, errorMsg, userData_);
    }

private:
    OH_AVRecorder_OnError callback_;
    void *userData_;
};

class NativeRecorderUriCallback {
public:
    NativeRecorderUriCallback(OH_AVRecorder_OnUri callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeRecorderUriCallback() = default;
 
    void OnUri(struct OH_AVRecorder *recorder, const std::string &uri)
    {
        CHECK_AND_RETURN_LOG(recorder != nullptr && callback_ != nullptr, "recorder or callback_ is nullptr!");
        auto mediaAssetHelper = Media::MediaAssetHelperFactory::CreateMediaAssetHelper();
        CHECK_AND_RETURN_LOG(mediaAssetHelper != nullptr, "Create mediaAssetHelper failed!");
 
        auto mediaAssetPtr = mediaAssetHelper->GetOhMediaAsset(uri);
        CHECK_AND_RETURN_LOG(mediaAssetPtr != nullptr, "mediaAssetPtr is nullptr!");

        OH_MediaAsset* mediaAsset = mediaAssetPtr.get();
        CHECK_AND_RETURN_LOG(mediaAsset != nullptr, "Create mediaAsset failed!");
 
        callback_(recorder, mediaAsset, userData_);
    }
 
private:
    OH_AVRecorder_OnUri callback_;
    void *userData_;
};

class NativeRecorderCallback : public RecorderCallback {
public:
    explicit NativeRecorderCallback(struct OH_AVRecorder *recorder) : recorder_(recorder) {}
    virtual ~NativeRecorderCallback() = default;

    void OnStateChange(OH_AVRecorder_State state, OH_AVRecorder_StateChangeReason reason)
    {
        MEDIA_LOGI("OnStateChange() is called, state: %{public}d", state);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(recorder_ != nullptr);

        if (stateChangeCallback_ != nullptr) {
            stateChangeCallback_->OnStateChange(recorder_, state, reason);
            return;
        }
    }

    void OnError(RecorderErrorType errorType, int32_t errorCode) override
    {
        MEDIA_LOGE("OnError() is called, errorType: %{public}d, errorCode: %{public}d", errorType, errorCode);
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(recorder_ != nullptr);

        if (errorCallback_ != nullptr) {
            errorCallback_->OnError(recorder_, errorCode, "error occurred!");
            return;
        }
    }

    void OnPhotoAssertAvailable(const std::string &uri) override
    {
        MEDIA_LOGI("OnPhotoAssertAvailable() is called, uri: %{public}s", uri.c_str());
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CHECK_AND_RETURN(recorder_ != nullptr);
 
        if (uriCallback_ != nullptr) {
            uriCallback_->OnUri(recorder_, uri);
            return;
        }
    }

    void OnInfo(int32_t type, int32_t extra) override
    {
        // No specific implementation is required and can be left blank.
    }

    bool SetStateChangeCallback(OH_AVRecorder_OnStateChange callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        stateChangeCallback_ = std::make_shared<NativeRecorderStateChangeCallback>(callback, userData);
        return stateChangeCallback_ != nullptr;
    }

    bool SetErrorCallback(OH_AVRecorder_OnError callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        errorCallback_ = std::make_shared<NativeRecorderErrorCallback>(callback, userData);
        return errorCallback_ != nullptr;
    }

    bool SetUriCallback(OH_AVRecorder_OnUri callback, void *userData)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        uriCallback_ = std::make_shared<NativeRecorderUriCallback>(callback, userData);
        return uriCallback_ != nullptr;
    }
 
private:
    std::shared_mutex mutex_;
    OH_AVRecorder *recorder_ = nullptr;
    std::shared_ptr<NativeRecorderStateChangeCallback> stateChangeCallback_ = nullptr;
    std::shared_ptr<NativeRecorderErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeRecorderUriCallback> uriCallback_ = nullptr;
};

OH_AVRecorder *OH_AVRecorder_Create(void)
{
    std::shared_ptr<Recorder> recorder = RecorderFactory::CreateRecorder();
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, nullptr, "failed to create recorder in RecorderFactory.");
    struct RecorderObject *recorderObj = new (std::nothrow) RecorderObject(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, nullptr, "failed to new RecorderObject");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVRecorder_Create", FAKE_POINTER(recorderObj));
    return recorderObj;
}

OH_AVErrCode SetProfile(OH_AVRecorder *recorder, OH_AVRecorder_Config *config)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    OutputFormatType outputFormat = static_cast<OutputFormatType>(config->profile.fileFormat);
    int32_t ret = recorderObj->recorder_->SetOutputFormat(outputFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set output format failed!");

    ret = recorderObj->recorder_->SetAudioEncodingBitRate(recorderObj->audioSourceId_, config->profile.audioBitrate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set audio encoding bitrate failed!");

    ret = recorderObj->recorder_->SetAudioChannels(recorderObj->audioSourceId_, config->profile.audioChannels);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set audio channels failed!");

    AudioCodecFormat audioCodec = static_cast<AudioCodecFormat>(config->profile.audioCodec);
    ret = recorderObj->recorder_->SetAudioEncoder(recorderObj->audioSourceId_, audioCodec);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set audio encoder failed!");

    ret = recorderObj->recorder_->SetAudioSampleRate(recorderObj->audioSourceId_, config->profile.audioSampleRate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set audio sample rate failed!");

    ret = recorderObj->recorder_->SetVideoEncodingBitRate(recorderObj->videoSourceId_, config->profile.videoBitrate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set video encoding bitrate failed!");

    VideoCodecFormat videoCodec = static_cast<VideoCodecFormat>(config->profile.videoCodec);
    ret = recorderObj->recorder_->SetVideoEncoder(recorderObj->videoSourceId_, videoCodec);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set video encoder failed!");

    ret = recorderObj->recorder_->SetVideoSize(recorderObj->videoSourceId_, config->profile.videoFrameWidth,
        config->profile.videoFrameHeight);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set video size failed!");

    ret = recorderObj->recorder_->SetVideoFrameRate(recorderObj->videoSourceId_, config->profile.videoFrameRate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set video frame rate failed!");

    if (config->profile.isHdr != true) {
        config->profile.isHdr = false;
    }
    ret = recorderObj->recorder_->SetVideoIsHdr(recorderObj->videoSourceId_, config->profile.isHdr);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "Set video IsHdr failed!");

    if (config->profile.enableTemporalScale != true) {
        config->profile.enableTemporalScale = false;
    }
    ret = recorderObj->recorder_->SetVideoEnableTemporalScale(recorderObj->videoSourceId_,
        config->profile.enableTemporalScale);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetVideoEnableTemporalScale failed!");
    
    return AV_ERR_OK;
}

OH_AVErrCode ConfigureUrl(OH_AVRecorder *recorder, OH_AVRecorder_Config *config)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    int32_t ret;
    if (!config->fileGenerationMode) {
        config->fileGenerationMode = OH_AVRecorder_FileGenerationMode::APP_CREATE;
    }
    FileGenerationMode fileGenerationMode = static_cast<FileGenerationMode>(config->fileGenerationMode);
    if (fileGenerationMode == FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
        ret = recorderObj->recorder_->SetFileGenerationMode(fileGenerationMode);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetFileGenerationMode failed!");
    } else {
        ret = MSERR_PARAMETER_VERIFICATION_FAILED;
        CHECK_AND_RETURN_RET_LOG(config->url != nullptr && config->url[0] != '\0', AV_ERR_INVALID_VAL,
            "config->url is null or empty!");
        std::string url = std::string(config->url);
        const std::string fdHead = "fd://";
        CHECK_AND_RETURN_RET_LOG(url.find(fdHead) != std::string::npos, AV_ERR_INVALID_VAL,
            "url wrong: missing 'fd://' prefix!");

        int32_t fd = -1; // -1 invalid value
        std::string inputFd = url.substr(fdHead.size());
        CHECK_AND_RETURN_RET_LOG(StrToInt(inputFd, fd) == true && fd >= 0, AV_ERR_INVALID_VAL,
            "url wrong: invalid file descriptor in url!");

        ret = recorderObj->recorder_->SetOutputFile(fd);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetOutputFile failed!");
    }

    return AV_ERR_OK;
}

int32_t GetVideoOrientation(const char* videoOrientation)
{
    std::unordered_map<std::string, int32_t> validOrientations = {
        {"0", 0},       // videoOrientation set to 0 degree
        {"90", 90},     // videoOrientation set to 90 degrees
        {"180", 180},   // videoOrientation set to 180 degrees
        {"270", 270}    // videoOrientation set to 270 degrees
    };

    if (videoOrientation == nullptr || videoOrientation[0] == '\0') {
        return 0; // 0 default value
    }

    auto it = validOrientations.find(videoOrientation);
    if (it != validOrientations.end()) {
        return it->second;
    } else {
        MEDIA_LOGE("Invalid videoOrientation value: %{public}s. Must be 0, 90, 180, or 270.",
                   videoOrientation);
        return -1; // -1 invalid value
    }
}

OH_AVErrCode Configure(OH_AVRecorder *recorder, OH_AVRecorder_Config *config)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    if (recorderObj->hasConfigured_) {
        MEDIA_LOGE("OH_AVRecorder_Config has been configured and will not be configured again.");
        return AV_ERR_OK;
    }

    AudioSourceType audioSourceType = static_cast<AudioSourceType>(config->audioSourceType);
    int32_t ret = recorderObj->recorder_->SetAudioSource(audioSourceType, recorderObj->audioSourceId_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL,
        "The audio parameter is not supported. Please check the type and range.");

    VideoSourceType videoSourceType = static_cast<VideoSourceType>(config->videoSourceType);
    ret = recorderObj->recorder_->SetVideoSource(videoSourceType, recorderObj->videoSourceId_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL,
        "The video parameter is not supported. Please check the type and range.");

    OH_AVErrCode err = SetProfile(recorder, config);
    CHECK_AND_RETURN_RET_LOG(err == AV_ERR_OK, AV_ERR_INVALID_VAL, "SetProfile failed!");

    int32_t videoOrientation = GetVideoOrientation(config->metadata.videoOrientation);
    if (videoOrientation == -1) { // -1 invalid value
        return AV_ERR_INVALID_VAL;
    }
    recorderObj->recorder_->SetOrientationHint(videoOrientation);

    CHECK_AND_RETURN_RET_LOG(config->metadata.location.latitude >= MIN_LATITUDE &&
        config->metadata.location.latitude <= MAX_LATITUDE && config->metadata.location.longitude >= MIN_LONGITUDE &&
        config->metadata.location.longitude <= MAX_LONGITUDE, AV_ERR_INVALID_VAL,
        "Invalid latitude or longitude! Latitude: %{public}.6f, Longitude: %{public}.6f",
        config->metadata.location.latitude, config->metadata.location.longitude);
    recorderObj->recorder_->SetLocation(config->metadata.location.latitude, config->metadata.location.longitude);

    if (config->metadata.genre != nullptr && config->metadata.genre[0] != '\0') {
        std::string genre = config->metadata.genre;
        ret = recorderObj->recorder_->SetGenre(genre);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetGenre failed!");
    }

    err = ConfigureUrl(recorder, config);
    CHECK_AND_RETURN_RET_LOG(err == AV_ERR_OK, AV_ERR_INVALID_VAL, "ConfigureUrl failed!");

    recorderObj->hasConfigured_ = true;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Prepare(OH_AVRecorder *recorder, OH_AVRecorder_Config *config)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL, "input config is nullptr!");

    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");
    
    int32_t ret = Configure(recorder, config);
    ret = recorderObj->recorder_->Prepare();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Prepare failed");

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::PREPARED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::PREPARED, OH_AVRecorder_StateChangeReason::USER);
    return AV_ERR_OK;
}

Location ConvertToLocation(const OH_AVRecorder_Location &ohLocation)
{
    Location location;
    location.latitude = static_cast<float>(ohLocation.latitude);
    location.longitude = static_cast<float>(ohLocation.longitude);
    return location;
}

OH_AVErrCode OH_AVRecorder_GetAVRecorderConfig(OH_AVRecorder *recorder, OH_AVRecorder_Config **config)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL, "config is nullptr!");
    CHECK_AND_RETURN_RET_LOG(*config != nullptr, AV_ERR_INVALID_VAL, "*config is nullptr!");

    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    recorderObj->ReleaseConfig(recorderObj->config_);
    recorderObj->config_ = *config;

    ConfigMap configMap;
    recorderObj->recorder_->GetAVRecorderConfig(configMap);

    OH_AVRecorder_Location ohlocation = {0.0f, 0.0f};
    Location location = ConvertToLocation(ohlocation);
    recorderObj->recorder_->GetLocation(location);

    recorderObj->config_->profile.audioBitrate = configMap["audioBitrate"];
    recorderObj->config_->profile.audioChannels = configMap["audioChannels"];
    recorderObj->config_->profile.audioCodec = static_cast<OH_AVRecorder_CodecMimeType>(configMap["audioCodec"]);
    recorderObj->config_->profile.audioSampleRate = configMap["audioSampleRate"];
    recorderObj->config_->profile.fileFormat =
        static_cast<OH_AVRecorder_ContainerFormatType>(configMap["fileFormat"]);
    recorderObj->config_->profile.videoBitrate = configMap["videoBitrate"];
    recorderObj->config_->profile.videoCodec = static_cast<OH_AVRecorder_CodecMimeType>(configMap["videoCodec"]);
    recorderObj->config_->profile.videoFrameHeight = configMap["videoFrameHeight"];
    recorderObj->config_->profile.videoFrameWidth = configMap["videoFrameWidth"];
    recorderObj->config_->profile.videoFrameRate = configMap["videoFrameRate"];

    recorderObj->config_->audioSourceType = static_cast<OH_AVRecorder_AudioSourceType>(configMap["audioSourceType"]);
    recorderObj->config_->videoSourceType = static_cast<OH_AVRecorder_VideoSourceType>(configMap["videoSourceType"]);

    const std::string fdHead = "fd://";
    recorderObj->config_->url = strdup((fdHead + std::to_string(configMap["url"])).c_str());
    CHECK_AND_RETURN_RET_LOG(recorderObj->config_->url != nullptr, AV_ERR_NO_MEMORY,
        "Failed to allocate memory for url string!");

    std::string videoOrientation = std::to_string(configMap["rotation"]);
    recorderObj->config_->metadata.videoOrientation = strdup(videoOrientation.c_str());
    CHECK_AND_RETURN_RET_LOG(recorderObj->config_->metadata.videoOrientation != nullptr, AV_ERR_NO_MEMORY,
        "Failed to allocate memory for videoOrientation string!");

    recorderObj->config_->metadata.location.latitude = location.latitude;
    recorderObj->config_->metadata.location.longitude = location.longitude;

    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_GetInputSurface(OH_AVRecorder *recorder, OHNativeWindow **window)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window != nullptr, AV_ERR_INVALID_VAL, "window pointer is nullptr!");

    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    sptr<OHOS::Surface> surface = recorderObj->recorder_->GetSurface(recorderObj->videoSourceId_);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, AV_ERR_INVALID_VAL, "surface is nullptr!");

    (*window) = CreateNativeWindowFromSurface(&surface);
    CHECK_AND_RETURN_RET_LOG(*window != nullptr, AV_ERR_INVALID_VAL, "*window pointer is nullptr!");
    CHECK_AND_RETURN_RET_LOG((*window)->surface != nullptr, AV_ERR_INVALID_VAL, "failed to get surface from recorder");

    SurfaceError error = SurfaceUtils::GetInstance()->Add((*window)->surface->GetUniqueId(), (*window)->surface);
    CHECK_AND_RETURN_RET_LOG(error == SURFACE_ERROR_OK, AV_ERR_INVALID_VAL, "failed to AddSurface");

    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_UpdateRotation(OH_AVRecorder *recorder, int32_t rotation)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");
    CHECK_AND_RETURN_RET_LOG(rotation == ROTATION_0 || rotation == ROTATION_90 || rotation == ROTATION_180 ||
        rotation == ROTATION_270, AV_ERR_INVALID_VAL, "Invalid rotation value. Must be 0, 90, 180, or 270.");
    recorderObj->recorder_->SetOrientationHint(rotation);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Start(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    int32_t ret = recorderObj->recorder_->Start();
    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");

    if (ret != MSERR_OK) {
        MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::ERROR);
        recorderObj->callback_->OnStateChange(OH_AVRecorder_State::ERROR, OH_AVRecorder_StateChangeReason::USER);
    }
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_OPERATE_NOT_PERMIT, "StartRecorder failed!");

    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::STARTED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::STARTED, OH_AVRecorder_StateChangeReason::USER);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Pause(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    int32_t ret = recorderObj->recorder_->Pause();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Pause failed");

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::PAUSED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::PAUSED, OH_AVRecorder_StateChangeReason::USER);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Resume(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    int32_t ret = recorderObj->recorder_->Resume();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Resume failed");

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::STARTED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::STARTED, OH_AVRecorder_StateChangeReason::USER);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Stop(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    bool block = false;
    int32_t ret = recorderObj->recorder_->Stop(block);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Stop failed");

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::STOPPED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::STOPPED, OH_AVRecorder_StateChangeReason::USER);

    recorderObj->hasConfigured_ = false;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Reset(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    int32_t ret = recorderObj->recorder_->Reset();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Reset failed");

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::IDLE);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::IDLE, OH_AVRecorder_StateChangeReason::USER);

    recorderObj->hasConfigured_ = false;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_Release(OH_AVRecorder *recorder)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");

    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    CHECK_AND_RETURN_RET_LOG(!recorderObj->isReleased_.load(), AV_ERR_OK, "recorder already isReleased");

    int32_t ret = recorderObj->recorder_->Release();
    recorderObj->isReleased_.store(true);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "recorder Release failed");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVRecorder_Release", FAKE_POINTER(recorderObj));

    CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL,
        "recorderObj->callback_ is nullptr!");
    MEDIA_LOGI("Change state to state code: %{public}d", OH_AVRecorder_State::RELEASED);
    recorderObj->callback_->OnStateChange(OH_AVRecorder_State::RELEASED, OH_AVRecorder_StateChangeReason::USER);
    
    recorderObj->hasConfigured_ = false;
    delete recorderObj;
    recorderObj = nullptr;
    recorder = nullptr;
    return AV_ERR_OK;
}

OH_AVRecorder_CodecMimeType ConvertMimeType(const std::string &mimeType)
{
    static const std::unordered_map<std::string, OH_AVRecorder_CodecMimeType> mimeTypeMap = {
        {"video/avc", OH_AVRecorder_CodecMimeType::VIDEO_AVC},
        {"video/mp4v-es", OH_AVRecorder_CodecMimeType::VIDEO_MPEG4},
        {"video/hevc", OH_AVRecorder_CodecMimeType::VIDEO_HEVC},
        {"audio/mp4a-latm", OH_AVRecorder_CodecMimeType::AUDIO_AAC},
        {"audio/mpeg", OH_AVRecorder_CodecMimeType::AUDIO_MP3},
        {"audio/g711mu", OH_AVRecorder_CodecMimeType::AUDIO_G711MU}
    };

    auto it = mimeTypeMap.find(mimeType);
    if (it != mimeTypeMap.end()) {
        return it->second;
    }
    return OH_AVRecorder_CodecMimeType::VIDEO_AVC;
}

void ConvertEncoderInfo(const EncoderCapabilityData &src, OH_AVRecorder_EncoderInfo &dest)
{
    dest.mimeType = ConvertMimeType(src.mimeType);

    dest.type = strdup(src.type.c_str());
    CHECK_AND_RETURN_LOG(dest.type != nullptr, "Failed to allocate memory for type string!");

    dest.bitRate.min = src.bitrate.minVal;
    dest.bitRate.max = src.bitrate.maxVal;

    dest.frameRate.min = src.frameRate.minVal;
    dest.frameRate.max = src.frameRate.maxVal;

    dest.width.min = src.width.minVal;
    dest.width.max = src.width.maxVal;

    dest.height.min = src.height.minVal;
    dest.height.max = src.height.maxVal;

    dest.channels.min = src.channels.minVal;
    dest.channels.max = src.channels.maxVal;

    dest.sampleRateLen = static_cast<int32_t>(src.sampleRate.size());
    if (dest.sampleRateLen == 0) {
        dest.sampleRate = nullptr;
        return;
    }
    dest.sampleRate = (int32_t *)malloc(dest.sampleRateLen * sizeof(int32_t));
    CHECK_AND_RETURN_LOG(dest.sampleRate != nullptr, "Failed to allocate memory for sampleRate array!");
    for (int j = 0; j < dest.sampleRateLen; ++j) {
        dest.sampleRate[j] = src.sampleRate[j];
    }
}

OH_AVErrCode OH_AVRecorder_GetAvailableEncoder(OH_AVRecorder *recorder,
    OH_AVRecorder_EncoderInfo **info, int32_t *length)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(info != nullptr, AV_ERR_INVALID_VAL, "input info is nullptr!");

    struct RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");
    
    recorderObj->ReleaseEncoderInfo(recorderObj->info_, recorderObj->length_);

    std::vector<EncoderCapabilityData> encoderInfo;
    int32_t ret = recorderObj->recorder_->GetAvailableEncoder(encoderInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK || !encoderInfo.empty(),
        AV_ERR_INVALID_VAL, "GetAvailableEncoder failed!");
    
    int32_t count = 0;
    for (size_t i = 0; i < encoderInfo.size(); ++i) {
        ++count;
    }
    recorderObj->length_ = count;
    *length = recorderObj->length_;

    CHECK_AND_RETURN_RET_LOG(*length > 0, AV_ERR_INVALID_VAL, "Invalid length, should be larger than zero!");
    recorderObj->info_ = (OH_AVRecorder_EncoderInfo *)malloc(*length * sizeof(OH_AVRecorder_EncoderInfo));
    CHECK_AND_RETURN_RET_LOG(recorderObj->info_ != nullptr, AV_ERR_NO_MEMORY, "Memory allocation failed for info!");

    for (size_t i = 0; i < encoderInfo.size(); ++i) {
        const EncoderCapabilityData &src = encoderInfo[i];
        OH_AVRecorder_EncoderInfo &dest = (recorderObj->info_)[i];
        ConvertEncoderInfo(src, dest);
    }

    *info = recorderObj->info_;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_SetStateCallback(OH_AVRecorder *recorder,
    OH_AVRecorder_OnStateChange callback, void *userData)
{
    MEDIA_LOGD("OH_AVRecorder_SetStateCallback Start");
    
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "input stateCallback is nullptr!");

    RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    if (recorderObj->callback_ == nullptr) {
        recorderObj->callback_ = std::make_shared<NativeRecorderCallback>(recorder);
        CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "callback_ is nullptr!");
        int32_t ret = recorderObj->recorder_->SetRecorderCallback(recorderObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetRecorderCallback failed!");
    }
    
    if (recorderObj->callback_ == nullptr || !recorderObj->callback_->SetStateChangeCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVRecorder_SetStateCallback error");
        return AV_ERR_NO_MEMORY;
    }

    MEDIA_LOGD("OH_AVRecorder_SetStateCallback End");

    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_SetErrorCallback(OH_AVRecorder *recorder, OH_AVRecorder_OnError callback, void *userData)
{
    MEDIA_LOGD("OH_AVRecorder_SetErrorCallback Start");
    
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "input errorCallback is nullptr!");

    RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");

    if (recorderObj->callback_ == nullptr) {
        recorderObj->callback_ = std::make_shared<NativeRecorderCallback>(recorder);
        CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "callback_ is nullptr!");
        int32_t ret = recorderObj->recorder_->SetRecorderCallback(recorderObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetRecorderCallback failed!");
    }

    if (recorderObj->callback_ == nullptr || !recorderObj->callback_->SetErrorCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVRecorder_SetErrorCallback error");
        return AV_ERR_NO_MEMORY;
    }

    MEDIA_LOGD("OH_AVRecorder_SetErrorCallback End");

    return AV_ERR_OK;
}

OH_AVErrCode OH_AVRecorder_SetUriCallback(OH_AVRecorder *recorder, OH_AVRecorder_OnUri callback, void *userData)
{
    MEDIA_LOGD("OH_AVRecorder_SetUriCallback Start");
 
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, AV_ERR_INVALID_VAL, "input recorder is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "input errorCallback is nullptr!");
 
    RecorderObject *recorderObj = reinterpret_cast<RecorderObject *>(recorder);
    CHECK_AND_RETURN_RET_LOG(recorderObj != nullptr, AV_ERR_INVALID_VAL, "recorderObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(recorderObj->recorder_ != nullptr, AV_ERR_INVALID_VAL, "recorder_ is null");
 
    if (recorderObj->callback_ == nullptr) {
        recorderObj->callback_ = std::make_shared<NativeRecorderCallback>(recorder);
        CHECK_AND_RETURN_RET_LOG(recorderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "callback_ is nullptr!");
        int32_t ret = recorderObj->recorder_->SetRecorderCallback(recorderObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetRecorderCallback failed!");
    }
 
    if (recorderObj->callback_ == nullptr || !recorderObj->callback_->SetUriCallback(callback, userData)) {
        MEDIA_LOGE("OH_AVRecorder_SetUriCallback error");
        return AV_ERR_NO_MEMORY;
    }
 
    MEDIA_LOGD("OH_AVRecorder_SetUriCallback End");
 
    return AV_ERR_OK;
}
