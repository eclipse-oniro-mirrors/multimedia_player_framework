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
#include <mutex>
#include <optional>
#include <string_view>

#include "avtranscoder.h"
#include "media_log.h"
#include "media_errors.h"
#include "native_player_magic.h"
#include "transcoder.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NativeAVTranscoder"};
    constexpr uint32_t ERROR_EXT_API_MAP_LENGTH = 23;
}

using namespace OHOS;
using namespace OHOS::Media;
using namespace OHOS::MediaAVCodec;

constexpr int32_t AVTRANSCODER_DEFAULT_AUDIO_BIT_RATE = INT32_MAX;
constexpr int32_t AVTRANSCODER_DEFAULT_VIDEO_BIT_RATE = -1;
constexpr int32_t AVTRANSCODER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t AVTRANSCODER_DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t AVTRANSCODER_DEFAULT_FD = -1;
constexpr int64_t AVTRANSCODER_DEFAULT_OFFSET = -1;
constexpr int64_t AVTRANSCODER_DEFAULT_LENGTH = -1;
constexpr int32_t MIN_PROGRESS = 0;
constexpr int32_t MAX_PROGRESS = 100;

namespace AVTranscoderOpts {
const std::string PREPARE = "Prepare";
const std::string START = "Start";
const std::string CANCEL = "Cancel";
const std::string RESUME = "Resume";
const std::string PAUSE = "Pause";
const std::string RELEASE = "Release";
}

namespace NativeTranscoderState {
const std::string IDLE = "idle";
const std::string PREPARED = "prepared";
const std::string STARTED = "started";
const std::string PAUSED = "paused";
const std::string CANCELLED = "cancelled";
const std::string COMPLETED = "completed";
const std::string RELEASED = "released";
const std::string ERROR = "error";
}


static const std::map<OH_AVTranscoder_State, std::string> STATE_MAP = {
    {OH_AVTranscoder_State::AVTRANSCODER_STARTED, NativeTranscoderState::STARTED},
    {OH_AVTranscoder_State::AVTRANSCODER_PREPARED, NativeTranscoderState::PREPARED},
    {OH_AVTranscoder_State::AVTRANSCODER_PAUSED, NativeTranscoderState::PAUSED},
    {OH_AVTranscoder_State::AVTRANSCODER_CANCELLED, NativeTranscoderState::CANCELLED},
    {OH_AVTranscoder_State::AVTRANSCODER_COMPLETED, NativeTranscoderState::COMPLETED},
};

static const std::map<std::string, std::vector<std::string>> STATE_LIST = {
    {NativeTranscoderState::IDLE, {
        AVTranscoderOpts::PREPARE,
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::PREPARED, {
        AVTranscoderOpts::START,
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::STARTED, {
        AVTranscoderOpts::CANCEL,
        AVTranscoderOpts::PAUSE,
        AVTranscoderOpts::RELEASE,
        AVTranscoderOpts::START,
        AVTranscoderOpts::RESUME,
    }},
    {NativeTranscoderState::PAUSED, {
        AVTranscoderOpts::START,
        AVTranscoderOpts::PAUSE,
        AVTranscoderOpts::RESUME,
        AVTranscoderOpts::CANCEL,
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::CANCELLED, {
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::COMPLETED, {
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::RELEASED, {
        AVTranscoderOpts::RELEASE,
    }},
    {NativeTranscoderState::ERROR, {
        AVTranscoderOpts::RELEASE,
    }},
};

const std::map<std::string, std::vector<std::string>> STATE_CTRL = {
    {NativeTranscoderState::IDLE, {}},
    {NativeTranscoderState::PREPARED, {}},
    {NativeTranscoderState::STARTED, {
        AVTranscoderOpts::START,
        AVTranscoderOpts::RESUME
    }},
    {NativeTranscoderState::PAUSED, {
        AVTranscoderOpts::PAUSE
    }},
    {NativeTranscoderState::CANCELLED, {
        AVTranscoderOpts::CANCEL
    }},
    {NativeTranscoderState::RELEASED, {
        AVTranscoderOpts::RELEASE
    }},
    {NativeTranscoderState::COMPLETED, {}},
    {NativeTranscoderState::ERROR, {}},
};

static const std::map<std::string_view, VideoCodecFormat> MIME_STR_TO_VIDEO_CODEC_FORMAT = {
    { CodecMimeType::VIDEO_AVC, VideoCodecFormat::H264 },
    { CodecMimeType::VIDEO_HEVC, VideoCodecFormat::H265 },
    { "", VideoCodecFormat::VIDEO_DEFAULT },
};

static const std::map<std::string_view, AudioCodecFormat> MIME_STR_TO_AUDIO_CODEC_FORMAT = {
    { CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
    { "", AudioCodecFormat::AUDIO_DEFAULT },
};

static const std::map<OH_AVOutputFormat, OutputFormatType> AV_OUTPUT_FORMAT_TO_OUTPUT_FORMAT_TYPE = {
    { OH_AVOutputFormat::AV_OUTPUT_FORMAT_MPEG_4, OutputFormatType::FORMAT_MPEG_4 },
    { OH_AVOutputFormat::AV_OUTPUT_FORMAT_M4A, OutputFormatType::FORMAT_M4A },
};

typedef struct TranscoderExtErrCodeAPIConvert {
    MediaServiceExtErrCodeAPI9 extErrCodeAPI;
    OH_AVErrCode avErrorCode;
} TranscoderExtErrCodeAPIConvert;

static const TranscoderExtErrCodeAPIConvert ERROR_EXT_API_MAP[ERROR_EXT_API_MAP_LENGTH] = {
    {MSERR_EXT_API9_OK, AV_ERR_OK},
    {MSERR_EXT_API9_NO_PERMISSION, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_PERMISSION_DENIED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_INVALID_PARAMETER, AV_ERR_INVALID_VAL},
    {MSERR_EXT_API9_UNSUPPORT_CAPABILITY, AV_ERR_UNSUPPORT},
    {MSERR_EXT_API9_NO_MEMORY, AV_ERR_NO_MEMORY},
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_IO, AV_ERR_IO},
    {MSERR_EXT_API9_TIMEOUT, AV_ERR_TIMEOUT},
    {MSERR_EXT_API9_SERVICE_DIED, AV_ERR_SERVICE_DIED},
    {MSERR_EXT_API9_UNSUPPORT_FORMAT, AV_ERR_UNSUPPORT},
    {MSERR_EXT_API9_AUDIO_INTERRUPTED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API14_IO_CANNOT_FIND_HOST, AV_ERR_IO_CANNOT_FIND_HOST},
    {MSERR_EXT_API14_IO_CONNECTION_TIMEOUT, AV_ERR_IO_CONNECTION_TIMEOUT},
    {MSERR_EXT_API14_IO_NETWORK_ABNORMAL, AV_ERR_IO_NETWORK_ABNORMAL},
    {MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE, AV_ERR_IO_NETWORK_UNAVAILABLE},
    {MSERR_EXT_API14_IO_NO_PERMISSION, AV_ERR_IO_NO_PERMISSION},
    {MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED, AV_ERR_IO_NETWORK_ACCESS_DENIED},
    {MSERR_EXT_API14_IO_RESOURE_NOT_FOUND, AV_ERR_IO_RESOURCE_NOT_FOUND},
    {MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED, AV_ERR_IO_SSL_CLIENT_CERT_NEEDED},
    {MSERR_EXT_API14_IO_SSL_CONNECT_FAIL, AV_ERR_IO_SSL_CONNECT_FAIL},
    {MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED, AV_ERR_IO_SSL_SERVER_CERT_UNTRUSTED},
    {MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST, AV_ERR_IO_UNSUPPORTED_REQUEST},
};

static OH_AVErrCode ExtErrCodeAPIToAVErrCode(MediaServiceExtErrCodeAPI9 errorCode)
{
    for (uint32_t i = 0; i < ERROR_EXT_API_MAP_LENGTH; i++) {
        if (ERROR_EXT_API_MAP[i].extErrCodeAPI == errorCode) {
            return ERROR_EXT_API_MAP[i].avErrorCode;
        }
    }
    return AV_ERR_UNKNOWN;
}

static std::optional<std::string> IsValidState(OH_AVTranscoder_State state)
{
    std::optional<std::string> res{ std::nullopt };
    auto stateMapIt = STATE_MAP.find(state);
    CHECK_AND_RETURN_RET_LOG(stateMapIt != STATE_MAP.end(), res,
        "IsValidState is called, current OH_AVTranscoder_State is invalid!");
    auto stateListIt = STATE_LIST.find(stateMapIt->second);
    CHECK_AND_RETURN_RET_LOG(stateListIt != STATE_LIST.end(), res,
        "IsValidState is called, current Native state is invalid!");
    return stateListIt->first;
}

static OH_AVErrCode GetOHAVErrCode(int32_t errCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 extErrCodeAPI = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    OH_AVErrCode avErrorCode = ExtErrCodeAPIToAVErrCode(extErrCodeAPI);
    std::string errorMsgExt = MSExtAVErrorToString(extErrCodeAPI) + errorMsg;
    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s check failed!", avErrorCode, errorMsgExt.c_str());
    return avErrorCode;
}

class NativeAVTranscoderOnStateChangeCallback {
public:
    NativeAVTranscoderOnStateChangeCallback(OH_AVTranscoder_OnStateChange callback, void* userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeAVTranscoderOnStateChangeCallback() = default;

    void OnStateChangeCallback(OH_AVTranscoder *transcoder, OH_AVTranscoder_State state)
    {
        CHECK_AND_RETURN(transcoder != nullptr && callback_ != nullptr);
        callback_(transcoder, state, userData_);
    }

private:
    OH_AVTranscoder_OnStateChange callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeAVTranscoderOnErrorCallback {
public:
    NativeAVTranscoderOnErrorCallback(OH_AVTranscoder_OnError callback, void* userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeAVTranscoderOnErrorCallback() = default;

    void OnErrorCallback(OH_AVTranscoder *transcoder, int32_t errorCode, const char *errorMsg)
    {
        CHECK_AND_RETURN(transcoder != nullptr && callback_ != nullptr);
        callback_(transcoder, errorCode, errorMsg, userData_);
    }

private:
    OH_AVTranscoder_OnError callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeAVTranscoderOnProgressUpdateCallback {
public:
    NativeAVTranscoderOnProgressUpdateCallback(OH_AVTranscoder_OnProgressUpdate callback, void* userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeAVTranscoderOnProgressUpdateCallback() = default;

    void OnProgressUpdateCallback(OH_AVTranscoder *transcoder, int progress)
    {
        CHECK_AND_RETURN(transcoder != nullptr && callback_ != nullptr);
        CHECK_AND_RETURN(progress >= MIN_PROGRESS && progress <= MAX_PROGRESS);
        callback_(transcoder, progress, userData_);
    }

private:
    OH_AVTranscoder_OnProgressUpdate callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeAVTranscoderCallback : public TransCoderCallback {
public:
    explicit NativeAVTranscoderCallback(OH_AVTranscoder *transcoder);
    virtual ~NativeAVTranscoderCallback() = default;

    OH_AVErrCode SetOnStateChangeCallback(OH_AVTranscoder_OnStateChange callback, void *userData);
    OH_AVErrCode SetOnErrorCallback(OH_AVTranscoder_OnError callback, void *userData);
    OH_AVErrCode SetOnProgressUpdateCallback(OH_AVTranscoder_OnProgressUpdate callback, void *userData);
    OH_AVErrCode IsValidOpt(const std::string &opt);
    OH_AVErrCode IsRepeatOpt(const std::string &opt);
    void OnStateChangeCallback(OH_AVTranscoder_State state);
    void OnProgressUpdateCallback(int32_t progress);

protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;

private:
    std::mutex mutex_;
    OH_AVTranscoder *transcoder_ = nullptr;
    std::shared_ptr<NativeAVTranscoderOnErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeAVTranscoderOnStateChangeCallback> stateChangeCallback_ = nullptr;
    std::shared_ptr<NativeAVTranscoderOnProgressUpdateCallback> progressUpdateCallback_ = nullptr;

    std::string state_ = NativeTranscoderState::IDLE;
    int32_t progress_ = MIN_PROGRESS;
};

struct NativeAVTranscoderConfig : public OH_AVTranscoder_Config {
    NativeAVTranscoderConfig() = default;
    ~NativeAVTranscoderConfig() = default;

    int32_t srcFd = AVTRANSCODER_DEFAULT_FD;
    int64_t srcOffset = AVTRANSCODER_DEFAULT_OFFSET;
    int64_t length = AVTRANSCODER_DEFAULT_LENGTH;
    int32_t dstFd = AVTRANSCODER_DEFAULT_FD;
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT;
    int32_t audioBitrate = AVTRANSCODER_DEFAULT_AUDIO_BIT_RATE;
    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;
    int32_t videoBitrate = AVTRANSCODER_DEFAULT_VIDEO_BIT_RATE;
    int32_t videoFrameWidth = AVTRANSCODER_DEFAULT_FRAME_HEIGHT;
    int32_t videoFrameHeight = AVTRANSCODER_DEFAULT_FRAME_WIDTH;
    bool enableBFrame = false;
};

struct NativeAVTranscoder : public OH_AVTranscoder {
    explicit NativeAVTranscoder(const std::shared_ptr<TransCoder> &transcoder);
    ~NativeAVTranscoder() = default;

    OH_AVErrCode AVTranscoderConfiguration(NativeAVTranscoderConfig *config);
    OH_AVErrCode CheckStateMachine(const std::string &opt);
    OH_AVErrCode CheckRepeatOptions(const std::string &opt);
    OH_AVErrCode OnStateChange(OH_AVTranscoder_State state);
    OH_AVErrCode SetTranscoderCallback();

    std::shared_ptr<TransCoderCallback> transcoderCb_ = nullptr;
    const std::shared_ptr<TransCoder> transcoder_ = nullptr;
};

NativeAVTranscoderCallback::NativeAVTranscoderCallback(OH_AVTranscoder *transcoder)
    : transcoder_(transcoder)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " NativeAVTranscoderCallback create", FAKE_POINTER(this));
}

OH_AVErrCode NativeAVTranscoderCallback::SetOnErrorCallback(OH_AVTranscoder_OnError callback, void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback != nullptr) {
        NativeAVTranscoderOnErrorCallback *errorCallback =
            new (std::nothrow) NativeAVTranscoderOnErrorCallback(callback, userData);
        CHECK_AND_RETURN_RET_LOG(errorCallback != nullptr, AV_ERR_NO_MEMORY, "errorCallback is nullptr!");
        errorCallback_ = std::shared_ptr<NativeAVTranscoderOnErrorCallback>(errorCallback);
    } else {
        errorCallback_ = nullptr;
    }
    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoderCallback::SetOnStateChangeCallback(OH_AVTranscoder_OnStateChange callback,
                                                                  void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback != nullptr) {
        NativeAVTranscoderOnStateChangeCallback *stateChangeCallback =
            new (std::nothrow) NativeAVTranscoderOnStateChangeCallback(callback, userData);
        CHECK_AND_RETURN_RET_LOG(stateChangeCallback != nullptr, AV_ERR_NO_MEMORY, "stateChangeCallback is nullptr!");
        stateChangeCallback_ = std::shared_ptr<NativeAVTranscoderOnStateChangeCallback>(stateChangeCallback);
    } else {
        stateChangeCallback_ = nullptr;
    }
    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoderCallback::SetOnProgressUpdateCallback(OH_AVTranscoder_OnProgressUpdate callback,
                                                                     void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback != nullptr) {
        NativeAVTranscoderOnProgressUpdateCallback *progressUpdateCallback =
            new (std::nothrow) NativeAVTranscoderOnProgressUpdateCallback(callback, userData);
        CHECK_AND_RETURN_RET_LOG(progressUpdateCallback != nullptr, AV_ERR_NO_MEMORY,
            "progressUpdateCallback is nullptr!");
        progressUpdateCallback_ = std::shared_ptr<NativeAVTranscoderOnProgressUpdateCallback>(progressUpdateCallback);
    } else {
        progressUpdateCallback_ = nullptr;
    }
    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoderCallback::IsValidOpt(const std::string &opt)
{
    auto currentState = STATE_LIST.find(state_);
    CHECK_AND_RETURN_RET_LOG(currentState != STATE_LIST.end(), AV_ERR_INVALID_VAL,
        "IsValidOpt is called, current state is invalid!");

    const auto& allowableOpts = currentState->second;
    CHECK_AND_RETURN_RET_LOG(
        std::find(allowableOpts.begin(), allowableOpts.end(), opt) != allowableOpts.end(),
        AV_ERR_OPERATE_NOT_PERMIT,
        "IsValidOpt is called, current state does not allow this opt! current state is %{public}s,\
        opt is %{public}s", state_.c_str(), opt.c_str());
    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoderCallback::IsRepeatOpt(const std::string &opt)
{
    auto currentState = STATE_LIST.find(state_);
    CHECK_AND_RETURN_RET_LOG(currentState != STATE_LIST.end(), AV_ERR_INVALID_VAL,
        "IsRepeatOpt is called, current state is invalid!");

    auto currentCtrlState = STATE_CTRL.find(state_);
    CHECK_AND_RETURN_RET_LOG(currentCtrlState != STATE_CTRL.end(), AV_ERR_INVALID_VAL,
        "IsRepeatOpt is called, current state is invalid!");

    const auto& repeatOpts = currentCtrlState->second;
    CHECK_AND_RETURN_RET_LOG(
        std::find(repeatOpts.begin(), repeatOpts.end(), opt) == repeatOpts.end(),
        AV_ERR_OPERATE_NOT_PERMIT,
        "IsRepeatOpt is called, please do not repeat the %{public}s operation!", opt.c_str());
    return AV_ERR_OK;
}

void NativeAVTranscoderCallback::OnError(int32_t errCode, const std::string &errorMsg)
{
    MEDIA_LOGE("NativeAVTranscoderCallback::OnError: %{public}d, %{public}s", errCode, errorMsg.c_str());
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(transcoder_ != nullptr,
        "NativeAVTranscoderCallback::OnError is called, transcoder_ is nullptr!");
    state_ = NativeTranscoderState::ERROR;
    lock.unlock();
    if (errorCallback_ != nullptr) {
        MediaServiceExtErrCodeAPI9 extErrCodeAPI =
            MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
        int32_t avErrorCode = ExtErrCodeAPIToAVErrCode(extErrCodeAPI);
        std::string errorMsgExt = MSExtAVErrorToString(extErrCodeAPI) + errorMsg;
        errorCallback_->OnErrorCallback(transcoder_, avErrorCode, errorMsgExt.c_str());
    }
}

void NativeAVTranscoderCallback::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGI("NativeAVTranscoderCallback::OnInfo enter.");
    CHECK_AND_RETURN_LOG(transcoder_ != nullptr,
        "NativeAVTranscoderCallback::OnInfo is called, transcoder_ is nullptr!");

    if (type == TransCoderOnInfoType::INFO_TYPE_TRANSCODER_COMPLETED) {
        OnStateChangeCallback(OH_AVTranscoder_State::AVTRANSCODER_COMPLETED);
    } else if (type == TransCoderOnInfoType::INFO_TYPE_PROGRESS_UPDATE) {
        OnProgressUpdateCallback(extra);
    }
}

void NativeAVTranscoderCallback::OnStateChangeCallback(OH_AVTranscoder_State state)
{
    MEDIA_LOGI("NativeAVTranscoderCallback::OnStateChangeCallback enter.");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(transcoder_ != nullptr,
        "OnStateChangeCallback is called, transcoder_ is nullptr!");
    CHECK_AND_RETURN_LOG(state_ != NativeTranscoderState::ERROR,
        "OnStateChangeCallback is called, current state is ERROR, only can execute release!");
    auto nativeState = IsValidState(state);
    CHECK_AND_RETURN_LOG(nativeState != std::nullopt,
        "OnStateChangeCallback is called, state is invalid!");
    state_ = nativeState.value();
    lock.unlock();
    if (stateChangeCallback_ != nullptr) {
        stateChangeCallback_->OnStateChangeCallback(transcoder_, state);
    }
}

void NativeAVTranscoderCallback::OnProgressUpdateCallback(int32_t progress)
{
    MEDIA_LOGI("NativeAVTranscoderCallback::OnProgressUpdateCallback enter.");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(transcoder_ != nullptr,
        "OnProgressUpdateCallback is called, transcoder_ is nullptr!");
    CHECK_AND_RETURN_LOG(progress >= MIN_PROGRESS && progress <= MAX_PROGRESS,
        "OnProgressUpdateCallback is called, progress is invalid!");
    progress_ = progress;
    lock.unlock();
    if (progressUpdateCallback_ != nullptr) {
        progressUpdateCallback_->OnProgressUpdateCallback(transcoder_, progress);
    }
}

OH_AVErrCode NativeAVTranscoder::AVTranscoderConfiguration(NativeAVTranscoderConfig *config)
{
    MEDIA_LOGI("NativeAVTranscoder::AVTranscoderConfiguration enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "AVTranscoderConfiguration is called, config is nullptr!");
    CHECK_AND_RETURN_RET_LOG(transcoder_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT,
        "AVTranscoderConfiguration is called, transcoder_ is nullptr!");

    int32_t errorCode {MSERR_OK};

    errorCode = transcoder_->SetInputFile(config->srcFd, config->srcOffset, config->length);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetInputFile"),
        "AVTranscoderConfiguration is called, SetInputFile check failed, srcFd:%{public}" PRId32
        ", srcOffset:%{public}" PRId64 ", srcLength:%{public}" PRId64, config->srcFd, config->srcOffset,
        config->length);

    errorCode = transcoder_->SetOutputFile(config->dstFd);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetOutputFile"),
        "AVTranscoderConfiguration is called, SetOutputFile check failed, dstFd:%{public}d", config->dstFd);

    errorCode = transcoder_->SetOutputFormat(config->fileFormat);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetOutputFormat"),
        "AVTranscoderConfiguration is called, SetOutputFormat check failed");

    errorCode = transcoder_->SetAudioEncoder(config->audioCodecFormat);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetAudioEncoder"),
        "AVTranscoderConfiguration is called, SetAudioEncoder check failed");

    errorCode = transcoder_->SetAudioEncodingBitRate(config->audioBitrate);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetAudioEncodingBitRate"),
        "AVTranscoderConfiguration is called, SetAudioEncodingBitRate check failed, audioBitrate:%{public}d",
        config->audioBitrate);

    errorCode = transcoder_->SetVideoEncoder(config->videoCodecFormat);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetVideoEncoder"),
        "AVTranscoderConfiguration is called, SetVideoEncoder check failed");

    errorCode = transcoder_->SetVideoSize(config->videoFrameWidth, config->videoFrameHeight);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetVideoSize"),
        "AVTranscoderConfiguration is called, SetVideoSize check failed, videoFrameWidth:%{public}d,\
        videoFrameHeight:%{public}d", config->videoFrameWidth, config->videoFrameHeight);

    errorCode = transcoder_->SetVideoEncodingBitRate(config->videoBitrate);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetVideoEncodingBitRate"),
        "AVTranscoderConfiguration is called, SetVideoEncodingBitRate check failed, videoFrameWidth:%{public}d",
        config->videoBitrate);

    errorCode = transcoder_->SetEnableBFrame(config->enableBFrame);
    CHECK_AND_RETURN_RET_LOG(errorCode == MSERR_OK, GetOHAVErrCode(errorCode, "SetEnableBFrame"),
        "AVTranscoderConfiguration is called, SetEnableBFrame check failed, enableBFrame:%{public}d",
        static_cast<int32_t>(config->enableBFrame));

    return AV_ERR_OK;
}

NativeAVTranscoder::NativeAVTranscoder(const std::shared_ptr<TransCoder> &transcoder)
    : transcoder_(transcoder)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " NativeAVTranscoder create", FAKE_POINTER(this));
    transcoderCb_ = std::make_shared<NativeAVTranscoderCallback>(this);
    if (transcoder_ != nullptr && transcoderCb_ != nullptr) {
        int32_t ret = transcoder_->SetTransCoderCallback(transcoderCb_);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("NativeAVTranscoder constructor failed, ret%{public}d.",
                GetOHAVErrCode(ret, "NativeAVTranscoderConstruct"));
        }
    }
}

OH_AVErrCode NativeAVTranscoder::SetTranscoderCallback()
{
    CHECK_AND_RETURN_RET_LOG(transcoder_ != nullptr, AV_ERR_INVALID_VAL,
        "NativeAVTranscoder::SetTranscoderCallback is called, transcoder_ is nullptr!");
    NativeAVTranscoderCallback *newCallback =
        new (std::nothrow) NativeAVTranscoderCallback(this);
    CHECK_AND_RETURN_RET_LOG(newCallback != nullptr, AV_ERR_NO_MEMORY,
        "NativeAVTranscoder::SetTranscoderCallback is called, transcoderCb_ construct failed!");
    transcoderCb_ = std::shared_ptr<NativeAVTranscoderCallback>(newCallback);
    CHECK_AND_RETURN_RET_LOG(transcoderCb_ != nullptr, AV_ERR_NO_MEMORY,
        "NativeAVTranscoder::SetTranscoderCallback is called, transcoderCb_ construct failed!");
    int32_t ret = transcoder_->SetTransCoderCallback(transcoderCb_);
    CHECK_AND_RETURN_RET_NOLOG(ret == MSERR_OK, GetOHAVErrCode(ret, "SetTransCoderCallback"));
    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoder::CheckStateMachine(const std::string &opt)
{
    CHECK_AND_RETURN_RET_LOG(transcoder_ != nullptr && transcoderCb_ != nullptr,
        AV_ERR_OPERATE_NOT_PERMIT, "CheckStateMachine is called, transcoder_ or transcoderCb_ is nullptr!");

    NativeAVTranscoderCallback* nativeCallback = reinterpret_cast<NativeAVTranscoderCallback*>(transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeCallback != nullptr,
        AV_ERR_OPERATE_NOT_PERMIT, "CheckStateMachine is called, nativeCallback is nullptr!");

    OH_AVErrCode isValidOpt = nativeCallback->IsValidOpt(opt);
    CHECK_AND_RETURN_RET_LOG(isValidOpt == AV_ERR_OK, isValidOpt,
        "CheckStateMachine is called, opt is invalid!");

    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoder::CheckRepeatOptions(const std::string &opt)
{
    CHECK_AND_RETURN_RET_LOG(transcoder_ != nullptr && transcoderCb_ != nullptr,
        AV_ERR_OPERATE_NOT_PERMIT, "CheckRepeatOptions is called, transcoder_ or transcoderCb_ is nullptr!");

    NativeAVTranscoderCallback* nativeCallback = reinterpret_cast<NativeAVTranscoderCallback*>(transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeCallback != nullptr,
        AV_ERR_OPERATE_NOT_PERMIT, "CheckRepeatOptions is called, nativeCallback is nullptr!");

    OH_AVErrCode isValidOpt = nativeCallback->IsRepeatOpt(opt);
    CHECK_AND_RETURN_RET_LOG(isValidOpt == AV_ERR_OK, isValidOpt,
        "CheckRepeatOptions is called, opt is repeat option!");

    return AV_ERR_OK;
}

OH_AVErrCode NativeAVTranscoder::OnStateChange(OH_AVTranscoder_State state)
{
    CHECK_AND_RETURN_RET_LOG(transcoder_ != nullptr && transcoderCb_ != nullptr, AV_ERR_INVALID_VAL,
        "OnStateChange is called, transcoder_ or transcoderCb_ is nullptr!");

    NativeAVTranscoderCallback* nativeCallback = reinterpret_cast<NativeAVTranscoderCallback*>(transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeCallback != nullptr, AV_ERR_INVALID_VAL,
        "OnStateChange is called, nativeCallback is nullptr!");

    CHECK_AND_RETURN_RET_LOG(IsValidState(state) != std::nullopt, AV_ERR_INVALID_VAL,
        "OnStateChange is called, current state is invalid!");

    nativeCallback->OnStateChangeCallback(state);
    return AV_ERR_OK;
}

OH_AVTranscoder_Config *OH_AVTranscoderConfig_Create()
{
    MEDIA_LOGI("OH_AVTranscoderConfig_Create enter.");
    NativeAVTranscoderConfig *config = new (std::nothrow) NativeAVTranscoderConfig();
    CHECK_AND_RETURN_RET_LOG(config != nullptr, nullptr,
        "OH_AVTranscoderConfig_Create is called, config is nullptr!");
    return config;
}

OH_AVErrCode OH_AVTranscoderConfig_Release(OH_AVTranscoder_Config* config)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_Release enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_Release is called, config is nullptr!");

    delete config;
    config = nullptr;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetSrcFD(
    OH_AVTranscoder_Config *config, int32_t srcFd, int64_t srcOffset, int64_t length)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetSrcFD enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetSrcFD is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetSrcFD is called, nativeConfig is nullptr!");

    CHECK_AND_RETURN_RET_LOG(srcFd >= 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetSrcFD is called, srcFd is less than zero!");

    CHECK_AND_RETURN_RET_LOG(srcOffset >= 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetSrcFD is called, srcOffset is less than zero!");

    CHECK_AND_RETURN_RET_LOG(length >= 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetSrcFD is called, length is less than zero!");

    nativeConfig->srcFd = srcFd;
    nativeConfig->srcOffset = srcOffset;
    nativeConfig->length = length;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstFD(OH_AVTranscoder_Config *config, int32_t dstFd)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstFD enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFD is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFD is called, nativeConfig is nullptr!");

    CHECK_AND_RETURN_RET_LOG(dstFd >= 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFD is called, dstFd is less than zero!");

    nativeConfig->dstFd = dstFd;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstVideoType(OH_AVTranscoder_Config *config, const char *mimeType)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstVideoType enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr && mimeType != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoType is called, config or mimeType is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoType is called, nativeConfig is nullptr!");

    auto currentMimeType = MIME_STR_TO_VIDEO_CODEC_FORMAT.find(mimeType);
    CHECK_AND_RETURN_RET_LOG(currentMimeType != MIME_STR_TO_VIDEO_CODEC_FORMAT.end(),
        AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoType is called, invalid mime type!");

    nativeConfig->videoCodecFormat = currentMimeType->second;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstAudioType(OH_AVTranscoder_Config *config, const char *mimeType)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstAudioType enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr && mimeType != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioType is called, config or mimeType is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioType is called, nativeConfig is nullptr!");

    auto currentMimeType = MIME_STR_TO_AUDIO_CODEC_FORMAT.find(mimeType);
    CHECK_AND_RETURN_RET_LOG(currentMimeType != MIME_STR_TO_AUDIO_CODEC_FORMAT.end(),
        AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioType is called, invalid mime type!");

    nativeConfig->audioCodecFormat = currentMimeType->second;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstFileType(OH_AVTranscoder_Config *config, OH_AVOutputFormat mimeType)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstFileType enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFileType is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFileType is called, nativeConfig is nullptr!");

    auto currentOutputFormat = AV_OUTPUT_FORMAT_TO_OUTPUT_FORMAT_TYPE.find(mimeType);
    CHECK_AND_RETURN_RET_LOG(currentOutputFormat != AV_OUTPUT_FORMAT_TO_OUTPUT_FORMAT_TYPE.end(),
        AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstFileType is called, invalid mime type!");

    nativeConfig->fileFormat = currentOutputFormat->second;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstAudioBitrate(OH_AVTranscoder_Config *config, int32_t bitrate)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstAudioBitrate enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioBitrate is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioBitrate is called, nativeConfig is nullptr!");

    CHECK_AND_RETURN_RET_LOG(bitrate > 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstAudioBitrate is called, bitrate is less than or equal to zero!");

    nativeConfig->audioBitrate = bitrate;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstVideoBitrate(OH_AVTranscoder_Config *config, int32_t bitrate)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstVideoBitrate enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoBitrate is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoBitrate is called, nativeConfig is nullptr!");

    CHECK_AND_RETURN_RET_LOG(bitrate > 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoBitrate is called, bitrate is less than or equal to zero!");

    nativeConfig->videoBitrate = bitrate;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_SetDstVideoResolution(OH_AVTranscoder_Config *config, int32_t width, int32_t height)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_SetDstVideoResolution enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoResolution is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoResolution is called, nativeConfig is nullptr!");

    CHECK_AND_RETURN_RET_LOG(width > 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoResolution is called, width is less than or equal to zero!");

    CHECK_AND_RETURN_RET_LOG(height > 0, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_SetDstVideoResolution is called, height is less than or equal to zero!");

    nativeConfig->videoFrameHeight = height;
    nativeConfig->videoFrameWidth = width;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoderConfig_EnableBFrame(OH_AVTranscoder_Config *config, bool enabled)
{
    MEDIA_LOGI("OH_AVTranscoderConfig_EnableBFrame enter.");
    CHECK_AND_RETURN_RET_LOG(config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_EnableBFrame is called, config is nullptr!");

    NativeAVTranscoderConfig* nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoderConfig_EnableBFrame is called, nativeConfig is nullptr!");

    nativeConfig->enableBFrame = enabled;

    return AV_ERR_OK;
}

OH_AVTranscoder *OH_AVTranscoder_Create()
{
    MEDIA_LOGI("OH_AVTranscoder_Create enter.");
    std::shared_ptr<TransCoder> transcoder = TransCoderFactory::CreateTransCoder();
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, nullptr,
        "OH_AVTranscoder_Create is called, TransCoderFactory::CreateTransCoder failed!");

    NativeAVTranscoder *nativeTranscoder =
        new (std::nothrow) NativeAVTranscoder(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, nullptr,
        "OH_AVTRanscoder_Create is called, NativeAVTranscoder construct failed!");

    return nativeTranscoder;
}

OH_AVErrCode OH_AVTranscoder_Prepare(OH_AVTranscoder *transcoder, OH_AVTranscoder_Config *config)
{
    MEDIA_LOGI("OH_AVTranscoder_Prepare enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr && config != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Prepare is called, transcoder is nullptr or config is nullptr!");

    NativeAVTranscoderConfig *nativeConfig = reinterpret_cast<NativeAVTranscoderConfig*>(config);
    CHECK_AND_RETURN_RET_LOG(nativeConfig != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Prepare is called, nativeConfig is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Prepare is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::PREPARE) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Prepare is called, CheckStateMachine failed!");

    OH_AVErrCode errCode = nativeTranscoder->AVTranscoderConfiguration(nativeConfig);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_ERR_OK,
        ((void)nativeTranscoder->transcoder_->Cancel(), errCode),
        "OH_AVTranscoder_Prepare is called, AVTranscoderConfiguration failed!");

    int32_t errPrepareCode = nativeTranscoder->transcoder_->Prepare();
    CHECK_AND_RETURN_RET_LOG(errPrepareCode == MSERR_OK,
        ((void)nativeTranscoder->transcoder_->Cancel(), GetOHAVErrCode(errPrepareCode, "Prepare")),
        "OH_AVTranscoder_Prepare is called, Prepare failed!");

    OH_AVErrCode avErrCode = nativeTranscoder->OnStateChange(OH_AVTranscoder_State::AVTRANSCODER_PREPARED);
    CHECK_AND_RETURN_RET_LOG(avErrCode == AV_ERR_OK, avErrCode,
        "OH_AVTranscoder_Prepare is called, OnStateChange failed!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_Start(OH_AVTranscoder *transcoder)
{
    MEDIA_LOGI("OH_AVTranscoder_Start enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Start is called, transcoder is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Start is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::START) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Start is called, CheckStateMachine failed!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckRepeatOptions(AVTranscoderOpts::START) == AV_ERR_OK,
        AV_ERR_OK, "OH_AVTranscoder_Start is called, Start operation was repeated!");

    int32_t errCode = nativeTranscoder->transcoder_->Start();
    CHECK_AND_RETURN_RET_LOG(errCode == MSERR_OK, GetOHAVErrCode(errCode, "Start"),
        "OH_AVTranscoder_Start is called, Start failed!");

    OH_AVErrCode avErrCode = nativeTranscoder->OnStateChange(OH_AVTranscoder_State::AVTRANSCODER_STARTED);
    CHECK_AND_RETURN_RET_LOG(avErrCode == AV_ERR_OK, avErrCode,
        "OH_AVTranscoder_Start is called, OnStateChange failed!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_Pause(OH_AVTranscoder *transcoder)
{
    MEDIA_LOGI("OH_AVTranscoder_Pause enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Pause is called, transcoder is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Pause is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::PAUSE) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Pause is called, CheckStateMachine failed!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckRepeatOptions(AVTranscoderOpts::PAUSE) == AV_ERR_OK,
        AV_ERR_OK, "OH_AVTranscoder_Pause is called, Pause operation was repeated!");

    int32_t errCode = nativeTranscoder->transcoder_->Pause();
    CHECK_AND_RETURN_RET_LOG(errCode == MSERR_OK, GetOHAVErrCode(errCode, "Pause"),
        "OH_AVTranscoder_Pause is called, Pause failed!");

    OH_AVErrCode avErrCode = nativeTranscoder->OnStateChange(OH_AVTranscoder_State::AVTRANSCODER_PAUSED);
    CHECK_AND_RETURN_RET_LOG(avErrCode == AV_ERR_OK, avErrCode,
        "OH_AVTranscoder_Pause is called, OnStateChange failed!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_Resume(OH_AVTranscoder *transcoder)
{
    MEDIA_LOGI("OH_AVTranscoder_Resume enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Resume is called, transcoder is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Resume is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::RESUME) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Resume is called, CheckStateMachine failed!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckRepeatOptions(AVTranscoderOpts::RESUME) == AV_ERR_OK,
        AV_ERR_OK, "OH_AVTranscoder_Resume is called, Resume operation was repeated!");

    int32_t errCode = nativeTranscoder->transcoder_->Resume();
    CHECK_AND_RETURN_RET_LOG(errCode == MSERR_OK, GetOHAVErrCode(errCode, "Resume"),
        "OH_AVTranscoder_Resume is called, Resume failed!");

    OH_AVErrCode avErrCode = nativeTranscoder->OnStateChange(OH_AVTranscoder_State::AVTRANSCODER_STARTED);
    CHECK_AND_RETURN_RET_LOG(avErrCode == AV_ERR_OK, avErrCode,
        "OH_AVTranscoder_Resume is called, OnStateChange failed!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_Cancel(OH_AVTranscoder *transcoder)
{
    MEDIA_LOGI("OH_AVTranscoder_Cancel enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Cancel is called, transcoder is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Cancel is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::CANCEL) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Cancel is called, CheckStateMachine failed!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckRepeatOptions(AVTranscoderOpts::CANCEL) == AV_ERR_OK,
        AV_ERR_OK, "OH_AVTranscoder_Cancel is called, Cancel operation was repeated!");

    int32_t errCode = nativeTranscoder->transcoder_->Cancel();
    CHECK_AND_RETURN_RET_LOG(errCode == MSERR_OK, GetOHAVErrCode(errCode, "Cancel"),
        "OH_AVTranscoder_Cancel is called, Cancel failed!");

    OH_AVErrCode avErrCode = nativeTranscoder->OnStateChange(OH_AVTranscoder_State::AVTRANSCODER_CANCELLED);
    CHECK_AND_RETURN_RET_LOG(avErrCode == AV_ERR_OK, avErrCode,
        "OH_AVTranscoder_Cancel is called, OnStateChange failed!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_Release(OH_AVTranscoder *transcoder)
{
    MEDIA_LOGI("OH_AVTranscoder_Release enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Release is called, transcoder is originally nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_Release is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckStateMachine(AVTranscoderOpts::RELEASE) == AV_ERR_OK,
        AV_ERR_OPERATE_NOT_PERMIT, "OH_AVTranscoder_Release is called, CheckStateMachine failed!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->CheckRepeatOptions(AVTranscoderOpts::RELEASE) == AV_ERR_OK,
        AV_ERR_OK, "OH_AVTranscoder_Release is called, Release operation was repeated!");

    int32_t errCode = nativeTranscoder->transcoder_->Release();
    CHECK_AND_RETURN_RET_LOG(errCode == MSERR_OK, GetOHAVErrCode(errCode, "Release"),
        "OH_AVTranscoder_Release is called, Release failed!");

    delete transcoder;
    transcoder = nullptr;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVTranscoder_SetStateCallback(
    OH_AVTranscoder *transcoder, OH_AVTranscoder_OnStateChange callback, void *userData)
{
    MEDIA_LOGI("OH_AVTranscoder_SetStateCallback enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr && callback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetStateCallback is called, transcoder or callback is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetStateCallback is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->transcoder_ != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetStateCallback is called, nativeTranscoder::transcoder_ is nullptr!");

    if (nativeTranscoder->transcoderCb_ == nullptr) {
        OH_AVErrCode ret = nativeTranscoder->SetTranscoderCallback();
        CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, ret,
            "OH_AVTranscoder_SetStateCallback is called, SetTranscoderCallback failed!");
    }

    NativeAVTranscoderCallback *nativeTranscoderCallback =
        reinterpret_cast<NativeAVTranscoderCallback*>(nativeTranscoder->transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeTranscoderCallback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetStateCallback is called, nativeTranscoderCallback is nullptr!");

    return nativeTranscoderCallback->SetOnStateChangeCallback(callback, userData);
}

OH_AVErrCode OH_AVTranscoder_SetErrorCallback(
    OH_AVTranscoder *transcoder, OH_AVTranscoder_OnError callback, void *userData)
{
    MEDIA_LOGI("OH_AVTranscoder_SetErrorCallback enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr && callback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetErrorCallback is called, transcoder or callback is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetErrorCallback is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->transcoder_ != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetErrorCallback is called, nativeTranscoder::transcoder_ is nullptr!");

    if (nativeTranscoder->transcoderCb_ == nullptr) {
        OH_AVErrCode ret = nativeTranscoder->SetTranscoderCallback();
        CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, ret,
            "OH_AVTranscoder_SetErrorCallback is called, SetTranscoderCallback failed!");
    }

    NativeAVTranscoderCallback *nativeTranscoderCallback =
        reinterpret_cast<NativeAVTranscoderCallback*>(nativeTranscoder->transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeTranscoderCallback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetErrorCallback is called, nativeTranscoderCallback is nullptr!");

    return nativeTranscoderCallback->SetOnErrorCallback(callback, userData);
}

OH_AVErrCode OH_AVTranscoder_SetProgressUpdateCallback(
    OH_AVTranscoder *transcoder, OH_AVTranscoder_OnProgressUpdate callback, void *userData)
{
    MEDIA_LOGI("OH_AVTranscoder_SetProgressUpdateCallback enter.");
    CHECK_AND_RETURN_RET_LOG(transcoder != nullptr && callback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetProgressUpdateCallback is called, transcoder or callback is nullptr!");

    NativeAVTranscoder *nativeTranscoder = reinterpret_cast<NativeAVTranscoder*>(transcoder);
    CHECK_AND_RETURN_RET_LOG(nativeTranscoder != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetProgressUpdateCallback is called, nativeTranscoder is nullptr!");

    CHECK_AND_RETURN_RET_LOG(nativeTranscoder->transcoder_ != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetProgressUpdateCallback is called, transcoder_ is nullptr!");

    if (nativeTranscoder->transcoderCb_ == nullptr) {
        OH_AVErrCode ret = nativeTranscoder->SetTranscoderCallback();
        CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, ret,
            "OH_AVTranscoder_SetProgressUpdateCallback is called, SetTranscoderCallback failed!");
    }

    NativeAVTranscoderCallback *nativeTranscoderCallback =
        reinterpret_cast<NativeAVTranscoderCallback*>(nativeTranscoder->transcoderCb_.get());
    CHECK_AND_RETURN_RET_LOG(nativeTranscoderCallback != nullptr, AV_ERR_INVALID_VAL,
        "OH_AVTranscoder_SetProgressUpdateCallback is called, nativeTranscoderCallback is nullptr!");

    return nativeTranscoderCallback->SetOnProgressUpdateCallback(callback, userData);
}