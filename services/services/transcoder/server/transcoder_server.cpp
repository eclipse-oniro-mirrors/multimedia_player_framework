/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#include "transcoder_server.h"
#include "map"
#include "media_log.h"
#include "media_errors.h"
#include "engine_factory_repo.h"
#include "param_wrapper.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "media_dfx.h"
#include "av_common.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "TransCoderServer"};
    const std::map<OHOS::Media::TransCoderServer::RecStatus, std::string> TRANSCODER_STATE_MAP = {
        {OHOS::Media::TransCoderServer::REC_INITIALIZED, "initialized"},
        {OHOS::Media::TransCoderServer::REC_CONFIGURED, "configured"},
        {OHOS::Media::TransCoderServer::REC_PREPARED, "prepared"},
        {OHOS::Media::TransCoderServer::REC_TRANSCODERING, "transcordring"},
        {OHOS::Media::TransCoderServer::REC_PAUSED, "paused"},
        {OHOS::Media::TransCoderServer::REC_ERROR, "error"},
    };
}

namespace OHOS {
namespace Media {
const std::string START_TAG = "TransCoderCreate->Start";
const std::string STOP_TAG = "TransCoderStop->Destroy";

std::shared_ptr<ITransCoderService> TransCoderServer::Create()
{
    std::shared_ptr<TransCoderServer> server = std::make_shared<TransCoderServer>();
    int32_t ret = server->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init TransCoderServer");
    return server;
}

TransCoderServer::TransCoderServer()
    : taskQue_("TranscoderServer")
{
    taskQue_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    instanceId_ = HiviewDFX::HiTraceChain::GetId().GetChainId();
}

TransCoderServer::~TransCoderServer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    taskQue_.Stop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t TransCoderServer::Init()
{
    MediaTrace trace("TransCoderServer::Init");
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    int32_t appUid = IPCSkeleton::GetCallingUid();
    int32_t appPid = IPCSkeleton::GetCallingPid();

    auto task = std::make_shared<TaskHandler<MediaServiceErrCode>>([this, appUid, appPid, tokenId, fullTokenId] {
        auto engineFactory = EngineFactoryRepo::Instance().GetEngineFactory(
            IEngineFactory::Scene::SCENE_TRANSCODER, appUid);
        CHECK_AND_RETURN_RET_LOG(engineFactory != nullptr, MSERR_CREATE_REC_ENGINE_FAILED,
            "failed to get factory");
        transCoderEngine_ = engineFactory->CreateTransCoderEngine(appUid, appPid, tokenId, fullTokenId);
        CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_CREATE_REC_ENGINE_FAILED,
            "failed to create transCoder engine");
        transCoderEngine_->SetInstanceId(instanceId_);
        return MSERR_OK;
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult() && result.Value() == MSERR_OK,
        result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION, "Result failed");

    status_ = REC_INITIALIZED;
    return MSERR_OK;
}

const std::string& TransCoderServer::GetStatusDescription(OHOS::Media::TransCoderServer::RecStatus status)
{
    static const std::string ILLEGAL_STATE = "PLAYER_STATUS_ILLEGAL";
    CHECK_AND_RETURN_RET(status >= OHOS::Media::TransCoderServer::REC_INITIALIZED &&
        status <= OHOS::Media::TransCoderServer::REC_ERROR, ILLEGAL_STATE);

    return TRANSCODER_STATE_MAP.find(status)->second;
}

void TransCoderServer::OnError(TransCoderErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    std::shared_ptr<TransCoderCallback> cb;
    std::string errMsg;
    {
        std::lock_guard<std::mutex> lock(cbMutex_);
        lastErrMsg_ = MSErrorToString(static_cast<MediaServiceErrCode>(errorCode));
        errMsg = lastErrMsg_;
        cb = transCoderCb_;
    }
    if (cb != nullptr) {
        MEDIA_LOGI("receive an error event, errorCode: %{public}d, errorMsg: %{public}s",
            errorCode, errMsg.c_str());
        cb->OnError(errorCode, errMsg);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_ = REC_ERROR;
    }
}

void TransCoderServer::OnInfo(TransCoderOnInfoType type, int32_t extra)
{
    std::shared_ptr<TransCoderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(cbMutex_);
        cb = transCoderCb_;
    }
    CHECK_AND_RETURN(cb != nullptr);
    cb->OnInfo(type, extra);
}

int32_t TransCoderServer::SetVideoEncoder(VideoCodecFormat encoder)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.videoCodec = encoder;
    VideoEnc vidEnc(encoder);
    MEDIA_LOGD("set video encoder encoder:%{public}d", encoder);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, vidEnc]() {
        return transCoderEngine_->Configure(vidEnc);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetVideoSize(int32_t width, int32_t height)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.width = width;
    config_.height = height;
    VideoRectangle vidSize(width, height);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, vidSize]() {
        return transCoderEngine_->Configure(vidSize);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetVideoEncodingBitRate(int32_t rate)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.videoBitRate = rate;
    VideoBitRate vidBitRate(rate);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, vidBitRate]() {
        return transCoderEngine_->Configure(vidBitRate);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetColorSpace(TranscoderColorSpace colorSpaceFormat)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.colorSpaceFormat = colorSpaceFormat;
    VideoColorSpace colorSpaceFmt(colorSpaceFormat);
    MEDIA_LOGD("set color space, format: %{public}d", static_cast<int32_t>(colorSpaceFormat));
    auto task = std::make_shared<TaskHandler<int32_t>>([this, colorSpaceFmt]() {
        return transCoderEngine_->Configure(colorSpaceFmt);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetEnableBFrame(bool enableBFrame)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.enableBFrame = enableBFrame;
    VideoEnableBFrameEncoding videoEnableBFrameEncoding(enableBFrame);
    MEDIA_LOGD("SetEnableBFrame: %{public}d", static_cast<int32_t>(enableBFrame));
    auto task = std::make_shared<TaskHandler<int32_t>>([this, videoEnableBFrameEncoding]() {
        return transCoderEngine_->Configure(videoEnableBFrameEncoding);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetVideoBitrateMode(int32_t bitrateMode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.videoBitrateMode = bitrateMode;
    VideoBitrateMode videoBitrateModeParam(bitrateMode);
    MEDIA_LOGD("SetVideoBitrateMode: %{public}d", bitrateMode);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, videoBitrateModeParam]() {
        return transCoderEngine_->Configure(videoBitrateModeParam);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetVideoSqrFactor(int32_t sqrFactor)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.videoSqrFactor = sqrFactor;
    VideoSqrFactor videoSqrFactorParam(sqrFactor);
    MEDIA_LOGD("SetVideoSqrFactor: %{public}d", sqrFactor);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, videoSqrFactorParam]() {
        return transCoderEngine_->Configure(videoSqrFactorParam);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetAudioEncoder(AudioCodecFormat encoder)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.audioCodec = encoder;
    AudioEnc audEnc(encoder);
    MEDIA_LOGD("set audio encoder encoder:%{public}d", encoder);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, audEnc]() {
        return transCoderEngine_->Configure(audEnc);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetAudioEncodingBitRate(int32_t bitRate)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.audioBitRate = bitRate;
    AudioBitRate audBitRate(bitRate);
    auto task = std::make_shared<TaskHandler<int32_t>>([this, audBitRate]() {
        return transCoderEngine_->Configure(audBitRate);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetOutputFormat(OutputFormatType format)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_INITIALIZED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.format = format;
    auto task = std::make_shared<TaskHandler<int32_t>>([this, format]() {
        return transCoderEngine_->SetOutputFormat(format);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_CONFIGURED : REC_INITIALIZED));
    return retValue;
}

int32_t TransCoderServer::SetInputFile(int32_t fd, int64_t offset, int64_t size)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_INITIALIZED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.srcFd = fd;
    config_.srcFdOffset = offset;
    config_.srcFdSize = size;
    uriHelper_ = std::make_unique<UriHelper>(fd, offset, size);
    CHECK_AND_RETURN_RET_LOG(uriHelper_->AccessCheck(UriHelper::URI_READ),
        MSERR_FILE_ACCESS_FAILED, "Failed to read the fd");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->SetInputFile(uriHelper_->FormattedUri());
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetOutputFile(int32_t fd)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_INITIALIZED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    config_.dstUrl = fd;
    auto task = std::make_shared<TaskHandler<int32_t>>([this, fd]() {
        return transCoderEngine_->SetOutputFile(fd);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::SetTransCoderCallback(const std::shared_ptr<TransCoderCallback> &callback)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_INITIALIZED || status_.load() == REC_CONFIGURED,
        MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    {
        std::lock_guard<std::mutex> cbLock(cbMutex_);
        transCoderCb_ = callback;
    }

    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    std::shared_ptr<ITransCoderEngineObs> obs = shared_from_this();
    auto task = std::make_shared<TaskHandler<int32_t>>([this, obs]() {
        return transCoderEngine_->SetObs(obs);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

int32_t TransCoderServer::Prepare()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("TransCoderServer::Prepare");
    CHECK_AND_RETURN_RET_LOG(status_.load() != REC_PREPARED, MSERR_INVALID_OPERATION, "Can not repeat Prepare");
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_CONFIGURED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->Prepare();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_PREPARED : REC_ERROR));
    return retValue;
}

int32_t TransCoderServer::Start()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("TransCoderServer::Start");
    CHECK_AND_RETURN_RET_LOG(status_.load() != REC_TRANSCODERING, MSERR_INVALID_OPERATION, "Can not repeat Start");
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_PREPARED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->Start();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_TRANSCODERING : REC_ERROR));
    return retValue;
}

int32_t TransCoderServer::Pause()
{
    MediaTrace trace("TransCoderServer::Pause");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() != REC_PAUSED, MSERR_INVALID_OPERATION, "Can not repeat Pause");
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_TRANSCODERING, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->Pause();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_PAUSED : REC_ERROR));
    return retValue;
}

int32_t TransCoderServer::Resume()
{
    MediaTrace trace("TransCoderServer::Resume");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(status_.load() != REC_TRANSCODERING, MSERR_INVALID_OPERATION, "Can not repeat Resume");
    CHECK_AND_RETURN_RET_LOG(status_.load() == REC_PAUSED, MSERR_INVALID_OPERATION,
        "invalid status, current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->Resume();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_TRANSCODERING : REC_ERROR));
    return retValue;
}

int32_t TransCoderServer::Cancel()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("TransCoderServer::Cancel");
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    CHECK_AND_RETURN_RET_LOG(status_.load() != REC_ERROR, MSERR_INVALID_OPERATION, "current status is error");
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        return transCoderEngine_->Cancel();
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    int32_t retValue = result.HasResult() ? result.Value() : MSERR_INVALID_OPERATION;
    lock.lock();
    ChangeStatus((retValue == MSERR_OK ? REC_INITIALIZED : REC_ERROR));
    return retValue;
}

int32_t TransCoderServer::Release()
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(!isReleased_, MSERR_OK, "server has been released");
    isReleased_ = true;
    lock.unlock();
    ReleaseInner();
    {
        std::lock_guard<std::mutex> cbLock(cbMutex_);
        transCoderCb_ = nullptr;
    }
    return MSERR_OK;
}

int32_t TransCoderServer::AddWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer, int32_t width, int32_t height)
{
    MEDIA_LOGI("AddWatermark in");
    std::unique_lock<std::mutex> lock(mutex_);
    MediaTrace trace("TransCoderServer::AddWatermark");
    CHECK_AND_RETURN_RET_LOG(status_.load() < REC_PREPARED, MSERR_INVALID_OPERATION, "Can not set Watermark");
    CHECK_AND_RETURN_RET_LOG(width <= WATERMARK_WIDTH_HEIGHT_MAX, MSERR_INVALID_VAL, "Invalid watermark width");
    CHECK_AND_RETURN_RET_LOG(height <= WATERMARK_WIDTH_HEIGHT_MAX, MSERR_INVALID_VAL, "Invalid watermark height");
    CHECK_AND_RETURN_RET_LOG(transCoderEngine_ != nullptr, MSERR_NO_MEMORY, "engine is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this, waterMarkBuffer, width, height]() {
        return transCoderEngine_->AddWatermark(
            const_cast<std::shared_ptr<AVBuffer> &>(waterMarkBuffer), width, height);
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    lock.unlock();
    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION, "task failed");
    return result.Value();
}

void TransCoderServer::ReleaseInner()
{
    MEDIA_LOGI("ReleaseInner enter");
    if (transCoderEngine_ == nullptr) {
        return;
    }
    auto task = std::make_shared<TaskHandler<int32_t>>([this]() {
        int32_t ret = transCoderEngine_->Cancel();
        transCoderEngine_ = nullptr;
        return ret;
    });
    (void)taskQue_.EnqueueTask(task);
    auto result = task->GetResult();
    (void)result.HasResult();
}

void TransCoderServer::ChangeStatus(RecStatus status)
{
    CHECK_AND_RETURN_LOG(status_.load() != REC_ERROR, "status is error");
    {
        status_ = status;
        MEDIA_LOGI("current status is %{public}s", GetStatusDescription(status_.load()).c_str());
    }
    return;
}

int32_t TransCoderServer::DumpInfo(int32_t fd)
{
    std::string dumpString;
    dumpString += "In TransCoderServer::DumpInfo\n";
    dumpString += "TransCoderServer current state is: " + std::to_string(static_cast<int32_t>(status_.load())) + "\n";
    if (lastErrMsg_.size() != 0) {
        dumpString += "TransCoderServer last error is: " + lastErrMsg_ + "\n";
    }
    dumpString += "TransCoderServer videoCodec is: " + std::to_string(config_.videoCodec) + "\n";
    dumpString += "TransCoderServer audioCodec is: " + std::to_string(config_.audioCodec) + "\n";
    dumpString += "TransCoderServer width is: " + std::to_string(config_.width) + "\n";
    dumpString += "TransCoderServer height is: " + std::to_string(config_.height) + "\n";
    dumpString += "TransCoderServer bitRate is: " + std::to_string(config_.videoBitRate) + "\n";
    dumpString += "TransCoderServer audioBitRate is: " + std::to_string(config_.audioBitRate) + "\n";
    dumpString += "TransCoderServer format is: " + std::to_string(config_.format) + "\n";
    write(fd, dumpString.c_str(), dumpString.size());

    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS
