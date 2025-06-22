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

#include "media_log.h"
#include "media_dfx.h"
#include "media_taihe_utils.h"
#include "avcodec_info.h"
#include "avtranscoder_callback_taihe.h"

using namespace ANI::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVTransCoderTaihe"};
}
namespace ANI::Media {
using namespace OHOS::MediaAVCodec;
const std::string STATE_PROGRESSUPDATE = "progressUpdate";

const std::map<std::string, std::vector<std::string>> STATE_CTRL = {
    {AVTransCoderState::STATE_IDLE, {
        AVTransCoderOpt::SET_AV_TRANSCODER_CONFIG,
    }},
    {AVTransCoderState::STATE_PREPARED, {}},
    {AVTransCoderState::STATE_STARTED, {
        AVTransCoderOpt::START,
        AVTransCoderOpt::RESUME
    }},
    {AVTransCoderState::STATE_PAUSED, {
        AVTransCoderOpt::PAUSE
    }},
    {AVTransCoderState::STATE_CANCELLED, {
        AVTransCoderOpt::CANCEL
    }},
    {AVTransCoderState::STATE_RELEASED, {
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_COMPLETED, {}},
    {AVTransCoderState::STATE_ERROR, {}},
};

std::map<std::string, AVTranscoderImpl::AvTransCoderTaskqFunc> AVTranscoderImpl::taskQFuncs_ = {
    {AVTransCoderOpt::START, &AVTranscoderImpl::Start},
    {AVTransCoderOpt::RESUME, &AVTranscoderImpl::Resume},
    {AVTransCoderOpt::CANCEL, &AVTranscoderImpl::Cancel},
    {AVTransCoderOpt::RELEASE, &AVTranscoderImpl::Release},
    {AVTransCoderOpt::PAUSE, &AVTranscoderImpl::Pause},
};

AVTranscoderImpl::AVTranscoderImpl()
{
    transCoder_ = TransCoderFactory::CreateTransCoder();
    if (transCoder_ == nullptr) {
        MEDIA_LOGE("failed to CreateTransCoder");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateTransCoder");
        return;
    }

    taskQue_ = std::make_unique<TaskQueue>("OS_AVTransCoderTaihe");
    (void)taskQue_->Start();
    
    transCoderCb_ = std::make_shared<AVTransCoderCallback>();
    if (transCoderCb_ == nullptr) {
        MEDIA_LOGE("failed to CreateTransCoderCb");
        MediaTaiheUtils::ThrowExceptionError("failed to CreateTransCoderCb");
        return;
    }
    (void)transCoder_->SetTransCoderCallback(transCoderCb_);
}

RetInfo GetReturnRet(int32_t errCode, const std::string &operate, const std::string &param, const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d", operate.c_str(), param.c_str(), errCode);
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

void AVTranscoderImpl::StateCallback(const std::string &state)
{
    MEDIA_LOGI("Change state to %{public}s", state.c_str());
    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    taiheCb->SendStateCallback(state, OHOS::Media::StateChangeReason::USER);
}

void AVTranscoderImpl::CancelCallback()
{
    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    taiheCb->ClearCallbackReference();
}

void AVTransCoderAsyncContext::AVTransCoderSignError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add)
{
    RetInfo retInfo = GetReturnRet(errCode, operate, param, add);
    set_business_error(retInfo.first, retInfo.second);
}

RetInfo AVTranscoderImpl::Start()
{
    int32_t ret = transCoder_->Start();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "Start", ""));
    StateCallback(AVTransCoderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVTranscoderImpl::Resume()
{
    int32_t ret = transCoder_->Resume();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "Resume", ""));
    StateCallback(AVTransCoderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVTranscoderImpl::Cancel()
{
    int32_t ret = transCoder_->Cancel();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "Stop", ""));
    StateCallback(AVTransCoderState::STATE_CANCELLED);
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVTranscoderImpl::Pause()
{
    int32_t ret = transCoder_->Pause();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "Pause", ""));
    StateCallback(AVTransCoderState::STATE_PAUSED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVTranscoderImpl::Release()
{
    int32_t ret = transCoder_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "Release", ""));

    StateCallback(AVTransCoderState::STATE_RELEASED);
    CancelCallback();
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

optional<AVTranscoder> CreateAVTranscoderSync()
{
    auto res = make_holder<AVTranscoderImpl, AVTranscoder>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVPlayer failed!");
        taihe::reset_error();
        return optional<AVTranscoder>(std::nullopt);
    }
    return optional<AVTranscoder>(std::in_place, res);
}

RetInfo AVTranscoderImpl::SetOutputFile(int32_t fd)
{
    int32_t ret = transCoder_->SetOutputFile(fd);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetOutputFile", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

double AVTranscoderImpl::GetFdDst()
{
    MediaTrace trace("AVTranscoderImpl::get url");
    MEDIA_LOGD("TaiheGetUrl Out Current Url: %{public}s", srcUrl_.c_str());
    return dstFd_;
}

void AVTranscoderImpl::SetFdDst(double fdDst)
{
    MediaTrace trace("AVTranscoderImpl::set fd");
    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder != nullptr, "failed to GetJsInstanceAndArgs");
    dstFd_ = fdDst;
    auto task = std::make_shared<TaskHandler<void>>([taihe = asyncCtx->avTransCoder]() {
        MEDIA_LOGI("JsSetSrcFd Task");
        taihe->SetOutputFile(taihe->dstFd_);
    });
    (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(task);
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            asyncCtx->SignError(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("TaiheSetDstFd Out");
}

ohos::multimedia::media::AVFileDescriptor AVTranscoderImpl::GetFdSrc()
{
    MediaTrace trace("AVTranscoderImpl::get url");
    ohos::multimedia::media::AVFileDescriptor fdSrc;
    fdSrc.fd = srcFd_.fd;
    fdSrc.offset = optional<double>(std::in_place_t{}, srcFd_.offset);
    fdSrc.length = optional<double>(std::in_place_t{}, srcFd_.length);
    MEDIA_LOGD("TaiheGetUrl Out Current Url: %{public}s", srcUrl_.c_str());
    return fdSrc;
}


void AVTranscoderImpl::SetFdSrc(ohos::multimedia::media::AVFileDescriptor const& fdSrc)
{
    MediaTrace trace("AVTranscoderImpl::set fd");
    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder != nullptr, "failed to GetJsInstanceAndArgs");
    srcFd_.fd = fdSrc.fd;
    if (fdSrc.offset.has_value()) {
        srcFd_.offset = fdSrc.offset.value();
    }
    if (fdSrc.length.has_value()) {
        srcFd_.length = fdSrc.length.value();
    }

    auto task = std::make_shared<TaskHandler<void>>([taihe = asyncCtx->avTransCoder]() {
        MEDIA_LOGI("JsSetSrcFd Task");
        taihe->SetInputFile(taihe->srcFd_.fd, taihe->srcFd_.offset, taihe->srcFd_.length);
    });
    (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(task);
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            asyncCtx->SignError(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();

    MEDIA_LOGI("TaiheSetSrcFd Out");
}

RetInfo AVTranscoderImpl::SetInputFile(int32_t fd, int64_t offset, int64_t size)
{
    int32_t ret = transCoder_->SetInputFile(fd, offset, size);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetInputFile", ""));
    return RetInfo(MSERR_EXT_API9_OK, "");
}

int32_t AVTranscoderImpl::CheckStateMachine(const std::string &opt)
{
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    CHECK_AND_RETURN_RET_LOG(taiheCb != nullptr, MSERR_INVALID_OPERATION, "taiheCb is nullptr!");

    std::string curState = taiheCb->GetState();
    CHECK_AND_RETURN_RET_LOG(STATE_LIST.find(curState) != STATE_LIST.end(), MSERR_INVALID_VAL, "state is not in list");
    std::vector<std::string> allowedOpt = STATE_LIST.at(curState);
    if (find(allowedOpt.begin(), allowedOpt.end(), opt) == allowedOpt.end()) {
        MEDIA_LOGE("The %{public}s operation is not allowed in the %{public}s state!", opt.c_str(), curState.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

int32_t AVTranscoderImpl::CheckRepeatOperation(const std::string &opt)
{
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    CHECK_AND_RETURN_RET_LOG(taiheCb != nullptr, MSERR_INVALID_OPERATION, "taiheCb is nullptr!");

    std::string curState = taiheCb->GetState();
    std::vector<std::string> repeatOpt = STATE_CTRL.at(curState);
    if (find(repeatOpt.begin(), repeatOpt.end(), opt) != repeatOpt.end()) {
        MEDIA_LOGI("Current state is %{public}s. Please do not call %{public}s again!",
            curState.c_str(), opt.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

void AVTranscoderImpl::PrepareSync(AVTranscoderConfig const& config)
{
    MediaTrace trace("AVTransCoder::TaihePrepare");
    const std::string &opt = AVTransCoderOpt::PREPARE;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder->taskQue_ != nullptr, "taskQue is nullptr!");

    RetInfo retInfo;
    if (CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->avTransCoder->GetConfig(asyncCtx, config) == MSERR_OK) {
            asyncCtx->task_ = AVTranscoderImpl::GetPrepareTask(asyncCtx);
            (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVTransCoderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    auto t1 = std::thread([asyncCtx = std::move(asyncCtx)]() {
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The taihe thread of prepare finishes execution and returns");
    });
    t1.detach();
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return;
}

std::shared_ptr<TaskHandler<RetInfo>> AVTranscoderImpl::GetPrepareTask(
    std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>(
        [avTransCoder = asyncCtx->avTransCoder, config = asyncCtx->config_]() {
        const std::string &option = AVTransCoderOpt::PREPARE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(avTransCoder != nullptr && avTransCoder->transCoder_ != nullptr && config != nullptr,
            GetReturnRet(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(avTransCoder->CheckStateMachine(option) == MSERR_OK,
            GetReturnRet(MSERR_INVALID_OPERATION, option, ""));

        RetInfo retinfo = avTransCoder->Configure(config);
        CHECK_AND_RETURN_RET(retinfo.first == MSERR_OK, ((void)avTransCoder->transCoder_->Cancel(), retinfo));

        int32_t ret = avTransCoder->transCoder_->Prepare();
        CHECK_AND_RETURN_RET(ret == MSERR_OK,
            ((void)avTransCoder->transCoder_->Cancel(), GetReturnRet(ret, "Prepare", "")));

        avTransCoder->StateCallback(AVTransCoderState::STATE_PREPARED);
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

void AVTranscoderImpl::PauseSync()
{
    MediaTrace trace("AVTransCoder::TaihePause");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::PAUSE);
}

void AVTranscoderImpl::ReleaseSync()
{
    MediaTrace trace("AVTransCoder::TaiheRelease");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::RELEASE);
}

void AVTranscoderImpl::StartSync()
{
    MediaTrace trace("AVTransCoder::TaiheStart");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::START);
}

void AVTranscoderImpl::ResumeSync()
{
    MediaTrace trace("AVTransCoder::TaiheResume");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::RESUME);
}

void AVTranscoderImpl::CancelSync()
{
    MediaTrace trace("AVTransCoder::TaiheCancel");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::CANCEL);
}

void AVTranscoderImpl::ExecuteByPromise(AVTranscoderImpl *taihe, const std::string &opt)
{
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder != nullptr, "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_LOG(asyncCtx->avTransCoder->taskQue_ != nullptr, "taskQue is nullptr!");

    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    if (asyncCtx->avTransCoder->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVTranscoderImpl::GetPromiseTask(asyncCtx->avTransCoder, opt);
        (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVTransCoderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    auto t1 = std::thread([asyncCtx = std::move(asyncCtx)]() {
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The taihe thread of prepare finishes execution and returns");
    });
    t1.detach();
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return;
}

std::shared_ptr<TaskHandler<RetInfo>> AVTranscoderImpl::GetPromiseTask(AVTranscoderImpl *taihe, const std::string &opt)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe, option = opt]() {
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(taihe != nullptr && taihe->transCoder_ != nullptr,
            GetReturnRet(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetReturnRet(MSERR_INVALID_OPERATION, option, ""));
        
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

void AVTranscoderImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVTranscoderImpl::OnError");
    MEDIA_LOGI("OnError Start");

    std::string callbackName = AVTransCoderState::STATE_ERROR;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnError End");
}

void AVTranscoderImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVTranscoderImpl::OffError");
    MEDIA_LOGI("OffError Start");

    std::string callbackName = AVTransCoderState::STATE_ERROR;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffError End");
}

void AVTranscoderImpl::OnComplete(callback_view<void(uintptr_t)> callback)
{
    MediaTrace trace("AVTranscoderImpl::OnComplete");
    MEDIA_LOGI("OnComplete Start");

    std::string callbackName = AVTransCoderState::STATE_COMPLETED;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnComplete End");
}

void AVTranscoderImpl::OffComplete(optional_view<callback<void(uintptr_t)>> callback)
{
    MediaTrace trace("AVTranscoderImpl::OffComplete");
    MEDIA_LOGI("OffComplete Start");

    std::string callbackName = AVTransCoderState::STATE_COMPLETED;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffComplete End");
}

void AVTranscoderImpl::OnProgressUpdate(callback_view<void(double)> callback)
{
    MediaTrace trace("AVTranscoderImpl::OnProgressUpdate");
    MEDIA_LOGI("OnProgressUpdate Start");

    std::string callbackName = STATE_PROGRESSUPDATE;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(double)>> taiheCallback =
            std::make_shared<taihe::callback<void(double)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnProgressUpdate End");
}

void AVTranscoderImpl::OffProgressUpdate(optional_view<callback<void(double)>> callback)
{
    MediaTrace trace("AVTranscoderImpl::OffProgressUpdate");
    MEDIA_LOGI("OffProgressUpdate Start");

    std::string callbackName = STATE_PROGRESSUPDATE;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffProgressUpdate End");
}

RetInfo AVTranscoderImpl::Configure(std::shared_ptr<AVTransCoderConfigInner> config)
{
    CHECK_AND_RETURN_RET(transCoder_ != nullptr, GetReturnRet(MSERR_INVALID_OPERATION, "Configure", ""));
    CHECK_AND_RETURN_RET(config != nullptr, GetReturnRet(MSERR_INVALID_VAL, "Configure", "config"));

    if (hasConfiged_) {
        MEDIA_LOGE("AVTransCoderConfig has been configured and will not be configured again");
        return RetInfo(MSERR_EXT_API9_OK, "");
    }

    int32_t ret = transCoder_->SetOutputFormat(config->fileFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetOutputFormat", "fileFormat"));

    ret = transCoder_->SetAudioEncoder(config->audioCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetAudioEncoder", "audioCodecFormat"));
    
    ret = transCoder_->SetAudioEncodingBitRate(config->audioBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetAudioEncoderBitRate", "audioBitrate"));
    
    ret = transCoder_->SetVideoEncoder(config->videoCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoEncoder", "videoCodecFormat"));
    
    ret = transCoder_->SetVideoSize(config->videoFrameWidth, config->videoFrameHeight);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoSize", "videoSize"));
    
    ret = transCoder_->SetVideoEncodingBitRate(config->videoBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoEncoderBitRate", "videoBitrate"));

    hasConfiged_ = true;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

int32_t AVTranscoderImpl::GetConfig(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx,
    AVTranscoderConfig const& config)
{
    asyncCtx->config_ = std::make_shared<AVTransCoderConfigInner>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (asyncCtx->AVTransCoderSignError(MSERR_NO_MEMORY, "AVTransCoderConfig", "AVTransCoderConfig"),
            MSERR_NO_MEMORY));

    std::shared_ptr<AVTransCoderConfigInner> configInner = asyncCtx->config_;

    int32_t ret = GetAudioConfig(config, asyncCtx);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetAudioConfig");

    ret = GetVideoConfig(config, asyncCtx);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetVideoConfig");

    std::string fileFormat = static_cast<std::string>(config.fileFormat.get_value());
    ret = GetOutputFormat(fileFormat, configInner->fileFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (asyncCtx->AVTransCoderSignError(ret, "GetOutputFormat", "fileFormat"), ret));

    return MSERR_OK;
}

int32_t AVTranscoderImpl::GetOutputFormat(const std::string &extension, OutputFormatType &type)
{
    MEDIA_LOGI("mime %{public}s", extension.c_str());
    const std::map<std::string, OutputFormatType> extensionToOutputFormat = {
        { "mp4", OutputFormatType::FORMAT_MPEG_4 },
        { "m4a", OutputFormatType::FORMAT_M4A },
        { "", OutputFormatType::FORMAT_DEFAULT },
    };

    auto iter = extensionToOutputFormat.find(extension);
    if (iter != extensionToOutputFormat.end()) {
        type = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVTranscoderImpl::GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, AudioCodecFormat> mimeStrToCodecFormat = {
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
        { "", AudioCodecFormat::AUDIO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVTranscoderImpl::GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, VideoCodecFormat> mimeStrToCodecFormat = {
        { OHOS::MediaAVCodec::CodecMimeType::VIDEO_AVC, VideoCodecFormat::H264 },
        { OHOS::MediaAVCodec::CodecMimeType::VIDEO_HEVC, VideoCodecFormat::H265 },
        { "", VideoCodecFormat::VIDEO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVTranscoderImpl::GetAudioConfig(AVTranscoderConfig const& config,
    std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx)
{
    std::shared_ptr<AVTransCoderConfigInner> configInner = asyncCtx->config_;
    std::string audioCodec;
    if (config.audioCodec.has_value()) {
        audioCodec = static_cast<std::string>(config.audioCodec.value());
    }
    (void)GetAudioCodecFormat(audioCodec, configInner->audioCodecFormat);
    if (config.audioBitrate.has_value()) {
        configInner->audioBitrate = config.audioBitrate.value();
    }
    return MSERR_OK;
}

int32_t AVTranscoderImpl::GetVideoConfig(AVTranscoderConfig const& config,
    std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx)
{
    std::shared_ptr<AVTransCoderConfigInner> configInner = asyncCtx->config_;
    std::string videoCodec;
    if (config.videoCodec.has_value()) {
        videoCodec = static_cast<std::string>(config.videoCodec.value());
    }
    (void)GetVideoCodecFormat(videoCodec, configInner->videoCodecFormat);
    if (config.videoBitrate.has_value()) {
        configInner->videoBitrate = config.videoBitrate.value();
    }
    if (config.videoFrameWidth.has_value()) {
        configInner->videoFrameWidth = config.videoFrameWidth.value();
    }
    if (config.videoFrameHeight.has_value()) {
        configInner->videoFrameHeight = config.videoFrameHeight.value();
    }
    return MSERR_OK;
}

void AVTransCoderAsyncContext::SignError(int32_t code, const std::string &message, bool del)
{
    errMessage = message;
    errCode = code;
    errFlag = true;
    delFlag = del;
    MEDIA_LOGE("SignError: %{public}s", message.c_str());
    set_business_error(errCode, errMessage);
}

void AVTranscoderImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void AVTranscoderImpl::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto taiheCb = std::static_pointer_cast<AVTransCoderCallback>(transCoderCb_);
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVTranscoderSync(CreateAVTranscoderSync);