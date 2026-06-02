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
#include "pixel_map_taihe.h"

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
const std::unordered_map<AudioCodecFormat, std::set<OutputFormatType>> AUDIO_MUX_FORMAT_INFO = {
    {AudioCodecFormat::AAC_LC, {OutputFormatType::FORMAT_MPEG_4, OutputFormatType::FORMAT_M4A,
        OutputFormatType::FORMAT_AAC}},
    {AudioCodecFormat::AUDIO_MPEG, {OutputFormatType::FORMAT_MPEG_4, OutputFormatType::FORMAT_MP3}},
    {AudioCodecFormat::AUDIO_AMR_NB, {OutputFormatType::FORMAT_AMR}},
    {AudioCodecFormat::AUDIO_AMR_WB, {OutputFormatType::FORMAT_AMR}},
    {AudioCodecFormat::AUDIO_RAW, {OutputFormatType::FORMAT_WAV}},
    {AudioCodecFormat::AUDIO_DEFAULT, {OutputFormatType::FORMAT_MPEG_4, OutputFormatType::FORMAT_M4A,
        OutputFormatType::FORMAT_AAC}},
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

int32_t AVTranscoderImpl::GetFdDst()
{
    MediaTrace trace("AVTranscoderImpl::get url");
    MEDIA_LOGD("TaiheGetUrl Out Current Url: %{public}s", srcUrl_.c_str());
    return dstFd_;
}

void AVTranscoderImpl::SetFdDst(int32_t fdDst)
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
    fdSrc.offset = optional<int64_t>(std::in_place_t{}, srcFd_.offset);
    fdSrc.length = optional<int64_t>(std::in_place_t{}, srcFd_.length);
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
    if (STATE_CTRL.find(curState) == STATE_CTRL.end()) {
        MEDIA_LOGI("Invalid state: %{public}s.", curState.c_str());
        return MSERR_INVALID_OPERATION;
    }
    std::vector<std::string> repeatOpt = STATE_CTRL.at(curState);
    if (find(repeatOpt.begin(), repeatOpt.end(), opt) != repeatOpt.end()) {
        MEDIA_LOGI("Current state is %{public}s. Please do not call %{public}s again!",
            curState.c_str(), opt.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

uintptr_t AVTranscoderImpl::PrepareSync(AVTranscoderConfig const& config)
{
    MediaTrace trace("AVTransCoder::TaihePrepare");
    const std::string &opt = AVTransCoderOpt::PREPARE;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder->taskQue_ != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "taskQue is nullptr!");

    asyncCtx->ConfigContextEnv();
    RetInfo retInfo;
    if (CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->avTransCoder->GetConfig(asyncCtx, config) == MSERR_OK) {
            asyncCtx->task_ = AVTranscoderImpl::GetPrepareTask(asyncCtx);
            (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVTransCoderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    ani_object promiseValue = asyncCtx->promise_;
    std::thread([asyncCtx = std::move(asyncCtx)]() {
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        RetInfo taiheRet = std::make_pair<int32_t, std::string>(0, "");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The taihe thread of prepare finishes execution and returns");
        asyncCtx->CompleteCallback(taiheRet);
    }).detach();
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return reinterpret_cast<uintptr_t>(promiseValue);
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

uintptr_t AVTranscoderImpl::PauseSync()
{
    MediaTrace trace("AVTransCoder::TaihePause");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::PAUSE);
}

uintptr_t AVTranscoderImpl::ReleaseSync()
{
    MediaTrace trace("AVTransCoder::TaiheRelease");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::RELEASE);
}

uintptr_t AVTranscoderImpl::StartSync()
{
    MediaTrace trace("AVTransCoder::TaiheStart");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::START);
}

uintptr_t AVTranscoderImpl::ResumeSync()
{
    MediaTrace trace("AVTransCoder::TaiheResume");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::RESUME);
}

uintptr_t AVTranscoderImpl::CancelSync()
{
    MediaTrace trace("AVTransCoder::TaiheCancel");
    AVTranscoderImpl *transcoder = this;
    return ExecuteByPromise(transcoder, AVTransCoderOpt::CANCEL);
}

uintptr_t AVTranscoderImpl::ExecuteByPromise(AVTranscoderImpl *taihe, const std::string &opt)
{
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder->taskQue_ != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "taskQue is nullptr!");

    asyncCtx->ConfigContextEnv();
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());
    if (asyncCtx->avTransCoder->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVTranscoderImpl::GetPromiseTask(asyncCtx->avTransCoder, opt);
        (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVTransCoderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    ani_object promiseValue = asyncCtx->promise_;
    std::thread([asyncCtx = std::move(asyncCtx)]() {
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        RetInfo taiheRet = std::make_pair<int32_t, std::string>(0, "");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The taihe thread of prepare finishes execution and returns");
        asyncCtx->CompleteCallback(taiheRet);
    }).detach();
    asyncCtx.release();

    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return reinterpret_cast<uintptr_t>(promiseValue);
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

void AVTranscoderImpl::OnProgressUpdate(callback_view<void(int32_t)> callback)
{
    MediaTrace trace("AVTranscoderImpl::OnProgressUpdate");
    MEDIA_LOGI("OnProgressUpdate Start");

    std::string callbackName = STATE_PROGRESSUPDATE;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(int32_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(int32_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("OnProgressUpdate End");
}

void AVTranscoderImpl::OffProgressUpdate(optional_view<callback<void(int32_t)>> callback)
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

    AudioCodecFormat outputAudioCodec = isAudioV2Valid ? config->audioCodecFormatV2 : config->audioCodecFormat;
    ret = transCoder_->SetAudioEncoder(outputAudioCodec);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetAudioEncoder", "audioCodecFormat"));
    
    ret = transCoder_->SetAudioEncodingBitRate(config->audioBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetAudioEncoderBitRate", "audioBitrate"));
    
    ret = transCoder_->SetVideoEncoder(config->videoCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoEncoder", "videoCodecFormat"));
    
    ret = transCoder_->SetVideoSize(config->videoFrameWidth, config->videoFrameHeight);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoSize", "videoSize"));
    
    ret = transCoder_->SetVideoEncodingBitRate(config->videoBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoEncoderBitRate", "videoBitrate"));

    ret = transCoder_->SetEnableBFrame(config->enableBFrame);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret, "SetVideoEncoderEnableBFrame", "enableBFrame"));

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
    if (isAudioV2Valid) {
        CHECK_AND_RETURN_RET(CanAddTrack(configInner->audioCodecFormatV2, configInner->fileFormat),
            (asyncCtx->AVTransCoderSignError(MSERR_INVALID_VAL, "GetOutputFormat", "fileFormat"), MSERR_INVALID_VAL));
    } else {
        CHECK_AND_RETURN_RET(CanAddTrack(AudioCodecFormat::AAC_LC, configInner->fileFormat),
            (asyncCtx->AVTransCoderSignError(MSERR_INVALID_VAL, "GetOutputFormat", "fileFormat"), MSERR_INVALID_VAL));
        CHECK_AND_RETURN_RET(configInner->fileFormat != OutputFormatType::FORMAT_AAC,
            (asyncCtx->AVTransCoderSignError(MSERR_INVALID_VAL, "GetOutputFormat", "fileFormat"), MSERR_INVALID_VAL));
    }

    return MSERR_OK;
}

int32_t AVTranscoderImpl::GetOutputFormat(const std::string &extension, OutputFormatType &type)
{
    MEDIA_LOGI("mime %{public}s", extension.c_str());
    const std::map<std::string, OutputFormatType> extensionToOutputFormat = {
        { "mp4", OutputFormatType::FORMAT_MPEG_4 },
        { "m4a", OutputFormatType::FORMAT_M4A },
        { "amr", OutputFormatType::FORMAT_AMR },
        { "mp3", OutputFormatType::FORMAT_MP3 },
        { "aac", OutputFormatType::FORMAT_AAC },
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

bool AVTranscoderImpl::CanAddTrack(const AudioCodecFormat &audioType, const OutputFormatType &muxerType)
{
    auto it = AUDIO_MUX_FORMAT_INFO.find(static_cast<AudioCodecFormat>(audioType));
    if (it == AUDIO_MUX_FORMAT_INFO.end()) {
        return false;
    }
    return it->second.find(muxerType) != it->second.end();
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

int32_t AVTranscoderImpl::GetAudioCodecFormatV2(const std::string &mime, AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, AudioCodecFormat> mimeStrToCodecFormat = {
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_NB, AudioCodecFormat::AUDIO_AMR_NB },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_AMR_WB, AudioCodecFormat::AUDIO_AMR_WB },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_MPEG, AudioCodecFormat::AUDIO_MPEG },
        { OHOS::MediaAVCodec::CodecMimeType::AUDIO_RAW, AudioCodecFormat::AUDIO_RAW },
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
    std::string audioCodecV2;
    if (config.audioCodec.has_value()) {
        audioCodec = static_cast<std::string>(config.audioCodec.value());
    }
    if (config.audioCodecV2.has_value()) {
        audioCodecV2 = static_cast<std::string>(config.audioCodecV2.value());
    }
    (void)GetAudioCodecFormat(audioCodec, configInner->audioCodecFormat);
    int32_t ret = GetAudioCodecFormatV2(audioCodecV2, configInner->audioCodecFormatV2);
    isAudioV2Valid = !audioCodecV2.empty();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to set audioCodecV2");
    if (isAudioV2Valid) {
        MEDIA_LOGI("audio encoder mime is v2 %{public}s", audioCodecV2.c_str());
    } else {
        MEDIA_LOGI("audio encoder mime is %{public}s", audioCodec.c_str());
    }
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
    if (config.enableBFrame.has_value()) {
        configInner->enableBFrame = config.enableBFrame.value();
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

AVTransCoderAsyncContext::~AVTransCoderAsyncContext()
{
}

ani_env* AVTransCoderAsyncContext::GetCurrentEnv(ani_vm *vm, bool &isAttach)
{
    CHECK_AND_RETURN_RET_LOG(vm != nullptr, nullptr, "null vm");

    ani_env *threadEnv;
    ani_status getEnvStatus = vm->GetEnv(ANI_VERSION_1, &threadEnv);
    
    if (getEnvStatus != ANI_OK) {
        MEDIA_LOGE("GetEnv failed, AttachCurrentThread");
        ani_options aniArgs {0, nullptr};
        ani_status status = vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &threadEnv);
        CHECK_AND_RETURN_RET_LOG(status == ANI_OK, nullptr,
            "GetCurrentEnv failed, all attachment attempts failed, status(%{public}d)", status);

        isAttach = true;
    }
    return threadEnv;
}

void AVTransCoderAsyncContext::ConfigContextEnv()
{
    env_ = taihe::get_env();
    CHECK_AND_RETURN_LOG(env_ != nullptr, "taihe env is null");

    ani_vm *etsVm;
    auto status = env_->GetVM(&etsVm);
    CHECK_AND_RETURN_LOG(status == ANI_OK, "GetVM failed, status: %{public}d", status);

    etsVm_ = etsVm;
    status = env_->Promise_New(&bindDeferred_, &promise_);
    CHECK_AND_RETURN_LOG(status == ANI_OK, "Promise_New failed, status: %{public}d", status);
}

void AVTransCoderAsyncContext::CompleteCallback(RetInfo& result)
{
    if (etsVm_ == nullptr) {
        MEDIA_LOGE("CompleteCallback: etsVm_ is nullptr");
        return;
    }
    
    ani_env *threadEnv = GetCurrentEnv(etsVm_, isAttach_);
    if (threadEnv == nullptr) {
        MEDIA_LOGE("taihe get current env is nullptr");
        return;
    }

    ani_size nr_refs = 16;
    threadEnv->CreateLocalScope(nr_refs);
    ani_ref err = nullptr;
    if (errCode == 0) {
        if (!result.second.empty()) {
            err = GetTaiheResult(threadEnv, result);
        } else {
            threadEnv->GetNull(&err);
        }
        auto status = threadEnv->PromiseResolver_Resolve(bindDeferred_, err);
        if (status != ANI_OK) {
            MEDIA_LOGE("PromiseResolver_Resolve failed, status: %{public}d", status);
        }
    } else {
        err = MediaTaiheUtils::ToBusinessError(threadEnv, errCode, errMessage);
        auto status = threadEnv->PromiseResolver_Reject(bindDeferred_, reinterpret_cast<ani_error>(err));
        if (status != ANI_OK) {
            MEDIA_LOGE("PromiseResolver_Reject failed, status: %{public}d", status);
        }
    }
    auto status = threadEnv->DestroyLocalScope();
    if (status != ANI_OK) {
        MEDIA_LOGE("DestroyLocalScope failed, status(%{public}d)", status);
    }

    if (isAttach_) {
        etsVm_->DetachCurrentThread();
    }
}

ani_ref AVTransCoderAsyncContext::GetTaiheResult(ani_env *threadEnv, RetInfo& result)
{
    std::string val = result.second;
    CHECK_AND_RETURN_RET_LOG(!val.empty(), nullptr, "result is null");
    ani_object taiheRet = IntToAniObject(threadEnv, static_cast<int32_t>(std::stoi(val)));
    return static_cast<ani_ref>(taiheRet);
}

ani_object AVTransCoderAsyncContext::IntToAniObject(ani_env *env, int32_t value)
{
    static constexpr const char *className = "std.core.Int";
    ani_object err {};
    ani_class cls {};
    CHECK_AND_RETURN_RET_LOG(env->FindClass(className, &cls) == ANI_OK, err,
        "find class %{public}s failed", "std.core.Int");
    ani_method ctor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(cls, "<ctor>", "i:", &ctor) == ANI_OK, err,
        "find method std.core.Int constructor failed");
    ani_object intObject {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(cls, ctor, &intObject, static_cast<ani_int>(value)) == ANI_OK, err,
        "new object %{public}s failed", "std.core.Int");
    return intObject;
}

uintptr_t AVTranscoderImpl::AddWatermarkSync(::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfiguration const& config)
{
    MediaTrace trace("AVTransCoder::TaiheAddWatermark");
    const std::string &opt = AVTransCoderOpt::ADD_WATERMARK;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVTransCoderAsyncContext>();
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to get AsyncContext");
    asyncCtx->avTransCoder = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "failed to GetTaiheInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->avTransCoder->taskQue_ != nullptr,
        reinterpret_cast<uintptr_t>(nullptr), "taskQue is nullptr!");
    asyncCtx->ConfigContextEnv();

    if (asyncCtx->avTransCoder->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->avTransCoder->GetWatermarkParameter(asyncCtx, watermark, config) == MSERR_OK) {
            asyncCtx->task_ = AVTranscoderImpl::AddWatermarkTask(asyncCtx);
            (void)asyncCtx->avTransCoder->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVTransCoderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    ani_object promiseValue = asyncCtx->promise_;
    std::thread([asyncCtx = std::move(asyncCtx)]() {
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        RetInfo taiheRet = std::make_pair<int32_t, std::string>(0, "");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
            taiheRet = result.Value();
        }
        MEDIA_LOGI("The taihe thread of AddWatermark finishes execution and returns");
        asyncCtx->CompleteCallback(taiheRet);
    }).detach();

    asyncCtx.release();
    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return reinterpret_cast<uintptr_t>(promiseValue);
}

std::shared_ptr<TaskHandler<RetInfo>> AVTranscoderImpl::AddWatermarkTask(
    const std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([avTransCoder = asyncCtx->avTransCoder,
        pixelMap = asyncCtx->pixelMap_, watermarkConfig = asyncCtx->watermarkConfig_]() mutable {
        const std::string &option = AVTransCoderOpt::ADD_WATERMARK;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(avTransCoder != nullptr, GetReturnRet(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(avTransCoder->CheckStateMachine(option) == MSERR_OK,
            GetReturnRet(MSERR_INVALID_OPERATION, option, ""));

        int32_t ret = avTransCoder->AddWatermark(pixelMap, watermarkConfig);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetReturnRet(ret, "AddWatermarkTask", ""),
            "AddWatermarkTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        if (avTransCoder->watermarkCount_ <= AVTRANSCODER_WATERMARK_MAX_NUM) {
            avTransCoder->watermarkCount_++;
        }
        MEDIA_LOGI("%{public}s End, watermark count: %{public}d", option.c_str(), avTransCoder->watermarkCount_);
        return RetInfo(MSERR_EXT_API9_OK, std::to_string(avTransCoder->watermarkCount_));
    });
}

int32_t AVTranscoderImpl::AddWatermark(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap,
    std::shared_ptr<OHOS::Media::WatermarkConfiguration> &watermarkConfig)
{
    MEDIA_LOGI("pixelMap Width %{public}d, height %{public}d, pixelformat %{public}d, RowStride %{public}d",
        pixelMap->GetWidth(), pixelMap->GetHeight(), pixelMap->GetPixelFormat(), pixelMap->GetRowStride());
    CHECK_AND_RETURN_RET_LOG(pixelMap->GetPixelFormat() == OHOS::Media::PixelFormat::RGBA_8888, MSERR_INVALID_VAL,
        "Invalid pixel format");
    size_t dataSize = pixelMap->GetHeight() * pixelMap->GetRowStride();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    auto buffer = AVBuffer::CreateAVBuffer(allocator, dataSize);
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MSERR_INVALID_VAL, "Create buffer failed");
    buffer->memory_->Write(pixelMap->GetPixels(), dataSize, 0);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_X>(watermarkConfig->left);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_Y>(watermarkConfig->top);
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_W>(pixelMap->GetWidth());
    buffer->meta_->Set<Tag::VIDEO_COORDINATE_H>(pixelMap->GetHeight());
    buffer->meta_->Set<Tag::VIDEO_STRIDE>(pixelMap->GetRowStride());
    return transCoder_->AddWatermark(buffer, watermarkConfig->width, watermarkConfig->height);
}

int32_t AVTranscoderImpl::GetWatermarkParameter(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx,
    ::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfiguration const& config)
{
    int32_t ret = GetWatermark(asyncCtx, watermark);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermark");

    ret = GetWatermarkConfig(asyncCtx, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermarkConfig");

    return MSERR_OK;
}

int32_t AVTranscoderImpl::GetWatermark(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx,
    ::ohos::multimedia::image::image::weak::PixelMap watermark)
{
    asyncCtx->pixelMap_ = Image::PixelMapImpl::GetPixelMap(watermark);
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_ != nullptr,
        (asyncCtx->AVTransCoderSignError(MSERR_INVALID_VAL, "GetWatermark", "pixelMap"), MSERR_INVALID_VAL));
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_->GetWidth() > 0
        && asyncCtx->pixelMap_->GetWidth() <= AVTRANSCODER_WATERMARK_MAX_LENGTH,
        (asyncCtx->AVTransCoderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermark", "pixelMap Width",
        "width of pixelmap must be greater than zero and less than 4097"), MSERR_PARAMETER_VERIFICATION_FAILED));
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_->GetHeight() > 0
        && asyncCtx->pixelMap_->GetHeight() <= AVTRANSCODER_WATERMARK_MAX_LENGTH,
        (asyncCtx->AVTransCoderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermark", "pixelMap Height",
        "height of pixelmap must be greater than zero and less than 4097"), MSERR_PARAMETER_VERIFICATION_FAILED));
    return MSERR_OK;
}

int32_t AVTranscoderImpl::GetWatermarkConfig(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::WatermarkConfiguration const& config)
{
    asyncCtx->watermarkConfig_ = std::make_shared<OHOS::Media::WatermarkConfiguration>();
    CHECK_AND_RETURN_RET(asyncCtx->watermarkConfig_,
        (asyncCtx->AVTransCoderSignError(MSERR_NO_MEMORY, "GetWatermarkConfig", "WatermarkConfiguration"),
            MSERR_NO_MEMORY));

    asyncCtx->watermarkConfig_->top = config.top;
    asyncCtx->watermarkConfig_->left = config.left;

    std::shared_ptr<OHOS::Media::WatermarkConfiguration> watermarkConfig = asyncCtx->watermarkConfig_;

    MEDIA_LOGI("watermarkConfig_ top %{public}d, left %{public}d, width %{public}d, height %{public}d",
        config.top, config.left, config.width.value_or(-1), config.height.value_or(-1));
    int32_t inputWidth = config.width.value_or(-1);
    int32_t inputHeight = config.height.value_or(-1);

    if (config.width.has_value()) {
        CHECK_AND_RETURN_RET(inputWidth > 0 && inputWidth <= AVTRANSCODER_WATERMARK_MAX_LENGTH,
            (asyncCtx->AVTransCoderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "width",
            "width of watermarkConfig must be greater than zero and less than 4097"),
            MSERR_PARAMETER_VERIFICATION_FAILED));
    }

    if (config.height.has_value()) {
        CHECK_AND_RETURN_RET(inputHeight > 0 && inputHeight <= AVTRANSCODER_WATERMARK_MAX_LENGTH,
            (asyncCtx->AVTransCoderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "height",
            "height of watermarkConfig must be greater than zero and less than 4097"),
             MSERR_PARAMETER_VERIFICATION_FAILED));
    }
    asyncCtx->watermarkConfig_->width = config.width.value_or(-1);
    asyncCtx->watermarkConfig_->height = config.height.value_or(-1);

    return MSERR_OK;
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVTranscoderSync(CreateAVTranscoderSync);